import readline from "readline";
import {
  Account,
  Address,
  Chain,
  createPublicClient,
  decodeEventLog,
  decodeFunctionData,
  encodeAbiParameters,
  encodeFunctionData,
  formatEther,
  getAddress,
  hexToBytes,
  isAddressEqual,
  Log,
  PublicClient,
  stringToHex,
  toHex,
  Transport,
  WalletClient,
} from "viem";
import {
  createBundlerClient,
  entryPoint06Abi,
  entryPoint06Address,
  toCoinbaseSmartAccount,
} from "viem/account-abstraction";
import { coinbaseSmartWalletAbi } from "./abi/CoinbaseSmartWallet";
import { coinbaseSmartWalletFactoryAbi } from "./abi/coinbaseSmartWalletFactory";
import { logger } from "./logger";

// ============================================================================
// P256/WebAuthn Signature Utilities
// ============================================================================

// P256 curve order - needed for signature normalization
const P256_N = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);
const P256_N_DIV_2 = P256_N / BigInt(2);

/**
 * Parse ASN.1 DER encoded P256 signature and normalize to low-s form.
 * WebAuthn.sol rejects signatures where s > P256_N / 2 (malleability protection).
 */
export function parseAsn1Signature(bytes: Uint8Array): {
  r: bigint;
  s: bigint;
} {
  // ASN.1 DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
  let offset = 2; // Skip sequence header (0x30 [length])

  // Parse r
  if (bytes[offset] !== 0x02) throw new Error("Expected integer tag for r");
  offset++;
  const rLength = bytes[offset];
  offset++;
  const rStart = bytes[offset] === 0x00 ? offset + 1 : offset;
  const rEnd = offset + rLength;
  const rBytes = bytes.slice(rStart, rEnd);
  offset = rEnd;

  // Parse s
  if (bytes[offset] !== 0x02) throw new Error("Expected integer tag for s");
  offset++;
  const sLength = bytes[offset];
  offset++;
  const sStart = bytes[offset] === 0x00 ? offset + 1 : offset;
  const sEnd = offset + sLength;
  const sBytes = bytes.slice(sStart, sEnd);

  // Pad to 32 bytes if needed
  const rPadded = new Uint8Array(32);
  const sPadded = new Uint8Array(32);
  rPadded.set(rBytes, 32 - rBytes.length);
  sPadded.set(sBytes, 32 - sBytes.length);

  let r = BigInt(toHex(rPadded));
  let s = BigInt(toHex(sPadded));

  // CRITICAL: Normalize s to low-s form
  // WebAuthn.sol rejects signatures where s > P256_N / 2 (malleability protection)
  if (s > P256_N_DIV_2) {
    s = P256_N - s;
  }

  return { r, s };
}

export interface WebAuthnResponse {
  authenticatorData: `0x${string}`;
  clientDataJSON: string;
  signature: `0x${string}`;
}

// WebAuthnAuth struct definition matching the smart contract
const WebAuthnAuthStruct = {
  components: [
    { name: "authenticatorData", type: "bytes" },
    { name: "clientDataJSON", type: "bytes" },
    { name: "challengeIndex", type: "uint256" },
    { name: "typeIndex", type: "uint256" },
    { name: "r", type: "uint256" },
    { name: "s", type: "uint256" },
  ],
  name: "WebAuthnAuth",
  type: "tuple",
} as const;

// SignatureWrapper struct definition
const SignatureWrapperStruct = {
  components: [
    { name: "ownerIndex", type: "uint256" },
    { name: "signatureData", type: "bytes" },
  ],
  name: "SignatureWrapper",
  type: "tuple",
} as const;

/**
 * Build a WebAuthn signature for CoinbaseSmartWallet.
 * Encodes the WebAuthn response into the format expected by the contract.
 */
export function buildWebAuthnSignature(
  response: WebAuthnResponse,
  ownerIndex: bigint = BigInt(0)
): `0x${string}` {
  const { r, s } = parseAsn1Signature(hexToBytes(response.signature));

  // clientDataJSON is already a UTF-8 string, find indices before encoding
  const challengeIndex = response.clientDataJSON.indexOf('"challenge":');
  const typeIndex = response.clientDataJSON.indexOf('"type":');

  // Encode the WebAuthn signature data
  // clientDataJSON must be encoded as bytes (hex of UTF-8 string)
  const webAuthnAuthBytes = encodeAbiParameters(
    [WebAuthnAuthStruct],
    [
      {
        authenticatorData: response.authenticatorData,
        clientDataJSON: stringToHex(response.clientDataJSON),
        challengeIndex: BigInt(challengeIndex),
        typeIndex: BigInt(typeIndex),
        r,
        s,
      },
    ]
  );

  // Wrap with SignatureWrapper struct (ownerIndex, signatureData)
  const wrappedSignature = encodeAbiParameters(
    [SignatureWrapperStruct],
    [
      {
        ownerIndex,
        signatureData: webAuthnAuthBytes,
      },
    ]
  );

  return wrappedSignature;
}

/**
 * Finds the index of the last passkey owner (non-address owner) in the smart account.
 * Address owners are padded to 32 bytes (0x + 24 zeros + 40 hex address = 66 chars).
 * Passkey owners are 64 bytes (0x + 128 hex chars = 130 chars) containing x,y coordinates.
 */
export async function findLastPasskeyOwnerIndex(
  client: ReturnType<typeof createPublicClient>,
  address: Address
): Promise<bigint> {
  const ownerCount = await client.readContract({
    abi: coinbaseSmartWalletAbi,
    functionName: "ownerCount",
    address,
  });

  let lastPasskeyIndex: bigint | null = null;

  for (let i = BigInt(0); i < ownerCount; i++) {
    const owner = await client.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "ownerAtIndex",
      address,
      args: [i],
    });

    // Padded address owners: 32 bytes with 12 leading zero bytes
    // Format: 0x000000000000000000000000 + 40 hex chars (20 byte address)
    if (owner.length > 66) {
      lastPasskeyIndex = i;
    }
  }

  if (lastPasskeyIndex === null) {
    throw new Error("No passkey owner found in smart account");
  }

  return lastPasskeyIndex;
}

// ============================================================================
// User Operation Utilities
// ============================================================================

// Default gas limits for when bundler estimation is not available
// These are conservative estimates for P256/WebAuthn verification
const DEFAULT_VERIFICATION_GAS_LIMIT = BigInt(2_000_000);
const DEFAULT_CALL_GAS_LIMIT = BigInt(500_000);
const DEFAULT_PRE_VERIFICATION_GAS = BigInt(100_000);

const DUMMY_SIGNATURE =
  "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001949fc7c88032b9fcb5f6efc7a7b8c63668eae9871b765e23123bb473ff57aa831a7c0d9276168ebcc29f2875a0239cffdf2a9cd1c2007c5c77c071db9264df1d000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273496a396e6164474850596759334b7156384f7a4a666c726275504b474f716d59576f4d57516869467773222c226f726967696e223a2268747470733a2f2f7369676e2e636f696e626173652e636f6d222c2263726f73734f726967696e223a66616c73657d00000000000000000000000000000000000000000000";

/**
 * Prepare a user operation with fallback to manual gas estimation.
 * Falls back if eth_estimateUserOperationGas is not available on the RPC.
 */
export async function prepareUserOperationWithFallback({
  bundlerClient,
  targetClient,
  smartAccount,
  calls,
}: {
  bundlerClient: ReturnType<typeof createBundlerClient>;
  targetClient: ReturnType<typeof createPublicClient>;
  smartAccount: Awaited<ReturnType<typeof toCoinbaseSmartAccount>>;
  calls: Parameters<typeof smartAccount.encodeCalls>[0];
}) {
  try {
    // Try the bundler's native estimation
    return await bundlerClient.prepareUserOperation({
      account: smartAccount,
      calls,
      initCode: "0x",
    });
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    // Check if the error is due to missing bundler RPC method
    if (
      !errorMessage.includes("does not exist") &&
      !errorMessage.includes("not available") &&
      !errorMessage.includes("eth_estimateUserOperationGas")
    ) {
      throw error;
    }

    logger.debug(
      "Bundler gas estimation not available, using fallback estimation..."
    );

    // Manual fallback: encode calls and estimate gas
    const callData = await smartAccount.encodeCalls(calls);
    const gasPrice = await targetClient.getGasPrice();
    const fees = await targetClient.estimateFeesPerGas();

    // Try to estimate call gas using eth_estimateGas
    let callGasLimit = DEFAULT_CALL_GAS_LIMIT;
    try {
      const estimatedGas = await targetClient.estimateGas({
        account: smartAccount.address,
        to: smartAccount.address,
        data: callData,
      });
      // Add buffer for execution overhead
      callGasLimit = (estimatedGas * BigInt(150)) / BigInt(100);
    } catch {
      logger.debug("Call gas estimation failed, using default");
    }

    return {
      sender: smartAccount.address,
      nonce: BigInt(0), // Will be set later
      initCode: "0x" as `0x${string}`,
      callData,
      callGasLimit,
      verificationGasLimit: DEFAULT_VERIFICATION_GAS_LIMIT,
      preVerificationGas: DEFAULT_PRE_VERIFICATION_GAS,
      maxFeePerGas: fees.maxFeePerGas || gasPrice,
      maxPriorityFeePerGas: fees.maxPriorityFeePerGas || gasPrice / BigInt(10),
      paymasterAndData: "0x" as `0x${string}`,
      signature: DUMMY_SIGNATURE as `0x${string}`,
    };
  }
}

export async function getUserOpFromCalldata({
  client,
  transactionHash,
  sender,
}: {
  client: PublicClient;
  transactionHash: `0x${string}`;
  sender: Address;
}) {
  const deployReceipt = await client.getTransactionReceipt({
    hash: transactionHash,
  });
  const deployTransaction = await client.getTransaction({
    hash: transactionHash,
  });

  const userOpEventLogs = deployReceipt.logs.filter((log) => {
    try {
      const event = decodeEventLog({
        abi: entryPoint06Abi,
        data: log.data,
        topics: log.topics,
      });
      return (
        event.eventName === "UserOperationEvent" &&
        isAddressEqual(event.args.sender, sender)
      );
    } catch (error) {
      return false;
    }
  });

  logger.debug(
    "userOpEventLogs",
    userOpEventLogs.map((log) =>
      decodeEventLog({
        abi: entryPoint06Abi,
        data: log.data,
        topics: log.topics,
      })
    )
  );

  const userOpEventLog = userOpEventLogs[0];

  if (!userOpEventLog) {
    throw new Error("User operation event not found");
  }

  const decodedEvent = decodeEventLog({
    abi: entryPoint06Abi,
    data: userOpEventLog.data,
    topics: userOpEventLog.topics,
  });

  if (decodedEvent.eventName !== "UserOperationEvent") {
    throw new Error("Invalid event name");
  }

  // Find userOp with hash
  const decodedCall = decodeFunctionData({
    abi: entryPoint06Abi,
    data: deployTransaction.input,
  });

  logger.debug("decodedCall", decodedCall);

  if (decodedCall.functionName !== "handleOps") {
    throw new Error("Transaction is not a handleOps call");
  }

  logger.debug(
    "decodedCall.args",
    JSON.stringify(
      decodedCall.args,
      (key, value) => (typeof value === "bigint" ? value.toString() : value),
      2
    )
  );

  const userOp = decodedCall.args[0].find((userOp: any) =>
    isAddressEqual(userOp.sender, sender)
  );

  if (!userOp) {
    throw new Error("User operation not found");
  }

  return userOp;
}

// Blockscout UserOps Indexer API response type
interface BlockscoutUserOpResponse {
  hash: string;
  sender: string;
  nonce: string;
  call_data: string;
  call_gas_limit: string;
  verification_gas_limit: string;
  pre_verification_gas: string;
  max_fee_per_gas: string;
  max_priority_fee_per_gas: string;
  signature: string;
  raw: {
    init_code: string;
    paymaster_and_data: string;
  };
  entry_point: string;
  transaction_hash: string;
  block_number: string;
  block_hash: string;
}

/**
 * Fetch a user operation from Blockscout UserOps Indexer API.
 * This replaces the bundler's eth_getUserOperationByHash RPC method.
 */
async function getUserOperationFromBlockscout({
  hash,
}: {
  hash: `0x${string}`;
}) {
  const response = await fetch(
    `https://user-ops-indexer-base-mainnet.k8s-prod-2.blockscout.com/api/v1/userOps/${hash}`
  );

  if (!response.ok) {
    throw new Error(
      `Failed to fetch user operation from Blockscout: ${response.status}`
    );
  }

  const data: BlockscoutUserOpResponse = await response.json();

  return {
    blockHash: data.block_hash as `0x${string}`,
    blockNumber: BigInt(data.block_number),
    entryPoint: data.entry_point as Address,
    transactionHash: data.transaction_hash as `0x${string}`,
    userOperation: {
      sender: data.sender as Address,
      nonce: BigInt(data.nonce),
      initCode: (data.raw.init_code || "0x") as `0x${string}`,
      callData: data.call_data as `0x${string}`,
      callGasLimit: BigInt(data.call_gas_limit),
      verificationGasLimit: BigInt(data.verification_gas_limit),
      preVerificationGas: BigInt(data.pre_verification_gas),
      maxFeePerGas: BigInt(data.max_fee_per_gas),
      maxPriorityFeePerGas: BigInt(data.max_priority_fee_per_gas),
      paymasterAndData: (data.raw.paymaster_and_data || "0x") as `0x${string}`,
      signature: data.signature as `0x${string}`,
    },
  };
}

export async function getUserOpsFromTransaction({
  client,
  transactionHash,
  sender,
}: {
  client: ReturnType<typeof createPublicClient>;
  transactionHash: `0x${string}`;
  sender?: Address;
}) {
  const deployReceipt = await client.getTransactionReceipt({
    hash: transactionHash,
  });

  const userOpEventLogs = deployReceipt.logs.filter((log) => {
    try {
      const event = decodeEventLog({
        abi: entryPoint06Abi,
        data: log.data,
        topics: log.topics,
      });
      return event.eventName === "UserOperationEvent";
    } catch (error) {
      return false;
    }
  });

  const userOps = await Promise.all(
    userOpEventLogs.map(async (log) => {
      const decodedEvent = decodeEventLog({
        abi: entryPoint06Abi,
        data: log.data,
        topics: log.topics,
      });

      if (decodedEvent.eventName !== "UserOperationEvent") {
        return null;
      }

      if (
        sender &&
        getAddress(decodedEvent.args.sender) !== getAddress(sender)
      ) {
        return null;
      }

      const userOp = await getUserOperationFromBlockscout({
        hash: decodedEvent.args.userOpHash,
      });

      return userOp;
    })
  );

  const filteredUserOps = userOps.filter((userOp) => userOp !== null);

  return filteredUserOps;
}

export async function promptUser(question: string): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

export async function syncSmartAccountOwners({
  baseClient,
  targetClient,
  targetWalletClient,
  address,
  passkeyMode = false,
}: {
  baseClient: PublicClient;
  targetClient: PublicClient;
  targetWalletClient: WalletClient<Transport, Chain, Account>;
  address: `0x${string}`;
  passkeyMode?: boolean;
}) {
  // Get all AddOwner events from Base using Blockscout API
  const response = await fetch(
    `https://base.blockscout.com/api/v2/addresses/${address}/logs`
  );
  const data = await response.json();

  // Map Blockscout response format and sort ascending by block number
  const logs = (data.items || []).map((log: any) => ({
    ...log,
    transactionHash: log.tx_hash,
  }));

  const addOwnerLogs = logs
    .filter((log: any) => {
      try {
        const event = decodeEventLog({
          abi: coinbaseSmartWalletAbi,
          data: log.data,
          topics: log.topics,
        });
        return event.eventName === "AddOwner";
      } catch (error) {
        return false;
      }
    })
    .map((log: any) => ({
      topics: log.topics,
      data: log.data,
      transactionHash: log.transaction_hash,
    }))
    .sort((a: any, b: any) => {
      const logA = decodeEventLog({
        abi: coinbaseSmartWalletAbi,
        data: a.data,
        topics: a.topics,
      });
      const logB = decodeEventLog({
        abi: coinbaseSmartWalletAbi,
        data: b.data,
        topics: b.topics,
      });

      if (logA.eventName !== "AddOwner" || logB.eventName !== "AddOwner") {
        return 0;
      }

      return Number(logA.args.index) - Number(logB.args.index);
    });

  logger.debug(
    "addOwnerLogs",
    addOwnerLogs.map((log: any) =>
      decodeEventLog({
        abi: coinbaseSmartWalletAbi,
        data: log.data,
        topics: log.topics,
      })
    )
  );

  if (!addOwnerLogs[0]) {
    throw new Error("No AddOwner logs found");
  }

  const deployTxHash = addOwnerLogs[0].transactionHash;

  logger.debug("deployTxHash", deployTxHash);

  const deployUserOp = await getUserOpFromCalldata({
    client: baseClient,
    transactionHash: deployTxHash,
    sender: address,
  });

  logger.debug("deployUserOp", deployUserOp);

  const isDeployed = await targetClient.getCode({
    address,
  });

  const initData = decodeFunctionData({
    abi: coinbaseSmartWalletFactoryAbi,
    data: ("0x" + deployUserOp.initCode.slice(42)) as `0x${string}`,
  });

  if (initData.functionName !== "createAccount") {
    throw new Error("Invalid init code");
  }

  const initialOwners = initData.args[0];

  // Get all replayable userOps from AddOwner transactions
  const addOwnerUserOps = await Promise.all(
    addOwnerLogs.map(async (log: Log) => {
      const userOps = await getUserOpsFromTransaction({
        transactionHash: log.transactionHash!,
        client: baseClient,
        sender: address,
      });

      // Replayable userOps have nonce key 8453
      const replayableUserOp = userOps.find(({ userOperation }) => {
        return userOperation.nonce >> BigInt(64) === BigInt(8453);
      });

      if (!replayableUserOp && log.transactionHash !== deployTxHash) {
        throw new Error(
          `No replayable userOp found for ${log.transactionHash}`
        );
      }

      return replayableUserOp;
    })
  );

  let nextAddOwnerIndex = initialOwners.length;

  logger.debug(
    `Account will be initialized with ${initialOwners.length} owners`
  );

  logger.debug("Deploy tx", {
    to: deployUserOp.initCode.slice(0, 42) as `0x${string}`,
    data: ("0x" + deployUserOp.initCode.slice(42)) as `0x${string}`,
  });

  if (isDeployed) {
    logger.info("Account already deployed");

    // Check how many owners and if indexes consistent with AddOwner events
    const ownerCount = await targetClient.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "ownerCount",
      address,
    });

    const ownerAtLastIndex = await targetClient.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "ownerAtIndex",
      address,
      args: [ownerCount - BigInt(1)],
    });

    logger.debug("Owner count on target chain", ownerCount);
    logger.debug("Owner at last index on target chain", ownerAtLastIndex);

    const baseOwnerAtSyncedIndex = decodeEventLog({
      abi: coinbaseSmartWalletAbi,
      data: addOwnerLogs[Number(ownerCount) - 1].data,
      topics: addOwnerLogs[Number(ownerCount) - 1].topics,
    });

    if (baseOwnerAtSyncedIndex.eventName !== "AddOwner") {
      throw new Error("Last AddOwner event is not valid");
    }

    if (ownerAtLastIndex !== baseOwnerAtSyncedIndex.args.owner) {
      throw new Error(
        `Owner at last index [${
          ownerCount - BigInt(1)
        }] does not match: ${ownerAtLastIndex} (target chain) !== ${
          baseOwnerAtSyncedIndex.args.owner
        } (Base)`
      );
    }

    nextAddOwnerIndex = Number(ownerCount);
  } else {
    logger.info("Account not deployed, deploying...");

    const deployTo = deployUserOp.initCode.slice(0, 42) as `0x${string}`;
    const deployData = ("0x" +
      deployUserOp.initCode.slice(42)) as `0x${string}`;

    // Estimate gas for deployment
    const estimatedGas = await targetClient.estimateGas({
      to: deployTo,
      data: deployData,
    });

    // Add 20% buffer
    const gasLimit = (estimatedGas * BigInt(120)) / BigInt(100);
    const gasPrice = await targetClient.getGasPrice();
    const requiredFunds = gasLimit * gasPrice;

    // Check bundler balance
    let bundlerBalance = await targetClient.getBalance({
      address: targetWalletClient.account!.address,
    });

    while (bundlerBalance < requiredFunds) {
      const shortfall = requiredFunds - bundlerBalance;
      const chain = targetWalletClient.chain;
      const symbol = chain?.nativeCurrency?.symbol || "ETH";

      logger.warn(`Bundler account needs funds for deployment!`);
      logger.info(`   Bundler: ${targetWalletClient.account!.address}`);
      logger.info(
        `   Current balance: ${formatEther(bundlerBalance)} ${symbol}`
      );
      logger.info(
        `   Required for deployment: ${formatEther(requiredFunds)} ${symbol}`
      );
      logger.info(`   Shortfall: ${formatEther(shortfall)} ${symbol}`);

      await promptUser(
        `\nPlease send at least ${formatEther(
          shortfall
        )} ${symbol} to the bundler address.\n[Press enter to check balance again]`
      );

      bundlerBalance = await targetClient.getBalance({
        address: targetWalletClient.account!.address,
      });
    }

    logger.debug(
      `Bundler has sufficient funds (${formatEther(bundlerBalance)} ${
        targetWalletClient.chain?.nativeCurrency?.symbol || "ETH"
      })`
    );

    // Deploy smart account
    const deployTx = await targetWalletClient.sendTransaction({
      to: deployTo,
      data: deployData,
      gas: gasLimit,
    });

    const receipt = await targetClient.waitForTransactionReceipt({
      hash: deployTx,
    });

    if (receipt.status !== "success") {
      throw new Error("Deployment failed");
    }

    logger.info(`Deployment successful (tx: ${deployTx})`);
  }

  logger.debug("Replaying from index", nextAddOwnerIndex);

  if (
    addOwnerUserOps.slice(nextAddOwnerIndex, nextAddOwnerIndex + 1).length === 0
  ) {
    return 0;
  }

  let userOpsToReplay = addOwnerUserOps
    .slice(nextAddOwnerIndex)
    .filter((op): op is NonNullable<typeof op> => op !== undefined)
    .map(({ userOperation }) => userOperation);

  // Check for Monad chain - UserOp replay is unreliable due to gas limit differences
  const MONAD_CHAIN_ID = 143;
  const targetChainId = await targetClient.getChainId();

  if (targetChainId === MONAD_CHAIN_ID && userOpsToReplay.length > 0) {
    logger.warn(`Monad chain detected (chainId: ${MONAD_CHAIN_ID})`);
    logger.info(
      `   Owner UserOp replay is disabled on Monad due to gas limit incompatibilities.`
    );
    logger.info(
      `   The callGasLimit from Base UserOps is often insufficient for Monad execution,`
    );
    logger.info(
      `   causing inner calls to run out of gas while still consuming the nonce.`
    );
    logger.info(
      `\n   Your account has been deployed with the INITIAL owners only:`
    );

    // Get and display initial owners
    const ownerCount = await targetClient.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "ownerCount",
      address,
    });

    for (let i = 0; i < Number(ownerCount); i++) {
      const owner = await targetClient.readContract({
        abi: coinbaseSmartWalletAbi,
        functionName: "ownerAtIndex",
        address,
        args: [BigInt(i)],
      });
      const ownerType = (owner as string).length === 66 ? "address" : "passkey";
      logger.info(`   - Owner ${i}: ${owner} (${ownerType})`);
    }

    logger.info(
      `\n   To add more owners on Monad, you must sign new transactions using`
    );
    logger.info(`   one of the initial owners listed above.`);
    logger.info(
      `\n   Skipping ${userOpsToReplay.length} owner operation(s) that would have been replayed.\n`
    );

    return ownerCount;
  }

  // In passkey mode, only replay up to and including the last addOwnerPublicKey call
  if (passkeyMode && userOpsToReplay.length > 0) {
    let lastAddOwnerPublicKeyIndex = -1;

    userOpsToReplay.forEach((userOp, index) => {
      const functionData = decodeFunctionData({
        abi: coinbaseSmartWalletAbi,
        data: userOp.callData,
      });

      if (functionData.functionName === "executeWithoutChainIdValidation") {
        const executeData = decodeFunctionData({
          abi: coinbaseSmartWalletAbi,
          data: `${functionData.args[0]}` as `0x${string}`,
        });

        if (executeData.functionName === "addOwnerPublicKey") {
          lastAddOwnerPublicKeyIndex = index;
        }
      }
    });

    if (lastAddOwnerPublicKeyIndex >= 0) {
      logger.debug(
        `Passkey mode: stopping at last addOwnerPublicKey call (replayableOps[${lastAddOwnerPublicKeyIndex}])`
      );
      userOpsToReplay = userOpsToReplay.slice(
        0,
        lastAddOwnerPublicKeyIndex + 1
      );
    } else {
      logger.debug(
        "Passkey mode: no addOwnerPublicKey calls found in pending ops, skipping replay"
      );
      userOpsToReplay = [];
    }
  }

  // Skip handleOps if no user ops to replay
  if (userOpsToReplay.length === 0) {
    logger.info("No user operations to replay, skipping handleOps");

    const ownerCount = await targetClient.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "ownerCount",
      address,
    });

    logger.info("Current owner count:", ownerCount, "\n");
    return ownerCount;
  }

  logger.info(`Replaying ${userOpsToReplay.length} owner operation(s)...`);

  // Helper to decode ownerIndex from signature
  const getOwnerIndexFromSignature = (signature: `0x${string}`): bigint => {
    // SignatureWrapper is abi.encode(uint256 ownerIndex, bytes signatureData)
    // After the outer tuple offset (32 bytes), next 32 bytes is ownerIndex
    const sigBytes = signature.slice(2); // remove 0x
    const ownerIndexHex = sigBytes.slice(64, 128); // bytes 32-64
    return BigInt("0x" + ownerIndexHex);
  };

  // Submit UserOps one at a time to handle signature dependencies
  // (later ops may be signed by owners added by earlier ops)
  for (let i = 0; i < userOpsToReplay.length; i++) {
    const userOp = userOpsToReplay[i];
    const ownerIndex = getOwnerIndexFromSignature(userOp.signature);

    // Check if the UserOp's nonce has already been consumed
    const nonceKey = userOp.nonce >> BigInt(64);
    const currentNonce = await targetClient.readContract({
      abi: entryPoint06Abi,
      address: entryPoint06Address,
      functionName: "getNonce",
      args: [address, nonceKey],
    });

    if (currentNonce > userOp.nonce) {
      // Nonce was consumed - check if the expected effect happened
      const expectedOwnerIndex = BigInt(nextAddOwnerIndex + i);
      const existingOwner = await targetClient.readContract({
        abi: coinbaseSmartWalletAbi,
        functionName: "ownerAtIndex",
        address,
        args: [expectedOwnerIndex],
      });

      if (existingOwner === "0x" || existingOwner.length <= 2) {
        throw new Error(
          `UserOp ${i + 1}/${
            userOpsToReplay.length
          } nonce already consumed (current: ${currentNonce}, userOp: ${
            userOp.nonce
          }), ` +
            `but owner at index ${expectedOwnerIndex} was NOT added. ` +
            `The inner call likely failed (e.g., out of gas). ` +
            `This UserOp cannot be replayed - you'll need to manually add the owner using an existing signer.`
        );
      } else {
        logger.info(
          `\nSkipping UserOp ${i + 1}/${
            userOpsToReplay.length
          } - nonce already consumed and owner at index ${expectedOwnerIndex} exists`
        );
        continue;
      }
    }

    // Check if the signing owner exists on target chain
    const ownerBytes = await targetClient.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "ownerAtIndex",
      address,
      args: [ownerIndex],
    });

    if (ownerBytes === "0x" || ownerBytes.length <= 2) {
      throw new Error(
        `Cannot replay UserOp ${i + 1}/${userOpsToReplay.length}: ` +
          `signature uses ownerIndex ${ownerIndex} which doesn't exist on target chain yet. ` +
          `This UserOp was likely signed by an owner that was added in a previous operation.`
      );
    }

    logger.info(
      `\nSubmitting UserOp ${i + 1}/${
        userOpsToReplay.length
      } (signed by ownerIndex ${ownerIndex})...`
    );

    // Calculate minimum gas needed based on UserOp gas limits
    // The outer transaction needs enough gas to cover:
    // - verificationGasLimit (for validateUserOp)
    // - callGasLimit (for the inner execution)
    // - preVerificationGas (overhead)
    // - EntryPoint overhead (~50k)
    const minGasNeeded =
      userOp.verificationGasLimit +
      userOp.callGasLimit +
      userOp.preVerificationGas +
      BigInt(100000); // Extra buffer for EntryPoint overhead

    logger.debug(
      `  UserOp gas limits: verification=${userOp.verificationGasLimit}, call=${userOp.callGasLimit}, preVerification=${userOp.preVerificationGas}`
    );
    logger.debug(`  Minimum gas needed for outer tx: ${minGasNeeded}`);

    // CRITICAL: Use EntryPoint's simulateHandleOp to detect inner UserOp failures
    // We use the target parameter to verify the expected state change occurred
    // After execution, simulateHandleOp calls target.call(targetCallData) and returns the result
    logger.debug(`  Simulating UserOp execution to verify it will succeed...`);

    // Decode the UserOp to find what state change to verify
    // For addOwner operations, we verify ownerCount increased
    let simulationTarget: `0x${string}` =
      "0x0000000000000000000000000000000000000000";
    let simulationTargetCallData: `0x${string}` = "0x";
    let expectedOwnerCount: bigint | null = null;

    try {
      const outerFunctionData = decodeFunctionData({
        abi: coinbaseSmartWalletAbi,
        data: userOp.callData,
      });

      if (
        outerFunctionData.functionName === "executeWithoutChainIdValidation"
      ) {
        const calls = outerFunctionData.args[0] as `0x${string}`[];
        if (calls.length > 0) {
          const innerFunctionData = decodeFunctionData({
            abi: coinbaseSmartWalletAbi,
            data: calls[0],
          });

          if (
            innerFunctionData.functionName === "addOwnerAddress" ||
            innerFunctionData.functionName === "addOwnerPublicKey"
          ) {
            // Get current owner count before simulation
            const currentOwnerCount = await targetClient.readContract({
              abi: coinbaseSmartWalletAbi,
              address,
              functionName: "ownerCount",
            });
            expectedOwnerCount = currentOwnerCount + BigInt(1);

            // After execution, verify ownerCount() returns currentCount + 1
            simulationTarget = address;
            simulationTargetCallData = encodeFunctionData({
              abi: coinbaseSmartWalletAbi,
              functionName: "ownerCount",
            });
            logger.debug(
              `  Current ownerCount: ${currentOwnerCount}, expecting ${expectedOwnerCount} after execution`
            );
          }
        }
      }
    } catch (decodeErr) {
      logger.debug(
        `  Warning: Could not decode UserOp for state verification: ${decodeErr}`
      );
    }

    try {
      // simulateHandleOp always reverts - we catch and parse the revert data
      await targetClient.simulateContract({
        abi: entryPoint06Abi,
        address: entryPoint06Address,
        functionName: "simulateHandleOp",
        args: [userOp, simulationTarget, simulationTargetCallData],
        gas: minGasNeeded * BigInt(2), // Extra gas for simulation overhead
      });

      // If we get here, something is wrong - simulateHandleOp should always revert
      logger.warn(`simulateHandleOp didn't revert (unexpected)`);
    } catch (e: any) {
      const errorMessage = e?.message || String(e);
      const errorData = e?.data || e?.cause?.data;

      // Check for FailedOp error (validation failed)
      if (errorMessage.includes("FailedOp") || errorMessage.includes("AA")) {
        const aaMatch = errorMessage.match(/AA\d+[^"')}\]]*/);
        logger.error(`Simulation FAILED - NOT submitting transaction`);
        logger.info(`   This prevents nonce consumption on a doomed UserOp`);
        if (aaMatch) {
          logger.info(`   ERC-4337 error: ${aaMatch[0]}`);
        }
        logger.info(`   Error: ${e?.shortMessage || errorMessage}`);

        throw new Error(
          `UserOp ${i + 1}/${
            userOpsToReplay.length
          } would fail - aborting to prevent nonce consumption. ` +
            `Error: ${e?.shortMessage || errorMessage}`
        );
      }

      // Check for ExecutionResult revert (this is the expected/success path)
      // ExecutionResult(uint256 preOpGas, uint256 paid, uint48 validAfter, uint48 validUntil, bool targetSuccess, bytes targetResult)
      if (errorMessage.includes("ExecutionResult")) {
        const decodedArgs = (errorData as any)?.args;
        if (Array.isArray(decodedArgs) && decodedArgs.length >= 6) {
          const preOpGas = decodedArgs[0];
          const targetSuccess = decodedArgs[4];
          const targetResult = decodedArgs[5];

          if (
            simulationTarget !== "0x0000000000000000000000000000000000000000" &&
            expectedOwnerCount !== null
          ) {
            // We made a verification call - check if it succeeded
            if (!targetSuccess) {
              logger.error(
                `Simulation FAILED - State verification call reverted`
              );
              logger.info(`   The inner UserOp execution likely failed`);
              logger.info(`   NOT submitting to prevent nonce consumption`);
              throw new Error(
                `UserOp ${i + 1}/${
                  userOpsToReplay.length
                } inner call would fail - state verification reverted. Aborting to prevent nonce consumption.`
              );
            }

            // Decode the result - should be ownerCount (uint256)
            let actualOwnerCount: bigint | null = null;
            try {
              if (targetResult) {
                if (
                  typeof targetResult === "string" &&
                  targetResult.startsWith("0x")
                ) {
                  // Hex string (viem usually returns this)
                  actualOwnerCount = BigInt(targetResult);
                } else if (typeof targetResult === "bigint") {
                  // Already a bigint
                  actualOwnerCount = targetResult;
                } else if (
                  targetResult instanceof Uint8Array ||
                  ArrayBuffer.isView(targetResult)
                ) {
                  // Bytes array - convert to hex then to bigint
                  const bytes = new Uint8Array(
                    targetResult.buffer || targetResult
                  );
                  const hex =
                    "0x" +
                    Array.from(bytes)
                      .map((b) => b.toString(16).padStart(2, "0"))
                      .join("");
                  actualOwnerCount = BigInt(hex);
                } else if (typeof targetResult === "number") {
                  actualOwnerCount = BigInt(targetResult);
                }
              }
            } catch {
              // If we can't decode, actualOwnerCount stays null
            }

            if (actualOwnerCount !== expectedOwnerCount) {
              logger.error(
                `Simulation FAILED - ownerCount did NOT increase as expected`
              );
              logger.info(
                `   Expected ownerCount: ${expectedOwnerCount}, got: ${actualOwnerCount}`
              );
              logger.info(
                `   The UserOp execution did not add the owner successfully`
              );
              logger.info(`   NOT submitting to prevent nonce consumption`);
              throw new Error(
                `UserOp ${i + 1}/${
                  userOpsToReplay.length
                } would not add owner. Expected ownerCount ${expectedOwnerCount}, simulation returned ${actualOwnerCount}. Aborting to prevent nonce consumption.`
              );
            }

            logger.debug(
              `  Simulation passed ✓ (preOpGas=${preOpGas}, ownerCount will be ${actualOwnerCount})`
            );
          } else {
            // No state verification - just report validation passed
            logger.debug(
              `  Simulation passed ✓ (validation succeeded, preOpGas=${preOpGas})`
            );
            logger.debug(
              `  Warning: Could not verify inner call success - proceeding cautiously`
            );
          }
        } else {
          logger.debug(`  Simulation returned ExecutionResult (validation OK)`);
          logger.debug(
            `  Warning: Could not parse ExecutionResult - proceeding cautiously`
          );
        }
      } else {
        // Unknown error - be cautious and fail
        logger.error(`Simulation error - NOT submitting transaction`);
        logger.info(`   Error: ${e?.shortMessage || errorMessage}`);

        throw new Error(
          `UserOp ${i + 1}/${
            userOpsToReplay.length
          } simulation failed - aborting. Error: ${
            e?.shortMessage || errorMessage
          }`
        );
      }
    }

    // Now estimate gas (should succeed since simulation passed)
    let handleOpsGasLimit: bigint;
    try {
      const handleOpsEstimatedGas = await targetClient.estimateContractGas({
        abi: entryPoint06Abi,
        address: entryPoint06Address,
        functionName: "handleOps",
        args: [[userOp], address],
      });
      // Add 50% buffer to estimation
      const estimatedWithBuffer =
        (handleOpsEstimatedGas * BigInt(150)) / BigInt(100);
      handleOpsGasLimit =
        estimatedWithBuffer > minGasNeeded ? estimatedWithBuffer : minGasNeeded;
      logger.debug(
        `  Estimated gas: ${handleOpsEstimatedGas}, using: ${handleOpsGasLimit}`
      );
    } catch (e) {
      // Estimation failed after simulation passed - use calculated minimum
      // This shouldn't happen, but handle it gracefully
      handleOpsGasLimit = (minGasNeeded * BigInt(150)) / BigInt(100);
      logger.debug(
        `  Gas estimation failed (unexpected), using calculated minimum: ${handleOpsGasLimit}`
      );
    }
    const gasPrice = await targetClient.getGasPrice();
    const requiredFunds = handleOpsGasLimit * gasPrice;

    // Check bundler balance
    let bundlerBalance = await targetClient.getBalance({
      address: targetWalletClient.account!.address,
    });

    while (bundlerBalance < requiredFunds) {
      const shortfall = requiredFunds - bundlerBalance;
      const chain = targetWalletClient.chain;
      const symbol = chain?.nativeCurrency?.symbol || "ETH";

      logger.warn(`Bundler account needs funds for owner replay!`);
      logger.info(`   Bundler: ${targetWalletClient.account!.address}`);
      logger.info(
        `   Current balance: ${formatEther(bundlerBalance)} ${symbol}`
      );
      logger.info(
        `   Required for handleOps: ${formatEther(requiredFunds)} ${symbol}`
      );
      logger.info(`   Shortfall: ${formatEther(shortfall)} ${symbol}`);

      await promptUser(
        `\nPlease send at least ${formatEther(
          shortfall
        )} ${symbol} to the bundler address.\n[Press enter to check balance again]`
      );

      bundlerBalance = await targetClient.getBalance({
        address: targetWalletClient.account!.address,
      });
    }

    // Submit this single UserOp
    const handleOpsTx = await targetWalletClient.writeContract({
      abi: entryPoint06Abi,
      address: entryPoint06Address,
      functionName: "handleOps",
      args: [[userOp], address],
      gas: handleOpsGasLimit,
    });

    logger.debug(`  Transaction submitted: ${handleOpsTx}`);

    const receipt = await targetClient.waitForTransactionReceipt({
      hash: handleOpsTx,
    });

    if (receipt.status !== "success") {
      logger.error(
        `Transaction reverted! Use: cast run ${handleOpsTx} --rpc-url https://rpc.monad.xyz --quick`
      );
      throw new Error(
        `HandleOps failed for UserOp ${i + 1} (tx: ${handleOpsTx})`
      );
    }

    logger.info(`UserOp ${i + 1} successful (tx: ${handleOpsTx})`);
  }

  const ownerCount = await targetClient.readContract({
    abi: coinbaseSmartWalletAbi,
    functionName: "ownerCount",
    address,
  });

  logger.info("\nOwners synced", ownerCount, "\n");

  return ownerCount;
}
