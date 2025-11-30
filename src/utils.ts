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
  getAddress,
  hexToBytes,
  Log,
  PublicClient,
  stringToHex,
  toHex,
  Transport,
  WalletClient,
} from "viem";
import {
  BundlerClient,
  createBundlerClient,
  entryPoint06Abi,
  entryPoint06Address,
  toCoinbaseSmartAccount,
} from "viem/account-abstraction";
import { coinbaseSmartWalletAbi } from "./abi/CoinbaseSmartWallet";
import { coinbaseSmartWalletFactoryAbi } from "./abi/coinbaseSmartWalletFactory";

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

    console.log(
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
      console.log("Call gas estimation failed, using default");
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

export async function getUserOpFromCalldata(
  client: PublicClient,
  transactionHash: `0x${string}`
) {
  const deployReceipt = await client.getTransactionReceipt({
    hash: transactionHash,
  });
  const deployTransaction = await client.getTransaction({
    hash: transactionHash,
  });

  const userOpEventLog = deployReceipt.logs.find((log) => {
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

  if (decodedCall.functionName !== "handleOps") {
    throw new Error("Transaction is not a handleOps call");
  }
  const userOp = decodedCall.args[0][0];

  if (!userOp) {
    throw new Error("User operation not found");
  }

  return userOp;
}

export async function getUserOpsFromTransaction({
  client,
  bundlerClient,
  transactionHash,
  sender,
}: {
  client: ReturnType<typeof createPublicClient>;
  bundlerClient: BundlerClient;
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

      const userOp = await bundlerClient.getUserOperation({
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
  baseBundlerClient,
  targetClient,
  targetWalletClient,
  address,
  passkeyMode = false,
}: {
  baseClient: PublicClient;
  baseBundlerClient: BundlerClient;
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
  const logs = (data.items || [])
    .map((log: any) => ({
      ...log,
      transactionHash: log.tx_hash,
    }))
    .sort((a: any, b: any) => a.block_number - b.block_number);

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
    }));

  if (!addOwnerLogs[0]) {
    throw new Error("No AddOwner logs found");
  }

  const deployTxHash = addOwnerLogs[0].transactionHash;
  const deployUserOp = await getUserOpFromCalldata(baseClient, deployTxHash);

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
        bundlerClient: baseBundlerClient,
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

  console.log(
    `Account will be initialized with ${initialOwners.length} owners`
  );

  console.log("Deploy tx", {
    to: deployUserOp.initCode.slice(0, 42) as `0x${string}`,
    data: ("0x" + deployUserOp.initCode.slice(42)) as `0x${string}`,
  });

  if (isDeployed) {
    console.log("Account already deployed");

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

    const baseOwnerAtSyncedIndex = decodeEventLog({
      abi: coinbaseSmartWalletAbi,
      data: addOwnerLogs[Number(ownerCount) - 1].data,
      topics: addOwnerLogs[Number(ownerCount) - 1].topics,
    });

    if (baseOwnerAtSyncedIndex.eventName !== "AddOwner") {
      throw new Error("Last AddOwner event is not valid");
    }

    if (ownerAtLastIndex !== baseOwnerAtSyncedIndex.args.owner) {
      throw new Error("Owner at last index does not match");
    }

    nextAddOwnerIndex = Number(ownerCount);
  } else {
    console.log("Account not deployed, deploying...");

    // Deploy smart account
    const deployTx = await targetWalletClient.sendTransaction({
      to: deployUserOp.initCode.slice(0, 42) as `0x${string}`,
      data: ("0x" + deployUserOp.initCode.slice(42)) as `0x${string}`,
    });

    const receipt = await targetClient.waitForTransactionReceipt({
      hash: deployTx,
    });

    if (receipt.status !== "success") {
      throw new Error("Deployment failed");
    }
  }

  console.log("Replaying from index", nextAddOwnerIndex);

  if (
    addOwnerUserOps.slice(nextAddOwnerIndex, nextAddOwnerIndex + 1).length === 0
  ) {
    return 0;
  }

  let userOpsToReplay = addOwnerUserOps
    .slice(nextAddOwnerIndex)
    .filter((op): op is NonNullable<typeof op> => op !== undefined)
    .map(({ userOperation }) => userOperation);

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
      console.log(
        `Passkey mode: stopping at last addOwnerPublicKey call (index ${lastAddOwnerPublicKeyIndex})`
      );
      userOpsToReplay = userOpsToReplay.slice(
        0,
        lastAddOwnerPublicKeyIndex + 1
      );
    } else {
      console.log(
        "Passkey mode: no addOwnerPublicKey calls found in pending ops, skipping replay"
      );
      userOpsToReplay = [];
    }
  }

  userOpsToReplay.forEach((userOp) => {
    const nonce = userOp.nonce & BigInt(0xfffffffff);

    const functionData = decodeFunctionData({
      abi: coinbaseSmartWalletAbi,
      data: userOp.callData,
    });

    if (functionData.functionName === "executeWithoutChainIdValidation") {
      const executeData = decodeFunctionData({
        abi: coinbaseSmartWalletAbi,
        data: `${functionData.args[0]}` as `0x${string}`,
      });
    }
  });

  // Skip handleOps if no user ops to replay
  if (userOpsToReplay.length === 0) {
    console.log("No user operations to replay, skipping handleOps");

    const ownerCount = await targetClient.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "ownerCount",
      address,
    });

    console.log("Current owner count:", ownerCount, "\n");
    return ownerCount;
  }

  // Replay all the userOps on target chain
  const handleOpsTx = await targetWalletClient.writeContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "handleOps",
    args: [userOpsToReplay, address],
  });

  const receipt = await targetClient.waitForTransactionReceipt({
    hash: handleOpsTx,
  });

  if (receipt.status !== "success") {
    throw new Error("HandleOps failed");
  }

  const ownerCount = await targetClient.readContract({
    abi: coinbaseSmartWalletAbi,
    functionName: "ownerCount",
    address,
  });

  console.log("Owners synced", ownerCount, "\n");

  return ownerCount;
}
