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
  entryPoint06Abi,
  entryPoint06Address,
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

  console.log("addOwnerLogs", addOwnerLogs);

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

  console.log("addOwnerUserOps", addOwnerUserOps);

  let nextAddOwnerIndex = initialOwners.length;

  console.log(
    `Account will be initialized with ${initialOwners.length} owners`
  );

  console.log("deploy tx", {
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

    console.log("addOwnerLogs index", addOwnerLogs[addOwnerLogs.length - 1]);

    const baseOwnerAtSyncedIndex = decodeEventLog({
      abi: coinbaseSmartWalletAbi,
      data: addOwnerLogs[Number(ownerCount) - 1].data,
      topics: addOwnerLogs[Number(ownerCount) - 1].topics,
    });

    if (baseOwnerAtSyncedIndex.eventName !== "AddOwner") {
      throw new Error("Last AddOwner event is not valid");
    }

    console.log("baseOwnerAtSyncedIndex", baseOwnerAtSyncedIndex);
    console.log("ownerAtLastIndex", ownerAtLastIndex);

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

  console.log("replaying from index", nextAddOwnerIndex);

  if (
    addOwnerUserOps.slice(nextAddOwnerIndex, nextAddOwnerIndex + 1).length === 0
  ) {
    return 0;
  }

  console.log("all addOwnerUserOps", addOwnerUserOps);

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

  console.log("replaying ", userOpsToReplay);

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

      console.log("nonce", nonce);
      console.log("executeData", executeData);
    } else {
      console.log("functionData", functionData);
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

  console.log("handleOps tx", {
    to: entryPoint06Address,
    data: encodeFunctionData({
      abi: entryPoint06Abi,
      functionName: "handleOps",
      args: [userOpsToReplay, address],
    }),
  });

  // Replay all the userOps on target chain
  const handleOpsTx = await targetWalletClient.writeContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "handleOps",
    args: [userOpsToReplay, address],
  });

  console.log("handleOpsTx", handleOpsTx);

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
