import readline from "readline";
import {
  Account,
  Address,
  Chain,
  createPublicClient,
  decodeEventLog,
  decodeFunctionData,
  encodeFunctionData,
  formatEther,
  Log,
  PublicClient,
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

      if (sender && decodedEvent.args.sender !== sender) {
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
}: {
  baseClient: PublicClient;
  baseBundlerClient: BundlerClient;
  targetClient: PublicClient;
  targetWalletClient: WalletClient<Transport, Chain, Account>;
  address: `0x${string}`;
}) {
  // Get all AddOwner events from Base
  const response = await fetch(
    `https://scope.sh/api/logs?chain=8453&address=${address}&cursor=0&limit=21&sort=asc`
  );
  const data = await response.json();

  const addOwnerLogs = data.logs.filter((log: any) => {
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
  });

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

  const userOpsToReplay = addOwnerUserOps
    .slice(nextAddOwnerIndex)
    .map(({ userOperation }) => userOperation);

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

  const gas = BigInt(500_000);
  const gasPrice = await targetClient.getGasPrice();
  const gasCost = gas * gasPrice;

  console.log("gasCost", formatEther(gasCost));
  console.log(
    "balance",
    formatEther(
      await targetClient.getBalance({
        address: "0x99d9B0Ad93a0E3aa6098ED0A91B231098b6840Fa",
      })
    )
  );

  // Estimate gas for handleOps
  // const gas = await targetClient.estimateGas({
  //   to: entryPoint06Address,
  //   data: encodeFunctionData({
  //     abi: entryPoint06Abi,
  //     functionName: "handleOps",
  //     args: [userOpsToReplay, address],
  //   }),
  // });

  // const gasPrice = await targetClient.getGasPrice();

  // const gasCost = gas * gasPrice;

  // console.log(
  //   `Gas cost: ${formatEther(gasCost)} ETH (${formatEther(gas)} gas)`
  // );

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
