#!/usr/bin/env node

import "dotenv/config";
import readline from "readline";
import {
  Address,
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  decodeFunctionData,
  encodeFunctionData,
  erc20Abi,
  formatEther,
  getAddress,
  http,
  parseAbi,
  parseEther,
  PublicClient,
} from "viem";
import {
  BundlerClient,
  createBundlerClient,
  entryPoint06Abi,
  entryPoint06Address,
  toCoinbaseSmartAccount,
} from "viem/account-abstraction";
import { mnemonicToAccount } from "viem/accounts";
import { base, degen } from "viem/chains";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { coinbaseSmartWalletAbi } from "./abi/CoinbaseSmartWallet";
import { degenClaimAbi } from "./abi/DegenClaimAbi";

const DEGEN_RPC_URL = process.env.RPC_URL_666666666 || "https://rpc.degen.tips";
const BASE_RPC_URL = process.env.RPC_URL_8453 || "https://mainnet.base.org";

// Parse command line arguments
const argv = yargs(hideBin(process.argv))
  .option("wallet", {
    type: "string",
    description: "Coinbase Smart Wallet address",
    demandOption: true,
  })
  .option("destination", {
    type: "string",
    description: "Destination address",
    demandOption: true,
  })
  .parseSync();

async function main() {
  let mnemonic =
    process.env.RECOVERY_MNEMONIC ||
    (await promptUser("Please enter your 13 word recovery phrase: \n> "));

  const words = mnemonic.trim().split(" ");

  if (words[0].toLowerCase() !== "wallet") {
    throw new Error(
      "Invalid recovery phrase. The first word should be 'wallet'."
    );
  }

  // Remove the first word "wallet"
  mnemonic = words.slice(1).join(" ");

  if (mnemonic.split(" ").length !== 12) {
    throw new Error(
      "Invalid recovery phrase. Expected 12 words (excluding 'wallet')."
    );
  }

  const recoveryOwnerAccount = mnemonicToAccount(mnemonic);

  let degenWalletClient = createWalletClient({
    account: recoveryOwnerAccount,
    chain: degen,
    transport: http(DEGEN_RPC_URL),
  });

  let degenClient = createPublicClient({
    chain: degen,
    transport: http(DEGEN_RPC_URL),
  });

  const bundlerClient = createBundlerClient({
    chain: degen,
    transport: http(),
    userOperation: {
      async estimateFeesPerGas(parameters) {
        const fees = await degenClient.estimateFeesPerGas();
        return fees;
      },
    },
  });

  const baseBundlerClient = createBundlerClient({
    chain: base,
    transport: http(BASE_RPC_URL),
  });

  const baseClient = createPublicClient({
    chain: base,
    transport: http(BASE_RPC_URL),
  });

  let deployerBalance = await degenClient.getBalance({
    address: recoveryOwnerAccount.address,
  });

  while (deployerBalance < parseEther("0.1")) {
    // Prompt to fund recovery owner account
    await promptUser(
      `Fund recovery owner account (${recoveryOwnerAccount.address}) with at least 0.1 DEGEN on Degen Chain.\n[Press enter to continue]`
    );

    deployerBalance = await degenClient.getBalance({
      address: recoveryOwnerAccount.address,
    });
  }

  console.log("Funded recovery owner account. Proceeding...");

  const response = await fetch(
    `https://scope.sh/api/logs?chain=8453&address=${argv.wallet}&cursor=0&limit=21&sort=asc`
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

  const deployUserOp = await getUserOpFromCalldata(
    baseClient as any,
    addOwnerLogs[0].transactionHash
  );

  if (!addOwnerLogs[addOwnerLogs.length - 1]) {
    throw new Error("Add recovery log not found");
  }

  // Get add recovery address UserOp
  const addRecoveryOwnerLog = addOwnerLogs.find((log: any) => {
    try {
      const event = decodeEventLog({
        abi: coinbaseSmartWalletAbi,
        data: log.data,
        topics: log.topics,
      });
      // Recovery owner is a 66 character hex string
      return event.eventName === "AddOwner" && event.args.owner.length === 66;
    } catch (error) {
      return false;
    }
  });

  if (!addRecoveryOwnerLog) {
    throw new Error("AddRecoveryOwner log not found");
  }

  const userOps = await getUserOpsFromTransaction({
    transactionHash: addRecoveryOwnerLog.transactionHash,
    bundlerClient: baseBundlerClient,
    client: baseClient as any,
    sender: argv.wallet as `0x${string}`,
  });

  // Replayable userOps have nonce key 8453
  const replayableUserOp = userOps.find(({ userOperation }) => {
    return userOperation.nonce >> BigInt(64) === BigInt(8453);
  });

  if (!replayableUserOp) {
    throw new Error("Replayable userOp not found");
  }

  console.log("Found replayable userOp");

  const isDeployed = await degenClient.getCode({
    address: argv.wallet as `0x${string}`,
  });

  console.log("deployTx", {
    to: deployUserOp.initCode.slice(0, 42) as `0x${string}`,
    data: ("0x" + deployUserOp.initCode.slice(42)) as `0x${string}`,
  });

  if (!isDeployed) {
    // Deploy wallet
    console.log("Deploying wallet");
    const deployTx = await degenWalletClient.sendTransaction({
      to: deployUserOp.initCode.slice(0, 42) as `0x${string}`,
      data: ("0x" + deployUserOp.initCode.slice(42)) as `0x${string}`,
    });

    console.log("Deployed", deployTx);
  }

  let isValidOwner = await degenClient.readContract({
    abi: coinbaseSmartWalletAbi,
    functionName: "isOwnerAddress",
    address: argv.wallet as `0x${string}`,
    args: [recoveryOwnerAccount.address],
  });

  if (!isValidOwner) {
    // Replay recovery address on destination
    const replayTx = await degenWalletClient.writeContract({
      abi: entryPoint06Abi,
      address: entryPoint06Address,
      functionName: "handleOps",
      args: [
        [
          {
            initCode: "0x",
            paymasterAndData: "0x",
            ...replayableUserOp.userOperation,
          },
        ],
        recoveryOwnerAccount.address,
      ],
    });

    await degenClient.waitForTransactionReceipt({ hash: replayTx });

    console.log("Replayed", replayTx);
  }

  isValidOwner = await degenClient.readContract({
    abi: coinbaseSmartWalletAbi,
    functionName: "isOwnerAddress",
    address: argv.wallet as `0x${string}`,
    args: [recoveryOwnerAccount.address],
  });

  const actualRecoveryAddress = await degenClient.readContract({
    abi: coinbaseSmartWalletAbi,
    functionName: "ownerAtIndex",
    address: argv.wallet as `0x${string}`,
    args: [BigInt(1)],
  });

  console.log("actualRecoveryAddress", actualRecoveryAddress);

  console.log("isValidOwner", isValidOwner);

  if (!isValidOwner) {
    throw new Error("Invalid owner");
  }

  // Submit UserOp signed by recovery address that transfers funds from destination to wallet
  const smartAccount = await toCoinbaseSmartAccount({
    client: bundlerClient,
    owners: [recoveryOwnerAccount],
    address: argv.wallet as `0x${string}`,
  });

  const proofResponse = await fetch(
    `https://api.degen.tips/airdrop2/season11/merkleproofs?wallet=${argv.wallet}`
  );
  const body = await proofResponse.json();

  const [proofBody] = body;

  console.log("body", body);

  if (!proofBody) {
    throw new Error("Proof body not found");
  }

  if (!proofBody.amount) {
    throw new Error("No claimable amount");
  }

  // Claim
  console.log("Claiming...");
  const userOperation1 = await bundlerClient.prepareUserOperation({
    account: smartAccount,
    calls: [
      {
        to: "0x08D830997d53650AAf9194F0d9Ff338b6f814fce", // degen airdrop distributor for specific season
        from: getAddress(argv.wallet),
        data: encodeFunctionData({
          abi: degenClaimAbi,
          functionName: "claim",
          args: [
            BigInt(proofBody.index),
            proofBody.wallet_address,
            BigInt(proofBody.amount),
            proofBody.proof,
          ],
        }),
      },
    ],
    maxFeePerGas: BigInt(0),
    callGasLimit: BigInt(1_000_000),
    preVerificationGas: BigInt(1_000_000),
    verificationGasLimit: BigInt(1_000_000),
    maxPriorityFeePerGas: BigInt(0),
    initCode: "0x",
  });

  const signature1 = await smartAccount.signUserOperation(userOperation1);

  // Transfer wdegen to destination
  const WDEGEN_ADDRESS = "0xEb54dACB4C2ccb64F8074eceEa33b5eBb38E5387";
  const wdegenBalance = await degenClient.readContract({
    abi: parseAbi([
      "function balanceOf(address account) view returns (uint256)",
    ]),
    address: WDEGEN_ADDRESS,
    functionName: "balanceOf",
    args: [smartAccount.address],
  });

  const destinationAddress = argv.destination as `0x${string}`;
  console.log(
    "transferring",
    formatEther(wdegenBalance),
    "to",
    destinationAddress
  );

  const destinationBalanceBefore = await degenClient.readContract({
    abi: erc20Abi,
    address: WDEGEN_ADDRESS,
    functionName: "balanceOf",
    args: [destinationAddress],
  });

  const userOperation = await bundlerClient.prepareUserOperation({
    account: smartAccount,
    calls: [
      {
        abi: erc20Abi,
        functionName: "transfer",
        to: WDEGEN_ADDRESS,
        args: [destinationAddress as `0x${string}`, wdegenBalance],
      },
    ],
    callGasLimit: BigInt(1_000_000),
    preVerificationGas: BigInt(1_000_000),
    verificationGasLimit: BigInt(1_000_000),
    initCode: "0x",
  });

  const signature = await smartAccount.signUserOperation(userOperation);

  const rescueTx = await degenWalletClient.writeContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "handleOps",
    args: [
      [{ ...userOperation, initCode: "0x", signature }],
      recoveryOwnerAccount.address,
    ],
  });

  console.log("rescueTx", rescueTx);

  const rescueReceipt = await degenClient.getTransactionReceipt({
    hash: rescueTx,
  });

  // Find transfer log
  const transferLog = rescueReceipt.logs.find((log) => {
    try {
      const event = decodeEventLog({
        abi: erc20Abi,
        data: log.data,
        topics: log.topics,
      });
      return event.eventName === "Transfer";
    } catch (error) {
      return false;
    }
  });

  if (!transferLog) {
    throw new Error("Transfer log not found");
  }

  // get balance of destination
  const destinationBalanceAfter = await degenClient.readContract({
    abi: erc20Abi,
    address: WDEGEN_ADDRESS,
    functionName: "balanceOf",
    args: [destinationAddress],
  });

  if (destinationBalanceAfter === destinationBalanceBefore) {
    throw new Error("Destination balance didn't change");
  }

  console.log("destinationBalanceAfter", formatEther(destinationBalanceAfter));
  console.log("Success!");
}

async function getUserOpFromCalldata(
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

async function promptUser(question: string): Promise<string> {
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

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
