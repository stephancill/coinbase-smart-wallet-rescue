#!/usr/bin/env node

import "dotenv/config";
import {
  Account,
  Address,
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  erc20Abi,
  formatEther,
  getAddress,
  http,
  isHex,
  parseAbi,
  parseEther,
} from "viem";
import {
  createBundlerClient,
  entryPoint06Abi,
  entryPoint06Address,
  toCoinbaseSmartAccount,
} from "viem/account-abstraction";
import { mnemonicToAccount, privateKeyToAccount } from "viem/accounts";
import * as chains from "viem/chains";
import { base } from "viem/chains";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { coinbaseSmartWalletAbi } from "./abi/CoinbaseSmartWallet";
import { degenClaimAbi } from "./abi/DegenClaimAbi";
import { promptUser, syncSmartAccountOwners } from "./utils";

const TARGET_RPC_URL = process.env.TARGET_RPC_URL || "https://rpc.degen.tips";
const BASE_RPC_URL = process.env.RPC_URL_8453 || "https://mainnet.base.org";

async function syncOwners({
  address,
  chainId,
  bundlerAccount,
  rpcUrl,
}: {
  address: `0x${string}`;
  chainId: number;
  bundlerAccount: Account;
  rpcUrl?: string;
}) {
  const chain = Object.values(chains).find((chain) => chain.id === chainId);

  if (!chain) {
    throw new Error(`Chain with id ${chainId} not found`);
  }

  console.log("chain", chain);

  const targetClient = createPublicClient({
    chain,
    transport: http(rpcUrl),
  });

  const bundlerClient = createWalletClient({
    account: bundlerAccount,
    chain: chain,
    transport: http(rpcUrl),
  });

  const baseClient = createPublicClient({
    chain: base,
    transport: http(BASE_RPC_URL),
  });
  const baseBundlerClient = createBundlerClient({
    chain: base,
    transport: http(BASE_RPC_URL),
  });

  await syncSmartAccountOwners({
    baseClient: baseClient as any,
    baseBundlerClient,
    targetClient: targetClient as any,
    targetWalletClient: bundlerClient,
    address,
  });
}

async function rescueDegenAirdrop({
  wallet: smartAccountAddress,
  destination,
  transferOnly,
}: {
  wallet: Address;
  destination: Address;
  transferOnly?: boolean;
}) {
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

  let targetWalletClient = createWalletClient({
    account: recoveryOwnerAccount,
    chain: chains.degen,
    transport: http(TARGET_RPC_URL),
  });

  let targetClient = createPublicClient({
    chain: chains.degen,
    transport: http(TARGET_RPC_URL),
  });

  const bundlerClient = createBundlerClient({
    chain: chains.degen,
    transport: http(),
    userOperation: {
      async estimateFeesPerGas(parameters) {
        const fees = await targetClient.estimateFeesPerGas();
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

  let deployerBalance = await targetClient.getBalance({
    address: recoveryOwnerAccount.address,
  });

  while (deployerBalance < parseEther("0.05")) {
    // Prompt to fund recovery owner account
    await promptUser(
      `Fund recovery owner account (${
        recoveryOwnerAccount.address
      }) with at least 0.1 native token on Target Chain.\nCurrent balance: ${formatEther(
        deployerBalance
      )} native token\n[Press enter to continue]`
    );

    deployerBalance = await targetClient.getBalance({
      address: recoveryOwnerAccount.address,
    });
  }

  console.log(
    `Funded recovery owner account (${recoveryOwnerAccount.address}). Proceeding...`
  );

  await syncSmartAccountOwners({
    baseClient: baseClient as any,
    baseBundlerClient,
    targetClient: targetClient as any,
    targetWalletClient,
    address: smartAccountAddress as `0x${string}`,
  });

  let isValidOwner = await targetClient.readContract({
    abi: coinbaseSmartWalletAbi,
    functionName: "isOwnerAddress",
    address: smartAccountAddress as `0x${string}`,
    args: [recoveryOwnerAccount.address],
  });

  if (!isValidOwner) {
    throw new Error("Owner is not valid");
  }

  // Submit UserOp signed by recovery address that transfers funds from destination to wallet
  const smartAccount = await toCoinbaseSmartAccount({
    client: bundlerClient,
    owners: [recoveryOwnerAccount],
    address: smartAccountAddress as `0x${string}`,
  });

  if (!transferOnly) {
    const proofResponse = await fetch(
      `https://api.degen.tips/airdrop2/season12/merkleproofs?wallet=${smartAccountAddress}`
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
    const claimUserOp = await bundlerClient.prepareUserOperation({
      account: smartAccount,
      calls: [
        {
          to: "0xc872DE3311917c421F1c82a845191e58155c1B8F", // degen airdrop distributor for specific season
          from: getAddress(smartAccountAddress),
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

    const claimUserOpSig = await smartAccount.signUserOperation(claimUserOp);

    const claimTx = await targetWalletClient.writeContract({
      abi: entryPoint06Abi,
      address: entryPoint06Address,
      functionName: "handleOps",
      args: [
        [{ ...claimUserOp, initCode: "0x", signature: claimUserOpSig }],
        recoveryOwnerAccount.address,
      ],
    });

    await targetClient.waitForTransactionReceipt({ hash: claimTx });

    console.log("Claimed", claimTx);
  }

  // Transfer wdegen to destination
  const WDEGEN_ADDRESS = "0xEb54dACB4C2ccb64F8074eceEa33b5eBb38E5387";
  const wdegenBalance = await targetClient.readContract({
    abi: parseAbi([
      "function balanceOf(address account) view returns (uint256)",
    ]),
    address: WDEGEN_ADDRESS,
    functionName: "balanceOf",
    args: [smartAccount.address],
  });

  const destinationAddress = destination as `0x${string}`;
  console.log(
    "transferring",
    formatEther(wdegenBalance),
    "to",
    destinationAddress
  );

  const destinationBalanceBefore = await targetClient.readContract({
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

  const rescueTx = await targetWalletClient.writeContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "handleOps",
    args: [
      [{ ...userOperation, initCode: "0x", signature }],
      recoveryOwnerAccount.address,
    ],
  });

  console.log("rescueTx", rescueTx);

  const rescueReceipt = await targetClient.getTransactionReceipt({
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
  const destinationBalanceAfter = await targetClient.readContract({
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

async function main() {
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
    })
    .option("transferOnly", {
      type: "boolean",
      description: "Skip claiming and only transfer existing balance",
      default: false,
    })
    .option("syncOnly", {
      type: "boolean",
      description: "Only sync the smart account owners",
      default: false,
    })
    .option("rpcUrl", {
      type: "string",
      description: "RPC URL",
      default: process.env.RPC_URL,
    })
    .option("privateKey", {
      type: "string",
      description: "Private key",
      default: process.env.PRIVATE_KEY,
    })
    .parseSync();

  if (argv.syncOnly) {
    const privateKey = argv.privateKey;

    if (!privateKey || !isHex(privateKey)) {
      throw new Error("privateKey is not set");
    }

    if (!argv.rpcUrl) {
      throw new Error("rpcUrl is not set");
    }

    const bundlerAccount = privateKeyToAccount(privateKey);

    const chainId = await createPublicClient({
      transport: http(argv.rpcUrl),
    }).getChainId();

    await syncOwners({
      address: argv.wallet as `0x${string}`,
      chainId,
      rpcUrl: argv.rpcUrl,
      bundlerAccount,
    });
  } else if (argv.rescueDegenAirdrop) {
    await rescueDegenAirdrop({
      wallet: argv.wallet as `0x${string}`,
      destination: argv.destination as `0x${string}`,
      transferOnly: argv.transferOnly,
    });
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
