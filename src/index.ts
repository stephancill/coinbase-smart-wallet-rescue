#!/usr/bin/env node

import "dotenv/config";
import fs from "fs";
import path from "path";
import {
  Account,
  Address,
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  erc20Abi,
  formatEther,
  formatUnits,
  http,
  isHex,
  parseUnits,
} from "viem";
import {
  createBundlerClient,
  entryPoint06Abi,
  entryPoint06Address,
  toCoinbaseSmartAccount,
} from "viem/account-abstraction";
import {
  generatePrivateKey,
  mnemonicToAccount,
  privateKeyToAccount,
} from "viem/accounts";
import * as chains from "viem/chains";
import { base } from "viem/chains";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import { coinbaseSmartWalletAbi } from "./abi/CoinbaseSmartWallet";
import {
  buildWebAuthnSignature,
  findLastPasskeyOwnerIndex,
  prepareUserOperationWithFallback,
  promptUser,
  syncSmartAccountOwners,
  WebAuthnResponse,
} from "./utils";
import { logger } from "./logger";

const DUMMY_SIGNATURE =
  "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000170000000000000000000000000000000000000000000000000000000000000001949fc7c88032b9fcb5f6efc7a7b8c63668eae9871b765e23123bb473ff57aa831a7c0d9276168ebcc29f2875a0239cffdf2a9cd1c2007c5c77c071db9264df1d000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008a7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273496a396e6164474850596759334b7156384f7a4a666c726275504b474f716d59576f4d57516869467773222c226f726967696e223a2268747470733a2f2f7369676e2e636f696e626173652e636f6d222c2263726f73734f726967696e223a66616c73657d00000000000000000000000000000000000000000000";

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

  await syncSmartAccountOwners({
    baseClient: baseClient as any,
    targetClient: targetClient as any,
    targetWalletClient: bundlerClient,
    address,
  });
}

async function rescueTokens({
  wallet: smartAccountAddress,
  destination,
  token,
  rpcUrl,
  mode,
}: {
  wallet: Address;
  destination: Address;
  token?: Address; // ERC-20 token address, undefined = native token
  rpcUrl: string;
  mode?: "passkey" | "mnemonic";
}) {
  // Fetch chainId from RPC
  const tempClient = createPublicClient({ transport: http(rpcUrl) });
  const chainId = await tempClient.getChainId();

  let chain = Object.values(chains).find((c) => c.id === chainId) as
    | chains.Chain
    | undefined;
  if (!chain) {
    logger.debug(
      `Chain with id ${chainId} not found in viem/chains, using fallback chain`
    );
    chain = {
      id: chainId,
      name: "Unknown Chain",
      nativeCurrency: {
        name: "Native Currency",
        symbol: "Native (e.g. ETH)",
        decimals: 18,
      },
      rpcUrls: {
        default: {
          http: [rpcUrl],
        },
      },
    } as unknown as chains.Chain;
  }

  logger.info(`Connected to ${chain.name} (chainId: ${chainId})`);

  const isPasskeyMode = mode === "passkey";
  const isNativeToken = !token;

  // Get or create bundler account
  let bundlerAccount: Account;
  let recoveryOwnerAccount: ReturnType<typeof mnemonicToAccount> | null = null;

  if (isPasskeyMode) {
    // In passkey mode, generate or load a bundler-only account
    // Reuse the same bundler across all wallets since it only pays for gas
    const bundlerKeyPath = path.join(process.cwd(), `.bundler-key.txt`);

    let privateKey: `0x${string}`;
    if (fs.existsSync(bundlerKeyPath)) {
      logger.debug(`Loading existing bundler key from ${bundlerKeyPath}`);
      privateKey = fs
        .readFileSync(bundlerKeyPath, "utf-8")
        .trim() as `0x${string}`;
    } else {
      logger.info(`Generating new bundler key...`);
      privateKey = generatePrivateKey();
      fs.writeFileSync(bundlerKeyPath, privateKey, { mode: 0o600 });
      logger.info(`Bundler key saved to ${bundlerKeyPath}`);
    }

    bundlerAccount = privateKeyToAccount(privateKey);
    logger.info(`Bundler account: ${bundlerAccount.address}`);
  } else {
    // Mnemonic mode - use recovery phrase
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

    recoveryOwnerAccount = mnemonicToAccount(mnemonic);
    bundlerAccount = recoveryOwnerAccount;
  }

  const targetWalletClient = createWalletClient({
    account: bundlerAccount,
    chain,
    transport: http(rpcUrl),
  });

  const targetClient = createPublicClient({
    chain,
    transport: http(rpcUrl),
  });

  const bundlerClient = createBundlerClient({
    chain,
    transport: http(rpcUrl),
    userOperation: {
      async estimateFeesPerGas() {
        const fees = await targetClient.estimateFeesPerGas();
        return fees;
      },
    },
  });

  const baseClient = createPublicClient({
    chain: base,
    transport: http(BASE_RPC_URL),
  });

  // Sync owners from Base
  await syncSmartAccountOwners({
    baseClient: baseClient as any,
    targetClient: targetClient as any,
    targetWalletClient,
    address: smartAccountAddress as `0x${string}`,
    passkeyMode: isPasskeyMode,
  });

  // In passkey mode, we create a smart account without a signer
  // The user will sign the userOp hash externally with their passkey
  const smartAccount = await toCoinbaseSmartAccount({
    client: bundlerClient,
    owners: recoveryOwnerAccount
      ? [recoveryOwnerAccount]
      : [privateKeyToAccount(generatePrivateKey())],
    address: smartAccountAddress as `0x${string}`,
  });

  // Verify owner in mnemonic mode
  if (!isPasskeyMode && recoveryOwnerAccount) {
    const isValidOwner = await targetClient.readContract({
      abi: coinbaseSmartWalletAbi,
      functionName: "isOwnerAddress",
      address: smartAccountAddress as `0x${string}`,
      args: [recoveryOwnerAccount.address],
    });

    if (!isValidOwner) {
      throw new Error("Recovery owner is not a valid owner of this wallet");
    }
  }

  // Get balance to transfer
  let balance: bigint;
  let tokenSymbol: string;
  let tokenDecimals: number;

  if (isNativeToken) {
    balance = await targetClient.getBalance({
      address: smartAccountAddress,
    });
    tokenSymbol = chain.nativeCurrency.symbol;
    tokenDecimals = 18; // Native tokens always use 18 decimals

    if (balance === BigInt(0)) {
      throw new Error(`No ${tokenSymbol} balance to transfer`);
    }
  } else {
    balance = await targetClient.readContract({
      abi: erc20Abi,
      address: token!,
      functionName: "balanceOf",
      args: [smartAccountAddress],
    });

    try {
      tokenSymbol = await targetClient.readContract({
        abi: erc20Abi,
        address: token!,
        functionName: "symbol",
      });
    } catch {
      tokenSymbol = "tokens";
    }

    try {
      tokenDecimals = await targetClient.readContract({
        abi: erc20Abi,
        address: token!,
        functionName: "decimals",
      });
    } catch {
      tokenDecimals = 18; // Fallback to 18 decimals if not readable
      logger.warn(
        `Could not read decimals from token contract, assuming ${tokenDecimals}`
      );
    }

    if (balance === BigInt(0)) {
      throw new Error(`No ${tokenSymbol} balance to transfer`);
    }
  }

  // Format the balance for display
  const formattedBalance = formatUnits(balance, tokenDecimals);
  logger.info(`\nAvailable balance: ${formattedBalance} ${tokenSymbol}`);

  // Ask user how much to transfer (loop until valid input)
  let transferAmount: bigint | null = null;

  while (transferAmount === null) {
    const amountInput = await promptUser(
      `How much ${tokenSymbol} would you like to transfer? (enter 'max' for full balance)\n> `
    );

    const normalizedInput = amountInput.trim().toLowerCase();

    if (normalizedInput === "max") {
      transferAmount = balance;
      logger.info(
        `Transferring full balance: ${formattedBalance} ${tokenSymbol}`
      );
    } else {
      let parsedAmount: bigint;
      try {
        parsedAmount = parseUnits(amountInput.trim(), tokenDecimals);
      } catch {
        logger.warn(
          `Invalid amount: "${amountInput}". Please enter a valid number or 'max'.`
        );
        continue;
      }

      if (parsedAmount <= BigInt(0)) {
        logger.warn("Transfer amount must be greater than 0");
        continue;
      }

      if (parsedAmount > balance) {
        logger.warn(
          `Insufficient balance. You have ${formattedBalance} ${tokenSymbol} but tried to transfer ${formatUnits(
            parsedAmount,
            tokenDecimals
          )} ${tokenSymbol}`
        );
        continue;
      }

      transferAmount = parsedAmount;
    }
  }

  logger.info(
    `Transferring ${formatUnits(
      transferAmount,
      tokenDecimals
    )} ${tokenSymbol} to ${destination}`
  );

  // Build the transfer call with the calculated transfer amount
  const calls = isNativeToken
    ? [
        {
          to: destination,
          value: transferAmount,
          data: "0x" as `0x${string}`,
        },
      ]
    : [
        {
          to: token!,
          value: BigInt(0),
          data: encodeFunctionData({
            abi: erc20Abi,
            functionName: "transfer" as const,
            args: [destination, transferAmount] as const,
          }),
        },
      ];

  // Prepare user operation with the actual transfer amount
  const userOperation = await prepareUserOperationWithFallback({
    bundlerClient,
    targetClient,
    smartAccount,
    calls,
  });

  const nonce = await targetClient.readContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "nonceSequenceNumber",
    args: [smartAccountAddress, BigInt(0)],
  });
  userOperation.nonce = nonce;

  let signature: `0x${string}`;

  // const userOpHash: `0x${string}` = getUserOperationHash({
  //   userOperation: {
  //     ...userOperation,
  //     sender: smartAccountAddress,
  //   },
  //   chainId,
  //   entryPointAddress: entryPoint06Address,
  //   entryPointVersion: "0.6",
  // });

  const userOpHash = await targetClient.readContract({
    abi: entryPoint06Abi,
    functionName: "getUserOpHash",
    address: entryPoint06Address,
    args: [
      {
        ...userOperation,
        paymasterAndData: "0x",
        signature: DUMMY_SIGNATURE,
      },
    ],
  });

  if (isPasskeyMode) {
    // Generate JavaScript code for user to paste in browser console
    const jsCode = `
(async () => {
  const hash = "${userOpHash}";
  const challenge = Uint8Array.from(hash.slice(2).match(/.{2}/g).map(byte => parseInt(byte, 16)));

  const credential = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: "keys.coinbase.com",
      userVerification: "preferred",
      allowCredentials: [],
    }
  });

  // Output the response data
  const authenticatorData = Array.from(new Uint8Array(credential.response.authenticatorData)).map(b => b.toString(16).padStart(2, '0')).join('');
  const clientDataJSON = new TextDecoder().decode(credential.response.clientDataJSON);
  const signature = Array.from(new Uint8Array(credential.response.signature)).map(b => b.toString(16).padStart(2, '0')).join('');

  console.log("=== COPY THE SINGLE LINE BELOW ===");
  console.log(JSON.stringify({ authenticatorData: "0x" + authenticatorData, clientDataJSON, signature: "0x" + signature }));
})();
`.trim();

    console.log("\n========== PASSKEY SIGNING REQUIRED ==========");
    console.log(`UserOperation Hash: ${userOpHash}`);
    console.log("\nUserOperation (for independent hash verification):");
    console.log(
      JSON.stringify(
        {
          sender: userOperation.sender,
          nonce: userOperation.nonce.toString(),
          initCode: "0x",
          callData: userOperation.callData,
          callGasLimit: userOperation.callGasLimit.toString(),
          verificationGasLimit: userOperation.verificationGasLimit.toString(),
          preVerificationGas: userOperation.preVerificationGas.toString(),
          maxFeePerGas: userOperation.maxFeePerGas.toString(),
          maxPriorityFeePerGas: userOperation.maxPriorityFeePerGas.toString(),
          paymasterAndData: "0x",
          signature: DUMMY_SIGNATURE,
        },
        null,
        2
      )
    );
    console.log("\n1. Open https://keys.coinbase.com/settings in your browser");
    console.log("2. Open the browser developer console (F12 or Cmd+Option+I)");
    console.log("3. Paste the following JavaScript code and press Enter:\n");
    console.log("--- COPY BELOW ---");
    console.log(jsCode);
    console.log("--- COPY ABOVE ---\n");
    console.log("4. Authenticate with your passkey when prompted");
    console.log("5. Copy the JSON output and paste it below");
    console.log("==============================================\n");

    // Wait for user to provide the credential response
    const responseJson = await promptUser(
      "Paste the JSON response from the browser console:\n> "
    );

    let response: WebAuthnResponse;
    try {
      response = JSON.parse(responseJson) as WebAuthnResponse;
    } catch {
      throw new Error(
        "Invalid JSON response. Please copy the entire JSON object."
      );
    }

    if (
      !response.authenticatorData ||
      !response.clientDataJSON ||
      !response.signature
    ) {
      throw new Error(
        "Invalid response format. Must contain authenticatorData, clientDataJSON, and signature."
      );
    }

    // Find the last passkey owner index
    const passkeyOwnerIndex = await findLastPasskeyOwnerIndex(
      targetClient,
      smartAccountAddress
    );

    logger.debug(`Using passkey owner at index ${passkeyOwnerIndex}`);

    // Build the WebAuthn signature with the correct owner index
    signature = buildWebAuthnSignature(response, passkeyOwnerIndex);
  } else {
    // Sign with recovery owner account
    signature = await smartAccount.signUserOperation(userOperation);
  }

  // Prepare the signed user operation for handleOps (extract only the fields needed by EntryPoint)
  const signedUserOp = {
    sender: userOperation.sender,
    nonce: userOperation.nonce,
    initCode: "0x" as `0x${string}`,
    callData: userOperation.callData,
    callGasLimit: userOperation.callGasLimit,
    verificationGasLimit: userOperation.verificationGasLimit,
    preVerificationGas: userOperation.preVerificationGas,
    maxFeePerGas: userOperation.maxFeePerGas,
    maxPriorityFeePerGas: userOperation.maxPriorityFeePerGas,
    paymasterAndData: "0x" as `0x${string}`,
    signature,
  };

  // Calculate gas prefund needed for the userOp (bundler will deposit this to EntryPoint)
  const totalUserOpGas =
    (signedUserOp.verificationGasLimit || BigInt(0)) +
    (signedUserOp.callGasLimit || BigInt(0)) +
    (signedUserOp.preVerificationGas || BigInt(0));
  const currentGasPrice = await targetClient.getGasPrice();
  const maxFeePerGas = signedUserOp.maxFeePerGas || currentGasPrice;

  // Add 50% buffer for gas price fluctuations
  const userOpGasPrefund =
    (totalUserOpGas * maxFeePerGas * BigInt(150)) / BigInt(100);

  // Estimate gas for handleOps call
  let handleOpsEstimatedGas: bigint;
  try {
    handleOpsEstimatedGas = await targetClient.estimateContractGas({
      abi: entryPoint06Abi,
      address: entryPoint06Address,
      functionName: "handleOps",
      args: [[signedUserOp], bundlerAccount.address],
    });
    logger.debug(
      `Estimated handleOps gas: ${handleOpsEstimatedGas.toLocaleString()}`
    );
  } catch {
    // If estimation fails (e.g., signature validation), use a fallback
    // P256/WebAuthn verification via FCL can use ~2M+ gas on some chains
    logger.debug(
      "Gas estimation failed (signature may not validate in simulation), using fallback"
    );
    handleOpsEstimatedGas = BigInt(2_500_000);
  }

  // Add 20% buffer for safety
  const handleOpsGasLimit = (handleOpsEstimatedGas * BigInt(120)) / BigInt(100);
  const handleOpsGasCost = handleOpsGasLimit * currentGasPrice;

  // Estimate gas for depositTo call (typically ~50k gas)
  const depositToGasLimit = BigInt(100_000);
  const depositToGasCost = depositToGasLimit * currentGasPrice;

  // Total required: userOp gas prefund + handleOps tx gas + depositTo tx gas
  const totalRequired = userOpGasPrefund + handleOpsGasCost + depositToGasCost;

  logger.debug(`\nGas breakdown:`);
  logger.debug(
    `  UserOp gas prefund: ${formatEther(userOpGasPrefund)} ${
      chain.nativeCurrency.symbol
    }`
  );
  logger.debug(
    `  handleOps tx gas: ${formatEther(handleOpsGasCost)} ${
      chain.nativeCurrency.symbol
    }`
  );
  logger.debug(
    `  depositTo tx gas: ${formatEther(depositToGasCost)} ${
      chain.nativeCurrency.symbol
    }`
  );
  logger.debug(
    `  Total required: ${formatEther(totalRequired)} ${
      chain.nativeCurrency.symbol
    }`
  );

  // Check bundler has enough balance
  let bundlerGasBalance = await targetClient.getBalance({
    address: bundlerAccount.address,
  });

  while (bundlerGasBalance < totalRequired) {
    const shortfall = totalRequired - bundlerGasBalance;
    logger.warn(`Bundler account needs more funds!`);
    logger.info(`   Bundler: ${bundlerAccount.address}`);
    logger.info(
      `   Current balance: ${formatEther(bundlerGasBalance)} ${
        chain.nativeCurrency.symbol
      }`
    );
    logger.info(
      `   Required: ${formatEther(totalRequired)} ${
        chain.nativeCurrency.symbol
      }`
    );
    logger.info(
      `   Shortfall: ${formatEther(shortfall)} ${chain.nativeCurrency.symbol}`
    );

    await promptUser(
      `\nPlease send at least ${formatEther(shortfall)} ${
        chain.nativeCurrency.symbol
      } to the bundler address.\n[Press enter to check balance again]`
    );

    bundlerGasBalance = await targetClient.getBalance({
      address: bundlerAccount.address,
    });
  }

  logger.debug(
    `Bundler has sufficient funds (${formatEther(bundlerGasBalance)} ${
      chain.nativeCurrency.symbol
    })`
  );

  // Step 1: Bundler deposits to EntryPoint on behalf of the smart wallet
  logger.info(
    `\nDepositing ${formatEther(userOpGasPrefund)} ${
      chain.nativeCurrency.symbol
    } to EntryPoint for gas...`
  );

  const depositTx = await targetWalletClient.writeContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "depositTo",
    args: [smartAccountAddress],
    value: userOpGasPrefund,
    gas: depositToGasLimit,
  });

  const depositReceipt = await targetClient.waitForTransactionReceipt({
    hash: depositTx,
  });

  if (depositReceipt.status !== "success") {
    throw new Error("Deposit to EntryPoint failed");
  }

  logger.info(`Deposit successful (tx: ${depositTx})`);

  // Step 2: Submit the user operation
  logger.info(`\nSubmitting rescue transaction...`);

  const rescueTx = await targetWalletClient.writeContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "handleOps",
    args: [[signedUserOp], bundlerAccount.address],
    gas: handleOpsGasLimit,
  });

  logger.debug("Transaction hash:", rescueTx);

  const rescueReceipt = await targetClient.waitForTransactionReceipt({
    hash: rescueTx,
  });

  if (rescueReceipt.status !== "success") {
    throw new Error("Transaction failed");
  }

  // Verify transfer
  if (!isNativeToken) {
    const transferLog = rescueReceipt.logs.find((log) => {
      try {
        const event = decodeEventLog({
          abi: erc20Abi,
          data: log.data,
          topics: log.topics,
        });
        return event.eventName === "Transfer";
      } catch {
        return false;
      }
    });

    if (!transferLog) {
      throw new Error("Transfer log not found");
    }
  }

  logger.info(
    `\nSuccess! Transferred ${formatUnits(
      transferAmount,
      tokenDecimals
    )} ${tokenSymbol} to ${destination} (tx: ${rescueTx})`
  );
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
      description: "Destination address for rescued tokens",
    })
    .option("token", {
      type: "string",
      description:
        "ERC-20 token address to transfer. If not provided, transfers native token (e.g. ETH)",
    })
    .option("rpcUrl", {
      type: "string",
      description: "RPC URL for the target network",
      default: process.env.TARGET_RPC_URL,
    })
    .option("mode", {
      type: "string",
      choices: ["passkey", "mnemonic"] as const,
      description:
        "Signing mode: 'passkey' for external passkey signing, 'mnemonic' for recovery phrase",
      default: "mnemonic",
    })
    .option("syncOnly", {
      type: "boolean",
      description: "Only sync the smart account owners without transferring",
      default: false,
    })
    .option("privateKey", {
      type: "string",
      description: "Private key for bundling transactions (syncOnly mode)",
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
  } else {
    // Rescue tokens mode
    if (!argv.destination) {
      throw new Error("--destination is required for token rescue");
    }

    if (!argv.rpcUrl) {
      throw new Error("--rpcUrl is required for token rescue");
    }

    await rescueTokens({
      wallet: argv.wallet as `0x${string}`,
      destination: argv.destination as `0x${string}`,
      token: argv.token as `0x${string}` | undefined,
      rpcUrl: argv.rpcUrl,
      mode: argv.mode as "passkey" | "mnemonic",
    });
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
