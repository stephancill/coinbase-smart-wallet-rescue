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
  erc20Abi,
  formatEther,
  http,
  isHex,
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
    console.log(
      `Chain with id ${chainId} not found in viem/chains, using fallback chain`
    );
    chain = {
      id: chainId,
      name: "Unknown Chain",
      nativeCurrency: {
        decimals: 18,
        name: "unknown",
        symbol: "unknown",
      },
      rpcUrls: {
        default: {
          http: [rpcUrl],
        },
      },
    } as unknown as chains.Chain;
  }

  console.log(`Connected to ${chain.name} (chainId: ${chainId})`);

  const isPasskeyMode = mode === "passkey";
  const isNativeToken = !token;

  // Get or create bundler account
  let bundlerAccount: Account;
  let recoveryOwnerAccount: ReturnType<typeof mnemonicToAccount> | null = null;

  if (isPasskeyMode) {
    // In passkey mode, generate or load a bundler-only account
    const bundlerKeyPath = path.join(
      process.cwd(),
      `.bundler-key-${smartAccountAddress.slice(0, 10)}.txt`
    );

    let privateKey: `0x${string}`;
    if (fs.existsSync(bundlerKeyPath)) {
      console.log(`Loading existing bundler key from ${bundlerKeyPath}`);
      privateKey = fs
        .readFileSync(bundlerKeyPath, "utf-8")
        .trim() as `0x${string}`;
    } else {
      console.log(`Generating new bundler key...`);
      privateKey = generatePrivateKey();
      fs.writeFileSync(bundlerKeyPath, privateKey, { mode: 0o600 });
      console.log(`Bundler key saved to ${bundlerKeyPath}`);
    }

    bundlerAccount = privateKeyToAccount(privateKey);
    console.log(`Bundler account: ${bundlerAccount.address}`);
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

  const baseBundlerClient = createBundlerClient({
    chain: base,
    transport: http(BASE_RPC_URL),
  });

  const baseClient = createPublicClient({
    chain: base,
    transport: http(BASE_RPC_URL),
  });

  // Sync owners from Base
  await syncSmartAccountOwners({
    baseClient: baseClient as any,
    baseBundlerClient,
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
  let transferAmount: bigint;

  if (isNativeToken) {
    balance = await targetClient.getBalance({
      address: smartAccountAddress,
    });
    tokenSymbol = chain.nativeCurrency.symbol;

    if (balance === BigInt(0)) {
      throw new Error(`No ${tokenSymbol} balance to transfer`);
    }

    // For native token, we need to estimate gas first to know how much to reserve
    // Prepare a test userOp with full balance to get gas estimates
    const testUserOp = await prepareUserOperationWithFallback({
      bundlerClient,
      targetClient,
      smartAccount,
      calls: [{ to: destination, value: balance, data: "0x" as `0x${string}` }],
    });

    // Calculate required gas prefund: (verificationGas + callGas + preVerificationGas) * maxFeePerGas
    const totalGas =
      (testUserOp.verificationGasLimit || BigInt(0)) +
      (testUserOp.callGasLimit || BigInt(0)) +
      (testUserOp.preVerificationGas || BigInt(0));
    const maxFeePerGas =
      testUserOp.maxFeePerGas || (await targetClient.getGasPrice());

    // Add 50% buffer for gas price fluctuations and safety margin
    const gasPrefund = (totalGas * maxFeePerGas * BigInt(150)) / BigInt(100);

    console.log(`Wallet balance: ${formatEther(balance)} ${tokenSymbol}`);
    console.log(
      `Estimated gas prefund (with 50% buffer): ${formatEther(
        gasPrefund
      )} ${tokenSymbol}`
    );

    if (balance <= gasPrefund) {
      throw new Error(
        `Insufficient balance. Need more than ${formatEther(
          gasPrefund
        )} ${tokenSymbol} to cover gas prefund.`
      );
    }

    transferAmount = balance - gasPrefund;
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

    if (balance === BigInt(0)) {
      throw new Error(`No ${tokenSymbol} balance to transfer`);
    }

    transferAmount = balance;
  }

  console.log(
    `Transferring ${formatEther(
      transferAmount
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
          abi: erc20Abi,
          functionName: "transfer" as const,
          to: token!,
          args: [destination, transferAmount] as const,
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

    console.log(`Using passkey owner at index ${passkeyOwnerIndex}`);

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

  // Estimate gas for handleOps call
  let estimatedGas: bigint;
  try {
    estimatedGas = await targetClient.estimateContractGas({
      abi: entryPoint06Abi,
      address: entryPoint06Address,
      functionName: "handleOps",
      args: [[signedUserOp], bundlerAccount.address],
      account: bundlerAccount,
    });
    console.log(`Estimated gas: ${estimatedGas.toLocaleString()}`);
  } catch {
    // If estimation fails (e.g., signature validation), use a fallback
    // P256/WebAuthn verification via FCL can use ~2M+ gas on some chains
    console.log(
      "Gas estimation failed (signature may not validate in simulation), using fallback"
    );
    estimatedGas = BigInt(2_500_000);
  }

  // Add 20% buffer for safety
  const handleOpsGasLimit = (estimatedGas * BigInt(120)) / BigInt(100);
  console.log(
    `Gas limit (with 20% buffer): ${handleOpsGasLimit.toLocaleString()}`
  );

  // Check bundler has enough balance for gas before submitting
  const currentGasPrice = await targetClient.getGasPrice();
  const requiredGasCost = handleOpsGasLimit * currentGasPrice;
  let bundlerGasBalance = await targetClient.getBalance({
    address: bundlerAccount.address,
  });

  while (bundlerGasBalance < requiredGasCost) {
    const shortfall = requiredGasCost - bundlerGasBalance;
    console.log(`\n⚠️  Bundler account needs more funds for gas!`);
    console.log(`   Bundler: ${bundlerAccount.address}`);
    console.log(
      `   Current balance: ${formatEther(bundlerGasBalance)} ${
        chain.nativeCurrency.symbol
      }`
    );
    console.log(
      `   Required for gas: ${formatEther(requiredGasCost)} ${
        chain.nativeCurrency.symbol
      }`
    );
    console.log(
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

  console.log(
    `\nBundler has sufficient gas funds (${formatEther(bundlerGasBalance)} ${
      chain.nativeCurrency.symbol
    })`
  );

  // Submit the user operation
  const rescueTx = await targetWalletClient.writeContract({
    abi: entryPoint06Abi,
    address: entryPoint06Address,
    functionName: "handleOps",
    args: [[signedUserOp], bundlerAccount.address],
    gas: handleOpsGasLimit,
  });

  console.log("Transaction hash:", rescueTx);

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

  console.log(
    `\nSuccess! Transferred ${formatEther(
      transferAmount
    )} ${tokenSymbol} to ${destination}`
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
      default: process.env.TARGET_RPC_URL || "https://rpc.degen.tips",
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
