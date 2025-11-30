# Rescue Tokens from Coinbase Smart Wallet on Unsupported Chains

Received an airdrop to your Coinbase Smart Wallet address on a chain that isn't supported by the wallet? This tool lets you rescue those tokens.

It works by deploying your wallet to the unsupported chain and replaying owner management transactions from Base, giving you full control to transfer tokens out.

## What It Does

1. **Deploys** your Coinbase Smart Wallet to the target chain (using deterministic addresses)
2. **Syncs owners** by replaying `AddOwner` operations from Base
3. **Transfers tokens** (ERC-20 or native) to your destination address

## Prerequisites

- **Node.js** v20+ (tested with v20.17.0)
- One of the following:
  - A **13-word recovery phrase** from Coinbase Smart Wallet (add one at [keys.coinbase.com/settings](https://keys.coinbase.com/settings))
  - Your **passkey** registered with the wallet (for passkey mode)

## Installation

```bash
npx coinbase-smart-wallet-rescue --wallet <wallet-address> --destination <destination-address>
```

## Usage

### Basic Usage (Recovery Phrase)

Transfer **native token** (e.g., ETH) using your recovery phrase:

```bash
npx coinbase-smart-wallet-rescue \
  --wallet 0xYourSmartWalletAddress \
  --destination 0xYourDestinationAddress
```

Transfer an **ERC-20 token** (e.g., USDC):

```bash
npx coinbase-smart-wallet-rescue \
  --wallet 0xYourSmartWalletAddress \
  --destination 0xYourDestinationAddress \
  --token 0xTokenContractAddress
```

### Passkey Mode

Use your passkey to sign transactions instead of a recovery phrase:

```bash
npx coinbase-smart-wallet-rescue \
  --wallet 0xYourSmartWalletAddress \
  --destination 0xYourDestinationAddress \
  --mode passkey
```

In passkey mode, the script will:

1. Generate a bundler account to pay for gas
2. Prompt you to fund the bundler account
3. Provide JavaScript code to paste in your browser console at [keys.coinbase.com](https://keys.coinbase.com/settings)
4. Wait for you to paste back the signed response

### Custom RPC / Different Chain

Rescue tokens from any EVM chain by specifying a custom RPC URL:

```bash
npx coinbase-smart-wallet-rescue \
  --wallet 0xYourSmartWalletAddress \
  --destination 0xYourDestinationAddress \
  --rpcUrl https://your-rpc-endpoint.com
```

### Sync Only Mode

Sync owners from Base without transferring any tokens:

```bash
npx coinbase-smart-wallet-rescue \
  --wallet 0xYourSmartWalletAddress \
  --syncOnly \
  --privateKey 0xYourPrivateKey \
  --rpcUrl https://your-rpc-endpoint.com
```

## CLI Options

| Option          | Description                                                 | Required |
| --------------- | ----------------------------------------------------------- | -------- |
| `--wallet`      | Coinbase Smart Wallet address                               | Yes      |
| `--destination` | Destination address for rescued tokens                      | Yes\*    |
| `--token`       | ERC-20 token address (omit for native token)                | No       |
| `--rpcUrl`      | RPC URL for target chain                                    | Yes      |
| `--mode`        | Signing mode: `mnemonic` or `passkey` (default: `mnemonic`) | No       |
| `--syncOnly`    | Only sync owners, don't transfer tokens                     | No       |
| `--privateKey`  | Private key for bundling (required for `--syncOnly`)        | No       |

\*Not required when using `--syncOnly`

## Environment Variables

| Variable            | Description                                  |
| ------------------- | -------------------------------------------- |
| `TARGET_RPC_URL`    | Default RPC URL for target chain             |
| `RPC_URL_8453`      | RPC URL for Base (default: mainnet.base.org) |
| `RECOVERY_MNEMONIC` | Recovery phrase (avoids interactive prompt)  |
| `PRIVATE_KEY`       | Private key for syncOnly mode                |

## How It Works

Coinbase Smart Wallet supports **cross-chain owner management** via replay-protected transactions. When you add an owner on Base, the transaction can be replayed on other chains because:

1. The wallet uses a special nonce key (`8453` for Base) for cross-chain operations
2. `executeWithoutChainIdValidation` allows the same signed operation to execute on any chain
3. The factory address and initialization data are deterministic across chains

This tool:

1. Fetches all `AddOwner` events from your wallet on Base via Blockscout API
2. Extracts the replayable UserOperations from those transactions
3. Deploys your wallet on the target chain (using the same init code)
4. Replays the AddOwner operations to sync your recovery account
5. Signs and submits a transfer operation using your recovery key or passkey

## Development

```bash
# Install dependencies
pnpm install

# Run directly with tsx
pnpm run tsx src/index.ts --wallet 0x... --destination 0x...

# Build for distribution
pnpm run build
```

### Local Testing with Anvil

Fork the target chain locally:

```bash
anvil --fork-url "https://your-rpc-endpoint.com"
```

Run against the fork:

```bash
TARGET_RPC_URL="http://127.0.0.1:8545" pnpm run tsx src/index.ts \
  --wallet 0x... \
  --destination 0x...
```

## License

ISC
