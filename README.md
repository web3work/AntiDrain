# 🛡️ AntiDrain — EVM Wallet Asset Recovery

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![EIP-7702](https://img.shields.io/badge/EIP--7702-Prague%20%2F%20Isthmus-green.svg)](https://eips.ethereum.org/EIPS/eip-7702)
[![EIP-712](https://img.shields.io/badge/EIP--712-Typed%20Authorization-orange.svg)](https://eips.ethereum.org/EIPS/eip-712)
[![Manifest V3](https://img.shields.io/badge/Manifest%20V3-Least%20Privilege-blueviolet.svg)](extension/manifest.json)
[![Tests: 236 Passing](https://img.shields.io/badge/Tests-236%20Passing-success.svg)](#security--verification-rigor)

**AntiDrain** is a non-custodial, open-source browser companion and CLI toolkit for rescuing tokens, native assets, and claimable airdrops from compromised Ethereum / EVM wallets — without ever funding the compromised account with gas.

It uses **EIP-7702 sponsored delegation** and **EIP-712 typed intents** so a designated **Sponsor Wallet** pays gas while the smart contract atomically sweeps assets to a verified **Safe Wallet** in a single transaction.

---

## How It Works

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    WEBPAGE (Untrusted)                                   │
│   Airdrop portals, dApps, hostile scripts                                │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ window.postMessage (EIP-1193)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              CONTENT SCRIPT (Isolated World)                             │
│   Sanitizes requests · Blocks signing oracles (Error 4100)               │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ chrome.runtime.sendMessage
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              BACKGROUND SERVICE WORKER                                   │
│   AES-256-GCM + PBKDF2 encrypted vault · Spending policy guards          │
│   Human confirmation modal · Restricted broadcast transport              │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ eth_sendRawTransaction
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              ON-CHAIN RESCUE CONTRACT                                    │
│   msg.sender == authorized sponsor (cryptographically bound via EIP-712) │
│   ERC-7201 unstructured nonces · EIP-1153 transient reentrancy lock     │
│   Atomic sweep → Immediate sponsored revocation to address(0)            │
└─────────────────────────────────────────────────────────────────────────┘
```

**Recovery flow:**
1. User configures their dedicated, user-funded Sponsor Wallet and Safe Destination Wallet.
2. Compromised victim EOA signs an EIP-7702 delegation tuple to the deterministic recovery delegate contract and an EIP-712 typed intent explicitly authorizing the sponsor wallet.
3. Sponsor broadcasts a Type 0x04 transaction paying gas. The delegate derives `sponsor = msg.sender`, validates that the victim authorized that exact sponsor, and atomically sweeps 100% of discovered tokens and native funds to the safe wallet.
4. A follow-up sponsored transaction immediately revokes the delegation to `address(0)`.

---

## Supported Networks

| Network | Chain ID | Gas Token | Broadcast Transport | Status |
|:---|:---:|:---:|:---|:---:|
| **Base Mainnet** | `8453` | ETH | Direct sequencer submission | 🟢 Active |
| **Ethereum** | `1` | ETH | Private builder relay (Flashbots Protect) | 🟢 Active |
| **Arbitrum One** | `42161` | ETH | Sequencer submission | 🟢 Active |
| **Optimism** | `10` | ETH | Sequencer submission | 🟢 Active |
| **Polygon PoS** | `137` | **POL** | Dedicated RPC submission | 🟢 Active |
| **Mantle** | `5000` | **MNT** | Sequencer submission | 🟢 Active |
| **Base Sepolia** | `84532` | ETH | Testnet RPC submission | 🟢 Verified |

All broadcast submissions route strictly to dedicated endpoints with **zero fallback to public RPC aggregators**.

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) v20+
- [Foundry](https://getfoundry.sh/) (`forge` / `anvil`)

### 1. Clone & Install

```bash
git clone https://github.com/web3work/AntiDrain.git
cd AntiDrain

# CLI
cd cli && npm install && npm run build && cd ..

# Smart Contracts
forge build --root contracts
```

### 2. Build the Browser Extension

```bash
node extension/scripts/package-store-zip.mjs
```

This compiles TypeScript sources and packages the extension for Chrome Web Store submission.

### 3. Load in Chrome / Brave (Developer Mode)

1. Open `chrome://extensions/`
2. Enable **Developer mode**
3. Click **Load unpacked** → select the `extension/` directory

---

## Usage

### Option A: CLI Operations

The CLI provides comprehensive commands for multi-chain discovery, sponsored sweeps, and airdrop claim rescues:

```bash
# 1. Initialize local encrypted vault (AES-256-GCM + PBKDF2)
node cli/dist/index.js vault init

# 2. Add compromised wallet and sponsor wallet
node cli/dist/index.js vault add

# 3. Check sponsor gas balances across all chains
node cli/dist/index.js sponsor check

# 4. Multi-chain asset scan (discovers native balances, ERC-20s, and delegation status)
node cli/dist/index.js scan <VICTIM_ADDRESS>

# 5. Interactive full rescue (sweeps tokens + native assets to safe cold wallet)
node cli/dist/index.js rescue

# 6. Generic airdrop claim + sweep (executes claim calldata and sweeps token atomically)
node cli/dist/index.js airdrop

# 7. Dedicated airdrop voucher claim & sweep
node cli/dist/index.js rescue-onefootball \
  --victim <VICTIM_ADDRESS> \
  --sponsor <SPONSOR_ADDRESS> \
  --safe <SAFE_COLD_WALLET> \
  --month 4

# 8. Web3 Claim Interceptor Bridge (local RPC bridge for 1-click dApp claims)
node cli/dist/index.js bridge --victim <VICTIM_ADDRESS> --safe <SAFE_COLD_WALLET>
```

### Option B: Browser Extension Companion

1. **Create Master Password** — Encrypts your vault locally with AES-256-GCM (PBKDF2, 600,000 rounds).
2. **Import Compromised Wallet** — Address + private key of the drained account.
3. **Set Recovery Destination** — Your safe cold / hardware wallet address (no key needed).
4. **Configure Gas Sponsor** — A funded wallet that pays rescue transaction fees.

#### Intercepted Web3 Claims

When interacting with an airdrop portal or dApp, AntiDrain:
1. Intercepts the `eth_sendTransaction` call.
2. Simulates the outcome advisory via `eth_call`.
3. Opens a **physical confirmation modal** displaying exact asset movements, gas costs, and destination addresses.
4. Upon explicit user confirmation, signs the sponsored rescue transaction and revokes delegation immediately.

---

## Security & Verification Rigor

### Automated Security Verification Matrix (236 Passing Tests)

AntiDrain enforces strict pre-production release gates. Every release must pass 100% of the 236 automated verification tests:

- **Smart Contract & Virtual Machine Invariants (125 Foundry Tests)**
  - EIP-7702 ephemeral delegation lifecycle and execution boundaries
  - ERC-7201 unstructured storage nonces (`0x20c4ef2d...`) proving zero storage collision inside delegated EOAs
  - EIP-1153 transient reentrancy protection locking out untrusted token callback vectors
  - Dual-authorization cryptographic gating (`msg.sender == sponsor` bound inside EIP-712 digest)
  - Non-standard ERC-20 handling (fee-on-transfer, missing return values, and malicious hook rejection)
  - Exact value accounting ensuring zero overfunding or stranded native balances
- **Core Security Invariants & Policy Bounds (44 Invariant Tests)**
  - INV-01 through INV-44: Ephemeral memory lifetimes, key clearing, capability contexts, and spending policies
- **Deterministic Cryptographic Proofs (67 Proof Tests)**
  - Bitwise EIP-712 digest encoding, schema hashing, and cross-chain domain separation
  - Negative adversarial signature matrix (sponsor mutation, safe wallet swapping, calldata tampering)
  - Deterministic CREATE2 deployment bytecode and salt derivation verification
- **Multi-Chain Compatibility & Fee Routing (17 Multi-Chain Tests)**
  - Production chain registry invariants across Ethereum, Base, Arbitrum, Optimism, Polygon, and Mantle
  - Non-ETH gas token handling (Polygon POL, Mantle MNT) with zero lossy floating-point arithmetic
  - Strict private builder (Flashbots Protect) and direct sequencer routing with zero fallback to public mempools
- **Web3 Bridge & Interceptor Security (31 Adversarial Tests)**
  - Origin verification, protocol domain fencing, and forbidden signing method rejection (Error 4100)
  - Double-spend and concurrent rescue race condition prevention (strictly 1 active rescue per account)
- **Airdrop Claim & Lifecycle Regression (16 Lifecycle Tests)**
  - Dynamic fee query verification and 11-point precondition validation
  - Post-rescue sponsored revocation verification confirming code reset to pure EOA (`0x`)

```bash
# Run the complete security release gate
node scripts/security-release-gate.js

# Smart contract test suite
forge test --root contracts

# Individual deterministic verification suites
node cli/dist/test/deterministic-verification-suite.js
node --test cli/dist/test/multi-chain-compatibility.js
node --test cli/dist/test/onefootball-validation-suite.js
node --test cli/dist/test/onefootball-orchestrator-regression.js
```

---

## Project Structure

```
AntiDrain/
├── contracts/                # Solidity smart contracts & Foundry test suite
│   ├── src/                  #   UniversalRecoveryDelegate.sol, BatchExecutor.sol
│   ├── test/                 #   125 Foundry tests (15 suites: fuzz, adversarial, matrix, value flows)
│   └── script/               #   CREATE2 deployment script
├── extension/                # Chrome Manifest V3 browser companion
│   ├── src/                  #   TypeScript source (background, content, inpage, popup, vault)
│   ├── manifest.json         #   Extension configuration (storage permission only)
│   ├── icons/                #   Extension icons
│   └── scripts/              #   Build & packaging scripts
├── cli/                      # TypeScript CLI coordinator
│   ├── src/                  #   Rescue orchestrator, EIP-712 encoder, bridge, simulator
│   └── src/test/             #   Deterministic verification & adversarial test suites
├── scripts/                  # Build verification & audit scripts
├── LICENSE                   # MIT License
├── PRIVACY.md                # Privacy policy (zero telemetry, local-only)
├── SECURITY.md               # Vulnerability disclosure via GitHub Security Advisories
└── README.md                 # This file
```

---

## Security Model & Disclosures

### What AntiDrain Protects Against
- ✅ Malicious webpage JavaScript accessing private keys
- ✅ Signing oracle attacks (`personal_sign`, `eth_sign`, `eth_signTypedData` → blocked with Error 4100)
- ✅ Frontrunning via public mempool exposure (restricted broadcast transport)
- ✅ Unauthorized asset routing (on-chain dual-authorization: sponsor + EIP-712 intent)
- ✅ Storage collisions in delegated EOAs (ERC-7201 unstructured nonces)
- ✅ Reentrancy during token callbacks (EIP-1153 transient lock)

### What AntiDrain Cannot Protect Against
- ⚠️ **Compromised browser or OS** — A fully compromised browser binary or operating system can read process memory.
- ⚠️ **Compromised extension update** — A malicious Chrome Web Store update could modify the background service worker.
- ⚠️ **Hardware-level attacks** — AntiDrain is a software wallet. Decrypted keys reside in V8 engine memory while unlocked. It is not equivalent to a hardware wallet or secure enclave.

### Broadcast Transport Reality
- **Ethereum**: Flashbots Protect provides true private builder auction with MEV privacy.
- **L2 Rollups** (Base, Arbitrum, Optimism, Mantle): Direct sequencer feeds with centralized FIFO ordering. No public p2p mempool.
- **Polygon PoS**: Dedicated Bor RPC gateway. **No cryptographic MEV privacy**.

Pre-broadcast simulation (`eth_call`) is an **advisory estimation** only. Asset destinations and transaction integrity are enforced on-chain by the smart contract.

---

## Deployment & Operational Model

- **Zero-Custody Architecture**: Assets move directly from the compromised account to the user's designated safe cold wallet in the same transaction. AntiDrain never takes custody of funds, and there are no intermediate contract escrows or fee deductions.
- **Deterministic CREATE2 Protocol**: The recovery delegate is designed for deterministic deployment across EVM chains via the standard CREATE2 factory (`0x4e59b44847b379578588920cA78FbF26c0B4956C`), ensuring contract bytecode is immutable, auditable, and identical across all supported networks.
- **Ephemeral Delegation & Immediate Revocation**: EIP-7702 delegation is temporary. Following every rescue execution, a sponsored follow-up transaction delegates the account to `address(0)`, permanently clearing contract code and restoring the account to a pure EOA.
- **Mandatory Preflight Simulation**: Every rescue strictly requires simulation via `eth_call` with state overrides prior to signing or broadcasting. No transaction can be broadcast without physical human confirmation.

---

## Contributing

Contributions are welcome. Please open an issue to discuss proposed changes before submitting a pull request.

---

## Security & Responsible Disclosure

If you discover a vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/web3work/AntiDrain/security/advisories/new).

See [SECURITY.md](SECURITY.md) for details.

---

## License

[MIT License](LICENSE) — Copyright (c) 2026 AntiDrain Contributors
