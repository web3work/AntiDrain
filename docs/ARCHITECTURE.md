# AntiDrain — System Architecture & Technical Specification

## 1. Overview

AntiDrain is a self-custodial asset recovery protocol and browser extension designed to rescue assets from compromised EVM wallets (EOAs) without funding the compromised wallet with gas.

```text
┌───────────────────────────┐      ┌──────────────────────────┐      ┌─────────────────────────┐
│     COMPROMISED WALLET    │      │      SPONSOR WALLET      │      │       SAFE WALLET       │
│  (Signs EIP-7702 & Intent)│      │  (Pays gas, sends tx)    │      │  (Receives all assets)  │
└─────────────┬─────────────┘      └────────────┬─────────────┘      └────────────▲────────────┘
              │                                 │                                 │
              │   1. Signs EIP-712 Rescue       │   2. Type 0x04 Envelope         │
              │      (Authorizes Sponsor)       │      (Delegates to Delegate)    │
              └────────────────┬────────────────┴─────────────────────────────────┘
                               │
                               ▼
              ┌─────────────────────────────────┐
              │    UniversalRecoveryDelegate    │
              │  • msg.sender == sponsor        │
              │  • Validates EIP-712 signature  │
              │  • Sweeps tokens & native funds │─────────────────────────────────┘
              │  • Sponsored Revocation to 0x0  │
              └─────────────────────────────────┘
```

---

## 2. Core Protocol Mechanics

### A. EIP-7702 Ephemeral Delegation
1. The compromised victim EOA signs an EIP-7702 authorization tuple delegating execution to the deterministic `UniversalRecoveryDelegate` contract (deployed via CREATE2).
2. The user-controlled Sponsor Wallet broadcasts an outer EIP-7702 (Type `0x04`) transaction, paying gas from the sponsor account.
3. The delegation temporarily sets code on the victim EOA for the duration of the rescue.
4. Immediately following recovery, a second sponsored Type `0x04` transaction delegates the victim to `address(0)`, permanently clearing code from the victim EOA.

### B. EIP-712 Intent Binding & Access Control
Access control inside the delegate contract is enforced cryptographically:

```solidity
struct Rescue {
    address safeWallet;
    address sponsor;
    Call[] calls;
    address[] tokens;
    uint256 nonce;
    uint256 deadline;
}
```

- **Sponsor Binding:** The contract derives `address sponsor = msg.sender;` and binds it in the EIP-712 digest. If any third party (or frontrunning bot) attempts to execute the transaction, `msg.sender` does not match the victim-signed sponsor, and execution reverts with `InvalidAuthorization()`.
- **Destination Binding:** Recovered assets are swept strictly to `safeWallet`.
- **Nonce Isolation:** Uses ERC-7201 unstructured storage (`0x20c4ef2d...`) to prevent storage collisions within delegated EOAs.

---

## 3. Browser Extension Security Architecture

### A. Strict Trust Boundary & Presentation Isolation
- **Inpage Provider (`inpage.js`):** Operates in the untrusted webpage main world. Zero access to private keys or the encrypted vault.
- **Content Script (`content.js`):** Isolated world bridge. Validates message structure and drops illegal request formats.
- **Background Worker (`background.js`):** Manages the WebCrypto AES-256-GCM vault, capability validation, and preflight simulation.

### B. Signing Oracle Elimination
Public EIP-1193 signing methods (`personal_sign`, `eth_sign`, `eth_signTypedData*`, `eth_signTransaction`, `wallet_sendCalls`) are blocked with Error `4100`. The extension only signs verified recovery transactions after physical human confirmation in the popup UI.

---

## 4. Key Management & Lifecycle

- **Encryption at Rest:** AES-256-GCM authenticated encryption with 600,000 PBKDF2-SHA-256 rounds.
- **Memory Lifetime:** When unlocked, keys are retained in memory in the background service worker context.
- **Auto-Lock:** Locks automatically after 15 minutes of inactivity, dereferencing memory objects. *(Note: JavaScript garbage-collected runtimes cannot guarantee physical RAM zeroization).*
