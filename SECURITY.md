# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

---

## Reporting a Vulnerability

We take the security of AntiDrain and user funds very seriously. If you believe you have discovered a security vulnerability in AntiDrain smart contracts, browser extension, or CLI tools, please report it responsibly.

### How to Report

* **GitHub Security Advisory**: Please report vulnerabilities privately via [GitHub Security Advisories](https://github.com/web3work/AntiDrain/security/advisories/new).
* **Scope**:
  * Smart Contract logic (`UniversalRecoveryDelegate.sol`, `BatchExecutor.sol`)
  * Extension IPC boundary (`inpage.js`, `content.js`, `background.js`)
  * Cryptographic signing logic & capability context validation
  * WebCrypto vault encryption & PBKDF2 parameters

### What to Include
1. A clear description of the vulnerability.
2. Steps to reproduce the issue (including a minimal Foundry test case or Playwright script).
3. The potential impact of the vulnerability.
4. Proposed fix or mitigation (if available).

### Response Timeline
* **Initial Response**: Within 24 hours.
* **Assessment & Status Update**: Within 48 hours.
* **Fix & Coordinated Disclosure**: As soon as a verified patch and staged testnet deployment are completed.
