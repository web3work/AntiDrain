# AntiDrain — Privacy & Data Protection Policy

## 1. Zero-Knowledge Local Custody

AntiDrain operates as a 100% self-custodial, client-side browser extension:

* **Zero Private Key Transmission:** Your private keys, seed phrases, and passwords **never leave your device**.
* **Zero Remote Analytics / Telemetry:** AntiDrain does not collect browsing history, wallet balances, or user identities.
* **Direct RPC Communication:** RPC requests are sent directly from your browser to the designated network RPC endpoints.
* **Encrypted Storage:** All wallet metadata is stored strictly in your browser's local storage (`chrome.storage.local`) using authenticated AES-256-GCM encryption.

---

## 2. Telemetry and Logging Policy

* No sensitive data is ever output to browser consoles or logs.
* In error states, only sanitized, high-level error descriptions are displayed to prevent leakage of internal state or addresses.
