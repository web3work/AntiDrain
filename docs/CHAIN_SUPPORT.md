# AntiDrain — Universal EVM Chain Support & Capability Matrix

## 1. Multi-Chain EVM Architecture

AntiDrain decouples **EVM Network Recognition** from **Production Rescue Capability**:

* Any standard EVM network can be recognized by the wallet for basic balance and transaction observation.
* EIP-7702 Rescue is strictly enabled on networks that have completed verification of the deterministic CREATE2 delegate contract.

---

## 2. Universal EVM Capability Matrix

| Network | Chain ID | Gas Token | EIP-7702 Status | Delegate Deployment | Bytecode Verified | Rescue Capability |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Ethereum Mainnet** | `1` | **ETH** | ✅ (Pectra) | CREATE2 Standard | ✅ | 🟢 **ENABLED** |
| **Base Mainnet** | `8453` | **ETH** | ✅ (May 2025) | CREATE2 Standard | ✅ | 🟢 **ENABLED** |
| **Base Sepolia (Testnet)** | `84532` | **ETH** | ✅ (May 2025) | CREATE2 Standard | ✅ | 🟢 **ENABLED** |
| **Arbitrum One** | `42161` | **ETH** | ✅ (ArbOS 40) | CREATE2 Standard | ✅ | 🟢 **ENABLED** |
| **Optimism** | `10` | **ETH** | ✅ (Isthmus) | CREATE2 Standard | ✅ | 🟢 **ENABLED** |
| **Polygon PoS** | `137` | **POL** | ✅ (PIP-61) | CREATE2 Standard | ✅ | 🟢 **ENABLED** |
| **Mantle** | `5000` | **MNT** | ✅ (Everest) | CREATE2 Standard | ✅ | 🟢 **ENABLED** |
| **Unknown EVM** | *Any* | *Any* | ❓ | *None* | *None* | 🔴 **DISABLED (FAIL-CLOSED)** |

---

## 3. Broadcast Transport Details

* **Ethereum (Chain 1):** Routes via Flashbots Protect for MEV privacy.
* **L2 Rollups (Base, Arbitrum, Optimism, Mantle):** Routes via official sequencer endpoints with centralized FIFO execution.
* **Polygon PoS (Chain 137):** Dedicated Bor RPC gateway (**POL** native gas token; no cryptographic MEV privacy).
