/**
 * Shared types for the AntiDrain CLI
 *
 * RULE: No private key types appear here. Keys exist only inside vault.ts
 * and are passed as opaque Account objects from viem.
 */

import type { Address, Hex } from "viem";

// ─── Chain Configuration ───────────────────────────────────────────────────

export type ChainSupportStatus =
  | "LIVE CANARY VERIFIED"
  | "SIMULATED & CODE-VERIFIED"
  | "SUPPORTED FOR VIEW/PLANNING ONLY"
  | "NOT SUPPORTED FOR RESCUE EXECUTION";

export interface ChainConfig {
  /** Human-readable chain name */
  name: string;
  /** EIP-155 chain ID */
  chainId: number;
  /** Native gas token details */
  nativeToken: { symbol: string; decimals: number };
  /** Authenticated or public RPC endpoint */
  rpcUrl: string;
  /** Block explorer URL (for tx links) */
  blockExplorerUrl: string;
  /** BatchExecutor address (deterministic via CREATE2 per sponsor or pre-deployed) */
  batchExecutorAddress: Address;
  /** EIP-7702 support flag */
  supportsEip7702: boolean;
  /** Type 0x04 transaction support flag */
  type04Supported: boolean;
  /** Verification and deployment status */
  status: ChainSupportStatus;
  /** Gas and fee policy guard limits */
  gasPolicy: {
    maxGasLimit: bigint;
    maxFeeWei: bigint;
  };
  /** EIP-7702 verification metadata */
  eip7702: {
    verified: boolean;
    activationDate: string;
    source: string;
  };
  /** Optional testnet counterpart */
  testnet?: {
    chainId: number;
    name: string;
    rpcUrl: string;
    faucetUrl?: string;
  };
}

// ─── Vault Types ───────────────────────────────────────────────────────────

export type WalletRole = "compromised" | "sponsor";

export type SponsorState = "available" | "pending" | "consumed" | "failed";

export interface VaultEntry {
  /** Human-readable name (e.g., "main-compromised", "gas-sponsor") */
  name: string;
  /** Ethereum address (derived from the key, stored for quick lookup) */
  address: Address;
  /** Role of this wallet */
  role: WalletRole;
  /** Chain IDs this wallet is relevant for */
  chains: number[];
  /** Lifecycle state for single-use sponsor wallets */
  sponsorState?: SponsorState;
}

export interface VaultManifest {
  version: number;
  createdAt: string;
  entries: VaultEntry[];
}

// ─── Rescue Types ──────────────────────────────────────────────────────────

/** A single call to execute during rescue (matches Solidity struct) */
export interface RescueCall {
  /** Target contract address (e.g., airdrop claim contract) */
  target: Address;
  /** ETH value to send with the call */
  value: bigint;
  /** Encoded calldata */
  data: Hex;
}

export type AirdropProtocolType =
  | "merkle-distributor"
  | "uniswap-merkle"
  | "signature-claim"
  | "onefootball-claim"
  | "payable-signature-claim"
  | "direct-claim"
  | "custom";

export interface AirdropClaimPlan {
  protocolId: AirdropProtocolType;
  claimContract: Address;
  expectedCodeHash?: Hex;
  claimToken: Address;
  claimant: Address;
  recipient: Address;
  expectedAmount: bigint;
  claimFeeWei?: bigint;
  merkleIndex?: bigint;
  merkleProof?: Hex[];
  signature?: Hex;
  nonce?: bigint;
  deadline?: bigint;
  extraData?: Hex;
}

/** Full rescue plan — everything needed to build the transaction */
export interface RescuePlan {
  /** Target chain */
  chainId: number;
  /** Compromised wallet to rescue from */
  compromisedAddress: Address;
  /** Safe destination wallet (user-provided, any valid address) */
  safeWallet: Address;
  /** Sponsor wallet that pays gas and is authorized to execute */
  sponsorAddress: Address;
  /** Structured airdrop claim specification (if executing an airdrop claim) */
  airdropPlan?: AirdropClaimPlan;
  /** Calls to execute before sweeping (claims, unstakes, etc.) */
  calls: RescueCall[];
  /** ERC-20 token addresses to sweep */
  tokens: Address[];
  /** Optional custom RPC endpoint override */
  rpcUrl?: string;
}

export type RecoveryStatus =
  | "RECOVERED_STATE_AND_EVENT_CORRELATED"
  | "RECOVERED_STATE_ONLY"
  | "PARTIALLY_RECOVERED"
  | "SOURCE_EMPTY"
  | "VERIFICATION_FAILED"
  | "UNVERIFIED";

export type FinalityStatus = "EXECUTED_UNFINALIZED" | "FINALIZED" | "REORGED";

export type AuthoritySanitationState =
  | "AUTHORITY_CLEAN"
  | "PERSISTENT_APPROVALS_DETECTED"
  | "AUTHORITY_UNKNOWN_ARBITRARY_CALLS";

// ─── Phase 5.11 Multi-Dimensional State Classification ─────────────────────

export type EvidenceLevel =
  | "LEVEL_0_TX_STATUS_SUCCESS"
  | "LEVEL_1_SOURCE_BALANCE_CHANGED"
  | "LEVEL_2_DESTINATION_BALANCE_CHANGED"
  | "LEVEL_3_RECEIPT_EVENT_EMITTED"
  | "LEVEL_4_STATE_AND_EVENT_CORRELATED"
  | "LEVEL_5_PROTOCOL_INVARIANT_VERIFIED";

export type ProofStatus =
  | "PROVEN"
  | "FAILED"
  | "UNVERIFIED"
  | "NOT_APPLICABLE"
  | "OUT_OF_SCOPE";

export type DelegationState =
  | "DELEGATION_REVOKED"
  | "DELEGATION_ACTIVE"
  | "REVOCATION_PENDING"
  | "DELEGATION_UNVERIFIED";

export type AuthorityState =
  | "AUTHORITY_DIFF_CLEAN"
  | "PERSISTENT_APPROVALS_DETECTED"
  | "AUTHORITY_DIFF_UNVERIFIED"
  | "AUTHORITY_UNKNOWN_ARBITRARY_CALLS";

export type InventoryState =
  | "INVENTORY_SCOPED_KNOWN_REGISTRY"
  | "INVENTORY_PARTIAL_UNVERIFIED"
  | "INVENTORY_COMPLETE_PROVEN";

export type FinalityState =
  | "INCLUDED"
  | "CANONICAL"
  | "FINALIZED"
  | "REORGED";

export interface AllowanceDiff {
  token: Address;
  symbol: string;
  spender: Address;
  before: bigint;
  after: bigint;
  delta: bigint;
}

export interface MultiDimensionalRescueState {
  assetRecovery: {
    evidenceLevel: EvidenceLevel;
    proofStatus: ProofStatus;
    summary: string;
  };
  delegation: {
    state: DelegationState;
    proofStatus: ProofStatus;
    accountCode: Hex;
  };
  authority: {
    state: AuthorityState;
    proofStatus: ProofStatus;
    allowanceDiffs: AllowanceDiff[];
  };
  inventory: {
    state: InventoryState;
    proofStatus: ProofStatus;
    scannedCount: number;
    discoveredCount: number;
  };
  finality: {
    state: FinalityState;
    proofStatus: ProofStatus;
    blockNumber: bigint;
    blockHash: Hex;
  };
}

// ─── Simulation Types ──────────────────────────────────────────────────────

export interface DiscoveredToken {
  token: Address;
  symbol: string;
  balance: bigint;
  balanceFormatted: string;
}

export interface SimulationResult {
  success: boolean;
  /** Predicted gas usage */
  gasEstimate: bigint;
  /** Predicted gas cost in native token (wei) */
  gasCostWei: bigint;
  /** Human-readable gas cost */
  gasCostFormatted: string;
  /** Per-call results */
  callResults: Array<{
    index: number;
    target: Address;
    success: boolean;
    returnData?: Hex;
    error?: string;
  }>;
  /** Per-token predicted sweep amounts */
  tokenSweeps: Array<{
    token: Address;
    symbol?: string;
    balance: bigint;
    balanceFormatted: string;
  }>;
  /** Total known tokens scanned in registry */
  scannedRegistryCount: number;
  /** Discovered positive-balance tokens omitted from the plan */
  omittedTokens: DiscoveredToken[];
  /** Total discovered positive-balance tokens */
  totalDiscoveredCount: number;
  /** Total tokens included in plan */
  totalIncludedCount: number;
  /** Native balance to sweep */
  nativeSweep: {
    balance: bigint;
    balanceFormatted: string;
  };
  /** Cryptographic Plan Hash (immutable commitment of all parameters) */
  planHash: Hex;
  /** Sponsor balance after gas cost */
  sponsorBalanceAfter: bigint;
  /** Whether this simulation used the exact final calldata with valid EIP-712 signature */
  isFullSimulation: boolean;
  /** Error message if simulation failed */
  error?: string;
}

// ─── Audit Log Types ───────────────────────────────────────────────────────

export interface AuditLogEntry {
  timestamp: string;
  chainId: number;
  chainName: string;
  txHash?: Hex;
  compromisedAddress: Address;
  safeWallet: Address;
  sponsorAddress: Address;
  tokensSwept: Address[];
  callsExecuted: number;
  simulationPassed: boolean;
  broadcastAttempted: boolean;
  success: boolean;
  gasUsed?: bigint;
  error?: string;
}
