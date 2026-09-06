/**
 * AntiDrain Web3 Claim Interceptor Bridge — Core Type Definitions
 *
 * Implements strict type separation across the 4 trust tiers:
 *   1. CapturedRequest   (Untrusted raw dApp RPC input)
 *   2. ValidatedClaim     (Sanitized & schema-checked request)
 *   3. BridgeRescuePlan   (Immutable EIP-712 rescue specification with bound sourceRequestHash)
 *   4. ExecutedBridgeResult (On-chain verified execution state & revocation)
 *
 * HARD CONSTRAINTS:
 * - NO lower-trust object may directly become an executable transaction.
 * - All signing oracle methods (personal_sign, eth_signTypedData_v4) are rejected with 4100/4200.
 */

import type { Address, Hex } from "viem";
import type { RescueIntentCall } from "../rescue/eip712.js";

// ─── Trust Tier 1: Captured Request ──────────────────────────────────────────

export type BridgeTransport = "local_rpc" | "walletconnect";

export interface CapturedRequest {
  readonly id: string | number;
  readonly method: string;
  readonly params: readonly any[];
  readonly timestamp: number;
  readonly transport: BridgeTransport;
  readonly requestHash: Hex;
  readonly origin?: string;
  readonly correlationId: string;
}

// ─── Trust Tier 2: Validated Claim ───────────────────────────────────────────

export interface ValidatedClaim {
  readonly from: Address;
  readonly to: Address;
  readonly data: Hex;
  readonly value: bigint;
  readonly gasLimit: bigint;
  readonly chainId: number;
  readonly rawRequest: CapturedRequest;
}

// ─── Calldata Classification ──────────────────────────────────────────────────

export type CalldataClassificationType =
  | "CLAIM"
  | "APPROVAL"
  | "TRANSFER"
  | "SWAP"
  | "STAKE"
  | "UNSTAKE"
  | "PERMIT"
  | "UNKNOWN";

export interface CalldataClassification {
  readonly type: CalldataClassificationType;
  readonly selector: Hex;
  readonly functionSignature?: string;
  readonly decodedArgs?: Record<string, any>;
  readonly isPersistentApproval: boolean;
  readonly hazardWarnings: readonly string[];
  readonly targetToken?: Address;
  readonly recipient?: Address;
  readonly claimedAmount?: bigint;
}

// ─── Policy Limits ────────────────────────────────────────────────────────────

export interface PolicyLimits {
  readonly maxClaimValueWei: bigint;         // Default: 0.05 ETH (approx $150)
  readonly maxGasLimit: bigint;              // Default: 1,500,000 gas
  readonly maxTotalSponsorCostWei: bigint;   // Default: 0.1 ETH
  readonly maxSlippageBps: number;           // Default: 100 bps (1%)
  readonly allowPersistentApprovals: boolean;// Default: false (Hard block)
}

export const DEFAULT_POLICY_LIMITS: PolicyLimits = {
  maxClaimValueWei: 50_000_000_000_000_000n, // 0.05 ETH
  maxGasLimit: 1_500_000n,
  maxTotalSponsorCostWei: 100_000_000_000_000_000n, // 0.1 ETH
  maxSlippageBps: 100,
  allowPersistentApprovals: false,
};

// ─── Trust Tier 3: Immutable Bridge Rescue Plan ──────────────────────────────

export interface ExpectedAssetDelta {
  readonly token: Address | "NATIVE";
  readonly symbol: string;
  readonly decimals: number;
  readonly expectedDelta: bigint;
  readonly minimumAcceptableDelta: bigint;
}

export interface BridgeRescuePlan {
  readonly chainId: number;
  readonly victim: Address;
  readonly safeWallet: Address;
  readonly calls: readonly RescueIntentCall[];
  readonly tokens: readonly Address[];
  readonly nonce: bigint;
  readonly deadline: bigint;
  readonly requiredNativeValue: bigint;
  readonly estimatedGas: bigint;
  readonly estimatedSponsorCostWei: bigint;
  readonly expectedAssetDeltas: readonly ExpectedAssetDelta[];
  readonly sourceRequestHash: Hex;
  readonly classification: CalldataClassification;
  readonly planDigest: Hex;
}

// ─── Trust Tier 4: Executed Result ───────────────────────────────────────────

export type RevocationStatus =
  | "REVOKED"
  | "REVOCATION_PENDING"
  | "NOT_DELEGATED"
  | "FAILED";

export interface ActualAssetDelta {
  readonly token: Address | "NATIVE";
  readonly symbol: string;
  readonly delta: bigint;
  readonly beforeBalance: bigint;
  readonly afterBalance: bigint;
}

export interface ExecutedBridgeResult {
  readonly success: boolean;
  readonly txHash?: Hex;
  readonly blockNumber?: bigint;
  readonly actualAssetDeltas: readonly ActualAssetDelta[];
  readonly revocationStatus: RevocationStatus;
  readonly revocationTxHash?: Hex;
  readonly finalCode: Hex;
  readonly error?: string;
  readonly correlationId: string;
}

// ─── EIP-1193 Standard Errors ────────────────────────────────────────────────

export class EIP1193Error extends Error {
  readonly code: number;
  readonly data?: any;

  constructor(code: number, message: string, data?: any) {
    super(message);
    this.name = "EIP1193Error";
    this.code = code;
    this.data = data;
  }
}

export const EIP1193_ERRORS = {
  USER_REJECTED: 4001,
  UNAUTHORIZED: 4100,
  UNSUPPORTED_METHOD: 4200,
  DISCONNECTED: 4900,
  CHAIN_DISCONNECTED: 4901,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
} as const;
