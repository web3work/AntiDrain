/**
 * AntiDrain Phase 0 — Deterministic Canonical Plan Serialization & planDigest
 *
 * Implements strict canonicalization of the authoritative RescuePlan:
 * - Address normalization to canonical 20-byte format.
 * - Unified CanonicalAssetDelta tuple sorting strictly by token address ascending.
 * - Strict ABI packing of all 11 authoritative execution fields.
 * - Deterministic planDigest = keccak256(canonicalEncoding).
 *
 * Security Invariant: Any single-byte or numerical mutation across any field
 * strictly alters the planDigest.
 */

import { encodeAbiParameters, getAddress, keccak256, parseAbiParameters, type Hex, type Address } from "viem";

export interface CanonicalAssetDelta {
  readonly token: Address;
  readonly minDelta: bigint;
}

export interface CanonicalCall {
  readonly target: Address;
  readonly value: bigint;
  readonly data: Hex;
}

export interface CanonicalRescuePlan {
  readonly version: 1;
  readonly chainId: number;
  readonly victim: Address;
  readonly safeWallet: Address;
  readonly calls: ReadonlyArray<CanonicalCall>;
  readonly assetDeltas: ReadonlyArray<CanonicalAssetDelta>;
  readonly feeWei: bigint;
  readonly gasLimit: bigint;
  readonly rescueNonce: bigint;
  readonly deadline: bigint;
}

/**
 * Deeply freezes an object and all nested references to enforce absolute runtime immutability.
 */
export function deepFreeze<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }
  Object.freeze(obj);
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    const val = (obj as Record<string, unknown>)[key];
    if (val !== null && typeof val === "object" && !Object.isFrozen(val)) {
      deepFreeze(val);
    }
  }
  return obj;
}

/**
 * Normalizes and sorts an array of asset deltas strictly by token address ascending.
 */
export function canonicalizeAssetDeltas(deltas: ReadonlyArray<{ token: string; minDelta: bigint }>): CanonicalAssetDelta[] {
  return [...deltas]
    .map((d) => ({
      token: getAddress(d.token),
      minDelta: d.minDelta,
    }))
    .sort((a, b) => a.token.toLowerCase().localeCompare(b.token.toLowerCase()));
}

/**
 * Normalizes and canonicalizes an array of calls.
 */
export function canonicalizeCalls(calls: ReadonlyArray<{ target: string; value: bigint; data: Hex }>): CanonicalCall[] {
  return calls.map((c) => ({
    target: getAddress(c.target),
    value: c.value,
    data: c.data,
  }));
}

/**
 * Builds a validated, normalized, deeply frozen CanonicalRescuePlan.
 */
export function createCanonicalRescuePlan(params: {
  readonly chainId: number;
  readonly victim: string;
  readonly safeWallet: string;
  readonly calls: ReadonlyArray<{ target: string; value: bigint; data: Hex }>;
  readonly assetDeltas: ReadonlyArray<{ token: string; minDelta: bigint }>;
  readonly feeWei: bigint;
  readonly gasLimit: bigint;
  readonly rescueNonce: bigint;
  readonly deadline: bigint;
}): CanonicalRescuePlan {
  if (!params.victim || !params.safeWallet) {
    throw new Error("CanonicalPlan requires valid victim and safeWallet addresses.");
  }
  if (params.chainId <= 0) {
    throw new Error("CanonicalPlan requires a positive chainId.");
  }

  const plan: CanonicalRescuePlan = {
    version: 1,
    chainId: params.chainId,
    victim: getAddress(params.victim),
    safeWallet: getAddress(params.safeWallet),
    calls: canonicalizeCalls(params.calls),
    assetDeltas: canonicalizeAssetDeltas(params.assetDeltas),
    feeWei: params.feeWei,
    gasLimit: params.gasLimit,
    rescueNonce: params.rescueNonce,
    deadline: params.deadline,
  };

  return deepFreeze(plan);
}

/**
 * Strict ABI parameter definition for CanonicalRescuePlan.
 */
const CANONICAL_PLAN_ABI = parseAbiParameters([
  "uint256", // 1. version
  "uint256", // 2. chainId
  "address", // 3. victim
  "address", // 4. safeWallet
  "(address,uint256,bytes)[]", // 5. calls
  "(address,uint256)[]", // 6. assetDeltas (sorted by token)
  "uint256", // 7. feeWei
  "uint256", // 8. gasLimit
  "uint256", // 9. rescueNonce
  "uint256", // 10. deadline
]);

/**
 * Deterministically ABI-encodes a CanonicalRescuePlan into canonical raw bytes.
 */
export function encodeCanonicalPlan(plan: CanonicalRescuePlan): Hex {
  return encodeAbiParameters(CANONICAL_PLAN_ABI, [
    BigInt(plan.version),
    BigInt(plan.chainId),
    plan.victim,
    plan.safeWallet,
    plan.calls.map((c) => [c.target, c.value, c.data] as const),
    plan.assetDeltas.map((d) => [d.token, d.minDelta] as const),
    plan.feeWei,
    plan.gasLimit,
    plan.rescueNonce,
    plan.deadline,
  ]);
}

/**
 * Computes the authoritative cryptographic planDigest for an immutable RescuePlan.
 */
export function computePlanDigest(plan: CanonicalRescuePlan): Hex {
  const encoded = encodeCanonicalPlan(plan);
  return keccak256(encoded);
}
