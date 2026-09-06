/**
 * AntiDrain Web3 Claim Interceptor Bridge — Policy Guard
 *
 * Enforces strict upper bounds on claim fee values, sponsor costs,
 * and blocks unauthorized persistent approval hazards before simulation.
 */

import { isAddress } from "viem";
import type { ValidatedClaim, CalldataClassification, PolicyLimits } from "./types.js";
import { DEFAULT_POLICY_LIMITS, EIP1193Error, EIP1193_ERRORS } from "./types.js";

export interface PolicyValidationResult {
  readonly passed: boolean;
  readonly violations: readonly string[];
  readonly warnings: readonly string[];
}

export function evaluatePolicy(
  claim: ValidatedClaim,
  classification: CalldataClassification,
  limits: PolicyLimits = DEFAULT_POLICY_LIMITS,
): PolicyValidationResult {
  const violations: string[] = [];
  const warnings: string[] = [...classification.hazardWarnings];

  // 1. Target Address Validation
  if (!isAddress(claim.to) || claim.to === "0x0000000000000000000000000000000000000000") {
    violations.push("Target address is invalid or zero address.");
  }

  // 2. Max Native Claim Value Guard (Sponsor fee protection)
  if (claim.value > limits.maxClaimValueWei) {
    violations.push(
      `Claim value (${claim.value.toString()} Wei) exceeds maximum policy limit (${limits.maxClaimValueWei.toString()} Wei).`
    );
  }

  // 3. Max Gas Limit Guard
  if (claim.gasLimit > limits.maxGasLimit) {
    violations.push(
      `Requested gas limit (${claim.gasLimit.toString()}) exceeds maximum allowed (${limits.maxGasLimit.toString()}).`
    );
  }

  // 4. Persistent Approval Blocker
  if (classification.isPersistentApproval && !limits.allowPersistentApprovals) {
    violations.push(
      "Persistent approval hazard: dApp attempted to create spending allowance. Blocked by security policy."
    );
  }

  // 5. Unknown Call Policy Check
  if (classification.type === "UNKNOWN") {
    warnings.push(
      "Unrecognized calldata selector. Will require explicit operator human verification."
    );
  }

  return {
    passed: violations.length === 0,
    violations,
    warnings,
  };
}

export function enforcePolicy(
  claim: ValidatedClaim,
  classification: CalldataClassification,
  limits: PolicyLimits = DEFAULT_POLICY_LIMITS,
): void {
  const result = evaluatePolicy(claim, classification, limits);
  if (!result.passed) {
    throw new EIP1193Error(
      EIP1193_ERRORS.UNAUTHORIZED,
      `Policy violation: ${result.violations.join(" | ")}`
    );
  }
}
