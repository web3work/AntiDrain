/**
 * AntiDrain Standalone Extension — Formal Capability Model & Typed Signer
 *
 * Implements strict capability-gated execution:
 * - NO generic `signTransaction()`, `personal_sign()`, or arbitrary signing functions.
 * - Capabilities:
 *   1. SIGN_RESCUE_AUTHORIZATION: Authorizes ONLY the registered CREATE2 delegate on target chain.
 *   2. SIGN_RESCUE_INTENT: Signs EIP-712 intent matching the verified canonical planDigest.
 *   3. BROADCAST_RESCUE_TRANSACTION: Executes outer Type 0x04 gas transaction under sponsor policy limits.
 *   4. BROADCAST_REVOCATION: Sponsors the post-rescue Type 0x04 zero-address delegation clearing tx.
 *
 * Rejects any parameters not matching the active immutable RecoverySession.
 */

import { type SponsorPolicy } from "../vault/webCryptoVault.js";
import { type RecoverySession } from "../rescue/stateMachine.js";
import { BATCH_EXECUTOR_DELEGATE } from "../core/chainRegistry.js";

export type SigningCapabilityType =
  | "SIGN_RESCUE_AUTHORIZATION"
  | "SIGN_RESCUE_INTENT"
  | "BROADCAST_RESCUE_TRANSACTION"
  | "BROADCAST_REVOCATION";

export interface CapabilityContext {
  capability: SigningCapabilityType;
  session: RecoverySession;
  targetChainId: number;
  delegateAddress: `0x${string}`;
  safeDestination: `0x${string}`;
  sponsorAddress: `0x${string}`;
  planDigest: `0x${string}`;
}

export interface RescueIntentCall {
  target: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
}

export interface RescueIntentMessage {
  safeWallet: `0x${string}`;
  sponsor: `0x${string}`;
  calls: readonly RescueIntentCall[];
  tokens: readonly `0x${string}`[];
  nonce: bigint;
  deadline: bigint;
}

export interface RescueIntentDomain {
  name: "AntiDrainRecovery";
  version: "1";
  chainId: number;
  verifyingContract: `0x${string}`;
}

export interface SignedRescueAuthorization {
  contractAddress: `0x${string}`;
  chainId: number;
  nonce: number;
  r: `0x${string}`;
  s: `0x${string}`;
  yParity: number;
}

export interface SignedRescueIntent {
  domain: RescueIntentDomain;
  message: RescueIntentMessage;
  signature: `0x${string}`;
  digest: `0x${string}`;
}

export interface SponsorTxPayload {
  to: `0x${string}`;
  value: bigint;
  data: `0x${string}`;
  gasLimit: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  nonce: number;
  chainId: number;
  authorizationList: SignedRescueAuthorization[];
}

/**
 * Validates that an invocation context matches the active immutable RecoverySession and trusted delegate.
 */
export function validateCapabilityContext(context: CapabilityContext): void {
  const { session, capability, targetChainId, delegateAddress, safeDestination, sponsorAddress, planDigest } = context;

  // 1. Session state must permit this capability
  if (capability === "SIGN_RESCUE_AUTHORIZATION" || capability === "SIGN_RESCUE_INTENT") {
    if (session.state !== "AUTHORIZED" && session.state !== "AWAITING_CONFIRMATION") {
      throw new Error(`Capability Error: ${capability} not permitted in session state ${session.state}.`);
    }
  }

  // 2. Chain ID must match session
  if (targetChainId !== session.targetChainId) {
    throw new Error(`Capability Violation: Chain ID mismatch (${targetChainId} != ${session.targetChainId}).`);
  }

  // 3. Delegate must match verified CREATE2 delegate
  if (delegateAddress.toLowerCase() !== BATCH_EXECUTOR_DELEGATE.toLowerCase()) {
    throw new Error(`Capability Violation: Delegate address (${delegateAddress}) is not the verified AntiDrain delegate.`);
  }

  // 4. Safe destination must match session
  if (safeDestination.toLowerCase() !== session.safeDestination.toLowerCase()) {
    throw new Error(`Capability Violation: Destination address (${safeDestination}) does not match session safe destination.`);
  }

  // 5. Sponsor must match session
  if (sponsorAddress.toLowerCase() !== session.approvedSponsor.toLowerCase()) {
    throw new Error(`Capability Violation: Sponsor address (${sponsorAddress}) does not match approved sponsor.`);
  }

  // 6. Plan digest must match session
  if (planDigest !== session.planDigest) {
    throw new Error(`Capability Violation: Plan digest mismatch.`);
  }
}

/**
 * Validates that a proposed sponsor gas expenditure conforms to the active SponsorPolicy.
 */
export function validateSponsorSpendingPolicy(
  policy: SponsorPolicy,
  estimatedCostWei: bigint
): void {
  const maxGasPerRescue = BigInt(policy.maxGasPerRescueWei);
  if (estimatedCostWei > maxGasPerRescue) {
    throw new Error(
      `Sponsor Policy Violation: Estimated cost (${estimatedCostWei.toString()} wei) exceeds configured maximum limit per rescue (${maxGasPerRescue.toString()} wei).`
    );
  }

  const dailyBudget = BigInt(policy.dailyGasBudgetWei);
  const spentToday = BigInt(policy.spentTodayWei);
  if (spentToday + estimatedCostWei > dailyBudget) {
    throw new Error(
      `Sponsor Policy Violation: Proposed transaction would exceed the daily sponsor gas budget (${dailyBudget.toString()} wei).`
    );
  }
}
