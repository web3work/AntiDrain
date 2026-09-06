/**
 * AntiDrain Phase 0 — 16-State Native Lifecycle State Machine
 *
 * Enforces strict, monotonic, authoritative state progression.
 * Prohibits illegal bypasses (e.g. Browser request -> Signing or Challenge -> Broadcast).
 *
 * Security Invariant: The ONLY valid path to vault unlocking and signing
 * is through NATIVE_CONFIRMED (trusted native human authorization gesture).
 */

import { type Hex } from "viem";
import { type CanonicalRescuePlan, computePlanDigest } from "./canonical.js";

export type RescueState =
  | "IDLE"
  | "REQUEST_RECEIVED"
  | "VALIDATED"
  | "CLASSIFIED"
  | "POLICY_APPROVED"
  | "SIMULATED"
  | "PLAN_CREATED"
  | "CHALLENGE_ISSUED"
  | "NATIVE_CONFIRMED"
  | "SIGNING"
  | "BROADCASTED"
  | "EXECUTED"
  | "RECOVERY_VERIFIED"
  | "REVOCATION_PENDING"
  | "REVOCATION_BROADCASTED"
  | "REVOKED"
  | "REJECTED"
  | "CANCELLED"
  | "EXPIRED";

export interface RescueSessionContext {
  readonly sessionId: string;
  readonly requestId: string;
  readonly challengeId: string;
  readonly chainId: number;
  readonly victim: string;
  readonly safeWallet: string;
  readonly rawTarget: string;
  readonly rawCalldata: Hex;
  readonly rawValue: bigint;
  readonly plan?: CanonicalRescuePlan;
  readonly planDigest?: Hex;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly txHash?: Hex;
  readonly revocationTxHash?: Hex;
}

const LEGAL_TRANSITIONS: Record<RescueState, ReadonlySet<RescueState>> = {
  IDLE: new Set(["REQUEST_RECEIVED"]),
  REQUEST_RECEIVED: new Set(["VALIDATED", "REJECTED"]),
  VALIDATED: new Set(["CLASSIFIED", "REJECTED"]),
  CLASSIFIED: new Set(["POLICY_APPROVED", "REJECTED"]),
  POLICY_APPROVED: new Set(["SIMULATED", "REJECTED"]),
  SIMULATED: new Set(["PLAN_CREATED", "REJECTED"]),
  PLAN_CREATED: new Set(["CHALLENGE_ISSUED", "REJECTED"]),
  CHALLENGE_ISSUED: new Set(["NATIVE_CONFIRMED", "CANCELLED", "EXPIRED", "REJECTED"]),
  NATIVE_CONFIRMED: new Set(["SIGNING", "REJECTED", "CANCELLED"]),
  SIGNING: new Set(["BROADCASTED", "REJECTED"]),
  BROADCASTED: new Set(["EXECUTED", "REJECTED"]),
  EXECUTED: new Set(["RECOVERY_VERIFIED", "REJECTED"]),
  RECOVERY_VERIFIED: new Set(["REVOCATION_PENDING", "REJECTED"]),
  REVOCATION_PENDING: new Set(["REVOCATION_BROADCASTED", "REJECTED"]),
  REVOCATION_BROADCASTED: new Set(["REVOKED", "REJECTED"]),
  REVOKED: new Set([]), // Terminal Success State
  REJECTED: new Set([]), // Terminal Rejection State
  CANCELLED: new Set([]), // Terminal Cancellation State
  EXPIRED: new Set([]), // Terminal Expiration State
};

export class RescueStateMachine {
  private _state: RescueState = "IDLE";
  private _context: RescueSessionContext;
  private _rejectionReason?: string;

  constructor(initialContext: RescueSessionContext) {
    this._context = { ...initialContext };
  }

  public get state(): RescueState {
    return this._state;
  }

  public get context(): Readonly<RescueSessionContext> {
    return this._context;
  }

  public get rejectionReason(): string | undefined {
    return this._rejectionReason;
  }

  /**
   * Advances the state machine to nextState if and only if the transition is strictly legal.
   */
  public transitionTo(nextState: RescueState, contextUpdates?: Partial<RescueSessionContext>, reason?: string): void {
    const allowed = LEGAL_TRANSITIONS[this._state];
    if (!allowed || !allowed.has(nextState)) {
      throw new Error(
        `Illegal State Transition: Cannot transition from "${this._state}" to "${nextState}". Strict lifecycle policy violated.`
      );
    }

    // Time-to-Live / Expiration check for active states before signing
    if (this._context.expiresAt > 0 && Date.now() > this._context.expiresAt && nextState !== "EXPIRED" && nextState !== "REJECTED") {
      this._state = "EXPIRED";
      this._rejectionReason = "Challenge expired before completion.";
      throw new Error("Challenge has expired. Execution aborted.");
    }

    this._state = nextState;
    if (contextUpdates) {
      this._context = { ...this._context, ...contextUpdates };
    }
    if (reason) {
      this._rejectionReason = reason;
    }
  }

  /**
   * Rejects the rescue and locks into the terminal REJECTED state.
   */
  public reject(reason: string): void {
    this._state = "REJECTED";
    this._rejectionReason = reason;
  }

  /**
   * Cancels the rescue and locks into the terminal CANCELLED state.
   */
  public cancel(reason: string): void {
    if (this._state === "SIGNING" || this._state === "BROADCASTED" || this._state === "EXECUTED" || this._state === "REVOKED") {
      throw new Error(`Cannot cancel rescue in irreversible state "${this._state}".`);
    }
    this._state = "CANCELLED";
    this._rejectionReason = reason;
  }

  /**
   * Validates that the plan digest attached to the session matches the authoritative computation.
   */
  public verifyPlanDigestIntegrity(): boolean {
    if (!this._context.plan || !this._context.planDigest) {
      return false;
    }
    const derived = computePlanDigest(this._context.plan);
    return derived.toLowerCase() === this._context.planDigest.toLowerCase();
  }
}
