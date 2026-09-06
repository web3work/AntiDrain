/**
 * AntiDrain Standalone Extension — Formal Recovery Session & State Machine Model
 *
 * Implements strict recovery session isolation:
 * - Sessions are ephemeral, single-use, and bound to immutable parameters:
 *   (victim, safeWallet, chainId, delegate, sponsor, planDigest, deadline)
 * - State progression:
 *   CREATED
 *     ↓
 *   READY
 *     ↓
 *   SIMULATING
 *     ↓
 *   AWAITING_CONFIRMATION
 *     ↓
 *   AUTHORIZED
 *     ↓
 *   EXECUTING
 *     ↓
 *   VERIFIED
 *     ↓
 *   REVOCATION_PENDING
 *     ↓
 *   REVOCATION_BROADCAST
 *     ↓
 *   REVOCATION_VERIFIED (on-chain eth_getCode == 0x)
 *     ↓
 *   CLEAN
 *
 * Terminal States (Non-Reusable):
 *   CLEAN, CLEANUP_REQUIRED, EXPIRED, ABORTED
 */

export type RecoverySessionState =
  | "CREATED"
  | "READY"
  | "SIMULATING"
  | "AWAITING_CONFIRMATION"
  | "AUTHORIZED"
  | "EXECUTING"
  | "RESCUE_NOT_BROADCAST"
  | "RESCUE_BROADCAST_UNKNOWN"
  | "RESCUE_INCLUDED"
  | "RESCUE_REVERTED"
  | "RESCUE_DROPPED"
  | "VERIFIED"
  | "REVOCATION_PENDING"
  | "REVOCATION_BROADCAST"
  | "REVOCATION_VERIFIED"
  | "CLEAN"
  | "CLEANUP_REQUIRED"
  | "EXPIRED"
  | "ABORTED";

export interface RecoverySession {
  readonly sessionId: string;
  readonly victimAddress: `0x${string}`;
  readonly safeDestination: `0x${string}`;
  readonly targetChainId: number;
  readonly approvedDelegate: `0x${string}`;
  readonly approvedSponsor: `0x${string}`;
  readonly planDigest: `0x${string}`;
  readonly createdAt: number;
  readonly expiresAt: number; // Max 30 minutes lifetime
  state: RecoverySessionState;
  rescueTxHash?: `0x${string}`;
  revocationTxHash?: `0x${string}`;
  assetsRecovered: Array<{ token: string; symbol: string; amount: string }>;
  errorMessage?: string;
  updatedAt: number;
}

const ALLOWED_TRANSITIONS: Record<RecoverySessionState, RecoverySessionState[]> = {
  CREATED: ["READY", "ABORTED", "EXPIRED"],
  READY: ["SIMULATING", "ABORTED", "EXPIRED"],
  SIMULATING: ["AWAITING_CONFIRMATION", "ABORTED", "EXPIRED", "CLEANUP_REQUIRED"],
  AWAITING_CONFIRMATION: ["AUTHORIZED", "ABORTED", "EXPIRED"],
  AUTHORIZED: ["EXECUTING", "RESCUE_NOT_BROADCAST", "CLEANUP_REQUIRED", "ABORTED"],
  EXECUTING: ["VERIFIED", "RESCUE_INCLUDED", "RESCUE_REVERTED", "RESCUE_DROPPED", "RESCUE_BROADCAST_UNKNOWN", "RESCUE_NOT_BROADCAST", "CLEANUP_REQUIRED"],
  RESCUE_NOT_BROADCAST: ["ABORTED", "CLEAN"], // No on-chain delegation established; safe reset
  RESCUE_BROADCAST_UNKNOWN: ["RESCUE_INCLUDED", "RESCUE_REVERTED", "RESCUE_DROPPED", "VERIFIED", "CLEANUP_REQUIRED", "ABORTED"], // Must reconcile on-chain
  RESCUE_INCLUDED: ["VERIFIED", "REVOCATION_PENDING", "CLEANUP_REQUIRED"],
  RESCUE_REVERTED: ["CLEANUP_REQUIRED", "ABORTED", "CLEAN"],
  RESCUE_DROPPED: ["ABORTED", "CLEAN"],
  VERIFIED: ["REVOCATION_PENDING", "CLEANUP_REQUIRED"],
  REVOCATION_PENDING: ["REVOCATION_BROADCAST", "CLEANUP_REQUIRED"],
  REVOCATION_BROADCAST: ["REVOCATION_VERIFIED", "CLEANUP_REQUIRED"],
  REVOCATION_VERIFIED: ["CLEAN"],
  CLEAN: [], // Terminal
  CLEANUP_REQUIRED: ["REVOCATION_PENDING", "REVOCATION_BROADCAST", "CLEAN", "ABORTED"],
  EXPIRED: [], // Terminal
  ABORTED: [], // Terminal
};

export class RecoverySessionController {
  private session: RecoverySession;

  constructor(session: RecoverySession) {
    this.session = { ...session };
  }

  public getSession(): Readonly<RecoverySession> {
    return Object.freeze({ ...this.session });
  }

  public getState(): RecoverySessionState {
    // Automatic expiration check
    if (
      Date.now() > this.session.expiresAt &&
      this.session.state !== "CLEAN" &&
      this.session.state !== "CLEANUP_REQUIRED" &&
      this.session.state !== "ABORTED"
    ) {
      this.session.state = "EXPIRED";
      this.session.updatedAt = Date.now();
    }
    return this.session.state;
  }

  public isTerminal(): boolean {
    const s = this.getState();
    return s === "CLEAN" || s === "EXPIRED" || s === "ABORTED";
  }

  public isRescueBlocked(): boolean {
    return this.getState() === "CLEANUP_REQUIRED";
  }

  public transitionTo(
    nextState: RecoverySessionState,
    mutation?: Partial<Omit<RecoverySession, "sessionId" | "victimAddress" | "safeDestination" | "targetChainId" | "approvedDelegate" | "approvedSponsor" | "planDigest" | "createdAt" | "expiresAt">>
  ): RecoverySession {
    const currentState = this.getState();

    // Check expiry
    if (Date.now() > this.session.expiresAt && nextState !== "EXPIRED" && nextState !== "CLEANUP_REQUIRED") {
      this.session.state = "EXPIRED";
      this.session.errorMessage = "Recovery session expired before completion.";
      this.session.updatedAt = Date.now();
      return this.session;
    }

    const allowed = ALLOWED_TRANSITIONS[currentState];
    if (!allowed || !allowed.includes(nextState)) {
      // Illegal jump forces CLEANUP_REQUIRED fail-closed
      this.session.state = "CLEANUP_REQUIRED";
      this.session.errorMessage = `Illegal recovery state transition from ${currentState} to ${nextState}.`;
      this.session.updatedAt = Date.now();
      return this.session;
    }

    this.session.state = nextState;
    if (mutation) {
      Object.assign(this.session, mutation);
    }
    this.session.updatedAt = Date.now();
    return this.session;
  }
}
