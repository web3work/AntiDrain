/**
 * AntiDrain Thin Companion — Shared Types & Protocol Schemas
 *
 * Enforces Invariant B0:
 * The extension contains ZERO private keys, ZERO seed phrases, ZERO signing primitives,
 * and ZERO authoritative RescuePlan construction logic.
 */

export interface DappContext {
  readonly tabId: number;
  readonly frameId: number;
  readonly origin: string;
  readonly chainId: number;
  readonly capturedAt: number;
  readonly requestId: string;
}

export interface InpageRequestMessage {
  readonly target: "ANTIDRAIN_CONTENT";
  readonly version: 1;
  readonly sessionId: string;
  readonly requestId: string;
  readonly method: string;
  readonly params?: unknown[];
}

export interface ContentResponseMessage {
  readonly target: "ANTIDRAIN_INPAGE";
  readonly version: 1;
  readonly requestId: string;
  readonly result?: unknown;
  readonly error?: {
    readonly code: number;
    readonly message: string;
  };
}

export const EIP1193_ERRORS = {
  USER_REJECTED: 4001,
  UNAUTHORIZED: 4100,
  UNSUPPORTED_METHOD: 4200,
  DISCONNECTED: 4900,
  CHAIN_DISCONNECTED: 4901,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
} as const;

export class EIP1193Error extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.code = code;
    this.data = data;
    this.name = "EIP1193Error";
  }
}
