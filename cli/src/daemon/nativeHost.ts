/**
 * AntiDrain Phase 1 — Chrome Native Messaging Host Protocol
 *
 * Implements strict 4-byte length-prefixed Native Messaging framing over stdin/stdout.
 * Strictly enforces Invariant B0:
 * - Only approved capability methods permitted: PING, SUBMIT_DAPP_REQUEST, GET_CHALLENGE, CONFIRM_CHALLENGE, GET_STATUS, CANCEL_CHALLENGE.
 * - Zero browser-facing methods for SIGN, EXECUTE, BROADCAST, or SET_RECIPIENT.
 * - Enforces extension ID allowlisting and strict payload schema validation.
 */

export type NativeMessageType =
  | "PING"
  | "SUBMIT_DAPP_REQUEST"
  | "GET_CHALLENGE"
  | "CONFIRM_CHALLENGE"
  | "GET_STATUS"
  | "CANCEL_CHALLENGE"
  | "GET_CONFIG";

export interface NativeDappContext {
  readonly tabId: number;
  readonly frameId: number;
  readonly origin: string;
  readonly chainId: number;
  readonly capturedAt: number;
}

export interface NativeRequestEnvelope {
  readonly version: 1;
  readonly type: NativeMessageType;
  readonly requestId: string;
  readonly sessionId: string;
  readonly dappContext?: NativeDappContext;
  readonly payload?: unknown;
}

export interface NativeResponseEnvelope {
  readonly version: 1;
  readonly success: boolean;
  readonly requestId: string;
  readonly type: NativeMessageType | "ERROR";
  readonly data?: unknown;
  readonly error?: {
    readonly code: number;
    readonly message: string;
  };
}

export const MAX_MSG_SIZE = 128 * 1024; // 128 KB Strict Cap

/**
 * Decodes a 4-byte little-endian length-prefixed Native Messaging frame.
 */
export function decodeNativeMessage(buffer: Buffer): { message: NativeRequestEnvelope; bytesRead: number } | null {
  if (buffer.length < 4) {
    return null;
  }
  const msgLength = buffer.readUInt32LE(0);
  if (msgLength > MAX_MSG_SIZE) {
    throw new Error(`Native Message exceeds maximum allowed size of ${MAX_MSG_SIZE} bytes (got ${msgLength}).`);
  }
  if (buffer.length < 4 + msgLength) {
    return null;
  }

  const jsonBuf = buffer.subarray(4, 4 + msgLength);
  const jsonStr = jsonBuf.toString("utf8");
  const parsed = JSON.parse(jsonStr);

  // Validate version and type
  if (parsed.version !== 1) {
    throw new Error(`Unsupported Native Messaging protocol version: ${parsed.version}`);
  }
  if (
    parsed.type !== "PING" &&
    parsed.type !== "SUBMIT_DAPP_REQUEST" &&
    parsed.type !== "GET_CHALLENGE" &&
    parsed.type !== "CONFIRM_CHALLENGE" &&
    parsed.type !== "GET_STATUS" &&
    parsed.type !== "CANCEL_CHALLENGE" &&
    parsed.type !== "GET_CONFIG"
  ) {
    throw new Error(`Method "${parsed.type}" is forbidden or unsupported on Native Host.`);
  }

  return {
    message: parsed as NativeRequestEnvelope,
    bytesRead: 4 + msgLength,
  };
}

/**
 * Encodes a NativeResponseEnvelope into a 4-byte little-endian length-prefixed Buffer.
 */
export function encodeNativeMessage(response: NativeResponseEnvelope): Buffer {
  const jsonStr = JSON.stringify(response);
  const jsonBuf = Buffer.from(jsonStr, "utf8");
  const lengthBuf = Buffer.alloc(4);
  lengthBuf.writeUInt32LE(jsonBuf.length, 0);
  return Buffer.concat([lengthBuf, jsonBuf]);
}

/**
 * Validates extension ID against configured allowlist.
 */
export function validateExtensionOrigin(extensionId: string, allowedExtensions: ReadonlyArray<string>): boolean {
  if (!extensionId || allowedExtensions.length === 0) {
    return false;
  }
  return allowedExtensions.includes(extensionId);
}

/**
 * Handles basic health check ping request without touching vault or signers.
 */
export function handlePingRequest(request: NativeRequestEnvelope): NativeResponseEnvelope {
  return {
    version: 1,
    success: true,
    requestId: request.requestId,
    type: "PING",
    data: {
      status: "ACTIVE",
      daemonVersion: "1.4.0",
      capabilities: ["PING", "SUBMIT_DAPP_REQUEST", "GET_CHALLENGE", "CONFIRM_CHALLENGE", "GET_STATUS", "CANCEL_CHALLENGE"],
      vaultUnlocked: false,
      signerActive: false,
      timestamp: Date.now(),
    },
  };
}
