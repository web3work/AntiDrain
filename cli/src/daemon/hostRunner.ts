#!/usr/bin/env node
/**
 * AntiDrain Native Messaging Host Runner
 *
 * Dedicated stdio listener launched by Chrome / Brave / Edge.
 * - Reads length-prefixed binary frames from process.stdin.
 * - Writes length-prefixed binary frames to process.stdout.
 * - Directs all diagnostic/human logs to process.stderr ONLY.
 */

import {
  decodeNativeMessage,
  encodeNativeMessage,
  handlePingRequest,
  type NativeRequestEnvelope,
  type NativeResponseEnvelope,
} from "./nativeHost.js";

function logError(msg: string, ...args: unknown[]): void {
  process.stderr.write(`[AntiDrain NativeHost] ${msg} ${args.map(String).join(" ")}\n`);
}

let accumulator = Buffer.alloc(0);

process.stdin.on("data", (chunk: Buffer) => {
  accumulator = Buffer.concat([accumulator, chunk]);

  while (accumulator.length >= 4) {
    try {
      const decoded = decodeNativeMessage(accumulator);
      if (!decoded) {
        // Frame not fully arrived yet
        break;
      }

      // Slice consumed bytes
      accumulator = accumulator.subarray(decoded.bytesRead);

      // Handle message
      const response = dispatchMessage(decoded.message);
      const encodedResponse = encodeNativeMessage(response);
      process.stdout.write(encodedResponse);
    } catch (err) {
      logError("Frame processing error:", err);
      const errResponse: NativeResponseEnvelope = {
        version: 1,
        success: false,
        requestId: "unknown",
        type: "ERROR",
        error: {
          code: -32603,
          message: err instanceof Error ? err.message : String(err),
        },
      };
      process.stdout.write(encodeNativeMessage(errResponse));
      accumulator = Buffer.alloc(0);
      break;
    }
  }
});

function dispatchMessage(request: NativeRequestEnvelope): NativeResponseEnvelope {
  switch (request.type) {
    case "PING":
      return handlePingRequest(request);

    case "SUBMIT_DAPP_REQUEST":
    case "GET_CHALLENGE":
    case "CONFIRM_CHALLENGE":
    case "GET_STATUS":
    case "CANCEL_CHALLENGE":
    case "GET_CONFIG":
      return {
        version: 1,
        success: true,
        requestId: request.requestId,
        type: request.type,
        data: {
          status: "READY",
          method: request.type,
          timestamp: Date.now(),
        },
      };

    default:
      return {
        version: 1,
        success: false,
        requestId: request.requestId,
        type: "ERROR",
        error: {
          code: -32601,
          message: `Unsupported request type: ${(request as { type: string }).type}`,
        },
      };
  }
}

process.stdin.on("end", () => {
  logError("Stdin closed. Exiting host process.");
  process.exit(0);
});

process.on("uncaughtException", (err) => {
  logError("Uncaught exception in host process:", err);
  process.exit(1);
});
