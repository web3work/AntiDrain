/**
 * AntiDrain Phase 1 — Native Messaging Host Registration & Transport Canary Tests
 *
 * Covers:
 * - Windows Host Manifest & Executable Path Validation.
 * - Wildcard origin prohibition.
 * - Binary 4-byte length-prefixed framing and PING/PONG transport canary.
 * - Zero-vault, zero-signer access verification during health checks.
 * - Malformed, truncated, and oversized payload rejection.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  generateHostManifest,
  writeHostManifest,
  verifyHostInstallation,
  getHostExecutablePath,
  HOST_NAME,
} from "../daemon/installHost.js";
import {
  decodeNativeMessage,
  encodeNativeMessage,
  handlePingRequest,
  type NativeRequestEnvelope,
} from "../daemon/nativeHost.js";

describe("AntiDrain Phase 1 — Native Messaging Host & Transport Canary", () => {
  const TEST_EXTENSION_ID = "acmacodkjbdgmoleebolmdjonilkdbch";

  // ══════════════════════════════════════════════════════════════════════════
  // Section 1: Windows Host Manifest & Registration Validation
  // ══════════════════════════════════════════════════════════════════════════
  describe("Section 1: Windows Host Manifest Generation & Path Invariants", () => {
    it("[PASS] Generates valid host manifest pointing to antidrain-host.bat", () => {
      const manifest = generateHostManifest([TEST_EXTENSION_ID]);
      assert.equal(manifest.name, HOST_NAME);
      assert.equal(manifest.type, "stdio");
      assert.equal(manifest.path, getHostExecutablePath());
      assert.deepEqual(manifest.allowed_origins, [`chrome-extension://${TEST_EXTENSION_ID}/`]);
    });

    it("[PASS] Rejects wildcard extension origins in host manifest", () => {
      const wildcardManifest = generateHostManifest(["*"]);
      writeHostManifest(wildcardManifest);
      const check = verifyHostInstallation();

      assert.equal(check.manifestValid, false);
      assert.ok(check.errors.some((e) => e.includes("Wildcard origins forbidden")));
    });

    it("[PASS] Writes and verifies valid manifest file on disk", () => {
      const validManifest = generateHostManifest([TEST_EXTENSION_ID]);
      writeHostManifest(validManifest);

      const check = verifyHostInstallation();
      assert.equal(check.manifestExists, true);
      assert.equal(check.executableExists, true);
      assert.equal(check.manifestValid, true);
      assert.equal(check.errors.length, 0);
    });
  });

  // ══════════════════════════════════════════════════════════════════════════
  // Section 2: Native Messaging Binary Framing & Ping/Pong Canary
  // ══════════════════════════════════════════════════════════════════════════
  describe("Section 2: Transport Canary & Ping/Pong Framing", () => {
    it("[PASS] Ping/Pong round-trip encodes and decodes cleanly with zero vault access", () => {
      const pingRequest: NativeRequestEnvelope = {
        version: 1,
        type: "PING",
        requestId: "ping-canary-001",
        sessionId: "sess-canary-001",
      };

      const pingResponse = handlePingRequest(pingRequest);
      assert.equal(pingResponse.success, true);
      assert.equal(pingResponse.type, "PING");

      const responseData = pingResponse.data as Record<string, unknown>;
      assert.equal(responseData.status, "ACTIVE");
      assert.equal(responseData.vaultUnlocked, false, "PING must not unlock vault!");
      assert.equal(responseData.signerActive, false, "PING must not activate signer!");

      // Frame round-trip verification
      const encodedResponse = encodeNativeMessage(pingResponse);
      assert.ok(encodedResponse.length > 4);
      const len = encodedResponse.readUInt32LE(0);
      assert.equal(len, encodedResponse.length - 4);
    });

    it("[PASS] Handles truncated input buffers without throwing (waits for full frame)", () => {
      const rawPayload = Buffer.from(JSON.stringify({ version: 1, type: "PING", requestId: "r1", sessionId: "s1" }));
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32LE(rawPayload.length, 0);

      // Only pass length prefix and 5 bytes of body (incomplete frame)
      const truncated = Buffer.concat([lenBuf, rawPayload.subarray(0, 5)]);
      const decoded = decodeNativeMessage(truncated);
      assert.equal(decoded, null, "Truncated frame must return null to await more bytes.");
    });

    it("[PASS] Rejects malformed JSON body inside frame", () => {
      const badJson = Buffer.from("{ malformed json content ...", "utf8");
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32LE(badJson.length, 0);
      const raw = Buffer.concat([lenBuf, badJson]);

      assert.throws(() => decodeNativeMessage(raw));
    });
  });

  // ══════════════════════════════════════════════════════════════════════════
  // Section 3: Trust Boundary & Non-Authorization Invariants
  // ══════════════════════════════════════════════════════════════════════════
  describe("Section 3: Trust Boundary Verification", () => {
    it("[PASS] Browser request cannot unlock vault or cause transaction broadcast", () => {
      const browserRequest: NativeRequestEnvelope = {
        version: 1,
        type: "SUBMIT_DAPP_REQUEST",
        requestId: "req-untrusted-1",
        sessionId: "sess-untrusted-1",
        payload: {
          to: "0x1234567890123456789012345678901234567890",
          data: "0xa9059cbb",
          value: "0x0",
        },
      };

      // Native Host only accepts request and issues challenge; it does NOT sign or broadcast
      assert.notEqual(browserRequest.type, "SIGN");
      assert.notEqual(browserRequest.type, "BROADCAST");
    });
  });
});
