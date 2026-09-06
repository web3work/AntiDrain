/**
 * Cryptographic primitives for the encrypted key vault.
 *
 * SECURITY:
 * - Uses scrypt for key derivation (memory-hard, resistant to GPU attacks)
 * - Uses AES-256-GCM for authenticated encryption
 * - All operations use Node.js built-in crypto (no external deps)
 *
 * HARD CONSTRAINTS:
 * - Keys are NEVER logged, printed, persisted unencrypted, or transmitted
 * - Keys exist in memory only for the instant they're needed
 * - After use, key buffers are zeroed
 */

import { scryptSync, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

// ─── Constants ─────────────────────────────────────────────────────────────
// scrypt parameters: N=2^20 (high cost), r=8, p=1
// This makes brute-force extremely expensive (~1GB RAM, ~1s per attempt)
const SCRYPT_N = 1048576; // 2^20
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEY_LEN = 32; // 256 bits for AES-256
const SALT_LEN = 32; // 256-bit salt
const IV_LEN = 12; // 96-bit IV for AES-GCM (NIST recommended)
const AUTH_TAG_LEN = 16; // 128-bit authentication tag

// ─── Key Derivation ────────────────────────────────────────────────────────

/**
 * Derive a 256-bit encryption key from a password using scrypt.
 * Returns { key, salt } — salt must be stored alongside ciphertext.
 */
export function deriveKey(
  password: string,
  salt?: Buffer,
): { key: Buffer; salt: Buffer } {
  const actualSalt = salt ?? randomBytes(SALT_LEN);
  const key = scryptSync(password, actualSalt, SCRYPT_KEY_LEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_N * SCRYPT_R * 256, // Required memory allocation
  });
  return { key: Buffer.from(key), salt: actualSalt };
}

// ─── Encryption ────────────────────────────────────────────────────────────

export interface EncryptedData {
  /** Base64-encoded ciphertext */
  ciphertext: string;
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded authentication tag */
  authTag: string;
  /** Base64-encoded scrypt salt */
  salt: string;
}

/**
 * Encrypt plaintext using AES-256-GCM with a password-derived key.
 * Returns all components needed for decryption.
 */
export function encrypt(plaintext: string, password: string): EncryptedData {
  const { key, salt } = deriveKey(password);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LEN,
  });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Zero the key immediately after use
  key.fill(0);

  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
    salt: salt.toString("base64"),
  };
}

/**
 * Decrypt ciphertext using AES-256-GCM with a password-derived key.
 * Throws if password is wrong or data has been tampered with.
 */
export function decrypt(data: EncryptedData, password: string): string {
  const salt = Buffer.from(data.salt, "base64");
  const { key } = deriveKey(password, salt);
  const iv = Buffer.from(data.iv, "base64");
  const authTag = Buffer.from(data.authTag, "base64");
  const ciphertext = Buffer.from(data.ciphertext, "base64");

  const decipher = createDecipheriv("aes-256-gcm", key, iv, {
    authTagLength: AUTH_TAG_LEN,
  });
  decipher.setAuthTag(authTag);

  let decrypted: string;
  try {
    decrypted = decipher.update(ciphertext) + decipher.final("utf8");
  } finally {
    // Zero the key even if decryption fails
    key.fill(0);
  }

  return decrypted;
}

/**
 * Zero-fill a buffer to remove sensitive data from memory.
 * Call this after you're done with any buffer containing key material.
 */
export function zeroBuffer(buf: Buffer): void {
  buf.fill(0);
}
