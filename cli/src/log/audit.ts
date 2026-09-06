/**
 * Encrypted Audit Log
 *
 * Records all rescue attempts (successful or not) to an encrypted
 * local log file. Uses the same scrypt+AES-GCM encryption as the vault.
 *
 * VERIFICATION PROTOCOL: Log is written BEFORE broadcast, updated AFTER.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { encrypt, decrypt, type EncryptedData } from "../vault/crypto.js";
import type { AuditLogEntry } from "../config/types.js";

const AUDIT_DIR = join(homedir(), ".antidrainwallet");
const AUDIT_FILE = join(AUDIT_DIR, "audit.enc");

/**
 * Append an entry to the encrypted audit log.
 *
 * How it works:
 * 1. If log exists, decrypt all existing entries
 * 2. Append new entry
 * 3. Re-encrypt the entire log
 * 4. Write to disk
 *
 * This is not the most efficient approach for large logs, but it ensures
 * the entire log is always encrypted as a single unit with a fresh IV.
 */
export function appendAuditLog(
  entry: AuditLogEntry,
  password: string,
): void {
  let entries: AuditLogEntry[] = [];

  // Load existing entries if file exists
  if (existsSync(AUDIT_FILE)) {
    try {
      const raw = readFileSync(AUDIT_FILE, "utf8");
      const encrypted: EncryptedData = JSON.parse(raw);
      const decrypted = decrypt(encrypted, password);
      entries = JSON.parse(decrypted);
    } catch {
      // If decryption fails (wrong password or corrupt), start fresh
      console.warn("  ⚠ Could not decrypt existing audit log, starting new one");
      entries = [];
    }
  }

  // Append new entry (serialize bigints as strings)
  const serializable = {
    ...entry,
    gasUsed: entry.gasUsed?.toString(),
  };
  entries.push(serializable as unknown as AuditLogEntry);

  // Re-encrypt and write
  if (!existsSync(AUDIT_DIR)) {
    mkdirSync(AUDIT_DIR, { recursive: true, mode: 0o700 });
  }

  const encrypted = encrypt(JSON.stringify(entries, null, 2), password);
  writeFileSync(AUDIT_FILE, JSON.stringify(encrypted, null, 2), {
    mode: 0o600,
  });
}

/**
 * Read all audit log entries (requires password).
 */
export function readAuditLog(password: string): AuditLogEntry[] {
  if (!existsSync(AUDIT_FILE)) {
    return [];
  }

  const raw = readFileSync(AUDIT_FILE, "utf8");
  const encrypted: EncryptedData = JSON.parse(raw);
  const decrypted = decrypt(encrypted, password);
  return JSON.parse(decrypted);
}
