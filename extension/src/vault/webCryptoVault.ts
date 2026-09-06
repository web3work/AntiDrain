/**
 * AntiDrain Standalone Extension — In-Browser WebCrypto Encrypted Vault
 *
 * Implements bank-grade authenticated encryption using standard browser WebCrypto:
 * - PBKDF2-SHA-256 (600,000 rounds) + random 128-bit salt for key derivation.
 * - AES-256-GCM with random 96-bit IV (12 bytes) and 128-bit authentication tag.
 * - Tamper detection (fails closed on password mismatch, bad IV, or corrupted tag).
 * - Multi-account storage categorized by role: PERSONAL, SPONSOR, VICTIM, SAFE.
 * - Auto-lock timeout (default: 15 minutes) and memory dereferencing.
 */

export type WalletRole = "PERSONAL" | "SPONSOR" | "VICTIM" | "SAFE";

export interface SponsorPolicy {
  maxGasPerRescueWei: string; // Serialized uint256
  dailyGasBudgetWei: string;  // Serialized uint256
  maxRescueCount: number;
  spentTodayWei: string;
  lastResetDate: string; // YYYY-MM-DD
}

export interface StoredAccount {
  id: string;
  role: WalletRole;
  name: string;
  address: `0x${string}`;
  privateKey?: `0x${string}`; // Exists for PERSONAL, SPONSOR, VICTIM. None for SAFE.
  sponsorPolicy?: SponsorPolicy;
  isCompromisedAcknowledged?: boolean;
  createdAt: number;
}

export interface VaultData {
  accounts: StoredAccount[];
  activeVictimId?: string;
  activeSafeId?: string;
  activeSponsorId?: string;
  activePersonalId?: string;
  selectedChainId: number;
  autoLockTimeoutMinutes: number;
}

export interface EncryptedVaultPayload {
  version: 1;
  kdf: {
    algorithm: "PBKDF2-SHA-256";
    iterations: 600000;
    saltHex: string;
  };
  cipher: {
    algorithm: "AES-256-GCM";
    ivHex: string;
    ciphertextHex: string;
  };
}

// ─── Byte & Hex Utilities ──────────────────────────────────────────────────

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleanHex.length % 2 !== 0) {
    throw new Error("Invalid hex string length");
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ─── WebCrypto Key Derivation & AES-256-GCM ────────────────────────────────

export async function deriveKey(password: string, salt: Uint8Array, iterations = 600000): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations,
      hash: "SHA-256",
    },
    passwordKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptVault(data: VaultData, password: string): Promise<EncryptedVaultPayload> {
  const salt = crypto.getRandomValues(new Uint8Array(16)); // 128-bit salt
  const iv = crypto.getRandomValues(new Uint8Array(12));   // 96-bit GCM IV
  const key = await deriveKey(password, salt, 600000);

  const enc = new TextEncoder();
  const plaintext = enc.encode(JSON.stringify(data));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
    },
    key,
    plaintext as BufferSource
  );

  return {
    version: 1,
    kdf: {
      algorithm: "PBKDF2-SHA-256",
      iterations: 600000,
      saltHex: bytesToHex(salt),
    },
    cipher: {
      algorithm: "AES-256-GCM",
      ivHex: bytesToHex(iv),
      ciphertextHex: bytesToHex(new Uint8Array(ciphertextBuffer)),
    },
  };
}

export async function decryptVault(payload: EncryptedVaultPayload, password: string): Promise<VaultData> {
  if (!payload || payload.version !== 1) {
    throw new Error("Unsupported vault format or invalid version.");
  }
  if (!payload.kdf || !payload.cipher) {
    throw new Error("Corrupted vault payload structure.");
  }

  const salt = hexToBytes(payload.kdf.saltHex);
  const iv = hexToBytes(payload.cipher.ivHex);
  const ciphertext = hexToBytes(payload.cipher.ciphertextHex);

  const key = await deriveKey(password, salt, payload.kdf.iterations);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource,
      },
      key,
      ciphertext as BufferSource
    );

    const dec = new TextDecoder();
    const jsonStr = dec.decode(decryptedBuffer);
    return JSON.parse(jsonStr) as VaultData;
  } catch {
    throw new Error("Decryption failed: Incorrect password or corrupted/tampered vault ciphertext.");
  }
}

// ─── Default Initial Vault Data ────────────────────────────────────────────

export function createDefaultVaultData(): VaultData {
  return {
    accounts: [],
    selectedChainId: 8453, // Default: Base
    autoLockTimeoutMinutes: 15,
  };
}
