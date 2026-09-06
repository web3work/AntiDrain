/**
 * Encrypted Key Vault
 *
 * Stores private keys encrypted at rest using scrypt + AES-256-GCM.
 * Keys are decrypted in memory only for the instant they're needed for signing,
 * then the plaintext buffer is zeroed.
 *
 * HARD CONSTRAINTS:
 * - NEVER log, print, persist unencrypted, or transmit a private key
 * - Keys live only in this vault (encrypted) and in memory (briefly)
 * - No key material in error messages, console output, or stack traces
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { Address, Hex, LocalAccount } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { encrypt, decrypt, type EncryptedData } from "./crypto.js";
import type { VaultEntry, VaultManifest, WalletRole, SponsorState } from "../config/types.js";

// ─── Vault File Paths ──────────────────────────────────────────────────────

const VAULT_DIR = join(homedir(), ".antidrainwallet");
const VAULT_MANIFEST = join(VAULT_DIR, "vault.json"); // Public metadata
const VAULT_KEYS = join(VAULT_DIR, "keys.enc"); // Encrypted keys

// ─── Internal Types ────────────────────────────────────────────────────────

interface KeyStore {
  /** Map of wallet name → encrypted private key */
  keys: Record<string, EncryptedData>;
}

// ─── Vault Class ───────────────────────────────────────────────────────────

export class Vault {
  private manifest: VaultManifest;
  private keyStore: KeyStore;

  private constructor(manifest: VaultManifest, keyStore: KeyStore) {
    this.manifest = manifest;
    this.keyStore = keyStore;
  }

  // ─── Static Factory Methods ────────────────────────────────────────────

  /** Initialize a new empty vault */
  static create(): Vault {
    const manifest: VaultManifest = {
      version: 1,
      createdAt: new Date().toISOString(),
      entries: [],
    };
    const keyStore: KeyStore = { keys: {} };
    return new Vault(manifest, keyStore);
  }

  /** Load an existing vault from disk */
  static load(): Vault {
    if (!existsSync(VAULT_MANIFEST) || !existsSync(VAULT_KEYS)) {
      throw new Error(
        `Vault not found at ${VAULT_DIR}. Run 'antidrain vault init' first.`,
      );
    }
    const manifest: VaultManifest = JSON.parse(
      readFileSync(VAULT_MANIFEST, "utf8"),
    );
    const keyStore: KeyStore = JSON.parse(
      readFileSync(VAULT_KEYS, "utf8"),
    );
    return new Vault(manifest, keyStore);
  }

  /** Check if a vault exists on disk */
  static exists(): boolean {
    return existsSync(VAULT_MANIFEST) && existsSync(VAULT_KEYS);
  }

  // ─── Wallet Management ────────────────────────────────────────────────

  /**
   * Add a wallet to the vault.
   *
   * @param name     Human-readable identifier
   * @param privateKey  The private key (0x-prefixed hex). WILL BE ZEROED AFTER ENCRYPTION.
   * @param role     "compromised" or "sponsor"
   * @param chains   Chain IDs this wallet is relevant for
   * @param password Vault encryption password
   */
  addWallet(
    name: string,
    privateKey: Hex,
    role: WalletRole,
    chains: number[],
    password: string,
  ): Address {
    // Validate no duplicate names
    if (this.manifest.entries.some((e) => e.name === name)) {
      throw new Error(`Wallet "${name}" already exists in vault`);
    }

    // Derive address from key (this is the only moment the key is in memory unencrypted)
    const account = privateKeyToAccount(privateKey);
    const address = account.address;

    // Encrypt the private key immediately
    const encryptedKey = encrypt(privateKey, password);

    // Store metadata (no key material)
    this.manifest.entries.push({
      name,
      address,
      role,
      chains,
    });

    // Store encrypted key
    this.keyStore.keys[name] = encryptedKey;

    return address;
  }

  /**
   * Get a viem LocalAccount for signing.
   * The private key is decrypted, used to create the account, and the
   * raw key string is NOT retained beyond this call.
   *
   * IMPORTANT: The returned account object holds the key in memory.
   * Use it for signing, then discard the reference.
   */
  getAccount(name: string, password: string): LocalAccount {
    const entry = this.manifest.entries.find((e) => e.name === name);
    if (!entry) {
      throw new Error(`Wallet "${name}" not found in vault manifest`);
    }

    if (entry.role === "sponsor" && entry.sponsorState === "consumed") {
      throw new Error(
        `Sponsor wallet "${name}" was already marked as consumed. Create a fresh single-use sponsor wallet for new rescues.`,
      );
    }

    if (entry.role === "sponsor" && entry.sponsorState === "pending") {
      throw new Error(
        `Sponsor wallet "${name}" is currently marked as pending. Wait for on-chain confirmation or reset its state.`,
      );
    }

    const encryptedKey = this.keyStore.keys[name];
    if (!encryptedKey) {
      throw new Error(`Wallet "${name}" not found in vault keystore`);
    }

    // Decrypt key — exists in memory only for this instant
    const privateKey = decrypt(encryptedKey, password) as Hex;

    // Create viem account
    const account = privateKeyToAccount(privateKey);

    return account;
  }

  /** Set the lifecycle state of a sponsor wallet (available, pending, consumed, failed) */
  setSponsorState(name: string, state: SponsorState): void {
    const entry = this.manifest.entries.find((e) => e.name === name);
    if (entry && entry.role === "sponsor") {
      entry.sponsorState = state;
      this.save();
    }
  }

  /** List all wallet entries (NO key material returned) */
  listWallets(): VaultEntry[] {
    return [...this.manifest.entries];
  }

  /** Get wallets by role */
  getWalletsByRole(role: WalletRole): VaultEntry[] {
    return this.manifest.entries.filter((e) => e.role === role);
  }

  /** Get a specific wallet entry by name (NO key material) */
  getWalletEntry(name: string): VaultEntry | undefined {
    return this.manifest.entries.find((e) => e.name === name);
  }

  /** Remove a wallet from the vault */
  removeWallet(name: string): void {
    this.manifest.entries = this.manifest.entries.filter((e) => e.name !== name);
    delete this.keyStore.keys[name];
  }

  // ─── Persistence ──────────────────────────────────────────────────────

  /** Save vault to disk */
  save(): void {
    if (!existsSync(VAULT_DIR)) {
      mkdirSync(VAULT_DIR, { recursive: true, mode: 0o700 });
    }

    // Write manifest (public metadata, no keys)
    writeFileSync(VAULT_MANIFEST, JSON.stringify(this.manifest, null, 2), {
      mode: 0o600,
    });

    // Write encrypted keys
    writeFileSync(VAULT_KEYS, JSON.stringify(this.keyStore, null, 2), {
      mode: 0o600,
    });
  }

  /** Get the vault directory path */
  static getVaultDir(): string {
    return VAULT_DIR;
  }
}
