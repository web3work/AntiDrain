/**
 * EIP-712 Rescue Intent — Single Source of Truth
 *
 * This module is the ONLY authoritative TypeScript representation of the
 * EIP-712 typed data structure used by UniversalRecoveryDelegate.sol.
 *
 * DO NOT duplicate these type definitions in any other module.
 * All other modules must import from here.
 *
 * SOLIDITY CONTRACT CORRESPONDENCE:
 *   CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)")
 *   RESCUE_TYPEHASH = keccak256("Rescue(address safeWallet,Call[] calls,address[] tokens,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)")
 *   Domain: { name: "AntiDrainRecovery", version: "1", chainId: block.chainid, verifyingContract: address(this) }
 *
 * NONCE STORAGE:
 *   ERC-7201 slot: 0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd00
 *   Derived from: keccak256(abi.encode(uint256(keccak256("antidrain.universalRecoveryDelegate.nonce.v1")) - 1)) & ~bytes32(uint256(0xff))
 *
 * HARD CONSTRAINTS:
 *   - Keys are NEVER logged, printed, or persisted
 *   - Signing uses viem's signTypedData which handles key internally
 */

import {
  type Address,
  type Hex,
  type PublicClient,
  type LocalAccount,
  hashTypedData,
  hexToBigInt,
} from "viem";

// ─── Constants ────────────────────────────────────────────────────────────

/**
 * ERC-7201 unstructured storage slot for the rescue nonce.
 * Derived: keccak256(abi.encode(uint256(keccak256("antidrain.universalRecoveryDelegate.nonce.v1")) - 1)) & ~bytes32(uint256(0xff))
 * = 0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd00
 */
export const NONCE_SLOT: Hex =
  "0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd00";

/** EIP-712 domain name — must exactly match Solidity: keccak256(bytes("AntiDrainRecovery")) */
export const EIP712_DOMAIN_NAME = "AntiDrainRecovery" as const;

/** EIP-712 domain version — must exactly match Solidity: keccak256(bytes("1")) */
export const EIP712_DOMAIN_VERSION = "1" as const;

// ─── EIP-712 Type Definitions ─────────────────────────────────────────────
// These MUST exactly match the Solidity typehashes.
// CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)")
// RESCUE_TYPEHASH = keccak256("Rescue(address safeWallet,Call[] calls,address[] tokens,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)")

/**
 * EIP-712 type definitions for the rescue intent.
 * The `as const` assertion is required for viem type inference.
 */
export const RESCUE_TYPES = {
  Call: [
    { name: "target", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
  ],
  Rescue: [
    { name: "safeWallet", type: "address" },
    { name: "sponsor", type: "address" },
    { name: "calls", type: "Call[]" },
    { name: "tokens", type: "address[]" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
} as const;

// ─── Structured Types ─────────────────────────────────────────────────────

export interface RescueIntentCall {
  target: Address;
  value: bigint;
  data: Hex;
}

export interface RescueIntentMessage {
  safeWallet: Address;
  sponsor: Address;
  calls: readonly RescueIntentCall[];
  tokens: readonly Address[];
  nonce: bigint;
  deadline: bigint;
}

export interface RescueIntentDomain {
  name: typeof EIP712_DOMAIN_NAME;
  version: typeof EIP712_DOMAIN_VERSION;
  chainId: number;
  verifyingContract: Address;
}

export interface SignedRescueIntent {
  /** The EIP-712 domain used */
  domain: RescueIntentDomain;
  /** The structured message that was signed */
  message: RescueIntentMessage;
  /** The EIP-712 signature (65 bytes, 0x-prefixed) */
  signature: Hex;
  /** The EIP-712 digest (for verification/display) */
  digest: Hex;
}

// ─── Domain Construction ──────────────────────────────────────────────────

/**
 * Construct the EIP-712 domain separator parameters.
 *
 * CRITICAL: verifyingContract MUST be the compromised EOA address,
 * because under EIP-7702 delegation, address(this) in the contract
 * evaluates to the delegating EOA.
 */
export function buildDomain(
  chainId: number,
  compromisedEOA: Address,
): RescueIntentDomain {
  return {
    name: EIP712_DOMAIN_NAME,
    version: EIP712_DOMAIN_VERSION,
    chainId,
    verifyingContract: compromisedEOA,
  };
}

// ─── Nonce Reading ────────────────────────────────────────────────────────

/**
 * Read the current rescue nonce from the compromised EOA's ERC-7201 storage slot.
 *
 * @param client - Public RPC client
 * @param compromisedEOA - The compromised wallet address (storage owner)
 * @returns The current nonce as uint256
 */
export async function readOnChainNonce(
  client: PublicClient<any, any>,
  compromisedEOA: Address,
): Promise<bigint> {
  const rawSlot = await client.getStorageAt({
    address: compromisedEOA,
    slot: NONCE_SLOT,
  });

  if (!rawSlot || rawSlot === "0x" || rawSlot === "0x0000000000000000000000000000000000000000000000000000000000000000") {
    return 0n;
  }

  // Interpret as uint256 (big-endian 32 bytes)
  return hexToBigInt(rawSlot);
}

// ─── Deadline Computation ─────────────────────────────────────────────────

/** Default deadline buffer: 300 seconds (5 minutes) */
export const DEFAULT_DEADLINE_BUFFER_SECONDS = 300n;

/**
 * Compute a rescue deadline from the latest on-chain block timestamp.
 *
 * REQUIREMENT: Uses chain time, NOT local machine clock.
 * Falls back to local time + extra buffer only if RPC fails,
 * and marks the result as a fallback.
 *
 * @param client - Public RPC client for the target chain
 * @param bufferSeconds - Seconds to add to current chain time (default: 300)
 * @returns { deadline, chainTimestamp, isFallback }
 */
export async function computeDeadline(
  client: PublicClient<any, any>,
  bufferSeconds: bigint = DEFAULT_DEADLINE_BUFFER_SECONDS,
): Promise<{
  deadline: bigint;
  chainTimestamp: bigint;
  isFallback: boolean;
}> {
  try {
    const block = await client.getBlock({ blockTag: "latest" });
    const chainTimestamp = block.timestamp;
    return {
      deadline: chainTimestamp + bufferSeconds,
      chainTimestamp,
      isFallback: false,
    };
  } catch {
    // Conservative fallback: local time + double buffer
    const localTimestamp = BigInt(Math.floor(Date.now() / 1000));
    console.warn("  ⚠ Failed to read chain timestamp. Using local clock with double buffer.");
    return {
      deadline: localTimestamp + bufferSeconds * 2n,
      chainTimestamp: localTimestamp,
      isFallback: true,
    };
  }
}

// ─── EIP-712 Digest Computation ───────────────────────────────────────────

/**
 * Compute the EIP-712 digest for a rescue intent.
 * This is a pure function — no private key involvement.
 * Used for display, verification, and test vectors.
 */
export function computeRescueDigest(
  domain: RescueIntentDomain,
  message: RescueIntentMessage,
): Hex {
  return hashTypedData({
    domain,
    types: RESCUE_TYPES,
    primaryType: "Rescue",
    message: {
      safeWallet: message.safeWallet,
      sponsor: message.sponsor,
      calls: message.calls.map((c) => ({
        target: c.target,
        value: c.value,
        data: c.data,
      })),
      tokens: [...message.tokens],
      nonce: message.nonce,
      deadline: message.deadline,
    },
  });
}

// ─── EIP-712 Signing ──────────────────────────────────────────────────────

/**
 * Sign a rescue intent using the compromised EOA's private key.
 *
 * SECURITY:
 * - The private key is handled internally by viem's LocalAccount.signTypedData
 * - The key is NEVER logged, printed, persisted, or returned from this function
 * - After this call, the caller should discard the account reference
 *
 * @param compromisedAccount - viem LocalAccount (holds key in memory)
 * @param domain - EIP-712 domain (verifyingContract = compromised EOA)
 * @param message - The rescue intent message
 * @returns SignedRescueIntent with signature, digest, domain, and message
 */
export async function signRescueIntent(
  compromisedAccount: LocalAccount,
  domain: RescueIntentDomain,
  message: RescueIntentMessage,
): Promise<SignedRescueIntent> {
  // Verify domain consistency: verifyingContract must match the signer
  if (domain.verifyingContract.toLowerCase() !== compromisedAccount.address.toLowerCase()) {
    throw new Error(
      `EIP-712 domain mismatch: verifyingContract (${domain.verifyingContract}) ` +
      `must equal compromised EOA (${compromisedAccount.address}). ` +
      `Under EIP-7702 delegation, address(this) == delegating EOA.`,
    );
  }

  // Compute digest for display/verification (pure, no key involvement)
  const digest = computeRescueDigest(domain, message);

  // Sign using viem's signTypedData — key stays inside LocalAccount
  const signature = await compromisedAccount.signTypedData({
    domain,
    types: RESCUE_TYPES,
    primaryType: "Rescue",
    message: {
      safeWallet: message.safeWallet,
      sponsor: message.sponsor,
      calls: message.calls.map((c) => ({
        target: c.target,
        value: c.value,
        data: c.data,
      })),
      tokens: [...message.tokens],
      nonce: message.nonce,
      deadline: message.deadline,
    },
  });

  return {
    domain,
    message,
    signature,
    digest,
  };
}
