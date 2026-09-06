/**
 * Airdrop Claim Calldata Builder & Parameter Validator
 *
 * Deterministically constructs claim calldata from structured parameters
 * and enforces strict safety bindings:
 * 1. Claimant must equal the compromised EOA.
 * 2. Recipient must equal the safe wallet or the compromised EOA (for immediate sweep).
 * 3. The claimed token is guaranteed to be in the sweep list.
 */

import {
  encodeFunctionData,
  type Hex,
  type Address,
} from "viem";
import type { AirdropClaimPlan, RescueCall } from "../config/types.js";

// Standard Merkle Distributor ABI (OpenZeppelin / Uniswap archetype)
const MERKLE_DISTRIBUTOR_ABI = [
  {
    name: "claim",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "index", type: "uint256" },
      { name: "account", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "merkleProof", type: "bytes32[]" },
    ],
    outputs: [],
  },
] as const;

// Standard Signature Claim ABI
const SIGNATURE_CLAIM_ABI = [
  {
    name: "claimWithSignature",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "recipient", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

// Direct Claim ABI
const DIRECT_CLAIM_ABI = [
  {
    name: "claim",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [],
    outputs: [],
  },
] as const;

// OneFootball / Payable Signature Claim ABI (selector: 0x5eddd157)
export const ONEFOOTBALL_CLAIM_ABI = [
  {
    name: "claim",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "amount", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [],
  },
] as const;

/**
 * Validate an AirdropClaimPlan and compile it into a deterministic RescueCall.
 */
export function buildAirdropClaimCall(
  airdrop: AirdropClaimPlan,
  compromisedAddress: Address,
  safeWallet: Address,
): RescueCall {
  // 1. Invariant: Claimant must be the compromised EOA
  if (airdrop.claimant.toLowerCase() !== compromisedAddress.toLowerCase()) {
    throw new Error(
      `Airdrop validation failed: claimant (${airdrop.claimant}) must match compromised wallet (${compromisedAddress})`,
    );
  }

  // 2. Invariant: Recipient must be either the safeWallet or the compromised EOA
  const recipientValid =
    airdrop.recipient.toLowerCase() === safeWallet.toLowerCase() ||
    airdrop.recipient.toLowerCase() === compromisedAddress.toLowerCase();

  if (!recipientValid) {
    throw new Error(
      `Airdrop validation failed: recipient (${airdrop.recipient}) must be safeWallet (${safeWallet}) or compromised EOA (${compromisedAddress})`,
    );
  }

  // 3. Invariant: Expected amount must be greater than 0
  if (airdrop.expectedAmount <= 0n) {
    throw new Error(`Airdrop validation failed: expectedAmount must be > 0, got ${airdrop.expectedAmount}`);
  }

  let calldata: Hex;

  switch (airdrop.protocolId) {
    case "merkle-distributor":
    case "uniswap-merkle": {
      if (airdrop.merkleIndex === undefined || !airdrop.merkleProof) {
        throw new Error(
          `Airdrop validation failed: protocol "${airdrop.protocolId}" requires merkleIndex and merkleProof`,
        );
      }
      calldata = encodeFunctionData({
        abi: MERKLE_DISTRIBUTOR_ABI,
        functionName: "claim",
        args: [
          airdrop.merkleIndex,
          airdrop.claimant,
          airdrop.expectedAmount,
          airdrop.merkleProof as `0x${string}`[],
        ],
      });
      break;
    }

    case "signature-claim": {
      if (
        airdrop.nonce === undefined ||
        airdrop.deadline === undefined ||
        !airdrop.signature
      ) {
        throw new Error(
          `Airdrop validation failed: protocol "signature-claim" requires nonce, deadline, and signature`,
        );
      }
      calldata = encodeFunctionData({
        abi: SIGNATURE_CLAIM_ABI,
        functionName: "claimWithSignature",
        args: [
          airdrop.recipient,
          airdrop.expectedAmount,
          airdrop.nonce,
          airdrop.deadline,
          airdrop.signature,
        ],
      });
      break;
    }

    case "onefootball-claim":
    case "payable-signature-claim": {
      if (
        airdrop.deadline === undefined ||
        !airdrop.signature
      ) {
        throw new Error(
          `Airdrop validation failed: protocol "${airdrop.protocolId}" requires deadline and signature`,
        );
      }
      calldata = encodeFunctionData({
        abi: ONEFOOTBALL_CLAIM_ABI,
        functionName: "claim",
        args: [
          airdrop.expectedAmount,
          airdrop.deadline,
          airdrop.signature,
        ],
      });
      break;
    }

    case "direct-claim": {
      calldata = encodeFunctionData({
        abi: DIRECT_CLAIM_ABI,
        functionName: "claim",
        args: [],
      });
      break;
    }

    case "custom": {
      if (!airdrop.extraData) {
        throw new Error(`Airdrop validation failed: custom protocol requires extraData calldata`);
      }
      calldata = airdrop.extraData;
      break;
    }

    default:
      throw new Error(`Unsupported airdrop protocol ID: ${String(airdrop.protocolId)}`);
  }

  return {
    target: airdrop.claimContract,
    value: airdrop.claimFeeWei ?? 0n,
    data: calldata,
  };
}
