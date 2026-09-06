/**
 * Authority Diff Engine
 *
 * Mechanically snapshots on-chain token allowances and operator permissions
 * BEFORE and AFTER rescue execution to detect persistent authority leaks.
 */

import {
  type Address,
  type PublicClient,
} from "viem";
import type { AllowanceDiff, AuthorityState, ProofStatus } from "../config/types.js";

const ERC20_ALLOWANCE_ABI = [
  {
    name: "allowance",
    type: "function",
    stateMutability: "view",
    inputs: [
      { name: "owner", type: "address" },
      { name: "spender", type: "address" },
    ],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    name: "symbol",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
] as const;

// Canonical Uniswap Permit2 address across major EVM chains
export const PERMIT2_CANONICAL_ADDRESS: Address = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

export interface AllowanceSnapshot {
  token: Address;
  symbol: string;
  spender: Address;
  allowance: bigint;
}

/**
 * Capture allowance snapshot for a list of tokens and candidate spenders.
 */
export async function snapshotAllowances(
  client: PublicClient,
  owner: Address,
  tokens: Address[],
  spenders: Address[],
  blockNumber?: bigint,
): Promise<AllowanceSnapshot[]> {
  const snapshots: AllowanceSnapshot[] = [];
  const candidateSpenders = [...new Set([...spenders, PERMIT2_CANONICAL_ADDRESS])];

  for (const token of tokens) {
    let symbol = token.slice(0, 8);
    try {
      symbol = (await client.readContract({
        address: token,
        abi: ERC20_ALLOWANCE_ABI,
        functionName: "symbol",
        blockNumber,
      })) as string;
    } catch {}

    for (const spender of candidateSpenders) {
      try {
        const allowance = (await client.readContract({
          address: token,
          abi: ERC20_ALLOWANCE_ABI,
          functionName: "allowance",
          args: [owner, spender],
          blockNumber,
        })) as bigint;

        snapshots.push({
          token,
          symbol,
          spender,
          allowance,
        });
      } catch {
        // Skip tokens that don't support standard allowance query
      }
    }
  }

  return snapshots;
}

/**
 * Compute the authority diff between pre-rescue and post-rescue snapshots.
 */
export function computeAuthorityDiff(
  preSnapshots: AllowanceSnapshot[],
  postSnapshots: AllowanceSnapshot[],
  hasArbitraryCalls: boolean,
): {
  state: AuthorityState;
  proofStatus: ProofStatus;
  diffs: AllowanceDiff[];
} {
  const diffs: AllowanceDiff[] = [];
  let persistentAuthorityFound = false;

  const preMap = new Map<string, bigint>();
  for (const s of preSnapshots) {
    preMap.set(`${s.token.toLowerCase()}-${s.spender.toLowerCase()}`, s.allowance);
  }

  for (const post of postSnapshots) {
    const key = `${post.token.toLowerCase()}-${post.spender.toLowerCase()}`;
    const before = preMap.get(key) ?? 0n;
    const delta = post.allowance - before;

    if (delta > 0n || (post.allowance > 0n && before === 0n)) {
      persistentAuthorityFound = true;
      diffs.push({
        token: post.token,
        symbol: post.symbol,
        spender: post.spender,
        before,
        after: post.allowance,
        delta,
      });
    }
  }

  if (persistentAuthorityFound) {
    return {
      state: "PERSISTENT_APPROVALS_DETECTED",
      proofStatus: "FAILED",
      diffs,
    };
  }

  if (hasArbitraryCalls) {
    return {
      state: "AUTHORITY_UNKNOWN_ARBITRARY_CALLS",
      proofStatus: "UNVERIFIED",
      diffs,
    };
  }

  return {
    state: "AUTHORITY_DIFF_CLEAN",
    proofStatus: "PROVEN",
    diffs,
  };
}
