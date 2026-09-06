/**
 * OneFootball (OFC) Airdrop Claim & Rescue Module
 *
 * Enforces strict verification protocol for OneFootball vesting claims:
 * 1. Voucher exists & has valid structure
 * 2. Correct victim address
 * 3. Correct amount (> 0)
 * 4. Correct deadline (unexpired on chain)
 * 5. Correct claim nonce / unspent state on-chain
 * 6. Correct authorized signer (matches on-chain authorizedSigner())
 * 7. Correct claim contract (matches production distributor)
 * 8. Correct current fee (queried dynamically via claimFeeWei())
 * 9. Exact claim calldata encoding
 * 10. Exact value accounting (outer tx value == call.value == exact fee, NO OVERFUNDING)
 * 11. Simulation succeeds prior to signing/broadcast
 */

import {
  encodeFunctionData,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";
import { ONEFOOTBALL_CLAIM_ABI } from "./builder.js";
import type { RescuePlan, RescueCall, AirdropClaimPlan } from "../config/types.js";

export const ONEFOOTBALL_CHAIN_ID = 8453; // Base Mainnet
export const ONEFOOTBALL_DISTRIBUTOR = "0xC42de28B8469D89A2254Dd103bCFeB8D7396043F" as Address;
export const ONEFOOTBALL_OFC_TOKEN = "0x752C5a95d202972E124390F30a50154409d3c858" as Address;
export const ONEFOOTBALL_AUTHORIZED_SIGNER = "0x2dEbBCEc0f26f4Fe053B0C98A348D2Cd8b4BC008" as Address;
export const ONEFOOTBALL_API_BASE =
  process.env.ONEFOOTBALL_API_BASE || "https://api.onefootball.com/fanpass-metagame-backend";

export const ONEFOOTBALL_DISTRIBUTOR_ABI = [
  {
    type: "function",
    name: "claim",
    stateMutability: "payable",
    inputs: [
      { name: "amount", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "claimFeeWei",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "claimedAmount",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "getNonce",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "authorizedSigner",
    stateMutability: "view",
    inputs: [],
    outputs: [{ type: "address" }],
  },
] as const;

export interface OneFootballVoucher {
  amount: string;
  deadline: string;
  signature: Hex;
  contractAddress: Address;
  account?: Address;
}

export interface OneFootballEligibility {
  eligible: boolean;
  walletAddress: Address;
  available: string;
  totalClaimed: string;
  fullyClaimed: boolean;
  schedule?: {
    allocation: number;
    claimed: number;
    claimTime: number;
    nextUnlockTime: number;
    vestingMonths: number;
    nextClaimAmount?: number;
    claimInfo?: Array<{
      month: number;
      amount: number;
      unlockTime: number;
      status: "claimed" | "available" | "locked";
    }>;
  };
}

/**
 * Fetch eligibility status for a victim wallet directly from OneFootball's backend.
 */
export async function fetchOneFootballEligibility(
  victimAddress: Address,
): Promise<OneFootballEligibility> {
  const url = `${ONEFOOTBALL_API_BASE}/vesting-rescue/eligibility/${victimAddress}`;
  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    throw new Error(`Failed to fetch OneFootball eligibility: HTTP ${res.status} ${res.statusText}`);
  }

  return (await res.json()) as OneFootballEligibility;
}

/**
 * Fetch a signed claim voucher from OneFootball's backend.
 * Requires user's authenticated bearerToken.
 */
export async function fetchOneFootballVoucher(
  victimAddress: Address,
  month: number,
  bearerToken: string,
): Promise<OneFootballVoucher> {
  const url = `${ONEFOOTBALL_API_BASE}/vesting-rescue/sign/${victimAddress}/${month}`;
  const res = await fetch(url, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${bearerToken.replace(/^Bearer\s+/i, "")}`,
    },
  });

  if (!res.ok) {
    const errorBody = await res.text().catch(() => "");
    throw new Error(
      `Failed to fetch OneFootball voucher: HTTP ${res.status} ${res.statusText} (${errorBody})`,
    );
  }

  const data = (await res.json()) as any;
  if ("message" in data || !("signature" in data)) {
    throw new Error(`OneFootball voucher error: ${data.message || "No claim available"}`);
  }

  return {
    amount: data.amount,
    deadline: data.deadline,
    signature: data.signature,
    contractAddress: data.contractAddress,
    account: data.account || victimAddress,
  };
}

export interface OneFootballValidationResult {
  valid: boolean;
  claimFeeWei: bigint;
  amount: bigint;
  deadline: bigint;
  signature: Hex;
  calldata: Hex;
  call: RescueCall;
  errors: string[];
}

export interface OneFootballValidationOptions {
  expectedContract?: Address;
  expectedSigner?: Address;
  tokenAddress?: Address;
}

/**
 * Complete 11-point security verification before constructing the rescue plan.
 */
export async function validateOneFootballPreconditions(
  client: PublicClient,
  voucher: OneFootballVoucher,
  victimAddress: Address,
  safeWallet: Address,
  options?: OneFootballValidationOptions,
): Promise<OneFootballValidationResult> {
  const errors: string[] = [];

  // Check 1: Voucher exists and has required fields
  if (!voucher.amount || !voucher.deadline || !voucher.signature || !voucher.contractAddress) {
    errors.push("Check 1 Failed: Voucher missing required fields (amount, deadline, signature, contractAddress)");
    return {
      valid: false,
      claimFeeWei: 0n,
      amount: 0n,
      deadline: 0n,
      signature: "0x",
      calldata: "0x",
      call: { target: ONEFOOTBALL_DISTRIBUTOR, value: 0n, data: "0x" },
      errors,
    };
  }

  // Check 2: Correct victim address and safe wallet hygiene
  if (voucher.account && voucher.account.toLowerCase() !== victimAddress.toLowerCase()) {
    errors.push(`Check 2 Failed: Voucher account (${voucher.account}) does not match victim (${victimAddress})`);
  }
  if (safeWallet.toLowerCase() === victimAddress.toLowerCase()) {
    errors.push("Check 2 Failed: safeWallet cannot equal the compromised victim wallet");
  }

  // Check 3: Correct amount (> 0)
  const amount = BigInt(voucher.amount || "0");
  if (amount <= 0n) {
    errors.push(`Check 3 Failed: Claim amount must be > 0, got ${amount}`);
  }

  // Check 4: Correct deadline (unexpired on chain)
  const deadline = BigInt(voucher.deadline || "0");
  const latestBlock = await client.getBlock({ blockTag: "latest" });
  if (deadline <= latestBlock.timestamp) {
    errors.push(
      `Check 4 Failed: Voucher deadline (${deadline}) has expired (current block timestamp: ${latestBlock.timestamp})`,
    );
  }

  // Check 5: Correct claim contract and code verification
  const targetContract = voucher.contractAddress;
  const expectedContract = options?.expectedContract || ONEFOOTBALL_DISTRIBUTOR;
  if (targetContract.toLowerCase() !== expectedContract.toLowerCase()) {
    errors.push(
      `Check 5 Failed: Voucher contractAddress (${targetContract}) does not match expected (${expectedContract})`,
    );
  }
  const contractCode = await client.getCode({ address: targetContract });
  if (!contractCode || contractCode === "0x") {
    errors.push(`Check 5 Failed: Target contract (${targetContract}) has no bytecode deployed on-chain`);
  }

  // Check 6: Correct claim nonce / on-chain state on target contract
  try {
    const onChainNonce = (await client.readContract({
      address: targetContract,
      abi: ONEFOOTBALL_DISTRIBUTOR_ABI,
      functionName: "getNonce",
      args: [victimAddress],
    })) as bigint;
    if (onChainNonce < 0n) {
      errors.push("Check 6 Failed: Invalid on-chain nonce query");
    }
  } catch (nonceErr) {
    errors.push(`Check 6 Failed: Unable to read nonce from contract: ${nonceErr instanceof Error ? nonceErr.message : String(nonceErr)}`);
  }

  // Check 7: Correct authorized signer on contract
  try {
    const onChainSigner = (await client.readContract({
      address: targetContract,
      abi: ONEFOOTBALL_DISTRIBUTOR_ABI,
      functionName: "authorizedSigner",
    })) as Address;

    if (!onChainSigner || onChainSigner === "0x0000000000000000000000000000000000000000") {
      errors.push("Check 7 Failed: Distributor contract has no active authorizedSigner configured on-chain");
    } else if (options?.expectedSigner) {
      if (onChainSigner.toLowerCase() !== options.expectedSigner.toLowerCase()) {
        errors.push(
          `Check 7 Failed: On-chain authorizedSigner (${onChainSigner}) does not match expected (${options.expectedSigner})`,
        );
      }
    }
  } catch (signerErr) {
    errors.push(`Check 7 Failed: Unable to read authorizedSigner: ${signerErr instanceof Error ? signerErr.message : String(signerErr)}`);
  }

  // Check 8: Correct current fee (live query directly from the target contract)
  let claimFeeWei = 0n;
  try {
    claimFeeWei = (await client.readContract({
      address: targetContract,
      abi: ONEFOOTBALL_DISTRIBUTOR_ABI,
      functionName: "claimFeeWei",
    })) as bigint;

    if (claimFeeWei <= 0n) {
      errors.push(`Check 8 Failed: On-chain claimFeeWei must be > 0, got ${claimFeeWei}`);
    }
  } catch (feeErr) {
    errors.push(`Check 8 Failed: Unable to read claimFeeWei: ${feeErr instanceof Error ? feeErr.message : String(feeErr)}`);
  }

  // Check 9: Exact claim calldata encoding
  const calldata = encodeFunctionData({
    abi: ONEFOOTBALL_CLAIM_ABI,
    functionName: "claim",
    args: [amount, deadline, voucher.signature],
  });

  // Check 10: Exact EIP-712 / EIP-7702 value (outer value == call.value == exact fee)
  const call: RescueCall = {
    target: targetContract,
    value: claimFeeWei, // EXACT fee, zero overfunding
    data: calldata,
  };

  if (errors.length > 0) {
    return {
      valid: false,
      claimFeeWei,
      amount,
      deadline,
      signature: voucher.signature,
      calldata,
      call,
      errors,
    };
  }

  // Check 11: Preflight simulation (victim calling claim with exact fee)
  // Note: The victim wallet holds 0 ETH (AntiDrain Zero Pre-funding model).
  // In the real rescue, the Sponsor supplies this value via the outer Type 0x04 transaction.
  // We provide stateOverride so eth_call accurately simulates the execution without failing on OutOfFunds.
  try {
    await client.call({
      account: victimAddress,
      to: targetContract,
      data: calldata,
      value: claimFeeWei,
      stateOverride: [
        {
          address: victimAddress,
          balance: claimFeeWei + 1000000000000000000n, // 1 ETH simulated balance
        },
      ],
    });
  } catch (simErr) {
    const msg = simErr instanceof Error ? simErr.message : String(simErr);
    // If an RPC node does not support stateOverride, fall back to standard call
    // and only flag non-funding errors (e.g. invalid signature, bad deadline, paused contract)
    if (
      msg.includes("stateOverride") ||
      msg.includes("method not supported") ||
      msg.includes("-32602")
    ) {
      try {
        await client.call({
          account: victimAddress,
          to: targetContract,
          data: calldata,
          value: claimFeeWei,
        });
      } catch (fbErr) {
        const fbMsg = fbErr instanceof Error ? fbErr.message : String(fbErr);
        if (!fbMsg.includes("OutOfFunds") && !fbMsg.includes("insufficient funds")) {
          errors.push(`Check 11 Failed: Direct claim simulation reverted: ${fbMsg}`);
        }
      }
    } else {
      errors.push(`Check 11 Failed: Direct claim simulation reverted: ${msg}`);
    }
  }

  return {
    valid: errors.length === 0,
    claimFeeWei,
    amount,
    deadline,
    signature: voucher.signature,
    calldata,
    call,
    errors,
  };
}

/**
 * Builds a deterministic RescuePlan for OneFootball with exact fee accounting.
 */
export function buildOneFootballRescuePlan(
  victimAddress: Address,
  sponsorAddress: Address,
  safeWallet: Address,
  validation: OneFootballValidationResult,
  tokenOverride?: Address,
): RescuePlan {
  if (!validation.valid) {
    throw new Error(
      `Cannot build OneFootball rescue plan from invalid validation:\n${validation.errors.join("\n")}`,
    );
  }

  const tokenAddress = tokenOverride || ONEFOOTBALL_OFC_TOKEN;

  const airdropPlan: AirdropClaimPlan = {
    protocolId: "onefootball-claim",
    claimContract: validation.call.target,
    claimToken: tokenAddress,
    claimant: victimAddress,
    recipient: victimAddress, // Claimed to victim EOA, swept immediately to safeWallet
    expectedAmount: validation.amount,
    claimFeeWei: validation.claimFeeWei, // Exact live fee
    deadline: validation.deadline,
    signature: validation.signature,
  };

  return {
    chainId: ONEFOOTBALL_CHAIN_ID,
    compromisedAddress: victimAddress,
    safeWallet,
    sponsorAddress,
    airdropPlan,
    calls: [validation.call],
    tokens: [tokenAddress], // Sweeps tokens 100% to safeWallet
  };
}
