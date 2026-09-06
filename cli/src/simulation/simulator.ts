/**
 * Simulation Engine — Mandatory pre-flight check.
 *
 * HARD CONSTRAINT (PROJECT_RULES.md Section 1, Rule #2):
 * "NEVER broadcast a transaction that hasn't been simulated first"
 *
 * This module runs the exact rescue transaction via eth_call against
 * the live chain state before any real broadcast, auto-discovers known
 * positive-balance tokens on the target chain, computes an immutable
 * cryptographic PLAN_HASH, and alerts the operator to any omitted assets.
 *
 * ABI: 6-parameter executeRescue(safeWallet, calls, tokens, nonce, deadline, signature)
 * Synchronized with UniversalRecoveryDelegate.sol (dual-auth contract).
 */

import {
  createPublicClient,
  http,
  encodeFunctionData,
  formatEther,
  formatUnits,
  keccak256,
  encodeAbiParameters,
  parseAbiParameters,
  type Address,
  type Hex,
} from "viem";
import { getChainConfig } from "../config/chains.js";
import { CHAIN_MAP } from "../rescue/authorization.js";
import type { RescuePlan, SimulationResult, DiscoveredToken } from "../config/types.js";

// ─── Known Major Tokens Registry (for Automated Discovery) ────────────────

const COMMON_CHAIN_TOKENS: Record<number, Address[]> = {
  // Ethereum Mainnet
  1: [
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", // USDC
    "0xdAC17F958D2ee523a2206206994597C13D831ec7", // USDT
    "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
    "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", // WETH
    "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599", // WBTC
  ],
  // Base
  8453: [
    "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", // USDC
    "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA", // USDbC
    "0x4200000000000000000000000000000000000006", // WETH
    "0x752C5a95d202972E124390F30a50154409d3c858", // OFC (OneFootball)
  ],
  // Arbitrum One
  42161: [
    "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", // USDC
    "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", // USDT
    "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", // WETH
    "0x912CE59144191C1204E64559FE8253a0e49E6548", // ARB
  ],
  // Optimism
  10: [
    "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", // USDC
    "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", // USDT
    "0x4200000000000000000000000000000000000042", // OP
    "0x4200000000000000000000000000000000000006", // WETH
  ],
  // Polygon PoS
  137: [
    "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", // USDC
    "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", // USDT
    "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270", // WPOL
  ],
  // Mantle
  5000: [
    "0x201EBa5CC46D216Ce631ef5775305999c7373DD7", // USDT
    "0x09Bc4E0D864854c6aFB6eB9A9cdF58aC190D0dF9", // USDC
    "0x78c1b0C915c4FAA5FffA6CAbf0219DA63d7f4cb8", // WMNT
  ],
};

// ─── UniversalRecoveryDelegate ABI (6-parameter dual-auth) ─────────────────
// MUST exactly match: executeRescue(address,Call[],address[],uint256,uint256,bytes)

const RECOVERY_DELEGATE_ABI = [
  {
    type: "constructor",
    stateMutability: "nonpayable",
    inputs: [],
  },
  {
    name: "executeRescue",
    type: "function",
    stateMutability: "payable",
    inputs: [
      { name: "safeWallet", type: "address" },
      {
        name: "calls",
        type: "tuple[]",
        components: [
          { name: "target", type: "address" },
          { name: "value", type: "uint256" },
          { name: "data", type: "bytes" },
        ],
      },
      { name: "tokens", type: "address[]" },
      { name: "nonce", type: "uint256" },
      { name: "deadline", type: "uint256" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [],
  },
  {
    name: "NONCE_SLOT",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
] as const;

// ─── ERC-20 ABI for balance reading ────────────────────────────────────

const ERC20_ABI = [
  {
    name: "balanceOf",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ name: "balance", type: "uint256" }],
  },
  {
    name: "symbol",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
  {
    name: "decimals",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
] as const;

// ─── Cryptographic Plan Hash Computation ────────────────────────────────

/**
 * Compute an immutable cryptographic hash of the entire rescue plan.
 * Used for multi-operator verification and tamper protection.
 */
export function computePlanHash(plan: RescuePlan): Hex {
  const encoded = encodeAbiParameters(
    parseAbiParameters(
      "uint256, address, address, address, address[], (address,uint256,bytes)[]",
    ),
    [
      BigInt(plan.chainId),
      plan.compromisedAddress,
      plan.sponsorAddress,
      plan.safeWallet,
      plan.tokens,
      plan.calls.map((c) => [c.target, c.value, c.data] as const),
    ],
  );
  return keccak256(encoded);
}

// ─── Calldata Encoding (6-parameter) ───────────────────────────────────

/**
 * Encode the full 6-parameter executeRescue calldata.
 * This is used for BOTH simulation and broadcast — byte-identical.
 */
export function encodeRescueCalldata(
  safeWallet: Address,
  calls: readonly { target: Address; value: bigint; data: Hex }[],
  tokens: readonly Address[],
  nonce: bigint,
  deadline: bigint,
  signature: Hex,
): Hex {
  return encodeFunctionData({
    abi: RECOVERY_DELEGATE_ABI,
    functionName: "executeRescue",
    args: [
      safeWallet,
      calls.map((c) => ({
        target: c.target,
        value: c.value,
        data: c.data,
      })),
      [...tokens],
      nonce,
      deadline,
      signature,
    ],
  });
}

// ─── Simulation & Discovery ────────────────────────────────────────────

/**
 * Simulate the rescue transaction via eth_call.
 * This runs the exact transaction payload against live chain state
 * WITHOUT broadcasting. Returns predicted outcomes and discovers omitted tokens.
 *
 * REQUIREMENT #4: When fullSimulation is true, uses the EXACT calldata
 * (including valid EIP-712 signature) that will be broadcast.
 * When fullSimulation is false (pre-signing discovery phase), returns
 * balance/gas estimates only, clearly labeled as incomplete.
 */
export async function simulateRescue(
  plan: RescuePlan,
  options?: {
    /** Pre-built calldata for realistic simulation (byte-identical to broadcast) */
    exactCalldata?: Hex;
    /** Whether this is a full simulation with valid signature */
    isFullSimulation?: boolean;
  },
): Promise<SimulationResult> {
  const chainConfig = getChainConfig(plan.chainId);
  const chain = CHAIN_MAP[plan.chainId];
  if (!chain) {
    throw new Error(`No viem chain for chainId ${plan.chainId}`);
  }

  const client = createPublicClient({
    chain,
    transport: http(plan.rpcUrl || chainConfig.rpcUrl),
  });

  const planHash = computePlanHash(plan);
  const planTokensSet = new Set(plan.tokens.map((t) => t.toLowerCase()));
  const isFullSim = options?.isFullSimulation ?? false;

  // 1. Read current token balances for tokens in the plan
  const tokenSweeps: SimulationResult["tokenSweeps"] = [];
  for (const tokenAddr of plan.tokens) {
    try {
      const [balance, symbol, decimals] = await Promise.all([
        client.readContract({
          address: tokenAddr,
          abi: ERC20_ABI,
          functionName: "balanceOf",
          args: [plan.compromisedAddress],
        }),
        client.readContract({
          address: tokenAddr,
          abi: ERC20_ABI,
          functionName: "symbol",
        }).catch(() => "UNKNOWN"),
        client.readContract({
          address: tokenAddr,
          abi: ERC20_ABI,
          functionName: "decimals",
        }).catch(() => 18 as number),
      ]);

      tokenSweeps.push({
        token: tokenAddr,
        symbol: symbol as string,
        balance: balance as bigint,
        balanceFormatted: formatUnits(balance as bigint, decimals as number),
      });
    } catch {
      tokenSweeps.push({
        token: tokenAddr,
        symbol: "ERROR",
        balance: 0n,
        balanceFormatted: "0",
      });
    }
  }

  // 2. Auto-Discovery: Scan known common tokens for omitted positive balances
  const omittedTokens: DiscoveredToken[] = [];
  const commonTokens = COMMON_CHAIN_TOKENS[plan.chainId] ?? [];

  for (const candidateAddr of commonTokens) {
    if (!planTokensSet.has(candidateAddr.toLowerCase())) {
      try {
        const balance = (await client.readContract({
          address: candidateAddr,
          abi: ERC20_ABI,
          functionName: "balanceOf",
          args: [plan.compromisedAddress],
        })) as bigint;

        if (balance > 0n) {
          const [symbol, decimals] = await Promise.all([
            client.readContract({
              address: candidateAddr,
              abi: ERC20_ABI,
              functionName: "symbol",
            }).catch(() => "UNKNOWN"),
            client.readContract({
              address: candidateAddr,
              abi: ERC20_ABI,
              functionName: "decimals",
            }).catch(() => 18 as number),
          ]);

          omittedTokens.push({
            token: candidateAddr,
            symbol: symbol as string,
            balance,
            balanceFormatted: formatUnits(balance, decimals as number),
          });
        }
      } catch {
        // Skip unreadable candidate
      }
    }
  }

  // 3. Read native balance
  const nativeBalance = await client.getBalance({
    address: plan.compromisedAddress,
  });

  // 4. Read sponsor balance
  const sponsorBalance = await client.getBalance({
    address: plan.sponsorAddress,
  });

  // 5. Gas estimation
  let gasEstimate: bigint;
  let simulationSuccess = false;
  let simulationError: string | undefined;

  const totalCallValue = plan.calls.reduce((sum, c) => sum + (c.value ?? 0n), 0n);

  if (options?.exactCalldata) {
    // Full simulation with exact calldata (including valid signature)
    try {
      // 1. Run eth_call preflight with exact value
      await client.call({
        account: plan.sponsorAddress,
        to: plan.compromisedAddress,
        data: options.exactCalldata,
        value: totalCallValue,
      });

      // 2. Run estimateGas with exact value
      gasEstimate = await client.estimateGas({
        account: plan.sponsorAddress,
        to: plan.compromisedAddress,
        data: options.exactCalldata,
        value: totalCallValue,
      });
      simulationSuccess = true;
    } catch (err) {
      // If full simulation fails, this is a real problem — do NOT silently fallback
      const errMsg = err instanceof Error ? err.message : String(err);
      if (isFullSim) {
        return {
          success: false,
          gasEstimate: 0n,
          gasCostWei: 0n,
          gasCostFormatted: "0",
          callResults: [],
          tokenSweeps,
          scannedRegistryCount: commonTokens.length,
          omittedTokens,
          totalDiscoveredCount: tokenSweeps.filter((s) => s.balance > 0n).length + omittedTokens.length,
          totalIncludedCount: plan.tokens.length,
          nativeSweep: { balance: nativeBalance, balanceFormatted: formatEther(nativeBalance) },
          planHash,
          sponsorBalanceAfter: sponsorBalance,
          isFullSimulation: true,
          error: `SIMULATION FAILED (full simulation with valid signature): ${errMsg}`,
        };
      }
      // Pre-signing fallback: use heuristic gas estimate, clearly labeled
      gasEstimate = 80000n + BigInt(plan.calls.length * 40000) + BigInt(plan.tokens.length * 30000);
      simulationError = `Fallback gas estimate (pre-signing, delegation may not be active yet): ${errMsg}`;
    }
  } else {
    // Pre-signing discovery: delegation likely not active, use heuristic estimate
    gasEstimate = 80000n + BigInt(plan.calls.length * 40000) + BigInt(plan.tokens.length * 30000);
    simulationError = "Pre-signing discovery phase: gas estimate is heuristic (delegation not yet active)";
  }

  // 6. Calculate gas cost
  const gasPrice = await client.getGasPrice().catch(() => 1000000000n);
  const gasCostWei = gasEstimate * gasPrice;
  const nativeDecimals = chainConfig.nativeToken.decimals;
  const gasCostFormatted = `${formatUnits(gasCostWei, nativeDecimals)} ${chainConfig.nativeToken.symbol}`;
  const totalRequiredFunding = gasCostWei + totalCallValue;
  const sponsorBalanceAfter = sponsorBalance - totalRequiredFunding;

  return {
    success: simulationSuccess || !isFullSim,
    gasEstimate,
    gasCostWei,
    gasCostFormatted,
    callResults: plan.calls.map((c, i) => ({
      index: i,
      target: c.target,
      success: true,
    })),
    tokenSweeps,
    scannedRegistryCount: commonTokens.length,
    omittedTokens,
    totalDiscoveredCount: tokenSweeps.filter((s) => s.balance > 0n).length + omittedTokens.length,
    totalIncludedCount: plan.tokens.length,
    nativeSweep: {
      balance: nativeBalance,
      balanceFormatted: formatEther(nativeBalance),
    },
    planHash,
    sponsorBalanceAfter,
    isFullSimulation: isFullSim,
    error:
      simulationError ??
      (sponsorBalanceAfter < 0n
        ? `Sponsor has insufficient ${chainConfig.nativeToken.symbol}. Need ${formatUnits(totalRequiredFunding, nativeDecimals)} ${chainConfig.nativeToken.symbol} (${gasCostFormatted} gas + ${formatUnits(totalCallValue, nativeDecimals)} claim fee), have ${formatUnits(sponsorBalance, nativeDecimals)} ${chainConfig.nativeToken.symbol}`
        : undefined),
  };
}

/** Get the RecoveryDelegate ABI for external use */
export function getRecoveryDelegateABI() {
  return RECOVERY_DELEGATE_ABI;
}
