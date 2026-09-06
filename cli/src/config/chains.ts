/**
 * Chain Registry — Verified configuration for all supported chains and testnets.
 *
 * Supported Production Chains:
 * 1. Ethereum (1) - Gas: ETH
 * 2. Base (8453) - Gas: ETH
 * 3. Arbitrum One (42161) - Gas: ETH
 * 4. Optimism (10) - Gas: ETH
 * 5. Polygon PoS (137) - Gas: POL (NOT MATIC, NOT ETH)
 * 6. Mantle (5000) - Gas: MNT (NOT ETH)
 *
 * Supported Testnets:
 * - Sepolia (11155111)
 * - Base Sepolia (84532) - Live Canary Verified
 * - Arbitrum Sepolia (421614)
 * - OP Sepolia (11155420)
 * - Polygon Amoy (80002)
 * - Mantle Sepolia (5003)
 * - Anvil Local (31337)
 */

import { createPublicClient, http } from "viem";
import type { ChainConfig } from "./types.js";

const BATCH_EXECUTOR_ADDRESS = "0x60BAf255624BEE5629e5D86Ae8976aF19795A314" as const;

const DEFAULT_GAS_POLICY = {
  maxGasLimit: 2000000n,
  maxFeeWei: 50000000000000000n, // 0.05 ETH equivalent
};

export const SUPPORTED_CHAINS: Record<number, ChainConfig> = {
  // ─── Ethereum Mainnet ─────────────────────────────────────────────────
  1: {
    name: "Ethereum",
    chainId: 1,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: process.env.ETH_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://eth-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://eth.llamarpc.com"),
    blockExplorerUrl: "https://etherscan.io",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-05-07",
      source: "Pectra upgrade, block 22431084",
    },
    testnet: {
      chainId: 11155111,
      name: "Sepolia",
      rpcUrl: process.env.ETH_SEPOLIA_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://rpc.sepolia.org"),
      faucetUrl: "https://sepoliafaucet.com",
    },
  },

  // ─── Base ─────────────────────────────────────────────────────────────
  8453: {
    name: "Base",
    chainId: 8453,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl:
      process.env.BASE_RPC_URL ||
      (process.env.ALCHEMY_API_KEY
        ? `https://base-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`
        : "https://mainnet.base.org"),
    blockExplorerUrl: "https://basescan.org",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-05-07",
      source: "OP Stack Isthmus upgrade",
    },
    testnet: {
      chainId: 84532,
      name: "Base Sepolia",
      rpcUrl:
        process.env.BASE_SEPOLIA_RPC_URL ||
        (process.env.ALCHEMY_API_KEY
          ? `https://base-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`
          : "https://sepolia.base.org"),
      faucetUrl: "https://www.alchemy.com/faucets/base-sepolia",
    },
  },

  // ─── Arbitrum One ─────────────────────────────────────────────────────
  42161: {
    name: "Arbitrum One",
    chainId: 42161,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: process.env.ARB_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://arb-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://arb1.arbitrum.io/rpc"),
    blockExplorerUrl: "https://arbiscan.io",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-06-17",
      source: "ArbOS 40 Callisto, Nitro v3.6.5",
    },
    testnet: {
      chainId: 421614,
      name: "Arbitrum Sepolia",
      rpcUrl: process.env.ARB_SEPOLIA_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://arb-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://sepolia-rollup.arbitrum.io/rpc"),
    },
  },

  // ─── Optimism ─────────────────────────────────────────────────────────
  10: {
    name: "Optimism",
    chainId: 10,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: process.env.OPT_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://opt-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://mainnet.optimism.io"),
    blockExplorerUrl: "https://optimistic.etherscan.io",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-05-09",
      source: "Isthmus hardfork",
    },
    testnet: {
      chainId: 11155420,
      name: "OP Sepolia",
      rpcUrl: process.env.OPT_SEPOLIA_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://opt-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://sepolia.optimism.io"),
    },
  },

  // ─── Polygon PoS (POL Gas Token) ──────────────────────────────────────
  137: {
    name: "Polygon PoS",
    chainId: 137,
    nativeToken: { symbol: "POL", decimals: 18 },
    rpcUrl:
      process.env.POLYGON_RPC_URL ||
      (process.env.ALCHEMY_API_KEY
        ? `https://polygon-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`
        : "https://polygon-bor-rpc.publicnode.com"),
    blockExplorerUrl: "https://polygonscan.com",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-07-10",
      source: "Bhilai hard fork, PIP-61",
    },
    testnet: {
      chainId: 80002,
      name: "Polygon Amoy",
      rpcUrl:
        process.env.POLYGON_AMOY_RPC_URL ||
        (process.env.ALCHEMY_API_KEY
          ? `https://polygon-amoy.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`
          : "https://rpc-amoy.polygon.technology"),
      faucetUrl: "https://faucet.polygon.technology",
    },
  },

  // ─── Mantle (MNT Gas Token) ───────────────────────────────────────────
  5000: {
    name: "Mantle",
    chainId: 5000,
    nativeToken: { symbol: "MNT", decimals: 18 },
    rpcUrl: process.env.MANTLE_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://mantle-mainnet.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://rpc.mantle.xyz"),
    blockExplorerUrl: "https://mantlescan.xyz",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2026-04-22",
      source: "Arsia upgrade",
    },
    testnet: {
      chainId: 5003,
      name: "Mantle Sepolia",
      rpcUrl: "https://rpc.sepolia.mantle.xyz",
      faucetUrl: "https://faucet.sepolia.mantle.xyz",
    },
  },

  // ─── Testnets ─────────────────────────────────────────────────────────
  11155111: {
    name: "Sepolia",
    chainId: 11155111,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: process.env.ETH_SEPOLIA_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://eth-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://rpc.sepolia.org"),
    blockExplorerUrl: "https://sepolia.etherscan.io",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-03-05",
      source: "Sepolia Pectra Testnet",
    },
  },
  421614: {
    name: "Arbitrum Sepolia",
    chainId: 421614,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: process.env.ARB_SEPOLIA_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://arb-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://sepolia-rollup.arbitrum.io/rpc"),
    blockExplorerUrl: "https://sepolia.arbiscan.io",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-05-15",
      source: "ArbOS 40 Callisto Testnet",
    },
  },
  84532: {
    name: "Base Sepolia",
    chainId: 84532,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: process.env.BASE_SEPOLIA_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://base-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://sepolia.base.org"),
    blockExplorerUrl: "https://sepolia.basescan.org",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "LIVE CANARY VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-04-10",
      source: "OP Stack Isthmus Testnet",
    },
  },
  11155420: {
    name: "OP Sepolia",
    chainId: 11155420,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: process.env.OPT_SEPOLIA_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://opt-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://sepolia.optimism.io"),
    blockExplorerUrl: "https://sepolia-optimism.etherscan.io",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-04-10",
      source: "OP Stack Isthmus Testnet",
    },
  },
  80002: {
    name: "Polygon Amoy",
    chainId: 80002,
    nativeToken: { symbol: "POL", decimals: 18 },
    rpcUrl: process.env.POLYGON_AMOY_RPC_URL || (process.env.ALCHEMY_API_KEY ? `https://polygon-amoy.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}` : "https://rpc-amoy.polygon.technology"),
    blockExplorerUrl: "https://amoy.polygonscan.com",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-06-01",
      source: "Bhilai Testnet",
    },
  },
  5003: {
    name: "Mantle Sepolia",
    chainId: 5003,
    nativeToken: { symbol: "MNT", decimals: 18 },
    rpcUrl: "https://rpc.sepolia.mantle.xyz",
    blockExplorerUrl: "https://sepolia.mantlescan.xyz",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2026-03-15",
      source: "Arsia Testnet",
    },
  },
  31337: {
    name: "Anvil Local",
    chainId: 31337,
    nativeToken: { symbol: "ETH", decimals: 18 },
    rpcUrl: "http://127.0.0.1:8545",
    blockExplorerUrl: "http://localhost:8545",
    batchExecutorAddress: BATCH_EXECUTOR_ADDRESS,
    supportsEip7702: true,
    type04Supported: true,
    status: "SIMULATED & CODE-VERIFIED",
    gasPolicy: DEFAULT_GAS_POLICY,
    eip7702: {
      verified: true,
      activationDate: "2025-01-01",
      source: "Local Anvil Prague Hardfork",
    },
  },
};

/** Get chain config by ID, throws if unsupported */
export function getChainConfig(chainId: number): ChainConfig {
  const config = SUPPORTED_CHAINS[chainId];
  if (!config) {
    throw new Error(
      `Unsupported chain ID: ${chainId}. Supported: ${Object.keys(SUPPORTED_CHAINS).join(", ")}`,
    );
  }
  return config;
}

/** Get all supported chain IDs */
export function getSupportedChainIds(): number[] {
  return Object.keys(SUPPORTED_CHAINS).map(Number);
}

/** Priority-ordered chain IDs (Base first per user request) */
export const CHAIN_PRIORITY_ORDER = [8453, 1, 42161, 10, 137, 5000];

/**
 * Health check utility for RPC endpoint availability.
 * If endpoint is unreachable, operations must fail-closed.
 */
export async function checkRpcHealth(chainId: number): Promise<{
  healthy: boolean;
  blockNumber?: bigint;
  latencyMs?: number;
  error?: string;
}> {
  const config = getChainConfig(chainId);
  const client = createPublicClient({
    transport: http(config.rpcUrl, { timeout: 4000 }),
  });

  const start = Date.now();
  try {
    const blockNumber = await client.getBlockNumber();
    const latencyMs = Date.now() - start;
    return {
      healthy: true,
      blockNumber,
      latencyMs,
    };
  } catch (err) {
    return {
      healthy: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
