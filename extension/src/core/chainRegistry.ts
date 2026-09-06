/**
 * AntiDrain Standalone Extension — Universal Capability-Driven EVM Registry
 *
 * Implements extensible EVM network discovery decoupled from rescue capability gating:
 * - Arbitrary EVM networks can be detected and used for standard read-only wallet tasks.
 * - Rescue capability is strictly restricted to verified chains with audited CREATE2 delegate deployments.
 * - Capability states:
 *   • LIVE_VERIFIED
 *   • CANARY_VERIFIED
 *   • CODE_VERIFIED
 *   • SIMULATION_ONLY
 *   • UNVERIFIED
 *   • UNSUPPORTED
 */

export type EvmCapabilityState =
  | "LIVE_VERIFIED"
  | "CANARY_VERIFIED"
  | "CODE_VERIFIED"
  | "SIMULATION_ONLY"
  | "UNVERIFIED"
  | "UNSUPPORTED";

export interface RpcEndpoint {
  url: string;
  isFallback?: boolean;
}

export interface GasToken {
  symbol: string;
  name: string;
  decimals: number;
}

export type BroadcastEndpointType =
  | "PRIVATE_BUILDER_RELAY"
  | "DIRECT_SEQUENCER_FEED"
  | "DEDICATED_GATEWAY"
  | "PUBLIC_RPC_GATEWAY";

export interface ChainDefinition {
  chainId: number;
  name: string;
  nativeToken: GasToken;
  rpcUrls: RpcEndpoint[];
  privateBroadcastUrl?: string;
  broadcastEndpointType?: BroadcastEndpointType;
  explorerUrl: string;
  supportsEip7702: boolean;
  supportsType04: boolean;
  eip7702ActivationBlock?: number;
  verifiedDelegateAddress: `0x${string}`;
  delegateBytecodeHash: `0x${string}`;
  deploymentStatus: "DEPLOYED" | "NOT_DEPLOYED" | "UNKNOWN";
  simulationSupport: boolean;
  rescueStatus: EvmCapabilityState;
  maxGasLimit: bigint;
  maxFeeWei: bigint;
}

// Canonical CREATE2 Deterministic Delegate deployed address and bytecode hash
export const BATCH_EXECUTOR_DELEGATE: `0x${string}` = "0x60BAf255624BEE5629e5D86Ae8976aF19795A314";
export const BATCH_EXECUTOR_BYTECODE_HASH: `0x${string}` = "0x4933ce6f42ff5ec5332c4e46e00e3f73a0e185ea03cc98418f030a05aca7a2dd";

export const CHAIN_REGISTRY: Record<number, ChainDefinition> = {
  // ─── 1. Base (Mainnet) ───────────────────────────────────────────────────
  8453: {
    chainId: 8453,
    name: "Base Mainnet",
    nativeToken: { symbol: "ETH", name: "Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://mainnet.base.org" },
      { url: "https://base.llamarpc.com", isFallback: true },
    ],
    privateBroadcastUrl: "https://mainnet-sequencer.base.org",
    broadcastEndpointType: "DIRECT_SEQUENCER_FEED",
    explorerUrl: "https://basescan.org",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CODE_VERIFIED",
    maxGasLimit: 2_000_000n,
    maxFeeWei: 50_000_000_000_000_000n, // 0.05 ETH
  },

  // ─── 2. Base Sepolia (Live Canary Testnet) ──────────────────────────────
  84532: {
    chainId: 84532,
    name: "Base Sepolia",
    nativeToken: { symbol: "ETH", name: "Sepolia Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://sepolia.base.org" },
      { url: "https://base-sepolia-rpc.publicnode.com", isFallback: true },
    ],
    privateBroadcastUrl: "https://sepolia-sequencer.base.org",
    broadcastEndpointType: "DIRECT_SEQUENCER_FEED",
    explorerUrl: "https://sepolia.basescan.org",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CANARY_VERIFIED",
    maxGasLimit: 2_000_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  },

  // ─── 3. Ethereum Mainnet ─────────────────────────────────────────────────
  1: {
    chainId: 1,
    name: "Ethereum Mainnet",
    nativeToken: { symbol: "ETH", name: "Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://eth.llamarpc.com" },
      { url: "https://cloudflare-eth.com", isFallback: true },
    ],
    privateBroadcastUrl: "https://rpc.flashbots.net/fast",
    broadcastEndpointType: "PRIVATE_BUILDER_RELAY",
    explorerUrl: "https://etherscan.io",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CODE_VERIFIED",
    maxGasLimit: 1_500_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  },

  // ─── 4. Arbitrum One ─────────────────────────────────────────────────────
  42161: {
    chainId: 42161,
    name: "Arbitrum One",
    nativeToken: { symbol: "ETH", name: "Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://arb1.arbitrum.io/rpc" },
      { url: "https://arbitrum.llamarpc.com", isFallback: true },
    ],
    privateBroadcastUrl: "https://arb1-sequencer.arbitrum.io/rpc",
    broadcastEndpointType: "DIRECT_SEQUENCER_FEED",
    explorerUrl: "https://arbiscan.io",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CODE_VERIFIED",
    maxGasLimit: 2_500_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  },

  // ─── 5. Optimism ─────────────────────────────────────────────────────────
  10: {
    chainId: 10,
    name: "OP Mainnet",
    nativeToken: { symbol: "ETH", name: "Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://mainnet.optimism.io" },
      { url: "https://optimism.llamarpc.com", isFallback: true },
    ],
    privateBroadcastUrl: "https://mainnet-sequencer.optimism.io",
    broadcastEndpointType: "DIRECT_SEQUENCER_FEED",
    explorerUrl: "https://optimistic.etherscan.io",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CODE_VERIFIED",
    maxGasLimit: 2_000_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  },

  // ─── 6. Polygon PoS (POL Gas Token) ──────────────────────────────────────
  137: {
    chainId: 137,
    name: "Polygon PoS",
    nativeToken: { symbol: "POL", name: "Polygon Ecosystem Token", decimals: 18 },
    rpcUrls: [
      { url: "https://polygon-bor-rpc.publicnode.com" },
      { url: "https://polygon.llamarpc.com", isFallback: true },
    ],
    privateBroadcastUrl: "https://polygon-bor-rpc.publicnode.com",
    broadcastEndpointType: "DEDICATED_GATEWAY",
    explorerUrl: "https://polygonscan.com",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CODE_VERIFIED",
    maxGasLimit: 3_000_000n,
    maxFeeWei: 100_000_000_000_000_000_000n, // 100 POL
  },

  // ─── 7. Mantle (MNT Gas Token) ───────────────────────────────────────────
  5000: {
    chainId: 5000,
    name: "Mantle Mainnet",
    nativeToken: { symbol: "MNT", name: "Mantle Token", decimals: 18 },
    rpcUrls: [
      { url: "https://rpc.mantle.xyz" },
      { url: "https://mantle.publicnode.com", isFallback: true },
    ],
    privateBroadcastUrl: "https://rpc.mantle.xyz",
    broadcastEndpointType: "DIRECT_SEQUENCER_FEED",
    explorerUrl: "https://mantlescan.xyz",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CODE_VERIFIED",
    maxGasLimit: 3_000_000n,
    maxFeeWei: 50_000_000_000_000_000_000n, // 50 MNT
  },

  // ─── 8. Arbitrum Sepolia ─────────────────────────────────────────────────
  421614: {
    chainId: 421614,
    name: "Arbitrum Sepolia",
    nativeToken: { symbol: "ETH", name: "Sepolia Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://sepolia-rollup.arbitrum.io/rpc" },
      { url: "https://arbitrum-sepolia.blockpi.network/v1/rpc/public", isFallback: true },
    ],
    privateBroadcastUrl: "https://sepolia-rollup.arbitrum.io/rpc",
    broadcastEndpointType: "DIRECT_SEQUENCER_FEED",
    explorerUrl: "https://sepolia.arbiscan.io",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CANARY_VERIFIED",
    maxGasLimit: 2_500_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  },

  // ─── 9. OP Sepolia ───────────────────────────────────────────────────────
  11155420: {
    chainId: 11155420,
    name: "OP Sepolia",
    nativeToken: { symbol: "ETH", name: "Sepolia Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://sepolia.optimism.io" },
      { url: "https://optimism-sepolia.blockpi.network/v1/rpc/public", isFallback: true },
    ],
    privateBroadcastUrl: "https://sepolia-sequencer.optimism.io",
    broadcastEndpointType: "DIRECT_SEQUENCER_FEED",
    explorerUrl: "https://sepolia-optimism.etherscan.io",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CANARY_VERIFIED",
    maxGasLimit: 2_000_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  },

  // ─── 10. Ethereum Sepolia ────────────────────────────────────────────────
  11155111: {
    chainId: 11155111,
    name: "Ethereum Sepolia",
    nativeToken: { symbol: "ETH", name: "Sepolia Ether", decimals: 18 },
    rpcUrls: [
      { url: "https://ethereum-sepolia-rpc.publicnode.com" },
      { url: "https://rpc.sepolia.org", isFallback: true },
    ],
    privateBroadcastUrl: "https://rpc-sepolia.flashbots.net",
    broadcastEndpointType: "PRIVATE_BUILDER_RELAY",
    explorerUrl: "https://sepolia.etherscan.io",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CANARY_VERIFIED",
    maxGasLimit: 1_500_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  },

  // ─── 11. Polygon Amoy (POL Gas Token) ────────────────────────────────────
  80002: {
    chainId: 80002,
    name: "Polygon Amoy",
    nativeToken: { symbol: "POL", name: "Polygon Ecosystem Token", decimals: 18 },
    rpcUrls: [
      { url: "https://polygon-amoy-bor-rpc.publicnode.com" },
      { url: "https://rpc-amoy.polygon.technology", isFallback: true },
    ],
    privateBroadcastUrl: "https://rpc-amoy.polygon.technology",
    broadcastEndpointType: "DEDICATED_GATEWAY",
    explorerUrl: "https://amoy.polygonscan.com",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CANARY_VERIFIED",
    maxGasLimit: 3_000_000n,
    maxFeeWei: 100_000_000_000_000_000_000n, // 100 POL
  },

  // ─── 12. Mantle Sepolia (MNT Gas Token) ──────────────────────────────────
  5003: {
    chainId: 5003,
    name: "Mantle Sepolia",
    nativeToken: { symbol: "MNT", name: "Mantle Token", decimals: 18 },
    rpcUrls: [
      { url: "https://rpc.sepolia.mantle.xyz" },
      { url: "https://mantle-sepolia.blockpi.network/v1/rpc/public", isFallback: true },
    ],
    explorerUrl: "https://sepolia.mantlescan.xyz",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CANARY_VERIFIED",
    maxGasLimit: 3_000_000n,
    maxFeeWei: 50_000_000_000_000_000_000n, // 50 MNT
  },

  // ─── 13. Anvil Local Testbed ─────────────────────────────────────────────
  31337: {
    chainId: 31337,
    name: "Anvil Local",
    nativeToken: { symbol: "ETH", name: "Ether", decimals: 18 },
    rpcUrls: [{ url: "http://127.0.0.1:8545" }],
    explorerUrl: "http://127.0.0.1:8545",
    supportsEip7702: true,
    supportsType04: true,
    verifiedDelegateAddress: BATCH_EXECUTOR_DELEGATE,
    delegateBytecodeHash: BATCH_EXECUTOR_BYTECODE_HASH,
    deploymentStatus: "DEPLOYED",
    simulationSupport: true,
    rescueStatus: "CODE_VERIFIED",
    maxGasLimit: 10_000_000n,
    maxFeeWei: 1_000_000_000_000_000_000n,
  },
};

/**
 * Resolves EVM chain metadata. If the chain is not in the built-in registry, returns
 * a standard unverified EVM definition (disabling rescue fail-closed).
 */
export function detectEvmChain(chainId: number): ChainDefinition {
  if (CHAIN_REGISTRY[chainId]) {
    return CHAIN_REGISTRY[chainId];
  }
  return {
    chainId,
    name: `Unknown EVM Chain (${chainId})`,
    nativeToken: { symbol: "ETH", name: "Native Token", decimals: 18 },
    rpcUrls: [],
    explorerUrl: "",
    supportsEip7702: false,
    supportsType04: false,
    verifiedDelegateAddress: "0x0000000000000000000000000000000000000000",
    delegateBytecodeHash: "0x0000000000000000000000000000000000000000000000000000000000000000",
    deploymentStatus: "UNKNOWN",
    simulationSupport: false,
    rescueStatus: "UNVERIFIED",
    maxGasLimit: 2_000_000n,
    maxFeeWei: 50_000_000_000_000_000n,
  };
}

export function getChainDefinition(chainId: number): ChainDefinition {
  const chain = CHAIN_REGISTRY[chainId];
  if (!chain) {
    throw new Error(`Chain ID ${chainId} is not supported by AntiDrain.`);
  }
  return chain;
}

export function isRescueAllowedOnChain(chainId: number): boolean {
  const chain = CHAIN_REGISTRY[chainId];
  if (!chain) return false;
  return (
    chain.supportsEip7702 &&
    chain.supportsType04 &&
    chain.simulationSupport &&
    chain.deploymentStatus === "DEPLOYED" &&
    (chain.rescueStatus === "LIVE_VERIFIED" ||
      chain.rescueStatus === "CANARY_VERIFIED" ||
      chain.rescueStatus === "CODE_VERIFIED")
  );
}

export function isChainSupportedForRescue(chainId: number): boolean {
  return isRescueAllowedOnChain(chainId);
}

export function getRescueUnsupportedReason(chainId: number): string {
  const chain = detectEvmChain(chainId);
  if (chain.rescueStatus === "UNSUPPORTED" || chain.rescueStatus === "UNVERIFIED") {
    return "This EVM network has not been verified for safe rescue execution. EIP-7702 delegation is disabled.";
  }
  if (!chain.supportsEip7702) {
    return "EIP-7702 is not activated on this network.";
  }
  if (chain.deploymentStatus !== "DEPLOYED") {
    return "AntiDrain UniversalRecoveryDelegate is not deployed on this network.";
  }
  return "Rescue execution is disabled on this network.";
}
