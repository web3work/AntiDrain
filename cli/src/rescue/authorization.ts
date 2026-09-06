/**
 * EIP-7702 Authorization Signing
 *
 * Signs EIP-7702 authorization tuples for the compromised wallet,
 * delegating execution to the BatchExecutor contract.
 *
 * VERIFIED API (viem v2.55.x):
 * - signAuthorization({ account, contractAddress, chainId?, nonce? })
 *   → { contractAddress, chainId, nonce, r, s, yParity }
 *
 * KEY DECISIONS:
 * - Use chain-specific chainId (NOT chainId: 0) to avoid nonce desync
 * - executor: 'self' is NOT needed (sponsor ≠ compromised)
 */

import {
  createWalletClient,
  http,
  type SignedAuthorization,
  type LocalAccount,
  type Chain,
} from "viem";
import {
  mainnet,
  arbitrum,
  base,
  optimism,
  polygon,
  mantle,
  sepolia,
  arbitrumSepolia,
  baseSepolia,
  optimismSepolia,
  polygonAmoy,
  mantleSepoliaTestnet,
  anvil,
} from "viem/chains";
import type { Address } from "viem";
import { getChainConfig } from "../config/chains.js";

// ─── Chain ID → viem Chain mapping ──────────────────────────────────────

export const CHAIN_MAP: Record<number, Chain> = {
  // Mainnets
  1: mainnet,
  42161: arbitrum,
  8453: base,
  10: optimism,
  137: polygon,
  5000: mantle,
  // Testnets
  11155111: sepolia,
  421614: arbitrumSepolia,
  84532: baseSepolia,
  11155420: optimismSepolia,
  80002: polygonAmoy,
  5003: mantleSepoliaTestnet,
  // Local
  31337: anvil,
};

/**
 * Sign an EIP-7702 authorization delegating the compromised wallet
 * to the BatchExecutor contract on a specific chain.
 *
 * @param compromisedAccount  Local account of the compromised wallet
 * @param chainId             Target chain ID (chain-specific, NOT 0)
 * @param batchExecutorAddress Address of the deployed BatchExecutor
 * @returns Signed authorization tuple
 */
export async function signRescueAuthorization(
  compromisedAccount: LocalAccount,
  chainId: number,
  batchExecutorAddress: Address,
): Promise<SignedAuthorization> {
  const chain = CHAIN_MAP[chainId];
  if (!chain) {
    throw new Error(`No viem chain definition for chainId ${chainId}`);
  }

  const chainConfig = getChainConfig(chainId);
  const client = createWalletClient({
    account: compromisedAccount,
    chain,
    transport: http(chainConfig.rpcUrl),
  });

  // Sign authorization with chain-specific chainId (NOT 0)
  // SECURITY: Use chain-specific chainId in authorizations
  // (NOT chainId: 0) to avoid nonce desynchronization across chains"
  const authorization = await client.signAuthorization({
    contractAddress: batchExecutorAddress,
    // chainId defaults to client.chain.id — which is exactly what we want
    // Do NOT pass chainId: 0 here
  });

  return authorization;
}

/**
 * Sign a revocation authorization — delegates to address(0) to clear
 * the EIP-7702 delegation after a rescue operation.
 *
 * VERIFIED: Delegating to address(0) clears the account's code
 * per EIP-7702 specification (web-verified Aug 21, 2026).
 */
export async function signRevocationAuthorization(
  compromisedAccount: LocalAccount,
  chainId: number,
  nonce?: number,
): Promise<SignedAuthorization> {
  const chain = CHAIN_MAP[chainId];
  if (!chain) {
    throw new Error(`No viem chain definition for chainId ${chainId}`);
  }

  const chainConfig = getChainConfig(chainId);
  const client = createWalletClient({
    account: compromisedAccount,
    chain,
    transport: http(chainConfig.rpcUrl),
  });

  // Delegate to address(0) = revoke delegation
  const authorization = await client.signAuthorization({
    contractAddress: "0x0000000000000000000000000000000000000000",
    ...(nonce !== undefined ? { nonce } : {}),
  });

  return authorization;
}
