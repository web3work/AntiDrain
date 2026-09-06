/**
 * Sponsor Wallet Manager
 *
 * Checks sponsor wallet balances across chains and ensures
 * sufficient gas funding before rescue operations.
 *
 * IMPORTANT: Polygon uses POL, Mantle uses MNT — NOT ETH.
 */

import {
  createPublicClient,
  http,
  formatUnits,
} from "viem";
import { getChainConfig } from "../config/chains.js";
import { CHAIN_MAP } from "../rescue/authorization.js";
import type { Address } from "viem";

export interface SponsorBalance {
  chainId: number;
  chainName: string;
  balance: bigint;
  balanceFormatted: string;
  nativeSymbol: string;
  sufficient: boolean;
}

/**
 * Check sponsor wallet balance on a specific chain.
 */
export async function checkSponsorBalance(
  sponsorAddress: Address,
  chainId: number,
  requiredGas?: bigint,
): Promise<SponsorBalance> {
  const chainConfig = getChainConfig(chainId);
  const chain = CHAIN_MAP[chainId];
  if (!chain) throw new Error(`No chain for ${chainId}`);

  const client = createPublicClient({
    chain,
    transport: http(chainConfig.rpcUrl),
  });

  const balance = await client.getBalance({ address: sponsorAddress });
  const formatted = formatUnits(balance, chainConfig.nativeToken.decimals);

  return {
    chainId,
    chainName: chainConfig.name,
    balance,
    balanceFormatted: `${formatted} ${chainConfig.nativeToken.symbol}`,
    nativeSymbol: chainConfig.nativeToken.symbol,
    sufficient: requiredGas ? balance >= requiredGas : balance > 0n,
  };
}

/**
 * Check sponsor balance across all relevant chains.
 */
export async function checkAllSponsorBalances(
  sponsorAddress: Address,
  chainIds: number[],
): Promise<SponsorBalance[]> {
  const results = await Promise.allSettled(
    chainIds.map((id) => checkSponsorBalance(sponsorAddress, id)),
  );

  return results
    .filter(
      (r): r is PromiseFulfilledResult<SponsorBalance> =>
        r.status === "fulfilled",
    )
    .map((r) => r.value);
}
