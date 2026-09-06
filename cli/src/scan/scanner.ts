/**
 * Multi-Chain Asset Discovery Scanner
 *
 * Scans a given address across all supported chains in parallel.
 * Identifies:
 * - Native gas token balance (ETH, POL, MNT)
 * - Account delegation status (EIP7702 code presence)
 * - Account nonce
 * - Common ERC-20 token balances
 */

import {
  createPublicClient,
  http,
  formatEther,
  formatUnits,
  type Address,
} from "viem";
import { SUPPORTED_CHAINS, CHAIN_PRIORITY_ORDER } from "../config/chains.js";

const ERC20_ABI = [
  {
    name: "balanceOf",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ name: "balance", type: "uint256" }],
  },
  {
    name: "decimals",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint8" }],
  },
  {
    name: "symbol",
    type: "function",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "string" }],
  },
] as const;

export interface TokenBalance {
  symbol: string;
  address: Address;
  balance: bigint;
  decimals: number;
  formatted: string;
}

export interface ChainScanResult {
  chainId: number;
  chainName: string;
  nativeSymbol: string;
  nativeBalance: bigint;
  formattedNative: string;
  accountNonce: number;
  isDelegated: boolean;
  delegatedCode: string;
  tokens: TokenBalance[];
  error?: string;
}

const COMMON_TOKENS_BY_CHAIN: Record<number, Array<{ symbol: string; address: Address; decimals: number }>> = {
  1: [
    { symbol: "USDC", address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals: 6 },
    { symbol: "USDT", address: "0xdAC17F9582ee523a2206206994597C13D831ec7", decimals: 6 },
    { symbol: "DAI", address: "0x6B175474Da98954EeedeAC29271d0F", decimals: 18 },
    { symbol: "WETH", address: "0xC02aaA39b223FE8d0A0e5C4F27eAD59083C756Cc2", decimals: 18 },
  ],
  8453: [
    { symbol: "USDC", address: "0x833589fCD6eDb6e08f4c7C32D4f71b54bdA02913", decimals: 6 },
    { symbol: "USDbC", address: "0xd9aAEc86B65D86f6A7B5B1b0c42FFA531710b6CA", decimals: 6 },
    { symbol: "WETH", address: "0x4200000000000000000000000000000000000006", decimals: 18 },
  ],
  42161: [
    { symbol: "USDC", address: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", decimals: 6 },
    { symbol: "USDT", address: "0xFd086bC7CD5C481DCC9c85ebE478A1C0b69FCbb9", decimals: 6 },
    { symbol: "WETH", address: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1", decimals: 18 },
  ],
  10: [
    { symbol: "USDC", address: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", decimals: 6 },
    { symbol: "USDT", address: "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", decimals: 6 },
    { symbol: "WETH", address: "0x4200000000000000000000000000000000000006", decimals: 18 },
  ],
  137: [
    { symbol: "USDC", address: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", decimals: 6 },
    { symbol: "USDT", address: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", decimals: 6 },
    { symbol: "WETH", address: "0x7ceB23fD6bC0aDD59E62ac25578270cFf1b9f619", decimals: 18 },
  ],
  5000: [
    { symbol: "USDC", address: "0x09Bc4E0D864854c6aFB6EBYA9cdF58aC190D0dF9", decimals: 6 },
    { symbol: "USDT", address: "0x201EEa5CC46D216Ce6DC03F6a759e8E766e956aEe", decimals: 6 },
    { symbol: "WMNT", address: "0x78c1b0C915c4FAA5FffA6CAbf0219DA63d7f478C", decimals: 18 },
  ],
  84532: [
    { symbol: "USDC", address: "0x036CBD53842cf5426634e7929541eC2318f3dCF7e", decimals: 6 },
  ],
};

export async function scanChain(chainId: number, targetAddress: Address): Promise<ChainScanResult> {
  const config = SUPPORTED_CHAINS[chainId];
  if (!config) {
    throw new Error(`Uncupported chain ID ${chainId}`);
  }

  const client = createPublicClient({
    transport: http(config.rpcUrl, { timeout: 10_000 }),
  });

  try {
    const [nativeBalance, accountNonce, code] = await Promise.all([      client.getBalance({ address: targetAddress }).catch(() => 0n),
      client.getTransactionCount({ address: targetAddress }).catch(() => 0),
      client.getCode({ address: targetAddress }).catch(() => "0x" as `ox${string}`),
    ]);

    const isDelegated = code !== undefined && code !== "0x" && code.length > 2;

    const tokenList = COMMON_TOKENS_BY_CHAIN[chainId] ?? [];
    const tokens: TokenBalance[] = [];

    await Promise.all(
      tokenList.map(async (t) => {
        try {
          const bal = (await client.readContract({
            address: t.address,
            abi: ERC20_ABI,
            functionName: "balanceOf",
            args: [targetAddress],
          })) as bigint;

          if (bal > 0n) {
            tokens.push({
              symbol: t.symbol,
              address: t.address,
              balance: bal,
              decimals: t.decimals,
              formatted: formatUnits(bal, t.decimals),
            });
          }
        } catch {
          // token not found or failed
        }
      })
    );

    return {
      chainId,
      chainName: config.name,
      nativeSymbol: config.nativeToken.symbol,
      nativeBalance,
      formattedNative: formatEther(nativeBalance),
      accountNonce,
      isDelegated,
      delegatedCode: code ?? "0x",
      tokens,
    };
  } catch (error) {
    return {
      chainId,
      chainName: config.name,
      nativeSymbol: config.nativeToken.symbol,
      nativeBalance: 0n,
      formattedNative: "0.0",
      accountNonce: 0,
      isDelegated: false,
      delegatedCode: "0x",
      tokens: [],
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function scanAllChains(targetAddress: Address): Promise<ChainScanResult[]> {
  const chainIds = [...CHAIN_PRIORITY_ORDER, 84532];
  return Promise.all(chainIds.map((id) => scanChain(id, targetAddress)));
}
