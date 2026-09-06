/**
 * AntiDrain Web3 Claim Interceptor Bridge — WalletConnect v2 Transport Handler
 *
 * HARD CONSTRAINTS:
 * - WalletConnect MUST NOT bypass the hardened provider pipeline.
 * - All session_request events are routed directly through AntiDrainBridgeProvider.
 * - WalletConnect cannot obtain arbitrary signatures (signing oracle blocked).
 * - Session is strictly bound to configuredVictim and configuredChainId.
 */

import { type Address, getAddress } from "viem";
import { AntiDrainBridgeProvider } from "./provider.js";
import { EIP1193Error, EIP1193_ERRORS } from "./types.js";

export interface WalletConnectHandlerOptions {
  readonly provider: AntiDrainBridgeProvider;
  readonly configuredVictim: Address;
  readonly configuredChainId: number;
}

export interface WalletConnectSessionProposal {
  readonly id: number;
  readonly params: {
    readonly requiredNamespaces?: Record<string, { chains?: string[]; methods?: string[]; events?: string[] }>;
    readonly optionalNamespaces?: Record<string, { chains?: string[]; methods?: string[]; events?: string[] }>;
    readonly proposer: {
      readonly metadata: {
        readonly name: string;
        readonly description: string;
        readonly url: string;
        readonly icons: string[];
      };
    };
  };
}

export interface WalletConnectSessionRequest {
  readonly id: number;
  readonly topic: string;
  readonly params: {
    readonly chainId: string; // e.g. "eip155:8453"
    readonly request: {
      readonly method: string;
      readonly params: any[];
    };
  };
}

export class WalletConnectBridgeHandler {
  private readonly provider: AntiDrainBridgeProvider;
  readonly configuredVictim: Address;
  readonly configuredChainId: number;

  constructor(options: WalletConnectHandlerOptions) {
    this.provider = options.provider;
    this.configuredVictim = getAddress(options.configuredVictim);
    this.configuredChainId = options.configuredChainId;
  }

  /**
   * Validate and approve a WalletConnect session proposal.
   * Restricts namespaces to the configured victim and chain.
   */
  validateSessionProposal(proposal: WalletConnectSessionProposal): {
    approved: boolean;
    namespaces: Record<string, any>;
  } {
    const targetChain = `eip155:${this.configuredChainId}`;

    // Verify required chains if specified
    const reqChains = proposal.params.requiredNamespaces?.eip155?.chains ?? [];
    if (reqChains.length > 0 && !reqChains.includes(targetChain)) {
      throw new EIP1193Error(
        EIP1193_ERRORS.CHAIN_DISCONNECTED,
        `WalletConnect Proposal Rejected: dApp requested unsupported chain(s) ${reqChains.join(", ")}. Bridge is bound to ${targetChain}.`
      );
    }

    const approvedNamespaces = {
      eip155: {
        accounts: [`${targetChain}:${this.configuredVictim}`],
        methods: [
          "eth_sendTransaction",
          "eth_accounts",
          "eth_chainId",
          "eth_call",
          "eth_getBalance",
          "eth_estimateGas",
        ],
        events: ["chainChanged", "accountsChanged"],
      },
    };

    return {
      approved: true,
      namespaces: approvedNamespaces,
    };
  }

  /**
   * Handle incoming WalletConnect session request through the provider pipeline.
   */
  async handleSessionRequest(request: WalletConnectSessionRequest): Promise<any> {
    const { chainId, request: rpcReq } = request.params;

    // 1. Validate Chain
    const expectedChain = `eip155:${this.configuredChainId}`;
    if (chainId !== expectedChain) {
      throw new EIP1193Error(
        EIP1193_ERRORS.CHAIN_DISCONNECTED,
        `WalletConnect Request Rejected: Request chain (${chainId}) does not match session chain (${expectedChain}).`
      );
    }

    // 2. Dispatch directly through hardened provider
    return await this.provider.request({
      method: rpcReq.method,
      params: rpcReq.params,
      transport: "walletconnect",
    });
  }
}
