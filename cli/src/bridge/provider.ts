/**
 * AntiDrain Web3 Claim Interceptor Bridge — Hardened EIP-1193 Provider
 *
 * HARD CONSTRAINTS:
 * - NO SIGNING ORACLE: personal_sign, eth_signTypedData, eth_sign are strictly REJECTED (4100).
 * - ACCOUNT ISOLATION: strictly exposes and accepts only configuredVictim.
 * - CHAIN ISOLATION: strictly bound to configuredChainId.
 * - NO GENERIC FALLBACK: unknown methods fail closed with EIP-1193 4200/ -32601.
 */

import {
  type Address,
  type Hex,
  type PublicClient,
  getAddress,
  isAddress,
  toHex,
  hexToBigInt,
  keccak256,
  toBytes,
} from "viem";
import type { CapturedRequest, ValidatedClaim, BridgeTransport } from "./types.js";
import { EIP1193Error, EIP1193_ERRORS } from "./types.js";

export interface BridgeProviderOptions {
  readonly configuredVictim: Address;
  readonly configuredChainId: number;
  readonly publicClient: PublicClient<any, any>;
  readonly onTransactionSubmit: (claim: ValidatedClaim) => Promise<Hex>;
}

export class AntiDrainBridgeProvider {
  readonly configuredVictim: Address;
  readonly configuredChainId: number;
  private readonly publicClient: PublicClient<any, any>;
  private readonly onTransactionSubmit: (claim: ValidatedClaim) => Promise<Hex>;

  constructor(options: BridgeProviderOptions) {
    if (!isAddress(options.configuredVictim)) {
      throw new Error(`Invalid configured victim address: ${options.configuredVictim}`);
    }
    this.configuredVictim = getAddress(options.configuredVictim);
    this.configuredChainId = options.configuredChainId;
    this.publicClient = options.publicClient;
    this.onTransactionSubmit = options.onTransactionSubmit;
  }

  /**
   * Standard EIP-1193 request dispatcher.
   */
  async request(args: {
    method: string;
    params?: any[];
    origin?: string;
    transport?: BridgeTransport;
  }): Promise<any> {
    const { method, params = [], origin, transport = "local_rpc" } = args;

    // ─── 1. Signing Oracle Block (HARD SECURITY BLOCKER) ─────────────────────
    if (
      method === "personal_sign" ||
      method === "eth_sign" ||
      method === "eth_signTypedData" ||
      method === "eth_signTypedData_v3" ||
      method === "eth_signTypedData_v4" ||
      method === "eth_signTransaction"
    ) {
      throw new EIP1193Error(
        EIP1193_ERRORS.UNAUTHORIZED,
        `AntiDrain Security Policy: Arbitrary signature method "${method}" is strictly disabled. The bridge cannot be used as an off-chain signing oracle.`
      );
    }

    // ─── 2. Account & Chain Identity Methods ─────────────────────────────────
    if (method === "eth_accounts" || method === "eth_requestAccounts") {
      return [this.configuredVictim];
    }

    if (method === "eth_chainId") {
      return toHex(this.configuredChainId);
    }

    if (method === "net_version") {
      return String(this.configuredChainId);
    }

    // ─── 3. Chain Switch Invariants ──────────────────────────────────────────
    if (method === "wallet_switchEthereumChain") {
      const requestedChainHex = params[0]?.chainId;
      if (!requestedChainHex) {
        throw new EIP1193Error(EIP1193_ERRORS.INVALID_PARAMS, "Missing chainId parameter.");
      }
      const requestedChainId = Number(hexToBigInt(requestedChainHex));
      if (requestedChainId !== this.configuredChainId) {
        throw new EIP1193Error(
          EIP1193_ERRORS.CHAIN_DISCONNECTED,
          `Chain switch rejected: Bridge is bound strictly to Chain ID ${this.configuredChainId}. Dynamic chain switching is forbidden during active rescue.`
        );
      }
      return null;
    }

    if (method === "wallet_addEthereumChain") {
      throw new EIP1193Error(
        EIP1193_ERRORS.UNSUPPORTED_METHOD,
        "wallet_addEthereumChain is not supported during an active rescue session."
      );
    }

    // ─── 4. Transaction Interception (Core Rescue Entrypoint) ────────────────
    if (method === "eth_sendTransaction") {
      const txObj = params[0];
      if (!txObj || typeof txObj !== "object") {
        throw new EIP1193Error(EIP1193_ERRORS.INVALID_PARAMS, "Missing transaction object parameter.");
      }

      // Account Isolation Check
      if (!txObj.from) {
        throw new EIP1193Error(EIP1193_ERRORS.INVALID_PARAMS, "Transaction 'from' field is mandatory.");
      }
      if (!isAddress(txObj.from)) {
        throw new EIP1193Error(EIP1193_ERRORS.INVALID_PARAMS, "Malformed 'from' address.");
      }
      const normalizedFrom = getAddress(txObj.from);
      if (normalizedFrom !== this.configuredVictim) {
        throw new EIP1193Error(
          EIP1193_ERRORS.UNAUTHORIZED,
          `Account Isolation Violation: Transaction 'from' (${normalizedFrom}) does not match configured victim (${this.configuredVictim}).`
        );
      }

      // Target Address Check
      if (!txObj.to || !isAddress(txObj.to)) {
        throw new EIP1193Error(EIP1193_ERRORS.INVALID_PARAMS, "Transaction 'to' is invalid or missing.");
      }
      const normalizedTo = getAddress(txObj.to);

      // Calldata Check
      const data: Hex = txObj.data ? (txObj.data as Hex) : "0x";
      if (!data.startsWith("0x")) {
        throw new EIP1193Error(EIP1193_ERRORS.INVALID_PARAMS, "Transaction 'data' must be a valid hex string.");
      }
      if (data.length > 65538) { // 32KB max
        throw new EIP1193Error(EIP1193_ERRORS.INVALID_PARAMS, "Transaction calldata exceeds maximum 32KB limit.");
      }

      // Value & Gas Parsing
      const value = txObj.value ? hexToBigInt(txObj.value) : 0n;
      const gasLimit = txObj.gas ? hexToBigInt(txObj.gas) : 500_000n;

      // Build Canonical Captured Request
      const correlationId = `req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
      const requestPayload = JSON.stringify({
        from: normalizedFrom,
        to: normalizedTo,
        data,
        value: value.toString(),
        chainId: this.configuredChainId,
      });
      const requestHash = keccak256(toBytes(requestPayload));

      const capturedRequest: CapturedRequest = {
        id: txObj.id ?? correlationId,
        method: "eth_sendTransaction",
        params: [txObj],
        timestamp: Date.now(),
        transport,
        requestHash,
        origin,
        correlationId,
      };

      const validatedClaim: ValidatedClaim = {
        from: normalizedFrom,
        to: normalizedTo,
        data,
        value,
        gasLimit,
        chainId: this.configuredChainId,
        rawRequest: capturedRequest,
      };

      // Dispatch to coordinator pipeline
      return await this.onTransactionSubmit(validatedClaim);
    }

    // ─── 5. Read-Only RPC Passthrough (Safe Queries) ─────────────────────────
    if (method === "eth_call") {
      const callObj = params[0];
      const blockTag = params[1] ?? "latest";
      return await this.publicClient.call({
        to: callObj.to,
        data: callObj.data,
        value: callObj.value ? hexToBigInt(callObj.value) : undefined,
        account: callObj.from ? getAddress(callObj.from) : undefined,
        blockTag,
      }).then((res) => res.data ?? "0x");
    }

    if (method === "web3_clientVersion") {
      return "AntiDrainBridge/v1.3.0";
    }

    if (method === "eth_syncing") {
      return false;
    }

    if (method === "eth_gasPrice") {
      const price = await this.publicClient.getGasPrice();
      return toHex(price);
    }

    if (method === "eth_maxPriorityFeePerGas") {
      return "0x1";
    }

    if (method === "eth_getTransactionCount") {
      const target = getAddress(params[0]);
      const count = await this.publicClient.getTransactionCount({
        address: target,
        blockTag: params[1] ?? "latest",
      });
      return toHex(count);
    }

    if (method === "eth_getBlockByNumber") {
      const isLatest = !params[0] || params[0] === "latest";
      const block = isLatest
        ? await this.publicClient.getBlock({ blockTag: "latest", includeTransactions: params[1] ?? false })
        : await this.publicClient.getBlock({ blockNumber: hexToBigInt(params[0]), includeTransactions: params[1] ?? false });
      return block;
    }

    if (method === "eth_getBalance") {
      const target = getAddress(params[0]);
      if (target.toLowerCase() === this.configuredVictim.toLowerCase()) {
        const actualBal = await this.publicClient.getBalance({ address: target });
        // Return at least 0.05 ETH virtual balance so dApp client-side pre-flight checks pass
        const virtualBal = actualBal > 50_000_000_000_000_000n ? actualBal : 50_000_000_000_000_000n;
        return toHex(virtualBal);
      }
      const bal = await this.publicClient.getBalance({ address: target });
      return toHex(bal);
    }

    if (method === "eth_getCode") {
      const target = getAddress(params[0]);
      const code = await this.publicClient.getCode({ address: target });
      return code ?? "0x";
    }

    if (method === "eth_estimateGas") {
      const callObj = params[0];
      try {
        const est = await this.publicClient.estimateGas({
          to: callObj.to,
          data: callObj.data,
          value: callObj.value ? hexToBigInt(callObj.value) : undefined,
          account: callObj.from ? getAddress(callObj.from) : undefined,
        });
        return toHex(est);
      } catch {
        // Return safe default gas estimate if on-chain simulation fails due to 0 victim balance
        return toHex(350_000n);
      }
    }

    if (method === "eth_blockNumber") {
      const num = await this.publicClient.getBlockNumber();
      return toHex(num);
    }

    if (method === "eth_getTransactionReceipt") {
      const hash = params[0];
      const receipt = await this.publicClient.getTransactionReceipt({ hash });
      return receipt;
    }

    // ─── 6. Fallback: Unknown Methods Fail Closed ────────────────────────────
    throw new EIP1193Error(
      EIP1193_ERRORS.METHOD_NOT_FOUND,
      `Method "${method}" is unsupported or disabled on AntiDrain Bridge.`
    );
  }
}
