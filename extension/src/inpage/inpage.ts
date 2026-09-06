/**
 * AntiDrain Inpage Provider & EIP-6963 Announcer
 *
 * Runs inside the webpage DOM context.
 * Invariant B0 Enforcement:
 * - Hard-blocks all signing oracle methods (personal_sign, eth_signTypedData_v4, etc.)
 * - Forwards transactions to content script with strict session and correlation tracking.
 * - Dynamic configuration: ZERO hardcoded private addresses or keys.
 */

(function () {
  const PROVIDER_UUID = "d48a6062-8178-4ea5-b9f4-3d178e2270a2"; // Compliant UUIDv4
  const SESSION_ID = Math.random().toString(36).substring(2, 15);

  class AntiDrainInpageProvider {
    public readonly isAntiDrain = true;
    public readonly isMetaMask = true; // Enables RainbowKit / Web3Modal 1-click connection
    public selectedAddress: string | null = null;
    public chainId = "0x2105"; // Default: Base (8453)
    public networkVersion = "8453";

    private readonly pendingRequests = new Map<
      string,
      { resolve: (val: unknown) => void; reject: (err: unknown) => void; method: string; params: unknown[] }
    >();
    private readonly listeners = new Map<string, Set<(...args: any[]) => void>>();

    constructor() {
      window.addEventListener("message", this.handleContentResponse.bind(this));
    }

    public isConnected(): boolean {
      return true;
    }

    public on(event: string, listener: (...args: any[]) => void): this {
      if (!this.listeners.has(event)) {
        this.listeners.set(event, new Set());
      }
      this.listeners.get(event)!.add(listener);
      return this;
    }

    public addListener(event: string, listener: (...args: any[]) => void): this {
      return this.on(event, listener);
    }

    public removeListener(event: string, listener: (...args: any[]) => void): this {
      this.listeners.get(event)?.delete(listener);
      return this;
    }

    public emit(event: string, ...args: any[]): boolean {
      const handlers = this.listeners.get(event);
      if (!handlers || handlers.size === 0) return false;
      for (const h of handlers) {
        try {
          h(...args);
        } catch (err) {
          console.error(`[AntiDrain Provider] Event handler error (${event}):`, err);
        }
      }
      return true;
    }

    private handleContentResponse(event: MessageEvent): void {
      const data = event.data;
      if (!data || typeof data !== "object" || data.target !== "ANTIDRAIN_INPAGE" || data.version !== 1) {
        return;
      }

      const pending = this.pendingRequests.get(data.requestId);
      if (!pending) {
        return;
      }
      this.pendingRequests.delete(data.requestId);

      if (data.error) {
        const error = new Error(data.error.message || "EIP-1193 Error");
        (error as any).code = data.error.code;
        pending.reject(error);
      } else {
        // Cache account if returned from accounts call
        if (Array.isArray(data.result)) {
          const prevAddress = this.selectedAddress;
          this.selectedAddress = typeof data.result[0] === "string" ? data.result[0] : null;
          this.emit("accountsChanged", data.result);
          if (this.selectedAddress && this.selectedAddress !== prevAddress) {
            this.emit("connect", { chainId: this.chainId });
          }
        } else if (
          (pending.method === "wallet_switchEthereumChain" || pending.method === "wallet_addEthereumChain") &&
          data.result === null
        ) {
          const targetChainHex = (pending.params?.[0] as any)?.chainId;
          if (typeof targetChainHex === "string" && targetChainHex.startsWith("0x")) {
            const prevChain = this.chainId;
            this.chainId = targetChainHex;
            try {
              this.networkVersion = String(parseInt(targetChainHex, 16));
            } catch {}
            if (prevChain !== this.chainId) {
              this.emit("chainChanged", this.chainId);
            }
          }
        } else if (typeof data.result === "string" && data.result.startsWith("0x")) {
          // Chain ID hex
          if (data.result.length <= 10) {
            const prevChain = this.chainId;
            this.chainId = data.result;
            try {
              this.networkVersion = String(parseInt(data.result, 16));
            } catch {}
            if (prevChain !== this.chainId) {
              this.emit("chainChanged", this.chainId);
            }
          }
        }
        pending.resolve(data.result);
      }
    }

    public async request(args: { method: string; params?: unknown[] }): Promise<unknown> {
      if (!args || typeof args.method !== "string" || !args.method) {
        const error = new Error("Invalid request: method string required.");
        (error as any).code = -32600;
        throw error;
      }

      const { method, params = [] } = args;

      // 1. Signing Oracle Elimination (Hard-Block)
      if (
        method === "personal_sign" ||
        method === "eth_sign" ||
        method === "eth_signTypedData" ||
        method === "eth_signTypedData_v3" ||
        method === "eth_signTypedData_v4" ||
        method === "eth_signTransaction" ||
        method === "wallet_sendCalls"
      ) {
        const error = new Error(
          `AntiDrain Security Policy: Method "${method}" is strictly disabled. The companion does not act as an off-chain signing oracle.`
        );
        (error as any).code = 4100;
        throw error;
      }

      // 2. Dispatch request to content script
      const requestId = `req_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
      const message = {
        target: "ANTIDRAIN_CONTENT",
        version: 1,
        sessionId: SESSION_ID,
        requestId,
        method,
        params,
      };

      return new Promise((resolve, reject) => {
        this.pendingRequests.set(requestId, { resolve, reject, method, params });
        window.postMessage(message, "*");
      });
    }
  }

  const provider = new AntiDrainInpageProvider();

  // EIP-6963 Provider Announcement with official AntiDrain Shield-Lock emblem
  function announceProvider(): void {
    const info = {
      uuid: PROVIDER_UUID,
      name: "AntiDrain Rescue Companion",
      icon: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgMTAwIiBmaWxsPSJub25lIj48ZGVmcz48bGluZWFyR3JhZGllbnQgaWQ9InNnIiB4MT0iNTAiIHkxPSI4IiB4Mj0iNTAiIHkyPSI5MiIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPjxzdG9wIG9mZnNldD0iMCUiIHN0b3AtY29sb3I9IiMzQjgyRjYiLz48c3RvcCBvZmZzZXQ9IjEwMCUiIHN0b3AtY29sb3I9IiMxMEI5ODEiLz48L2xpbmVhckdyYWRpZW50PjwvZGVmcz48cGF0aCBkPSJNNTAgOCBMODggMjYgTDg4IDUyIEM4OCA3MiA3MiA4OCA1MCA5NSBDMjggODggMTIgNzIgMTIgNTIgTDEyIDI2IFoiIHN0cm9rZT0idXJsKCNzZykiIHN0cm9rZS13aWR0aD0iNiIgZmlsbD0iIzBCMEYxOSIvPjxwYXRoIGQ9Ik01MCAxNiBMODIgMzEgTDgyIDUyIEM4MiA2OCA2OCA4MiA1MCA4OCBDMzIgODIgMTggNjggMTggNTIgTDE4IDMxIFoiIGZpbGw9InVybCgjc2cpIiBvcGFjaXR5PSIwLjI1Ii8+PHJlY3QgeD0iMzciIHk9IjQ3IiB3aWR0aD0iMjYiIGhlaWdodD0iMjEiIHJ4PSI0IiBmaWxsPSIjRkZGRkZGIi8+PHBhdGggZD0iTTQyIDQ3IFYzOSBDNDIgMzQgNDUuNSAzMCA1MCAzMCBDNTQuNSAzMCA1OCAzNCA1OCAzOSBWNDciIHN0cm9rZT0iI0ZGRkZGRiIgc3Ryb2tlLXdpZHRoPSI0LjUiIGZpbGw9Im5vbmUiIHN0cm9rZS1saW5lY2FwPSJyb3VuZCIvPjxjaXJjbGUgY3g9IjUwIiBjeT0iNTUiIHI9IjIuOCIgZmlsbD0iIzBCMEYxOSIvPjxyZWN0IHg9IjQ4LjgiIHk9IjU2IiB3aWR0aD0iMi40IiBoZWlnaHQ9IjUiIHJ4PSIxIiBmaWxsPSIjMEIwRjE5Ii8+PC9zdmc+",
      rdns: "org.antidrain.rescue",
    };
    window.dispatchEvent(
      new CustomEvent("eip6963:announceProvider", {
        detail: Object.freeze({ info, provider }),
      })
    );
  }

  // Announce on request and on initialization
  window.addEventListener("eip6963:requestProvider", () => {
    announceProvider();
  });
  announceProvider();

  // Injection into window.ethereum for legacy RainbowKit / Web3Modal
  try {
    Object.defineProperty(window, "ethereum", {
      value: provider,
      writable: true,
      configurable: true,
    });
  } catch {
    (window as any).ethereum = provider;
  }
})();
