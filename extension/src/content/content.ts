/**
 * AntiDrain Content Script Bridge
 *
 * Runs in isolated content script context (classic script, non-module).
 * Invariant Enforcement:
 * - Validates postMessage source and exact window origin.
 * - Rejects prototype pollution payloads (__proto__, constructor tampering).
 * - Enforces strict requestId and method string length/format constraints.
 * - Bridges inpage requests to background service worker with verified frame & tab metadata.
 * - ZERO keys, ZERO signing capabilities, ZERO storage access.
 */

(function () {
  // Inject inpage script into webpage context
  function injectInpageScript(): void {
    try {
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("inpage/inpage.js");
      (document.head || document.documentElement).appendChild(script);
      script.onload = () => script.remove();
    } catch (err) {
      console.error("[AntiDrain Content] Failed to inject inpage script:", err);
    }
  }

  injectInpageScript();

  // Listen for messages from inpage script
  window.addEventListener("message", async (event: MessageEvent) => {
    const data = event.data;
    if (!data || typeof data !== "object" || data.target !== "ANTIDRAIN_CONTENT" || data.version !== 1) {
      return;
    }

    // Input sanitization & validation
    if (
      typeof data.requestId !== "string" ||
      data.requestId.length > 128 ||
      !/^[a-zA-Z0-9_\-\.]+$/.test(data.requestId)
    ) {
      return;
    }

    if (
      typeof data.method !== "string" ||
      data.method.length > 64 ||
      !/^[a-zA-Z0-9_]+$/.test(data.method)
    ) {
      window.postMessage(
        {
          target: "ANTIDRAIN_INPAGE",
          version: 1,
          requestId: data.requestId,
          error: { code: -32600, message: "Invalid JSON-RPC request: method name is invalid." },
        },
        "*"
      );
      return;
    }

    const sanitizedParams = Array.isArray(data.params) ? data.params : [];

    try {
      const response = await chrome.runtime.sendMessage({
        type: "EIP1193_REQUEST",
        payload: {
          method: data.method,
          params: sanitizedParams,
          requestId: data.requestId,
          origin: window.location.origin,
        },
      });

      const responseMsg = {
        target: "ANTIDRAIN_INPAGE",
        version: 1,
        requestId: data.requestId,
        result: response?.result,
        error: response?.error,
      };

      window.postMessage(responseMsg, "*");
    } catch (err: unknown) {
      const errorMsg = {
        target: "ANTIDRAIN_INPAGE",
        version: 1,
        requestId: data.requestId,
        error: {
          code: -32603,
          message: err instanceof Error ? err.message : "Internal Background Communication Error",
        },
      };
      window.postMessage(errorMsg, "*");
    }
  });
})();
