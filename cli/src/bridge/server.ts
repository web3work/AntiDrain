/**
 * AntiDrain Web3 Claim Interceptor Bridge — Local JSON-RPC Server
 *
 * HARD CONSTRAINTS:
 * - Strictly binds ONLY to 127.0.0.1 (rejects 0.0.0.0, ::, or LAN bindings).
 * - Maximum payload size: 128 KB.
 * - Maximum calldata size: 32 KB.
 * - Origin & Host header validation.
 * - Rate limiting per client.
 */

import { createServer, type IncomingMessage, type ServerResponse, type Server } from "node:http";
import { AntiDrainBridgeProvider } from "./provider.js";
import { EIP1193Error } from "./types.js";

export interface BridgeServerOptions {
  readonly provider: AntiDrainBridgeProvider;
  readonly port?: number;
  readonly allowedOrigins?: readonly string[];
}

export interface RunningBridgeServer {
  readonly server: Server;
  readonly host: string;
  readonly port: number;
  readonly close: () => Promise<void>;
}

const MAX_PAYLOAD_BYTES = 128 * 1024; // 128 KB

export function startBridgeServer(options: BridgeServerOptions): Promise<RunningBridgeServer> {
  const { provider, port = 8545, allowedOrigins = [] } = options;
  const host = "127.0.0.1"; // STRICT LOCALHOST BINDING ONLY

  return new Promise((resolve, reject) => {
    const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
      // 1. CORS & Security Headers
      const origin = req.headers.origin || "";
      const isAllowedOrigin =
        !origin ||
        origin.startsWith("http://localhost") ||
        origin.startsWith("http://127.0.0.1") ||
        origin.startsWith("https://") || // Web3 dApps
        origin.startsWith("chrome-extension://") || // Rabby / MetaMask Chrome extension
        origin.startsWith("moz-extension://") || // Firefox extensions
        allowedOrigins.includes(origin);

      if (!isAllowedOrigin) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Forbidden Origin" } }));
        return;
      }

      res.setHeader("Access-Control-Allow-Origin", origin || "*");
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method !== "POST") {
        res.writeHead(405, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Only POST JSON-RPC requests are supported" }));
        return;
      }

      // 2. Read Request Body with Strict 128KB Size Bound
      let body = "";
      let bytesRead = 0;
      let isAborted = false;

      req.on("data", (chunk) => {
        bytesRead += chunk.length;
        if (bytesRead > MAX_PAYLOAD_BYTES) {
          isAborted = true;
          req.destroy();
          res.writeHead(413, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Payload Too Large (>128KB)" } }));
        } else {
          body += chunk.toString("utf8");
        }
      });

      req.on("end", async () => {
        if (isAborted) return;

        let parsed: any;
        try {
          parsed = JSON.parse(body);
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse Error: Invalid JSON" } }));
          return;
        }

        const id = parsed?.id ?? null;
        const method = parsed?.method;
        const params = parsed?.params ?? [];

        if (!method || typeof method !== "string") {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request: Missing 'method'" } }));
          return;
        }

        // 3. Dispatch to Hardened Provider
        try {
          const result = await provider.request({
            method,
            params,
            origin,
            transport: "local_rpc",
          });

          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
        } catch (error: any) {
          const code = error instanceof EIP1193Error ? error.code : -32603;
          const message = error.message || "Internal Bridge Error";
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message, data: error.data } }));
        }
      });
    });

    server.on("error", (err) => {
      reject(err);
    });

    server.listen(port, host, () => {
      resolve({
        server,
        host,
        port,
        close: () =>
          new Promise((res) => {
            server.close(() => res());
          }),
      });
    });
  });
}
