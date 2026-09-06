/**
 * AntiDrain Phase 1 — Windows Native Messaging Host Registration
 *
 * Manages host manifest generation and Windows Registry keys for Chrome, Brave, and Edge.
 */

import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const HOST_NAME = "org.antidrain.native_host";

export interface HostManifest {
  name: string;
  description: string;
  path: string;
  type: "stdio";
  allowed_origins: string[];
}

export function getHostManifestPath(): string {
  const rootDir = path.resolve(__dirname, "../../../");
  return path.join(rootDir, `${HOST_NAME}.json`);
}

export function getHostExecutablePath(): string {
  const rootDir = path.resolve(__dirname, "../../../");
  const exePath = path.join(rootDir, "antidrain-host.exe");
  if (fs.existsSync(exePath)) {
    return exePath;
  }
  return path.join(rootDir, "antidrain-host.bat");
}

export function generateHostManifest(allowedExtensionIds: string[]): HostManifest {
  const execPath = getHostExecutablePath();
  const allowedOrigins = allowedExtensionIds.map((id) =>
    id.startsWith("chrome-extension://") ? id : `chrome-extension://${id}/`
  );

  return {
    name: HOST_NAME,
    description: "AntiDrain Native Messaging Host for Chrome, Brave, and Edge",
    path: execPath,
    type: "stdio",
    allowed_origins: allowedOrigins,
  };
}

export function writeHostManifest(manifest: HostManifest): string {
  const manifestPath = getHostManifestPath();
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), "utf8");
  return manifestPath;
}

const REGISTRY_TARGETS = [
  { name: "Google Chrome", key: `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}` },
  { name: "Brave Browser", key: `HKCU\\Software\\BraveSoftware\\Brave-Browser\\NativeMessagingHosts\\${HOST_NAME}` },
  { name: "Microsoft Edge", key: `HKCU\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\${HOST_NAME}` },
];

export function registerHostInWindowsRegistry(manifestPath: string): { success: boolean; registered: string[] } {
  const registered: string[] = [];

  for (const target of REGISTRY_TARGETS) {
    try {
      const cmd = `reg add "${target.key}" /ve /t REG_SZ /d "${manifestPath}" /f`;
      execSync(cmd, { stdio: "pipe" });
      registered.push(target.name);
    } catch {
      // Continue to other browsers if one fails
    }
  }

  return {
    success: registered.length > 0,
    registered,
  };
}

export function unregisterHostFromWindowsRegistry(): { success: boolean; removed: string[] } {
  const removed: string[] = [];

  for (const target of REGISTRY_TARGETS) {
    try {
      const cmd = `reg delete "${target.key}" /f`;
      execSync(cmd, { stdio: "pipe" });
      removed.push(target.name);
    } catch {
      // Ignore if key doesn't exist
    }
  }

  return {
    success: true,
    removed,
  };
}

export function verifyHostInstallation(): {
  manifestExists: boolean;
  executableExists: boolean;
  manifestValid: boolean;
  manifest?: HostManifest;
  errors: string[];
} {
  const errors: string[] = [];
  const manifestPath = getHostManifestPath();
  const execPath = getHostExecutablePath();

  const manifestExists = fs.existsSync(manifestPath);
  if (!manifestExists) {
    errors.push(`Manifest file missing at ${manifestPath}`);
  }

  const executableExists = fs.existsSync(execPath);
  if (!executableExists) {
    errors.push(`Executable launcher missing at ${execPath}`);
  }

  let manifestValid = false;
  let manifest: HostManifest | undefined;

  if (manifestExists) {
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
      if (manifest?.name !== HOST_NAME) {
        errors.push(`Invalid host name in manifest: ${manifest?.name}`);
      }
      if (manifest?.type !== "stdio") {
        errors.push(`Invalid host type in manifest: ${manifest?.type}`);
      }
      if (!Array.isArray(manifest?.allowed_origins) || manifest?.allowed_origins.length === 0) {
        errors.push("No allowed origins in manifest");
      } else if (manifest?.allowed_origins.some((o) => o.includes("*"))) {
        errors.push("Wildcard origins forbidden in manifest");
      }
      manifestValid = errors.length === 0;
    } catch (err) {
      errors.push(`Failed to parse manifest JSON: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  return {
    manifestExists,
    executableExists,
    manifestValid,
    manifest,
    errors,
  };
}
