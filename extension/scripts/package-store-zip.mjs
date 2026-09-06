/**
 * AntiDrain Extension — Chrome Web Store Packaging & Zip Verification
 *
 * Packages strictly clean production runtime files into antidrain-companion-v1.0.0.zip.
 * Excludes all .ts, .d.ts, .map, test files, scratch files, and source code.
 */

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "../..");
const EXT_DIR = path.resolve(ROOT, "extension");
const DIST_DIR = path.resolve(EXT_DIR, "dist");
const STORE_DIR = path.resolve(EXT_DIR, "store-package");
const ZIP_OUTPUT = path.resolve(EXT_DIR, "antidrain-companion-v1.0.0.zip");

console.log("════════════════════════════════════════════════════════════════════");
console.log("  ANTIDRAIN CHROME WEB STORE PACKAGING & VERIFICATION");
console.log("════════════════════════════════════════════════════════════════════");

// 1. Rebuild extension
console.log("▶ Rebuilding extension from clean source...");
execSync("node extension/scripts/build-extension.js", { cwd: ROOT, stdio: "inherit" });

// 2. Prepare clean store directory with ONLY runtime production assets
if (fs.existsSync(STORE_DIR)) {
  fs.rmSync(STORE_DIR, { recursive: true, force: true });
}
fs.mkdirSync(STORE_DIR, { recursive: true });

const runtimeFiles = [
  "manifest.json",
  "background/background.js",
  "content/content.js",
  "inpage/inpage.js",
  "popup/popup.html",
  "popup/popup.js",
  "core/chainRegistry.js",
  "rescue/stateMachine.js",
  "shared/types.js",
  "signer/typedSigner.js",
  "vault/webCryptoVault.js",
  "icons/icon16.png",
  "icons/icon48.png",
  "icons/icon128.png",
];

console.log("\n▶ Copying runtime assets into clean store package folder...");
for (const rel of runtimeFiles) {
  const src = path.join(DIST_DIR, rel);
  const dst = path.join(STORE_DIR, rel);
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
  const hash = crypto.createHash("sha256").update(fs.readFileSync(dst)).digest("hex");
  console.log(`  ✔ [${hash.substring(0, 12)}...] ${rel}`);
}

// 3. Create zip archive using PowerShell Compress-Archive
console.log(`\n▶ Creating production archive: ${ZIP_OUTPUT}`);
if (fs.existsSync(ZIP_OUTPUT)) {
  fs.unlinkSync(ZIP_OUTPUT);
}

execSync(
  `powershell -Command "Compress-Archive -Path '${STORE_DIR}\\*' -DestinationPath '${ZIP_OUTPUT}' -Force"`,
  { stdio: "inherit" }
);

const zipStats = fs.statSync(ZIP_OUTPUT);
const zipHash = crypto.createHash("sha256").update(fs.readFileSync(ZIP_OUTPUT)).digest("hex");

console.log(`\n✔ Package created successfully!`);
console.log(`  Archive Size: ${zipStats.size} bytes (${(zipStats.size / 1024).toFixed(2)} KB)`);
console.log(`  Archive SHA-256: ${zipHash}`);
console.log("════════════════════════════════════════════════════════════════════\n");
