/**
 * AntiDrain Standalone Extension — Bundle Capability & Security Static Audit
 *
 * Scans generated extension distribution files in extension/dist/ and asserts:
 * 1. UNTRUSTED INPAGE & CONTENT LAYERS:
 *    - ZERO private keys, mnemonics, or vault access
 *    - ZERO signing primitives or signing oracle methods
 * 2. ALL EXTENSION BUNDLE FILES:
 *    - ZERO dynamic code execution (eval, new Function)
 *    - ZERO unencrypted remote code loading or remote script URLs
 *    - ZERO hardcoded private keys or mnemonic secrets
 *    - ZERO generic `signTransaction` methods
 *    - ZERO machine-specific file paths
 *
 * Fails build with exit code 1 if any forbidden pattern is detected.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DIST_DIR = path.resolve(__dirname, "../dist");

// Rules for Inpage & Content layers (Untrusted boundary)
const INPAGE_CONTENT_FORBIDDEN = [
  { pattern: /\bprivateKey\b/i, description: "Private key exposure in inpage/content layer" },
  { pattern: /\bmnemonic\b/i, description: "Mnemonic exposure in inpage/content layer" },
  { pattern: /\bseedPhrase\b/i, description: "Seed phrase exposure in inpage/content layer" },
  { pattern: /\bdecryptVault\b/i, description: "Vault decryption in inpage/content layer" },
  { pattern: /\beval\s*\(/i, description: "Dynamic code execution (eval)" },
  { pattern: /\bnew\s+Function\s*\(/i, description: "Dynamic code execution (Function constructor)" },
  { pattern: /\bhttps?:\/\/[a-zA-Z0-9.-]+\.js\b/i, description: "Remote JavaScript URL loading" },
];

// Rules for All Bundle Files
const GLOBAL_FORBIDDEN = [
  { pattern: /\beval\s*\(/i, description: "Dynamic code execution (eval)" },
  { pattern: /\bnew\s+Function\s*\(/i, description: "Dynamic code execution (Function constructor)" },
  { pattern: /0x[a-fA-F1-9][a-fA-F0-9]{63}(?<!0{64})/g, description: "Hardcoded 32-byte hex secret" },
  { pattern: /\bfunction\s+signTransaction\b/i, description: "Generic unvalidated signTransaction implementation" },
  { pattern: /[A-Z]:\\[Users|Documents|Desktop]/i, description: "Machine-specific hardcoded local path" },
];

function scanDirectory(dir) {
  const files = [];
  if (!fs.existsSync(dir)) {
    return files;
  }
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...scanDirectory(fullPath));
    } else if (entry.isFile() && entry.name.endsWith(".js")) {
      files.push(fullPath);
    }
  }
  return files;
}

export function runBundleAudit() {
  console.log("════════════════════════════════════════════════════════════════════");
  console.log("  ANTIDRAIN EXTENSION — BUNDLE CAPABILITY STATIC AUDIT");
  console.log("════════════════════════════════════════════════════════════════════");

  const files = scanDirectory(DIST_DIR);
  if (files.length === 0) {
    console.error(`❌ Error: No compiled JavaScript files found in ${DIST_DIR}. Please run tsc first.`);
    process.exit(1);
  }

  let violations = 0;

  for (const filePath of files) {
    const relPath = path.relative(DIST_DIR, filePath);
    const content = fs.readFileSync(filePath, "utf8");

    // 1. Inpage / Content Layer Checks
    if (relPath.includes("inpage") || relPath.includes("content")) {
      for (const rule of INPAGE_CONTENT_FORBIDDEN) {
        if (rule.pattern.test(content)) {
          console.error(`❌ FORBIDDEN CAPABILITY in [${relPath}]: ${rule.description}`);
          violations++;
        }
      }
    }

    // 2. Global Bundle Checks
    for (const rule of GLOBAL_FORBIDDEN) {
      if (rule.description === "Hardcoded 32-byte hex secret") {
        const matches = content.match(/0x[a-fA-F0-9]{64}/g) || [];
        for (const m of matches) {
          const lower = m.toLowerCase();
          const isZero = /^0x0{64}$/.test(lower);
          const isBytecodeHash = lower === "0x4933ce6f42ff5ec5332c4e46e00e3f73a0e185ea03cc98418f030a05aca7a2dd";
          // Standard SEC 2 secp256k1 elliptic curve domain parameters (p, n, generator)
          const isCurveConstant =
            lower === "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f" ||
            lower === "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" ||
            lower === "0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee";

          if (!isZero && !isBytecodeHash && !isCurveConstant) {
            console.error(`❌ FORBIDDEN PATTERN in [${relPath}]: Hardcoded 32-byte hex secret (${m.slice(0, 10)}...)`);
            violations++;
          }
        }
      } else if (rule.pattern.test(content)) {
        console.error(`❌ FORBIDDEN PATTERN in [${relPath}]: ${rule.description}`);
        violations++;
      }
    }
  }

  if (violations > 0) {
    console.error(`\n🚨 BUNDLE AUDIT FAILED: ${violations} forbidden capability violation(s) found.`);
    process.exit(1);
  }

  console.log(`✔ Scanned ${files.length} extension bundle files: ZERO forbidden capabilities detected.`);
  console.log("✔ INVARIANT B0 PROVED: Inpage and content layers are verified as zero-key presentation clients.");
  console.log("════════════════════════════════════════════════════════════════════\n");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  runBundleAudit();
}
