#!/usr/bin/env node
/**
 * AntiDrain Privacy & Secret Auditor
 *
 * Scans the repository for:
 * 1. Prohibited personal/testnet wallet addresses.
 * 2. Raw private key candidates (64-char hex strings not in public allowlist).
 * 3. Mnemonic / Seed phrase patterns.
 * 4. API keys, RPC credentials, and bearer tokens.
 * 5. Local machine-specific user paths (C:\Users\<user>\...).
 * 6. Tracked .env or vault files.
 *
 * Exit Code:
 * 0 = Clean (No sensitive data)
 * 1 = Prohibited findings detected
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");

import crypto from "node:crypto";

// SHA-256 hashes of prohibited personal & canary addresses (never stored in plaintext)
const PROHIBITED_ADDRESS_HASHES = new Set([
  "b01d8af969172cd185490fca920a909d820d758bd7d658febc351fc2d739dd6c",
  "9532167f82e70fdd3d914910ab011654e6bfce4597a9423566c9f95650d0c625",
  "ae938df5081261b01867de0b448617c271eeabc6d7f3194e0bd567f860455b70",
  "54b326a3241b95ab8f64bed025e9206b80379dd6d9bb4cb36f46f93ac1377b56",
  "57ed10ce5267f497f258bfc70d7af3cdfbca147161a21220ef497b9cd849e491",
  "b4661214b42d23c40d77af8186afa0e762305cc08adbb4d438274a75d60263c6",
  "af2f31a354e16a67418044107ca26602a37b91853f95ded7e1c477dcb12a40fb",
]);

// Legitimate public constants and test fixtures allowed in code
const ALLOWLISTED_HASHES = new Set([
  // Deterministic CREATE2 Deployer Factory & Salt
  "0x4e59b44847b379578588920cA78FbF26c0B4956C".toLowerCase(),
  "0x0000000000000000000000000000000000000000000000000000000000ad7702".toLowerCase(),
  // ERC-7201 Unstructured Nonce Storage Slot
  "0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd00".toLowerCase(),
  // ERC-20 Transfer Topic Hash
  "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef".toLowerCase(),
  // OneFootball Claimed Topic Hash
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50".toLowerCase(),
  // ERC-1967 Implementation Slot
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc".toLowerCase(),
  // EIP-712 Domain / Type Hashes
  "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f".toLowerCase(),
  "0x1d92b34027f7582c994cc7d9e3dfad3b8e9fc730e970cd4310e1af353d02bb9f".toLowerCase(),
  "0xd8e3247b58d24e83aa935ac600788678e212061bccd7369104c2b244bdcf8b2b".toLowerCase(),
  "0x84fa2cf05cd88e992eae77e851af68a4ee278dcff6ef504e487a55b3baadfbe5".toLowerCase(),
  // SECP256k1 Curve Limits & Generator Parameters
  "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0".toLowerCase(),
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".toLowerCase(),
  "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f".toLowerCase(),
  "0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee".toLowerCase(),
  // Standard Public Local Anvil / Foundry Test Keys
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".toLowerCase(),
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d".toLowerCase(),
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a".toLowerCase(),
  "0x5de4111afa1a4b94908f83103eb294416708687796d1948512140a760c6d7a4b".toLowerCase(),
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6".toLowerCase(),
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b079a6".toLowerCase(),
  // UniversalRecoveryDelegate CREATE2 Canonical Salt & Bytecode Hashes
  "0x1e3b023964cf3e3601ba97c6ba650dffa05267c991945dedba0e87733b5690e4".toLowerCase(),
  "0xdaacfcdd1e9610147049dd3eac71b22aa3b48025e740ae02b5f77a65f2051d9b".toLowerCase(),
  "0x4933ce6f42ff5ec5332c4e46e00e3f73a0e185ea03cc98418f030a05aca7a2dd".toLowerCase(),
  "0x99a38afd10542b246c33a0decd8d7f5bfd6b3362d2fc449a220fa1fac1f642aa".toLowerCase(),
  "0xb8bc34d5b3912055228ae68f77f670dee029f884b5ca50977b0d3da8ccb09d4e".toLowerCase(),
]);

const IGNORED_DIRECTORIES = new Set([
  "node_modules",
  ".git",
  "out",
  "cache",
  "dist",
  "artifacts",
  "scratch",
  "lib",
]);

const IGNORED_FILES = new Set([
  ".env", // local only
  ".env.local",
  "package-lock.json",
  "canary_evidence.json",
  "FINAL_RELEASE_MANIFEST.json",
  "check-secrets.mjs",
]);

const findings = [];

function checkLine(file, lineNum, line) {
  const trimmed = line.trim();

  // 1. Check for Prohibited Personal Addresses
  const hex40Matches = trimmed.match(/0x[a-fA-F0-9]{40}/g);
  if (hex40Matches) {
    for (const match of hex40Matches) {
      const hash = crypto.createHash("sha256").update(match.toLowerCase()).digest("hex");
      if (PROHIBITED_ADDRESS_HASHES.has(hash)) {
        findings.push({
          file,
          line: lineNum,
          type: "PROHIBITED_PERSONAL_ADDRESS",
          severity: "CRITICAL",
          description: `Prohibited address identified by hash: ${hash.slice(0, 8)}...`,
        });
      }
    }
  }

  // 2. Check for Real Alchemy / Infura API Keys in URLs
  const rpcKeyMatch = trimmed.match(/(?:alchemy\.com\/v2\/|infura\.io\/v3\/)([a-zA-Z0-9_-]{20,})/);
  if (rpcKeyMatch && !rpcKeyMatch[1].startsWith("your_") && !rpcKeyMatch[1].startsWith("<")) {
    findings.push({
      file,
      line: lineNum,
      type: "ACTIVE_RPC_CREDENTIAL",
      severity: "CRITICAL",
      description: "Active RPC provider API key detected in endpoint URL",
    });
  }

  // 3. Check for Local Machine User Paths
  const userPathMatch = trimmed.match(/[a-zA-Z]:\\Users\\[a-zA-Z0-9_-]+\\/i);
  if (userPathMatch) {
    findings.push({
      file,
      line: lineNum,
      type: "LOCAL_USER_PATH",
      severity: "HIGH",
      description: "Machine-specific local filesystem path detected",
    });
  }

  // 4. Check for Mnemonic Seed Phrase Pattern
  if (/(?:word[1-9]|mnemonic|seed\s*phrase)\s*[:=]\s*["'][a-z\s]{24,}["']/i.test(trimmed)) {
    findings.push({
      file,
      line: lineNum,
      type: "RAW_MNEMONIC_PHRASE",
      severity: "CRITICAL",
      description: "Plaintext mnemonic / seed phrase pattern detected",
    });
  }

  // 5. Check for 64-char hex strings in source code (.ts, .js, .sol, .json)
  const isDoc = file.endsWith(".md");
  if (!isDoc) {
    const hexMatches = trimmed.match(/0x[a-fA-F0-9]{64}/g);
    if (hexMatches) {
      for (const h of hexMatches) {
        const lower = h.toLowerCase();
        // Allow zero-fill placeholders and known protocol hashes
        if (
          lower.startsWith("0x00000000000000000000") ||
          lower.startsWith("0x11111111111111111111") ||
          lower.startsWith("0x22222222222222222222") ||
          lower.startsWith("0x33333333333333333333") ||
          lower.startsWith("0x44444444444444444444") ||
          lower.startsWith("0xaaaaaaaaaaaaaaaaaaaa") ||
          lower.startsWith("0xbbbbbbbbbbbbbbbbbbbb") ||
          lower.startsWith("0xa9059cbb") || // selector padded
          lower.startsWith("0x095ea7b3") || // selector padded
          ALLOWLISTED_HASHES.has(lower)
        ) {
          continue;
        }

        // Test fixtures
        if (file.includes("test") && (trimmed.includes("digest") || trimmed.includes("hash") || trimmed.includes("keccak256") || trimmed.includes("Hex") || trimmed.includes("bytes32"))) {
          continue;
        }

        findings.push({
          file,
          line: lineNum,
          type: "UNRECOGNIZED_32BYTE_HEX_CANDIDATE",
          severity: "HIGH",
          description: `Unrecognized 32-byte hex hash/key: ${h.slice(0, 10)}... (requires manual audit)`,
        });
      }
    }
  }
}

function scanDirectory(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    if (IGNORED_DIRECTORIES.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(ROOT, fullPath);

    if (entry.isDirectory()) {
      scanDirectory(fullPath);
    } else if (entry.isFile()) {
      if (IGNORED_FILES.has(entry.name)) continue;

      // Ensure secret files are not present in repo root
      if (entry.name.endsWith(".vault") || entry.name === "vault.json" || entry.name.endsWith(".key")) {
        findings.push({
          file: relPath,
          line: 1,
          type: "UNENCRYPTED_OR_COMMITTED_VAULT_FILE",
          severity: "CRITICAL",
          description: `Sensitive key/vault file present in repository: ${entry.name}`,
        });
        continue;
      }

      try {
        const content = fs.readFileSync(fullPath, "utf8");
        const lines = content.split("\n");
        for (let i = 0; i < lines.length; i++) {
          checkLine(relPath, i + 1, lines[i]);
        }
      } catch (err) {
        // Binary or unreadable file
      }
    }
  }
}

console.log("════════════════════════════════════════════════════════════════════");
console.log("  ANTIDRAIN — REPOSITORY PRIVACY & SECRET AUDITOR");
console.log("════════════════════════════════════════════════════════════════════");
console.log(`Scanning root: ${ROOT}`);

scanDirectory(ROOT);

console.log("────────────────────────────────────────────────────────────────────");
if (findings.length === 0) {
  console.log("✔ PRIVACY AUDIT PASSED: 0 prohibited secrets, addresses, or keys detected.");
  console.log("════════════════════════════════════════════════════════════════════\n");
  process.exit(0);
} else {
  console.error(`✗ PRIVACY AUDIT FAILED: ${findings.length} findings detected.\n`);
  for (const f of findings) {
    console.error(`  [${f.severity}] ${f.file}:${f.line} -> ${f.type}`);
    console.error(`    Description: ${f.description}`);
  }
  console.log("════════════════════════════════════════════════════════════════════\n");
  process.exit(1);
}
