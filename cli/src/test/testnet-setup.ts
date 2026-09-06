/**
 * Testnet Setup Script
 *
 * Generates fresh sponsor + compromised wallets, encrypts keys into vault,
 * and displays addresses for the user to fund with testnet ETH.
 *
 * SECURITY: Private keys are generated in memory, encrypted immediately
 * into the vault, and NEVER printed to console or logs.
 */

import "dotenv/config";
import { generatePrivateKey } from "viem/accounts";
import { Vault } from "../vault/vault.js";

const VAULT_PASSWORD = "testnet-rehearsal-2026";

async function main() {
  console.log("═".repeat(60));
  console.log("  TESTNET SETUP — Generating Fresh Wallets");
  console.log("═".repeat(60));
  console.log("");

  // Initialize or load vault
  const vault = Vault.exists() ? Vault.load() : Vault.create();

  // Generate sponsor wallet
  console.log("[1/2] Generating sponsor wallet...");
  const sponsorKey = generatePrivateKey();
  const sponsorAddress = vault.addWallet(
    "testnet-sponsor",
    sponsorKey,
    "sponsor",
    [84532], // Base Sepolia
    VAULT_PASSWORD,
  );
  console.log(`  ✓ Sponsor address: ${sponsorAddress}`);
  console.log("    (private key encrypted and stored in vault)");

  // Generate compromised wallet
  console.log("\n[2/2] Generating compromised wallet...");
  const compromisedKey = generatePrivateKey();
  const compromisedAddress = vault.addWallet(
    "testnet-compromised",
    compromisedKey,
    "compromised",
    [84532], // Base Sepolia
    VAULT_PASSWORD,
  );
  console.log(`  ✓ Compromised address: ${compromisedAddress}`);
  console.log("    (private key encrypted and stored in vault)");

  // Save vault
  vault.save();
  console.log(`\n  ✓ Vault saved at: ${Vault.getVaultDir()}`);

  // Display funding instructions
  console.log("\n" + "═".repeat(60));
  console.log("  ACTION REQUIRED — Send Base Sepolia testnet ETH");
  console.log("═".repeat(60));
  console.log("");
  console.log("  From your existing wallet with Base Sepolia ETH, send:");
  console.log("");
  console.log(`  1. SPONSOR wallet (pays gas):`);
  console.log(`     Address: ${sponsorAddress}`);
  console.log(`     Amount:  0.01 ETH (Base Sepolia)`);
  console.log("");
  console.log(`  2. COMPROMISED wallet (we'll rescue from this):`);
  console.log(`     Address: ${compromisedAddress}`);
  console.log(`     Amount:  0.005 ETH (Base Sepolia)`);
  console.log("");
  console.log("  Network: Base Sepolia (Chain ID 84532)");
  console.log("  ─────────────────────────────────────────────");
  console.log("  After sending, tell the agent and it will:");
  console.log("    → Deploy BatchExecutor to Base Sepolia");
  console.log("    → Run the full rescue rehearsal");
  console.log("");
  console.log(`  Vault password for this testnet session: ${VAULT_PASSWORD}`);
  console.log("  (Change this for production use)");
  console.log("");
}

main().catch((err) => {
  console.error("Setup failed:", err);
  process.exit(1);
});
