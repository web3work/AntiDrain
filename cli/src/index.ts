#!/usr/bin/env node

// Load .env file for ALCHEMY_API_KEY (must be before any chain config imports)
import "dotenv/config";

/**
 * AntiDrain Wallet Rescue CLI
 *
 * A personal tool for rescuing assets from compromised wallets
 * using EIP-7702 sponsored delegation.
 *
 * Commands:
 *   vault init          Initialize encrypted key vault
 *   vault add           Add a wallet (compromised or sponsor)
 *   vault list          List stored wallets (no key material shown)
 *   vault remove        Remove a wallet
 *   sponsor check       Check sponsor balances across chains
 *   rescue              Execute a rescue operation
 *   audit               View encrypted audit log
 *
 * HARD CONSTRAINTS (Project Security Rules):
 */

import { Command } from "commander";
import { createInterface } from "node:readline";
import type { Hex, Address } from "viem";
import { isAddress } from "viem";
import { Vault } from "./vault/vault.js";
import { checkAllSponsorBalances } from "./sponsor/manager.js";
import { executeRescue } from "./rescue/orchestrator.js";
import { scanAllChains } from "./scan/scanner.js";
import { AntiDrainBridgeProvider } from "./bridge/provider.js";
import { BridgeCoordinator } from "./bridge/coordinator.js";
import { startBridgeServer } from "./bridge/server.js";
import { createPublicClient, http, getAddress, formatEther } from "viem";
import {
  SUPPORTED_CHAINS,
  getSupportedChainIds,
  CHAIN_PRIORITY_ORDER,
  getChainConfig,
} from "./config/chains.js";
import type { RescuePlan, RescueCall } from "./config/types.js";
import {
  fetchOneFootballEligibility,
  fetchOneFootballVoucher,
  validateOneFootballPreconditions,
  buildOneFootballRescuePlan,
  ONEFOOTBALL_CHAIN_ID,
  type OneFootballVoucher,
} from "./airdrop/onefootball.js";
import fs from "node:fs";

// ─── Helper: Prompt for password (no echo) ─────────────────────────────

async function promptPassword(message: string): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    // Note: This doesn't hide input in basic terminals.
    // For production, use a library like 'read' that supports silent input.
    rl.question(`${message}: `, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

async function promptInput(message: string): Promise<string> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise((resolve) => {
    rl.question(`${message}: `, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

// ─── CLI Program ───────────────────────────────────────────────────────

const program = new Command();

program
  .name("antidrain")
  .description("EIP-7702 wallet rescue CLI — claim airdrops and sweep assets from compromised wallets")
  .version("0.1.0");

// ─── Vault Commands ────────────────────────────────────────────────────

const vault = program.command("vault").description("Manage encrypted key vault");

vault
  .command("init")
  .description("Initialize a new encrypted key vault")
  .action(async () => {
    if (Vault.exists()) {
      console.log(`Vault already exists at ${Vault.getVaultDir()}`);
      console.log("Use 'vault add' to add wallets.");
      return;
    }
    const v = Vault.create();
    v.save();
    console.log(`✓ Vault initialized at ${Vault.getVaultDir()}`);
    console.log("Use 'antidrain vault add' to add compromised and sponsor wallets.");
  });

vault
  .command("add")
  .description("Add a wallet to the vault")
  .action(async () => {
    const v = Vault.exists() ? Vault.load() : Vault.create();
    const password = await promptPassword("Vault password");

    const name = await promptInput("Wallet name (e.g., 'my-compromised-1', 'gas-sponsor')");
    const role = await promptInput("Role (compromised/sponsor)");
    if (role !== "compromised" && role !== "sponsor") {
      console.error("Role must be 'compromised' or 'sponsor'");
      return;
    }

    console.log("\n⚠  SECURITY: Your private key will be encrypted immediately.");
    console.log("   It will NOT be logged, printed, or stored in plaintext anywhere.\n");
    const privateKey = await promptInput("Private key (0x-prefixed hex)");

    if (!privateKey.startsWith("0x") || privateKey.length !== 66) {
      console.error("Invalid private key format. Must be 0x followed by 64 hex characters.");
      return;
    }

    const chainsInput = await promptInput(
      `Chain IDs (comma-separated, supported: ${getSupportedChainIds().join(",")})`
    );
    const chains = chainsInput.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));

    try {
      const address = v.addWallet(name, privateKey as Hex, role, chains, password);
      v.save();
      console.log(`\n✓ Wallet "${name}" added`);
      console.log(`  Address: ${address}`);
      console.log(`  Role: ${role}`);
      console.log(`  Chains: ${chains.join(", ")}`);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
    }
  });

vault
  .command("list")
  .description("List all wallets in the vault (no key material shown)")
  .action(() => {
    if (!Vault.exists()) {
      console.log("No vault found. Run 'antidrain vault init' first.");
      return;
    }
    const v = Vault.load();
    const wallets = v.listWallets();

    if (wallets.length === 0) {
      console.log("Vault is empty. Use 'antidrain vault add' to add wallets.");
      return;
    }

    console.log("\n  Stored Wallets:");
    console.log("  " + "─".repeat(70));
    for (const w of wallets) {
      const chainNames = w.chains
        .map((id) => SUPPORTED_CHAINS[id]?.name ?? `Chain ${id}`)
        .join(", ");
      console.log(`  ${w.name}`);
      console.log(`    Address: ${w.address}`);
      console.log(`    Role:    ${w.role}`);
      console.log(`    Chains:  ${chainNames}`);
      console.log("");
    }
  });

vault
  .command("remove")
  .description("Remove a wallet from the vault")
  .argument("<name>", "Wallet name to remove")
  .action((name: string) => {
    if (!Vault.exists()) {
      console.log("No vault found.");
      return;
    }
    const v = Vault.load();
    const entry = v.getWalletEntry(name);
    if (!entry) {
      console.error(`Wallet "${name}" not found.`);
      return;
    }
    v.removeWallet(name);
    v.save();
    console.log(`✓ Wallet "${name}" (${entry.address}) removed.`);
  });

// ─── Sponsor Commands ──────────────────────────────────────────────────

const sponsor = program.command("sponsor").description("Manage sponsor wallet");

sponsor
  .command("check")
  .description("Check sponsor wallet balances across all chains")
  .action(async () => {
    if (!Vault.exists()) {
      console.log("No vault found. Run 'antidrain vault init' first.");
      return;
    }
    const v = Vault.load();
    const sponsors = v.getWalletsByRole("sponsor");

    if (sponsors.length === 0) {
      console.log("No sponsor wallets in vault. Add one with 'antidrain vault add'.");
      return;
    }

    for (const s of sponsors) {
      console.log(`\n  Sponsor: ${s.name} (${s.address})`);
      console.log("  " + "─".repeat(50));

      const balances = await checkAllSponsorBalances(s.address, s.chains);
      for (const b of balances) {
        const icon = b.sufficient ? "✓" : "✗";
        console.log(`  ${icon} ${b.chainName}: ${b.balanceFormatted}`);
      }
    }
  });

// ─── Scan Command ───────────────────────────────────────────────────────

program
  .command("scan [address]")
  .description("Scan an address across all chains to discover assets, balances, and delegation state")
  .action(async (addressArg?: string) => {
    let targetAddress: Address;
    if (addressArg) {
      if (!isAddress(addressArg)) {
        console.error("Invalid Ethereum address.");
        return;
      }
      targetAddress = addressArg as Address;
    } else {
      if (!Vault.exists()) {
        const addr = await promptInput("Enter compromised wallet address (0x...)");
        if (!isAddress(addr)) {
          console.error("Invalid Ethereum address.");
          return;
        }
        targetAddress = addr as Address;
      } else {
        const v = Vault.load();
        const wallets = v.listWallets();
        if (wallets.length === 0) {
          const addr = await promptInput("Enter wallet address to scan (0x...)");
          if (!isAddress(addr)) {
            console.error("Invalid Ethereum address.");
            return;
          }
          targetAddress = addr as Address;
        } else {
          console.log("\nWallets in vault:");
          wallets.forEach((w, i) => console.log(`  ${i + 1}. ${w.name} (${w.address}) [${w.role}]`));
          console.log(`  ${wallets.length + 1}. Enter custom address`);
          const choice = parseInt(await promptInput("Select wallet or custom"), 10) - 1;
          if (choice >= 0 && choice < wallets.length) {
            targetAddress = wallets[choice].address as Address;
          } else {
            const addr = await promptInput("Enter wallet address to scan (0x...)");
            if (!isAddress(addr)) {
              console.error("Invalid Ethereum address.");
              return;
            }
            targetAddress = addr as Address;
          }
        }
      }
    }

    console.log(`\n🔍 Scanning multi-chain assets for ${targetAddress}...`);
    console.log("═".repeat(70));

    const results = await scanAllChains(targetAddress);

    let totalDiscoveredAssets = 0;

    for (const r of results) {
      const isPositiveNative = r.nativeBalance > 0n;
      const hasTokens = r.tokens.length > 0;
      const statusIcon = isPositiveNative || hasTokens ? "🟢" : "⚪";

      console.log(`\n${statusIcon} ${r.chainName} (Chain ID: ${r.chainId})`);
      console.log(`   • Nonce: ${r.accountNonce} | Delegated Code: ${r.isDelegated ? "⚠️ ACTIVE (" + r.delegatedCode.slice(0, 10) + "...)" : "Pure EOA (0x)"}`);
      console.log(`   • Native Balance: ${r.formattedNative} ${r.nativeSymbol}`);

      if (isPositiveNative) totalDiscoveredAssets++;

      if (r.tokens.length > 0) {
        console.log("   • ERC-20 Tokens Discovered:");
        for (const t of r.tokens) {
          console.log(`     - ${t.symbol}: ${t.formatted} (${t.address})`);
          totalDiscoveredAssets++;
        }
      }

      if (r.error) {
        console.log(`   ⚠ RPC Note: ${r.error}`);
      }
    }

    console.log("\n" + "═".repeat(70));
    console.log(`✓ Scan complete. Total recoverable asset positions identified: ${totalDiscoveredAssets}`);
    if (totalDiscoveredAssets > 0) {
      console.log("Run 'antidrain rescue' to execute a sponsored recovery of these assets.");
    }
  });

// ─── Bridge Command ────────────────────────────────────────────────────

program
  .command("bridge")
  .description("Start Web3 Claim Interceptor Bridge for 1-click airdrop claims")
  .option("--victim <address>", "Compromised victim wallet address")
  .option("--safe <address>", "Safe destination wallet address")
  .option("--chain <chainId>", "Target chain ID (default: 8453 for Base)", "8453")
  .option("--port <number>", "Local RPC server port (default: 8545)", "8545")
  .action(async (options) => {
    let victimAddress: Address;
    let safeAddress: Address;

    if (options.victim && isAddress(options.victim)) {
      victimAddress = getAddress(options.victim);
    } else {
      const addr = await promptInput("Enter compromised wallet address (0x...)");
      if (!isAddress(addr)) {
        console.error("Invalid Ethereum address.");
        return;
      }
      victimAddress = getAddress(addr);
    }

    if (options.safe && isAddress(options.safe)) {
      safeAddress = getAddress(options.safe);
    } else {
      const addr = await promptInput("Enter safe destination address (0x...)");
      if (!isAddress(addr)) {
        console.error("Invalid Ethereum address.");
        return;
      }
      safeAddress = getAddress(addr);
    }

    const chainId = parseInt(options.chain, 10);
    const port = parseInt(options.port, 10);
    const chainConfig = getChainConfig(chainId);

    const publicClient = createPublicClient({
      transport: http(chainConfig.rpcUrl),
    });

    console.log("\n" + "═".repeat(70));
    console.log("  🔌 AntiDrain Web3 Claim Interceptor Bridge");
    console.log("═".repeat(70));
    console.log(`  • Bound Victim:       ${victimAddress}`);
    console.log(`  • Destination Safe:   ${safeAddress}`);
    console.log(`  • Target Chain:       ${chainConfig.name} (Chain ID: ${chainId})`);
    console.log(`  • Signing Oracle:     🚫 STRICTLY DISABLED (personal_sign/signTypedData blocked)`);
    console.log(`  • Concurrency Guard:  🟢 1 Active Rescue per Victim Enforced`);

    const coordinator = new BridgeCoordinator({
      configuredVictim: victimAddress,
      safeWallet: safeAddress,
      chainId,
      publicClient,
      requireHumanConfirmation: true,
      onHumanConfirmationPrompt: async (plan) => {
        console.log("\n" + "─".repeat(70));
        console.log("  ⚡ INTERCEPTED CLAIM DETECTED BY ANTIDRAIN BRIDGE");
        console.log("─".repeat(70));
        console.log(`  • Operation Type:      ${plan.classification.type}`);
        console.log(`  • Function Selector:   ${plan.classification.selector}`);
        console.log(`  • Claim Target:        ${plan.calls[0]?.target}`);
        console.log(`  • Required Native Fee: ${plan.requiredNativeValue.toString()} Wei`);
        console.log(`  • Request Hash:        ${plan.sourceRequestHash.slice(0, 18)}...`);

        if (plan.classification.hazardWarnings.length > 0) {
          console.log("\n  ⚠ Hazard Warnings:");
          plan.classification.hazardWarnings.forEach((w) => console.log(`    - ${w}`));
        }

        const ans = await promptInput("\nType 'CONFIRM' to execute sponsored recovery to safe wallet");
        return ans.trim().toUpperCase() === "CONFIRM";
      },
    });

    const provider = new AntiDrainBridgeProvider({
      configuredVictim: victimAddress,
      configuredChainId: chainId,
      publicClient,
      onTransactionSubmit: async (claim) => {
        return await coordinator.handleClaim(claim);
      },
    });

    const running = await startBridgeServer({
      provider,
      port,
    });

    console.log(`\n  🟢 Local RPC Bridge active at http://${running.host}:${running.port}`);
    console.log("  👉 Connect your browser wallet (Rabby/MetaMask) to http://127.0.0.1:8545 and click 'Claim' on the dApp.");
    console.log("  Press Ctrl+C to stop bridge server.\n");
  });

// ─── Rescue Command ────────────────────────────────────────────────────

program
  .command("rescue")
  .description("Execute a rescue operation (interactive)")
  .action(async () => {
    if (!Vault.exists()) {
      console.log("No vault found. Run 'antidrain vault init' first.");
      return;
    }

    const v = Vault.load();
    const compromised = v.getWalletsByRole("compromised");
    const sponsors = v.getWalletsByRole("sponsor");

    if (compromised.length === 0) {
      console.error("No compromised wallets in vault.");
      return;
    }
    if (sponsors.length === 0) {
      console.error("No sponsor wallets in vault.");
      return;
    }

    // Select compromised wallet
    console.log("\nCompromised wallets:");
    compromised.forEach((w, i) => console.log(`  ${i + 1}. ${w.name} (${w.address})`));
    const compIdx = parseInt(await promptInput("Select compromised wallet number"), 10) - 1;
    const compWallet = compromised[compIdx];
    if (!compWallet) { console.error("Invalid selection."); return; }

    // Select sponsor wallet
    console.log("\nSponsor wallets:");
    sponsors.forEach((w, i) => console.log(`  ${i + 1}. ${w.name} (${w.address})`));
    const sponsorIdx = parseInt(await promptInput("Select sponsor wallet number"), 10) - 1;
    const sponsorWallet = sponsors[sponsorIdx];
    if (!sponsorWallet) { console.error("Invalid selection."); return; }

    // Select chain
    console.log("\nSupported chains (priority order):");
    CHAIN_PRIORITY_ORDER.forEach((id, i) => {
      const c = SUPPORTED_CHAINS[id];
      if (c) console.log(`  ${i + 1}. ${c.name} (${id}) — gas: ${c.nativeToken.symbol}`);
    });
    const chainIdx = parseInt(await promptInput("Select chain number"), 10) - 1;
    const chainId = CHAIN_PRIORITY_ORDER[chainIdx];
    if (!chainId || !SUPPORTED_CHAINS[chainId]) { console.error("Invalid chain."); return; }

    // Safe wallet address (user provides any address)
    const safeWalletInput = await promptInput("Safe destination wallet address (0x...)");
    if (!isAddress(safeWalletInput)) {
      console.error("Invalid Ethereum address.");
      return;
    }
    const safeWallet = safeWalletInput as Address;

    // Token addresses to sweep
    const tokensInput = await promptInput(
      "ERC-20 token addresses to sweep (comma-separated, or 'none')"
    );
    const tokens: Address[] =
      tokensInput.toLowerCase() === "none"
        ? []
        : tokensInput.split(",").map((s) => s.trim() as Address).filter((s) => isAddress(s));

    // Custom calls (claims, unstakes)
    const callsInput = await promptInput(
      "Custom calls JSON array (or 'none' for sweep-only)"
    );
    let calls: RescueCall[] = [];
    if (callsInput.toLowerCase() !== "none") {
      try {
        calls = JSON.parse(callsInput);
      } catch {
        console.error("Invalid JSON for calls. Use format: [{\"target\":\"0x...\",\"value\":\"0\",\"data\":\"0x...\"}]");
        return;
      }
    }

    // Build plan
    const plan: RescuePlan = {
      chainId,
      compromisedAddress: compWallet.address,
      safeWallet,
      sponsorAddress: sponsorWallet.address,
      calls: calls.map(c => ({
        ...c,
        value: BigInt(c.value),
      })),
      tokens,
    };

    // Get password and decrypt accounts
    const password = await promptPassword("\nVault password to decrypt keys");
    const compAccount = v.getAccount(compWallet.name, password);
    const sponsorAccount = v.getAccount(sponsorWallet.name, password);

    // Execute rescue (simulation + confirmation + broadcast + revocation)
    const result = await executeRescue(plan, compAccount, sponsorAccount);

    if (result.success) {
      console.log("\n🎉 Rescue operation completed successfully!");
    } else {
      console.error(`\n❌ Rescue failed: ${result.error}`);
    }
  });

// ─── Dedicated Airdrop Claim Rescue Command ────────────────────────────

program
  .command("airdrop")
  .description("Execute an atomic airdrop claim + sweep rescue operation")
  .action(async () => {
    if (!Vault.exists()) {
      console.log("No vault found. Run 'antidrain vault init' first.");
      return;
    }

    const v = Vault.load();
    const compromised = v.getWalletsByRole("compromised");
    const sponsors = v.getWalletsByRole("sponsor");

    if (compromised.length === 0) {
      console.error("No compromised wallets in vault. Add one with 'antidrain vault add'.");
      return;
    }
    if (sponsors.length === 0) {
      console.error("No sponsor wallets in vault. Add one with 'antidrain vault add'.");
      return;
    }

    // 1. Select compromised wallet
    console.log("\nCompromised wallets in vault:");
    compromised.forEach((w, i) => console.log(`  ${i + 1}. ${w.name} (${w.address})`));
    const compIdx = parseInt(await promptInput("Select compromised wallet number"), 10) - 1;
    const compWallet = compromised[compIdx];
    if (!compWallet) { console.error("Invalid selection."); return; }

    // 2. Select sponsor wallet
    console.log("\nSponsor wallets in vault (pays gas):");
    sponsors.forEach((w, i) => console.log(`  ${i + 1}. ${w.name} (${w.address})`));
    const sponsorIdx = parseInt(await promptInput("Select sponsor wallet number"), 10) - 1;
    const sponsorWallet = sponsors[sponsorIdx];
    if (!sponsorWallet) { console.error("Invalid selection."); return; }

    // 3. Select chain
    console.log("\nSupported chains:");
    CHAIN_PRIORITY_ORDER.forEach((id, i) => {
      const c = SUPPORTED_CHAINS[id];
      if (c) console.log(`  ${i + 1}. ${c.name} (${id})`);
    });
    const chainIdx = parseInt(await promptInput("Select chain number (e.g. 3 for Base)"), 10) - 1;
    const chainId = CHAIN_PRIORITY_ORDER[chainIdx];
    if (!chainId || !SUPPORTED_CHAINS[chainId]) { console.error("Invalid chain."); return; }

    // 4. Safe destination wallet
    const safeWalletInput = await promptInput("Safe destination wallet address (0x...)");
    if (!isAddress(safeWalletInput)) {
      console.error("Invalid Ethereum address.");
      return;
    }
    const safeWallet = safeWalletInput as Address;

    // 5. Airdrop Distributor contract address
    const targetInput = await promptInput("Airdrop distributor contract address (0x...)");
    if (!isAddress(targetInput)) {
      console.error("Invalid distributor address.");
      return;
    }
    const target = targetInput as Address;

    // 6. Claim token address
    const tokenInput = await promptInput("Claim token address to sweep (0x...)");
    if (!isAddress(tokenInput)) {
      console.error("Invalid token address.");
      return;
    }
    const token = tokenInput as Address;

    // 7. Claim Calldata (hex)
    const calldataInput = await promptInput("Claim Calldata hex (0x...)");
    if (!calldataInput.startsWith("0x") || calldataInput.length < 10) {
      console.error("Invalid calldata hex.");
      return;
    }
    const data = calldataInput as Hex;

    // Build structured plan
    const plan: RescuePlan = {
      chainId,
      compromisedAddress: compWallet.address,
      safeWallet,
      sponsorAddress: sponsorWallet.address,
      calls: [
        {
          target,
          value: 0n,
          data,
        },
      ],
      tokens: [token],
    };

    // Get password and decrypt accounts
    const password = await promptPassword("\nVault password to decrypt keys");
    const compAccount = v.getAccount(compWallet.name, password);
    const sponsorAccount = v.getAccount(sponsorWallet.name, password);

    // Execute rescue (simulation + confirmation + broadcast + revocation)
    const result = await executeRescue(plan, compAccount, sponsorAccount);

    if (result.success) {
      console.log("\n🎉 Airdrop Claim & Rescue operation completed successfully!");
    } else {
      console.error(`\n❌ Airdrop Claim Rescue failed: ${result.error}`);
    }
  });

// ─── Dedicated OneFootball OFC Claim & Rescue Command (Path A) ───────────

program
  .command("rescue-onefootball")
  .description("Execute an atomic OneFootball OFC claim and sweep rescue on Base (Path A, Zero Victim ETH)")
  .option("--victim <address>", "Compromised victim wallet address")
  .option("--sponsor <address>", "Sponsor wallet address to pay gas and fee")
  .option("--safe <address>", "Safe destination wallet address")
  .option("--month <number>", "Vesting month to claim (e.g. 4)", "4")
  .option("--voucher <path>", "Path to JSON file containing OneFootball claim voucher")
  .option("--token <bearerToken>", "OneFootball API Bearer token to fetch voucher directly")
  .option("--contract <address>", "Distributor contract address override (optional)")
  .option("--signer <address>", "Authorized backend signer address override (optional)")
  .option("--token-address <address>", "Claimed token address override (optional)")
  .option("--rpc <url>", "Base RPC endpoint URL override (optional)")
  .action(async (opts) => {
    if (!Vault.exists()) {
      console.log("No vault found. Run 'antidrain vault init' first.");
      return;
    }

    const v = Vault.load();
    const compromised = v.getWalletsByRole("compromised");
    const sponsors = v.getWalletsByRole("sponsor");

    if (compromised.length === 0) {
      console.error("No compromised wallets in vault. Add one with 'antidrain vault add'.");
      return;
    }
    if (sponsors.length === 0) {
      console.error("No sponsor wallets in vault. Add one with 'antidrain vault add'.");
      return;
    }

    // 1. Resolve compromised wallet
    let compWallet = opts.victim
      ? compromised.find((w) => w.address.toLowerCase() === opts.victim.toLowerCase())
      : undefined;
    if (!compWallet) {
      console.log("\nCompromised wallets in vault:");
      compromised.forEach((w, i) => console.log(`  ${i + 1}. ${w.name} (${w.address})`));
      const compIdx = parseInt(await promptInput("Select compromised wallet number"), 10) - 1;
      compWallet = compromised[compIdx];
      if (!compWallet) { console.error("Invalid selection."); return; }
    }
    const victimAddress = compWallet.address;

    // 2. Resolve sponsor wallet
    let sponsorWallet = opts.sponsor
      ? sponsors.find((w) => w.address.toLowerCase() === opts.sponsor.toLowerCase())
      : undefined;
    if (!sponsorWallet) {
      console.log("\nSponsor wallets in vault (pays gas + claim fee):");
      sponsors.forEach((w, i) => console.log(`  ${i + 1}. ${w.name} (${w.address})`));
      const sponsorIdx = parseInt(await promptInput("Select sponsor wallet number"), 10) - 1;
      sponsorWallet = sponsors[sponsorIdx];
      if (!sponsorWallet) { console.error("Invalid selection."); return; }
    }

    // 3. Safe destination wallet
    let safeWallet = opts.safe;
    if (!safeWallet || !isAddress(safeWallet)) {
      const input = await promptInput("Safe destination wallet address (0x...)");
      if (!isAddress(input)) {
        console.error("Invalid Ethereum address.");
        return;
      }
      safeWallet = input as Address;
    }

    // 4. Query live eligibility from OneFootball backend
    console.log(`\n[1/4] Checking OneFootball eligibility for ${victimAddress}...`);
    try {
      const eligibility = await fetchOneFootballEligibility(victimAddress);
      console.log(`  ✓ Eligible:        ${eligibility.eligible}`);
      console.log(`  ✓ Total Claimed:   ${(BigInt(eligibility.totalClaimed) / 10n**18n).toString()} OFC`);
      console.log(`  ✓ Available Now:   ${(BigInt(eligibility.available) / 10n**18n).toString()} OFC`);
      if (eligibility.schedule?.claimInfo) {
        const targetMonth = parseInt(opts.month, 10);
        const monthInfo = eligibility.schedule.claimInfo.find((m) => m.month === targetMonth);
        if (monthInfo) {
          console.log(`  ✓ Month ${targetMonth} Status: ${monthInfo.status.toUpperCase()} (${monthInfo.amount} OFC)`);
        }
      }
    } catch (err) {
      console.log(`  ⚠ Notice: Could not fetch eligibility API (${err instanceof Error ? err.message : String(err)})`);
    }

    // 5. Obtain Voucher
    let voucher: OneFootballVoucher;
    if (opts.voucher) {
      console.log(`\n[2/4] Reading voucher from file: ${opts.voucher}`);
      const raw = fs.readFileSync(opts.voucher, "utf8");
      voucher = JSON.parse(raw);
    } else if (opts.token) {
      console.log(`\n[2/4] Fetching voucher for month ${opts.month} from OneFootball API...`);
      voucher = await fetchOneFootballVoucher(victimAddress, parseInt(opts.month, 10), opts.token);
    } else {
      console.log("\n[2/4] OneFootball Claim Voucher Required:");
      console.log("  1. Paste JSON voucher directly");
      console.log("  2. Provide OneFootball Bearer Token");
      const choice = await promptInput("Select option (1 or 2)");
      if (choice === "2") {
        const token = await promptPassword("OneFootball Bearer Token");
        const monthNum = parseInt(await promptInput("Vesting Month to claim (e.g. 4)"), 10);
        voucher = await fetchOneFootballVoucher(victimAddress, monthNum, token);
      } else {
        const rawJson = await promptInput("Paste voucher JSON payload");
        voucher = JSON.parse(rawJson);
      }
    }

    // 6. Connect to Base Mainnet & Execute 11-point Precondition Validation
    console.log("\n[3/4] Executing 11-point security verification on Base Mainnet...");
    const baseConfig = getChainConfig(ONEFOOTBALL_CHAIN_ID);
    const rpcEndpoint = opts.rpc || baseConfig.rpcUrl;
    const client = createPublicClient({
      chain: (await import("viem/chains")).base,
      transport: http(rpcEndpoint),
    });

    const validation = await validateOneFootballPreconditions(
      client as any,
      voucher,
      victimAddress,
      safeWallet,
      {
        expectedContract: opts.contract,
        expectedSigner: opts.signer,
        tokenAddress: opts.tokenAddress,
      },
    );

    if (!validation.valid) {
      console.error("\n❌ PRECONDITION CHECKS FAILED:");
      validation.errors.forEach((e) => console.error(`  - ${e}`));
      return;
    }

    console.log("  ✓ Check 1: Voucher integrity & required fields verified");
    console.log(`  ✓ Check 2: Claimant matches victim EOA (${victimAddress})`);
    console.log(`  ✓ Check 3: Claim amount verified: ${formatEther(validation.amount)} OFC`);
    console.log(`  ✓ Check 4: Deadline verified unexpired (${new Date(Number(validation.deadline) * 1000).toISOString()})`);
    console.log(`  ✓ Check 5: Claim contract verified on-chain: ${validation.call.target}`);
    console.log("  ✓ Check 6: Claim nonce & unspent state verified on-chain");
    console.log("  ✓ Check 7: Contract authorizedSigner verified active on-chain");
    console.log(`  ✓ Check 8: Live dynamic fee queried: ${validation.claimFeeWei.toString()} wei (~0.0008 ETH)`);
    console.log("  ✓ Check 9: Exact claim calldata (0x5eddd157) verified");
    console.log("  ✓ Check 10: Exact value accounting enforced (msg.value == call.value == exact fee)");
    console.log("  ✓ Check 11: Direct claim simulation on Base RPC succeeded");

    // 7. Build deterministic rescue plan
    const plan = buildOneFootballRescuePlan(
      victimAddress,
      sponsorWallet.address,
      safeWallet,
      validation,
      opts.tokenAddress,
    );
    if (opts.rpc) {
      plan.rpcUrl = opts.rpc;
    }

    // 8. Decrypt keys and run orchestrator
    console.log("\n[4/4] Decrypting keys and launching sponsored rescue pipeline...");
    const password = await promptPassword("Vault password to decrypt keys");
    const compAccount = v.getAccount(compWallet.name, password);
    const sponsorAccount = v.getAccount(sponsorWallet.name, password);

    const result = await executeRescue(plan, compAccount, sponsorAccount);

    if (result.success) {
      console.log("\n🎉 ONEFOOTBALL RESCUE OPERATION EXECUTED!");
      console.log(`  ✓ Claimed: ${formatEther(validation.amount)} OFC directly to safe wallet: ${safeWallet}`);
      console.log(`  ✓ Victim residual ETH: 0 (No funding stranded)`);
      if (result.finalAccountCodeClean) {
        console.log(`  ✓ Delegation verified REVOKED via sponsored follow-up transaction (Code: 0x)`);
      } else {
        console.warn(`  ⚠ NOTICE: Delegation revocation status: ${result.revocationStatus || "UNKNOWN"}`);
        console.warn(`  ⚠ STATUS: CLEANUP_REQUIRED — The victim account remains delegated until revoked.`);
      }
    } else {
      console.error(`\n❌ OneFootball Rescue failed: ${result.error}`);
      if (result.revocationStatus === "CLEANUP_REQUIRED") {
        console.error(`  🚨 STATUS: CLEANUP_REQUIRED — Delegation persisted on-chain.`);
      }
    }
  });

// ─── Audit Command ─────────────────────────────────────────────────────

// ─── Host Commands (Windows Native Messaging) ───────────────────────────

const hostCmd = program.command("host").description("Manage Chrome/Brave Native Messaging Host");

hostCmd
  .command("register")
  .description("Register Native Messaging host in Windows Registry for Chrome and Brave")
  .option("--extension-id <id>", "Extension ID to allow", "acmacodkjbdgmoleebolmdjonilkdbch")
  .action(async (opts) => {
    const { generateHostManifest, writeHostManifest, registerHostInWindowsRegistry } = await import("./daemon/installHost.js");
    const manifest = generateHostManifest([opts.extensionId]);
    const manifestPath = writeHostManifest(manifest);
    const regResult = registerHostInWindowsRegistry(manifestPath);

    console.log("\n════════════════════════════════════════════════════════════════════");
    console.log("  ANTIDRAIN NATIVE MESSAGING HOST REGISTRATION");
    console.log("════════════════════════════════════════════════════════════════════");
    console.log(`  Host Name:     ${manifest.name}`);
    console.log(`  Manifest Path: ${manifestPath}`);
    console.log(`  Allowed ID:    ${opts.extensionId}`);
    console.log(`  Registered in: ${regResult.registered.join(", ")}`);
    console.log("════════════════════════════════════════════════════════════════════\n");
  });

hostCmd
  .command("unregister")
  .description("Remove Native Messaging host entries from Windows Registry")
  .action(async () => {
    const { unregisterHostFromWindowsRegistry } = await import("./daemon/installHost.js");
    const result = unregisterHostFromWindowsRegistry();
    console.log(`\n✔ Removed host keys from Windows Registry (${result.removed.join(", ")})\n`);
  });

hostCmd
  .command("verify")
  .description("Verify Native Messaging host manifest and registry installation")
  .action(async () => {
    const { verifyHostInstallation } = await import("./daemon/installHost.js");
    const check = verifyHostInstallation();

    console.log("\n════════════════════════════════════════════════════════════════════");
    console.log("  ANTIDRAIN NATIVE MESSAGING HOST VERIFICATION");
    console.log("════════════════════════════════════════════════════════════════════");
    console.log(`  Manifest File Exists:   ${check.manifestExists ? "✓ YES" : "✗ NO"}`);
    console.log(`  Executable Exists:      ${check.executableExists ? "✓ YES" : "✗ NO"}`);
    console.log(`  Manifest JSON Valid:    ${check.manifestValid ? "✓ YES" : "✗ NO"}`);
    if (check.errors.length > 0) {
      console.log("\n  Errors detected:");
      for (const err of check.errors) {
        console.log(`    - ${err}`);
      }
    } else {
      console.log("\n  ✔ Host installation is valid and ready for Chrome/Brave.");
    }
    console.log("════════════════════════════════════════════════════════════════════\n");
  });

// ─── Run ───────────────────────────────────────────────────────────────

program.parse();
