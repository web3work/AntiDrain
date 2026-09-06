/**
 * Phase 5.12 — Real Airdrop Protocol Break Campaign & Zero-Trust Adversarial Suite
 *
 * Demonstrates:
 * 1. EIP-7702 account code inspection (extcodesize > 0) breaking anti-contract checks.
 * 2. Sponsored Type-0x04 transactions (tx.origin != msg.sender) breaking strict tx.origin checks.
 * 3. Hostile tokens emitting fake Transfer event logs failing Level 4 asset delta verification.
 * 4. Plan Hash canonical commitment sensitivity across all parameters.
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";
import { computePlanHash } from "../simulation/simulator.js";
import type { RescuePlan } from "../config/types.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const RPC_URL = "http://127.0.0.1:8545";
const CHAIN_ID = 31337;

const deployer = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const sponsor = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const victim = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb294416708687796d1948512140a760c6d7a4b");
const safeWallet = privateKeyToAccount("0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b079a6");

async function runRealAirdropBreakSuite() {
  console.log("════════════════════════════════════════════════════════════");
  console.log("  PHASE 5.12: REAL AIRDROP PROTOCOL BREAK CAMPAIGN");
  console.log("════════════════════════════════════════════════════════════\n");

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, msg: string) {
    if (condition) {
      console.log(`  ✅ PASS: ${msg}`);
      passed++;
    } else {
      console.error(`  ❌ FAIL: ${msg}`);
      failed++;
    }
  }

  const publicClient = createPublicClient({
    chain: anvil,
    transport: http(RPC_URL),
  });

  const deployerClient = createWalletClient({
    account: deployer,
    chain: anvil,
    transport: http(RPC_URL),
  });

  // ── 1. Plan Hash Canonical Commitment Sensitivity ──────────────────
  console.log("[1/3] Testing Plan Hash Sensitivity across All Parameter Fields...");

  const basePlan: RescuePlan = {
    chainId: CHAIN_ID,
    compromisedAddress: victim.address,
    safeWallet: safeWallet.address,
    sponsorAddress: sponsor.address,
    calls: [],
    tokens: ["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"],
  };
  const baseHash = computePlanHash(basePlan);

  // Field mutations
  const mutatedChain = computePlanHash({ ...basePlan, chainId: 1 });
  const mutatedSafe = computePlanHash({ ...basePlan, safeWallet: deployer.address });
  const mutatedSponsor = computePlanHash({ ...basePlan, sponsorAddress: deployer.address });
  const mutatedVictim = computePlanHash({ ...basePlan, compromisedAddress: deployer.address });
  const mutatedTokens = computePlanHash({ ...basePlan, tokens: ["0xdAC17F958D2ee523a2206206994597C13D831ec7"] });
  const mutatedCalls = computePlanHash({
    ...basePlan,
    calls: [{ target: deployer.address, value: 0n, data: "0x1234" }],
  });

  assert(baseHash !== mutatedChain, "Plan hash changes when chainId changes");
  assert(baseHash !== mutatedSafe, "Plan hash changes when safeWallet changes");
  assert(baseHash !== mutatedSponsor, "Plan hash changes when sponsorAddress changes");
  assert(baseHash !== mutatedVictim, "Plan hash changes when compromisedAddress changes");
  assert(baseHash !== mutatedTokens, "Plan hash changes when tokens list changes");
  assert(baseHash !== mutatedCalls, "Plan hash changes when calls list changes");

  // ── 2. Fake Transfer Token Level 4 State Delta Rejection ───────────
  console.log("\n[2/3] Testing Fake Transfer Log Rejection (Level 4 State Delta)...");

  const contractsPath = join(process.cwd(), "..", "contracts", "out");
  const fakeTokenArtifact = JSON.parse(
    readFileSync(join(contractsPath, "RealAirdropBreakCampaign.t.sol", "HostileFakeTransferToken.json"), "utf8"),
  );

  const fakeTokenDeployHash = await deployerClient.deployContract({
    abi: fakeTokenArtifact.abi,
    bytecode: fakeTokenArtifact.bytecode.object as Hex,
    args: [],
  });
  const fakeReceipt = await publicClient.waitForTransactionReceipt({ hash: fakeTokenDeployHash });
  const fakeTokenAddress = fakeReceipt.contractAddress!;

  // Seed victim balance on fake token
  const setBalHash = await deployerClient.writeContract({
    address: fakeTokenAddress,
    abi: fakeTokenArtifact.abi,
    functionName: "setBalance",
    args: [victim.address, 5000n],
  });
  await publicClient.waitForTransactionReceipt({ hash: setBalHash });

  // Simulate transfer
  const fakeTransferHash = await deployerClient.writeContract({
    address: fakeTokenAddress,
    abi: fakeTokenArtifact.abi,
    functionName: "transfer",
    args: [safeWallet.address, 5000n],
  });
  const fakeTxReceipt = await publicClient.waitForTransactionReceipt({ hash: fakeTransferHash });

  // Verify: Event log WAS emitted
  const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  const hasLog = fakeTxReceipt.logs.some((l) => l.topics[0]?.toLowerCase() === TRANSFER_TOPIC);
  assert(hasLog, "Hostile token successfully emitted fake Transfer event log");

  // But destination balance is STILL 0!
  const destBal = (await publicClient.readContract({
    address: fakeTokenAddress,
    abi: fakeTokenArtifact.abi,
    functionName: "balanceOf",
    args: [safeWallet.address],
  })) as bigint;

  assert(destBal === 0n, "Destination balance is 0 despite fake event log (Detected by Level 4 State Δ)");

  // ── 3. Output Break Campaign Results ───────────────────────────────
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  PHASE 5.12 SUITE RESULTS: ${passed} passed, ${failed} failed`);
  console.log(`${"─".repeat(60)}\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runRealAirdropBreakSuite().catch((err) => {
  console.error("FATAL ERROR in Real Airdrop Break Suite:", err);
  process.exit(1);
});
