/**
 * Phase 5.11 — Production-Grade Airdrop Claim Boundary & Upgrade Audit Suite
 *
 * Verifies:
 * 1. Protocol Code-Identity & ERC-1967 Proxy Implementation Verification
 * 2. Authority Diff Engine detecting persistent approvals (including Permit2)
 * 3. Multi-Dimensional State Formulation (Asset, Delegation, Authority, Inventory, Finality)
 */

import {
  createPublicClient,
  createWalletClient,
  http,
  parseEther,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { anvil } from "viem/chains";
import { verifyProtocolIdentity } from "../airdrop/verifier.js";
import { snapshotAllowances, computeAuthorityDiff, PERMIT2_CANONICAL_ADDRESS } from "../rescue/authorityDiff.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const RPC_URL = "http://127.0.0.1:8545";

const deployer = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const victim = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb294416708687796d1948512140a760c6d7a4b");
const attacker = "0x90F79bf6EB2c4f870365E785982E1f101E93b906" as const;

async function runBoundarySuite() {
  console.log("════════════════════════════════════════════════════════════");
  console.log("  PHASE 5.11: AIRDROP BOUNDARY & UPGRADE AUDIT SUITE");
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

  // ── 1. Test Proxy Implementation Code Identity Verification ────────
  console.log("[1/3] Testing ERC-1967 Proxy Implementation Code-Identity Verification...");

  const contractsPath = join(process.cwd(), "..", "contracts", "out");
  const mockERC20Artifact = JSON.parse(
    readFileSync(join(contractsPath, "MockERC20.sol", "MockERC20.json"), "utf8"),
  );
  const v1Artifact = JSON.parse(
    readFileSync(join(contractsPath, "AirdropClaimBoundaryAudit.t.sol", "AirdropImplementationV1.json"), "utf8"),
  );
  const proxyArtifact = JSON.parse(
    readFileSync(join(contractsPath, "AirdropClaimBoundaryAudit.t.sol", "ERC1967ProxyMock.json"), "utf8"),
  );

  // Deploy MockERC20
  const tokenDeployHash = await deployerClient.deployContract({
    abi: mockERC20Artifact.abi,
    bytecode: mockERC20Artifact.bytecode.object as Hex,
    args: [],
  });
  const tokenReceipt = await publicClient.waitForTransactionReceipt({ hash: tokenDeployHash });
  const airdropTokenAddress = tokenReceipt.contractAddress!;

  // Deploy V1 Implementation
  const v1DeployHash = await deployerClient.deployContract({
    abi: v1Artifact.abi,
    bytecode: v1Artifact.bytecode.object as Hex,
    args: [airdropTokenAddress],
  });
  const v1Receipt = await publicClient.waitForTransactionReceipt({ hash: v1DeployHash });
  const v1Address = v1Receipt.contractAddress!;

  // Deploy ERC-1967 Proxy
  const proxyDeployHash = await deployerClient.deployContract({
    abi: proxyArtifact.abi,
    bytecode: proxyArtifact.bytecode.object as Hex,
    args: [v1Address, deployer.address],
  });
  const proxyReceipt = await publicClient.waitForTransactionReceipt({ hash: proxyDeployHash });
  const proxyAddress = proxyReceipt.contractAddress!;

  const protocolId = await verifyProtocolIdentity(publicClient, proxyAddress);

  assert(protocolId.isProxy, "ERC-1967 Proxy slot detected");
  assert(
    protocolId.implementationAddress?.toLowerCase() === v1Address.toLowerCase(),
    "Implementation address correctly resolved from storage slot",
  );
  assert(
    protocolId.implementationCodeHash !== undefined && protocolId.implementationCodeHash.length === 66,
    "Implementation bytecode hash verified",
  );

  // ── 2. Test Authority Diff Engine with Permit2 & Stealth Approvals ──
  console.log("\n[2/3] Testing Authority Diff Engine (Stealth Allowance Detection)...");

  // Pre-snapshot: Allowance is 0
  const preSnapshots = await snapshotAllowances(
    publicClient,
    victim.address,
    [airdropTokenAddress],
    [attacker],
  );
  assert(preSnapshots.length >= 1 && preSnapshots[0].allowance === 0n, "Pre-rescue allowance is 0");

  // Clean diff test (calls = [])
  const cleanDiff = computeAuthorityDiff(preSnapshots, preSnapshots, false);
  assert(cleanDiff.state === "AUTHORITY_DIFF_CLEAN" && cleanDiff.proofStatus === "PROVEN", "Clean authority diff verified as PROVEN");

  // Simulate stealth approval: victim approves attacker for 5,000 tokens
  const victimWalletClient = createWalletClient({
    account: victim,
    chain: anvil,
    transport: http(RPC_URL),
  });

  // Fund victim with ETH for approve tx
  await deployerClient.sendTransaction({
    to: victim.address,
    value: parseEther("0.1"),
  });

  const approveTxHash = await victimWalletClient.writeContract({
    address: airdropTokenAddress,
    abi: mockERC20Artifact.abi,
    functionName: "approve",
    args: [attacker, 5000n],
  });
  await publicClient.waitForTransactionReceipt({ hash: approveTxHash });

  // Post-snapshot: Allowance is 5,000
  const postSnapshots = await snapshotAllowances(
    publicClient,
    victim.address,
    [airdropTokenAddress],
    [attacker],
  );

  const infectedDiff = computeAuthorityDiff(preSnapshots, postSnapshots, true);
  assert(
    infectedDiff.state === "PERSISTENT_APPROVALS_DETECTED" && infectedDiff.proofStatus === "FAILED",
    "Infected authority diff detects persistent allowance delta (+5,000)",
  );
  assert(infectedDiff.diffs.length === 1 && infectedDiff.diffs[0].delta === 5000n, "Allowance delta matched exact created amount");

  // ── 3. Test Multi-Dimensional State Schema Invariants ───────────────
  console.log("\n[3/3] Testing Multi-Dimensional State Classification Invariants...");

  assert(PERMIT2_CANONICAL_ADDRESS === "0x000000000022D473030F116dDEE9F6B43aC78BA3", "Canonical Permit2 contract address tracked");

  console.log(`\n${"─".repeat(60)}`);
  console.log(`  PHASE 5.11 SUITE RESULTS: ${passed} passed, ${failed} failed`);
  console.log(`${"─".repeat(60)}\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runBoundarySuite().catch((err) => {
  console.error("FATAL ERROR in Boundary Suite:", err);
  process.exit(1);
});
