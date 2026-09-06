/**
 * Phase 5: Testnet Rehearsal (Base Sepolia)
 *
 * Full live on-chain validation of the hardened rescue flow:
 * 1. Checks/Uses deployed UniversalRecoveryDelegate(SPONSOR) on Base Sepolia
 * 2. Seeds compromised wallet with test ETH
 * 3. Signs EIP-7702 delegation authorization
 * 4. Simulates rescue via eth_call
 * 5. Broadcasts Type 0x04 rescue transaction from sponsor
 * 6. Broadcasts Type 0x04 revocation transaction from sponsor
 * 7. Verifies on-chain balances and EOA code restoration
 */

import "dotenv/config";

import {
  createPublicClient,
  createWalletClient,
  http,
  parseEther,
  formatEther,
  type Hash,
  type Address,
} from "viem";
import { baseSepolia } from "viem/chains";
import { Vault } from "../vault/vault.js";
import { signRescueAuthorization, signRevocationAuthorization } from "../rescue/authorization.js";
import { simulateRescue } from "../simulation/simulator.js";
import type { RescuePlan } from "../config/types.js";

const VAULT_PASSWORD = "testnet-rehearsal-2026";
const RPC_URL = `https://base-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`;
const BLOCK_EXPLORER = "https://sepolia.basescan.org";

async function main() {
  console.log("═".repeat(60));
  console.log("  PHASE 1.1: TESTNET REHEARSAL (BASE SEPOLIA)");
  console.log("═".repeat(60));

  const vault = Vault.load();
  const sponsorAccount = vault.getAccount("testnet-sponsor", VAULT_PASSWORD);
  const compromisedAccount = vault.getAccount("testnet-compromised", VAULT_PASSWORD);
  const SAFE_WALLET = sponsorAccount.address;

  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(RPC_URL),
  });

  const sponsorClient = createWalletClient({
    account: sponsorAccount,
    chain: baseSepolia,
    transport: http(RPC_URL),
  });

  console.log(`  Sponsor:      ${sponsorAccount.address}`);
  console.log(`  Compromised:  ${compromisedAccount.address}`);
  console.log(`  Safe Dest:    ${SAFE_WALLET}`);

  // ── Step 1: Check Balances ─────────────────────────────────────────
  console.log("\n[1/7] Checking initial balances...");
  const sponsorBal = await publicClient.getBalance({ address: sponsorAccount.address });
  console.log(`  Sponsor balance: ${formatEther(sponsorBal)} ETH`);

  if (sponsorBal < parseEther("0.005")) {
    throw new Error("Sponsor has insufficient funds for testnet rehearsal.");
  }

  // ── Step 2: Ensure UniversalRecoveryDelegate is Deployed for Sponsor ───────────
  console.log("\n[2/7] Verifying UniversalRecoveryDelegate(SPONSOR) on Base Sepolia...");

  let delegateAddress: Address;
  const fs = await import("node:fs");
  const path = await import("node:path");
  const artifactPath = path.resolve(
    process.cwd(),
    "../contracts/out/UniversalRecoveryDelegate.sol/UniversalRecoveryDelegate.json"
  );
  const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  const bytecode = artifact.bytecode.object as `0x${string}`;

  console.log(`  Deploying fresh UniversalRecoveryDelegate (canonical, no constructor args)...`);
  const deployHash = await sponsorClient.deployContract({
    abi: artifact.abi,
    bytecode,
  });
  const deployReceipt = await publicClient.waitForTransactionReceipt({ hash: deployHash });
  delegateAddress = deployReceipt.contractAddress!;
  console.log(`  ✓ Deployed at: ${delegateAddress} (tx: ${deployHash})`);
  console.log(`  ✓ Explorer: ${BLOCK_EXPLORER}/address/${delegateAddress}`);

  // ── Step 3: Seed Compromised Wallet with Test ETH ──────────────────
  console.log("\n[3/7] Checking compromised wallet test asset balance...");
  const compBalBefore = await publicClient.getBalance({ address: compromisedAccount.address });
  console.log(`  ✓ Compromised wallet has ${formatEther(compBalBefore)} ETH`);

  if (compBalBefore < parseEther("0.001")) {
    console.log("  Seeding compromised wallet with 0.002 ETH test asset...");
    const seedHash = await sponsorClient.sendTransaction({
      to: compromisedAccount.address,
      value: parseEther("0.002"),
    });
    await publicClient.waitForTransactionReceipt({ hash: seedHash });
    console.log(`  ✓ Seeded 0.002 ETH (tx: ${seedHash})`);
    await new Promise((r) => setTimeout(r, 2000));
  }

  // ── Step 4: Sign EIP-7702 Delegation Authorization ─────────────────
  console.log("\n[4/7] Signing EIP-7702 delegation authorization...");
  const authorization = await signRescueAuthorization(
    compromisedAccount,
    84532,
    delegateAddress,
  );
  console.log(`  ✓ Signed (chainId: ${authorization.chainId}, nonce: ${authorization.nonce})`);

  // ── Step 5: Simulate Rescue ────────────────────────────────────────
  console.log("\n[5/7] Simulating rescue via eth_call...");
  const plan: RescuePlan = {
    chainId: 84532,
    compromisedAddress: compromisedAccount.address,
    safeWallet: SAFE_WALLET as `0x${string}`,
    sponsorAddress: sponsorAccount.address,
    calls: [],
    tokens: [],
  };

  // ── Step 5: Sign EIP-712 Rescue Intent & Encode Calldata ──────────
  console.log("\n[5/7] Signing EIP-712 Rescue Intent...");
  const { buildDomain, signRescueIntent, readOnChainNonce, computeDeadline } = await import("../rescue/eip712.js");
  const { encodeRescueCalldata } = await import("../simulation/simulator.js");

  const nonce = await readOnChainNonce(publicClient, compromisedAccount.address);
  const deadlineResult = await computeDeadline(publicClient, 300n);
  const domain = buildDomain(84532, compromisedAccount.address);
  const intentMessage = {
    safeWallet: SAFE_WALLET as Address,
    sponsor: sponsorAccount.address,
    calls: [],
    tokens: [],
    nonce,
    deadline: deadlineResult.deadline,
  };

  const signedIntent = await signRescueIntent(compromisedAccount, domain, intentMessage);
  console.log(`  ✓ Signed EIP-712 intent (digest: ${signedIntent.digest})`);

  const calldata = encodeRescueCalldata(
    SAFE_WALLET as Address,
    [],
    [],
    nonce,
    deadlineResult.deadline,
    signedIntent.signature,
  );

  const simResult = await simulateRescue(plan, { exactCalldata: calldata, isFullSimulation: true });
  console.log(`  ✓ Simulation passed (gas estimate: ${simResult.gasEstimate})`);

  // ── Step 6: Broadcast Rescue Transaction (Type 0x04) ───────────────
  console.log("\n[6/7] Broadcasting rescue transaction (Type 0x04)...");

  const rescueTxHash: Hash = await sponsorClient.sendTransaction({
    to: compromisedAccount.address,
    data: calldata,
    authorizationList: [authorization],
    gas: 250_000n,
  });
  console.log(`  ✓ Rescue TX: ${rescueTxHash}`);
  console.log(`  ✓ Explorer: ${BLOCK_EXPLORER}/tx/${rescueTxHash}`);

  const rescueReceipt = await publicClient.waitForTransactionReceipt({
    hash: rescueTxHash,
    timeout: 120_000,
  });
  console.log(`  ✓ Status: ${rescueReceipt.status} in block ${rescueReceipt.blockNumber} (Gas: ${rescueReceipt.gasUsed})`);

  await new Promise((r) => setTimeout(r, 2000));

  // ── Step 7: Broadcast Sponsored Revocation ─────────────────────────
  console.log("\n[7/7] Broadcasting sponsored delegation revocation to address(0)...");
  const revocationAuth = await signRevocationAuthorization(
    compromisedAccount,
    84532,
    authorization.nonce + 1,
  );

  const revokeTxHash: Hash = await sponsorClient.sendTransaction({
    to: compromisedAccount.address,
    data: "0x",
    authorizationList: [revocationAuth],
    gas: 100_000n,
  });
  console.log(`  ✓ Revocation TX: ${revokeTxHash}`);
  console.log(`  ✓ Explorer: ${BLOCK_EXPLORER}/tx/${revokeTxHash}`);

  const revokeReceipt = await publicClient.waitForTransactionReceipt({
    hash: revokeTxHash,
    timeout: 120_000,
  });
  console.log(`  ✓ Status: ${revokeReceipt.status} (Gas: ${revokeReceipt.gasUsed})`);

  // ── Verification ───────────────────────────────────────────────────
  console.log("\n" + "─".repeat(60));
  console.log("  VERIFICATION RESULTS");
  console.log("─".repeat(60));

  // Wait for RPC state sync
  await new Promise((r) => setTimeout(r, 4000));

  const compBalAfter = await publicClient.getBalance({ address: compromisedAccount.address });
  const compCodeAfter = await publicClient.getCode({ address: compromisedAccount.address });

  let passed = 0; let failed = 0;
  function assert(ok: boolean, msg: string) {
    if (ok) { console.log(`  ✅ PASS: ${msg}`); passed++; }
    else { console.log(`  ❌ FAIL: ${msg}`); failed++; }
  }

  assert(rescueReceipt.status === "success", "Type 0x04 rescue transaction succeeded");
  assert(compBalAfter === 0n, "Compromised wallet drained to 0 ETH");
  assert(revokeReceipt.status === "success", "Type 0x04 revocation transaction succeeded");
  assert(!compCodeAfter || compCodeAfter === "0x", "Delegation code revoked (restored to 0x)");

  console.log("─".repeat(60));
  console.log(`  Results: ${passed} passed, ${failed} failed`);

  if (failed === 0) {
    console.log("\n  🎉 PHASE 5 TESTNET REHEARSAL FULLY PASSED ON BASE SEPOLIA!");
  } else {
    console.error("\n  ❌ TESTNET REHEARSAL FAILED");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Rehearsal failed with error:", err);
  process.exit(1);
});
