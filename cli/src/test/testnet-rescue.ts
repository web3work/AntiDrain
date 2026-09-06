/**
 * Testnet Rescue — Using deployed UniversalRecoveryDelegate under Dual-Auth
 */

import "dotenv/config";

import {
  createPublicClient,
  createWalletClient,
  http,
  formatEther,
  type Hash,
  type Address,
} from "viem";
import { baseSepolia } from "viem/chains";
import { Vault } from "../vault/vault.js";
import { encodeRescueCalldata } from "../simulation/simulator.js";
import {
  buildDomain,
  signRescueIntent,
  readOnChainNonce,
  computeDeadline,
} from "../rescue/eip712.js";
import { CANONICAL_DELEGATE_ADDRESS } from "../rescue/create2.js";

const VAULT_PASSWORD = "testnet-rehearsal-2026";
const RPC_URL = `https://base-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`;
const SAFE_WALLET = "0x90F79bf6EB2c4f870365E785982E1f101E93b906" as Address;
const BLOCK_EXPLORER = "https://sepolia.basescan.org";
const BATCH_EXECUTOR = CANONICAL_DELEGATE_ADDRESS;

async function main() {
  console.log("═".repeat(60));
  console.log("  BASE SEPOLIA RESCUE — Using deployed UniversalRecoveryDelegate");
  console.log("═".repeat(60));

  const vault = Vault.load();
  const sponsorAccount = vault.getAccount("testnet-sponsor", VAULT_PASSWORD);
  const compromisedAccount = vault.getAccount("testnet-compromised", VAULT_PASSWORD);

  const publicClient = createPublicClient({
    chain: baseSepolia,
    transport: http(RPC_URL),
  });

  const sponsorClient = createWalletClient({
    account: sponsorAccount,
    chain: baseSepolia,
    transport: http(RPC_URL),
  });

  console.log(`\n  Sponsor:        ${sponsorAccount.address}`);
  console.log(`  Compromised:    ${compromisedAccount.address}`);
  console.log(`  Safe Wallet:    ${SAFE_WALLET}`);
  console.log(`  BatchExecutor:  ${BATCH_EXECUTOR}`);

  // ── Check balances ────────────────────────────────────────────────
  console.log("\n[1/5] Checking balances...");
  const sponsorBal = await publicClient.getBalance({ address: sponsorAccount.address });
  const compBal = await publicClient.getBalance({ address: compromisedAccount.address });
  const safeBal = await publicClient.getBalance({ address: SAFE_WALLET });

  console.log(`  Sponsor:      ${formatEther(sponsorBal)} ETH`);
  console.log(`  Compromised:  ${formatEther(compBal)} ETH`);
  console.log(`  Safe Wallet:  ${formatEther(safeBal)} ETH`);

  if (compBal === 0n) {
    console.log("  ⚠ Compromised wallet is already empty. Nothing to rescue.");
    process.exit(0);
  }

  // ── Get nonces ────────────────────────────────────────────────────
  const sponsorNonce = await publicClient.getTransactionCount({ address: sponsorAccount.address });
  const nonce = await readOnChainNonce(publicClient, compromisedAccount.address);
  const deadlineResult = await computeDeadline(publicClient, 300n);
  console.log(`  Sponsor nonce:     ${sponsorNonce}`);
  console.log(`  Contract nonce:    ${nonce}`);

  // ── Sign authorization & EIP-712 Intent ───────────────────────────
  console.log("\n[2/5] Signing EIP-7702 authorization & EIP-712 Intent...");
  const authorization = await sponsorClient.signAuthorization({
    account: compromisedAccount,
    contractAddress: BATCH_EXECUTOR,
  });
  console.log(`  ✓ Signed auth (chainId: ${authorization.chainId}, nonce: ${authorization.nonce})`);

  const domain = buildDomain(84532, compromisedAccount.address);
  const intentMessage = {
    safeWallet: SAFE_WALLET,
    sponsor: sponsorAccount.address,
    calls: [],
    tokens: [],
    nonce,
    deadline: deadlineResult.deadline,
  };

  const signedIntent = await signRescueIntent(compromisedAccount, domain, intentMessage);
  console.log(`  ✓ Signed EIP-712 intent (digest: ${signedIntent.digest})`);

  // ── Encode calldata ───────────────────────────────────────────────
  console.log("\n[3/5] Encoding 6-parameter rescue calldata...");
  const rescueCalldata = encodeRescueCalldata(
    SAFE_WALLET,
    [],
    [],
    nonce,
    deadlineResult.deadline,
    signedIntent.signature,
  );
  console.log(`  ✓ Encoded (${rescueCalldata.length / 2 - 1} bytes)`);

  // ── Broadcast ─────────────────────────────────────────────────────
  console.log("\n[4/5] Broadcasting rescue (Type 0x04)...");

  let rescueTxHash: Hash;
  try {
    rescueTxHash = await sponsorClient.sendTransaction({
      to: compromisedAccount.address,
      data: rescueCalldata,
      authorizationList: [authorization],
      nonce: sponsorNonce,
    });
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    console.error(`  ✗ Failed: ${msg}`);
    process.exit(1);
  }

  console.log(`  ✓ TX: ${rescueTxHash}`);
  console.log(`  ✓ ${BLOCK_EXPLORER}/tx/${rescueTxHash}`);

  // ── Wait + verify ─────────────────────────────────────────────────
  console.log("\n[5/5] Waiting for confirmation...");
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: rescueTxHash,
    timeout: 120_000,
  });

  console.log(`  Status: ${receipt.status}`);
  console.log(`  Block:  ${receipt.blockNumber}`);
  console.log(`  Gas:    ${receipt.gasUsed}`);

  const compBalAfter = await publicClient.getBalance({ address: compromisedAccount.address });
  const safeBalAfter = await publicClient.getBalance({ address: SAFE_WALLET });

  console.log(`\n  Compromised: ${formatEther(compBal)} → ${formatEther(compBalAfter)} ETH`);
  console.log(`  Safe wallet: ${formatEther(safeBal)} → ${formatEther(safeBalAfter)} ETH`);

  console.log("\n" + "─".repeat(60));
  let passed = 0; let failed = 0;
  function assert(ok: boolean, msg: string) {
    if (ok) { console.log(`  ✅ ${msg}`); passed++; }
    else { console.log(`  ❌ ${msg}`); failed++; }
  }

  assert(receipt.status === "success", "Transaction succeeded");
  assert(compBalAfter === 0n, "Compromised wallet drained to 0");
  assert(safeBalAfter > safeBal, "Safe wallet received ETH");

  console.log("─".repeat(60));
  console.log(`  ${passed} passed, ${failed} failed`);

  if (failed === 0) {
    console.log("\n  ✅ TESTNET RESCUE PASSED!");
    console.log(`  Rescue TX: ${BLOCK_EXPLORER}/tx/${rescueTxHash}`);
  } else {
    console.error("\n  ❌ TESTNET RESCUE FAILED");
    process.exit(1);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
