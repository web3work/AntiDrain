/**
 * Testnet Revocation Test
 *
 * Tests revoking the EIP-7702 delegation on Base Sepolia
 * by signing an authorization pointing to address(0).
 *
 * VERIFIED: After this transaction, the EOA code should return to 0x.
 */

import "dotenv/config";
import {
  createPublicClient,
  createWalletClient,
  http,
  type Hash,
} from "viem";
import { baseSepolia } from "viem/chains";
import { Vault } from "../vault/vault.js";
import { signRevocationAuthorization } from "../rescue/authorization.js";

const VAULT_PASSWORD = "testnet-rehearsal-2026";
const RPC_URL = `https://base-sepolia.g.alchemy.com/v2/${process.env.ALCHEMY_API_KEY}`;
const BLOCK_EXPLORER = "https://sepolia.basescan.org";

async function main() {
  console.log("═".repeat(60));
  console.log("  BASE SEPOLIA REVOCATION TEST");
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

  console.log(`  Sponsor:     ${sponsorAccount.address}`);
  console.log(`  Compromised: ${compromisedAccount.address}`);

  // Check current code on compromised EOA
  const codeBefore = await publicClient.getCode({ address: compromisedAccount.address });
  console.log(`\n  Delegation code before: ${codeBefore}`);

  // Sign revocation authorization (contractAddress: 0x0000000000000000000000000000000000000000)
  console.log("\n[1/3] Signing revocation authorization (delegate to address(0))...");
  const revocationAuth = await signRevocationAuthorization(
    compromisedAccount,
    84532,
  );
  console.log(`  ✓ Revocation auth signed (nonce: ${revocationAuth.nonce})`);

  // Get current sponsor nonce
  const sponsorNonce = await publicClient.getTransactionCount({
    address: sponsorAccount.address,
  });

  // Broadcast Type 4 transaction with revocation auth
  console.log("\n[2/3] Broadcasting revocation transaction (Type 0x04)...");
  const txHash: Hash = await sponsorClient.sendTransaction({
    to: compromisedAccount.address,
    data: "0x",
    authorizationList: [revocationAuth],
    nonce: sponsorNonce,
  });
  console.log(`  ✓ TX: ${txHash}`);
  console.log(`  ✓ ${BLOCK_EXPLORER}/tx/${txHash}`);

  // Wait for receipt
  console.log("\n[3/3] Waiting for confirmation...");
  const receipt = await publicClient.waitForTransactionReceipt({
    hash: txHash,
    timeout: 120_000,
  });
  console.log(`  Status: ${receipt.status}`);
  console.log(`  Block:  ${receipt.blockNumber}`);
  console.log(`  Gas:    ${receipt.gasUsed}`);

  // Check code on compromised EOA after revocation
  const codeAfter = await publicClient.getCode({ address: compromisedAccount.address });
  console.log(`\n  Delegation code after: ${codeAfter ?? "0x (none)"}`);

  if (receipt.status === "success" && (!codeAfter || codeAfter === "0x")) {
    console.log("\n  ✅ REVOCATION SUCCEEDED! EOA is restored to pure account state.");
  } else {
    console.warn("\n  ⚠ Revocation check result:", { status: receipt.status, codeAfter });
  }
}

main().catch((err) => {
  console.error("Revocation failed:", err);
  process.exit(1);
});
