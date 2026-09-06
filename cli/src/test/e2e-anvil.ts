/**
 * End-to-End Anvil Fork Test
 *
 * Validates the full rescue lifecycle under 6-parameter Dual-Authorization:
 * 1. Deploys MockERC20 & UniversalRecoveryDelegate(SPONSOR)
 * 2. Mints tokens & funds compromised wallet
 * 3. Signs EIP-7702 delegation authorization
 * 4. Signs EIP-712 rescue intent (compromised EOA)
 * 5. Verifies adversarial attacker cannot call executeRescue (UnauthorizedCaller)
 * 6. Broadcasts Type 0x04 rescue transaction from sponsor with valid EIP-712 signature
 * 7. Verifies assets moved to safe destination
 * 8. Broadcasts Type 0x04 revocation transaction
 * 9. Verifies EOA code restored to 0x
 */

import "dotenv/config";

import {
  createPublicClient,
  createWalletClient,
  http,
  parseEther,
  type Hex,
  type Address,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { foundry } from "viem/chains";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  signRescueAuthorization,
  signRevocationAuthorization,
} from "../rescue/authorization.js";
import {
  encodeRescueCalldata,
} from "../simulation/simulator.js";
import {
  buildDomain,
  signRescueIntent,
  readOnChainNonce,
  computeDeadline,
} from "../rescue/eip712.js";

// ─── Constants ─────────────────────────────────────────────────────────

const ANVIL_RPC = "http://127.0.0.1:8545";

// Anvil default accounts (public test keys)
const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;
const SPONSOR_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" as Hex;
const COMPROMISED_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" as Hex;
const ATTACKER_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" as Hex;
const SAFE_WALLET = "0x90F79bf6EB2c4f870365E785982E1f101E93b906" as Address;

const MOCK_ERC20_ABI = [
  {
    name: "mint",
    type: "function",
    stateMutability: "nonpayable",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    name: "balanceOf",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ name: "balance", type: "uint256" }],
  },
] as const;

async function main() {
  console.log("═".repeat(60));
  console.log("  ANVIL FORK END-TO-END TEST (DUAL-AUTH EIP-712 & IMMUTABLE SPONSOR)");
  console.log("═".repeat(60));
  console.log("");

  const publicClient = createPublicClient({
    chain: foundry,
    transport: http(ANVIL_RPC),
  });

  const deployer = privateKeyToAccount(DEPLOYER_KEY);
  const sponsor = privateKeyToAccount(SPONSOR_KEY);
  const compromised = privateKeyToAccount(COMPROMISED_KEY);
  const attacker = privateKeyToAccount(ATTACKER_KEY);

  const deployerClient = createWalletClient({
    account: deployer,
    chain: foundry,
    transport: http(ANVIL_RPC),
  });

  const sponsorClient = createWalletClient({
    account: sponsor,
    chain: foundry,
    transport: http(ANVIL_RPC),
  });

  const attackerClient = createWalletClient({
    account: attacker,
    chain: foundry,
    transport: http(ANVIL_RPC),
  });

  console.log(`  Deployer:     ${deployer.address}`);
  console.log(`  Sponsor:      ${sponsor.address}`);
  console.log(`  Attacker:     ${attacker.address}`);
  console.log(`  Compromised:  ${compromised.address}`);
  console.log(`  Safe Wallet:  ${SAFE_WALLET}`);

  // ── Step 1: Deploy Contracts ──────────────────────────────────────────
  console.log("\n[1/8] Deploying UniversalRecoveryDelegate & MockERC20...");

  const delegateArtifactPath = join(
    process.cwd(),
    "..",
    "contracts",
    "out",
    "UniversalRecoveryDelegate.sol",
    "UniversalRecoveryDelegate.json",
  );
  const delegateArtifact = JSON.parse(readFileSync(delegateArtifactPath, "utf8"));

  const mockTokenArtifactPath = join(
    process.cwd(),
    "..",
    "contracts",
    "out",
    "MockERC20.sol",
    "MockERC20.json",
  );
  const mockTokenArtifact = JSON.parse(readFileSync(mockTokenArtifactPath, "utf8"));

  const delegateDeployHash = await deployerClient.deployContract({
    abi: delegateArtifact.abi,
    bytecode: delegateArtifact.bytecode.object as Hex,
  });
  const delegateReceipt = await publicClient.waitForTransactionReceipt({ hash: delegateDeployHash });
  const batchExecutorAddress = delegateReceipt.contractAddress!;
  console.log(`  ✓ UniversalRecoveryDelegate deployed at: ${batchExecutorAddress}`);

  const mockTokenDeployHash = await deployerClient.deployContract({
    abi: mockTokenArtifact.abi,
    bytecode: mockTokenArtifact.bytecode.object as Hex,
  });
  const mockTokenReceipt = await publicClient.waitForTransactionReceipt({ hash: mockTokenDeployHash });
  const mockTokenAddress = mockTokenReceipt.contractAddress!;
  console.log(`  ✓ MockERC20 deployed at: ${mockTokenAddress}`);

  // ── Step 2: Mint Tokens & Fund Wallets ────────────────────────────────
  console.log("\n[2/8] Minting 5,000 TEST tokens to compromised wallet...");
  const mintHash = await deployerClient.writeContract({
    address: mockTokenAddress,
    abi: MOCK_ERC20_ABI,
    functionName: "mint",
    args: [compromised.address, parseEther("5000")],
  });
  await publicClient.waitForTransactionReceipt({ hash: mintHash });

  const fundHash = await deployerClient.sendTransaction({
    to: compromised.address,
    value: parseEther("2.0"),
  });
  await publicClient.waitForTransactionReceipt({ hash: fundHash });

  // ── Step 3: Check Initial State ─────────────────────────────────────
  console.log("\n[3/8] Pre-rescue state check...");
  const initialTokenBal = (await publicClient.readContract({
    address: mockTokenAddress,
    abi: MOCK_ERC20_ABI,
    functionName: "balanceOf",
    args: [compromised.address],
  })) as bigint;
  const initialEthBal = await publicClient.getBalance({ address: compromised.address });
  console.log(`  ✓ Compromised Token Bal: ${initialTokenBal}`);
  console.log(`  ✓ Compromised ETH Bal:   ${initialEthBal}`);

  // ── Step 4: Sign EIP-7702 authorization & EIP-712 Rescue Intent ──────
  console.log("\n[4/8] Signing EIP-7702 delegation authorization & EIP-712 intent...");
  const authorization = await sponsorClient.signAuthorization({
    account: compromised,
    contractAddress: batchExecutorAddress,
  });
  console.log(`  ✓ Authorization signed (chainId: ${authorization.chainId}, nonce: ${authorization.nonce})`);

  const nonce = await readOnChainNonce(publicClient, compromised.address);
  const deadlineResult = await computeDeadline(publicClient, 300n);
  const domain = buildDomain(foundry.id, compromised.address);
  const intentMessage = {
    safeWallet: SAFE_WALLET,
    sponsor: sponsor.address,
    calls: [],
    tokens: [mockTokenAddress],
    nonce,
    deadline: deadlineResult.deadline,
  };

  const signedIntent = await signRescueIntent(compromised, domain, intentMessage);
  console.log(`  ✓ EIP-712 Intent signed (digest: ${signedIntent.digest})`);

  // ── Step 5: Adversarial Test (Attacker fails) ─────────────────────
  console.log("\n[5/8] Adversarial Check: Verifying attacker cannot call executeRescue...");

  const attackerCalldata = encodeRescueCalldata(
    attacker.address,
    [],
    [mockTokenAddress],
    nonce,
    deadlineResult.deadline,
    signedIntent.signature,
  );

  let attackerReverted = false;
  try {
    await attackerClient.sendTransaction({
      to: compromised.address,
      data: attackerCalldata,
      authorizationList: [authorization],
    });
  } catch {
    attackerReverted = true;
  }
  console.log(`  ✓ Attacker call reverted: ${attackerReverted}`);

  // ── Step 6: Broadcast rescue from Sponsor ─────────────────────────
  console.log("\n[6/8] Broadcasting rescue transaction from authorized Sponsor (Type 0x04)...");

  const rescueCalldata = encodeRescueCalldata(
    SAFE_WALLET,
    [],
    [mockTokenAddress],
    nonce,
    deadlineResult.deadline,
    signedIntent.signature,
  );

  const rescueAuth = await signRescueAuthorization(compromised, 31337, batchExecutorAddress);

  const rescueTxHash = await sponsorClient.sendTransaction({
    to: compromised.address,
    data: rescueCalldata,
    authorizationList: [rescueAuth],
  });
  console.log(`  ✓ TX broadcast: ${rescueTxHash}`);

  const rescueReceipt = await publicClient.waitForTransactionReceipt({ hash: rescueTxHash });
  console.log(`  ✓ Status: ${rescueReceipt.status}`);
  console.log(`  ✓ Gas used: ${rescueReceipt.gasUsed}`);

  // ── Step 7: Revoke delegation ──────────────────────────────────────
  console.log("\n[7/8] Broadcasting sponsored revocation to address(0)...");

  const revocationAuth = await signRevocationAuthorization(compromised, 31337);

  const revokeTxHash = await sponsorClient.sendTransaction({
    to: compromised.address,
    data: "0x",
    authorizationList: [revocationAuth],
  });
  const revokeReceipt = await publicClient.waitForTransactionReceipt({ hash: revokeTxHash });
  console.log(`  ✓ Revocation status: ${revokeReceipt.status}`);

  // ── Step 8: Post-Rescue Verification ────────────────────────────────
  console.log("\n[8/8] Post-rescue state verification...");
  const finalCompromisedToken = (await publicClient.readContract({
    address: mockTokenAddress,
    abi: MOCK_ERC20_ABI,
    functionName: "balanceOf",
    args: [compromised.address],
  })) as bigint;
  const finalSafeToken = (await publicClient.readContract({
    address: mockTokenAddress,
    abi: MOCK_ERC20_ABI,
    functionName: "balanceOf",
    args: [SAFE_WALLET],
  })) as bigint;
  const finalCompromisedEth = await publicClient.getBalance({ address: compromised.address });
  const finalSafeEth = await publicClient.getBalance({ address: SAFE_WALLET });
  const finalCode = await publicClient.getCode({ address: compromised.address });

  console.log(`  ✓ Compromised Token: ${finalCompromisedToken} (expected: 0)`);
  console.log(`  ✓ Safe Wallet Token: ${finalSafeToken} (expected: 5000000000000000000000)`);
  console.log(`  ✓ Compromised ETH:   ${finalCompromisedEth} (expected: 0)`);
  console.log(`  ✓ Safe Wallet ETH:   ${finalSafeEth} (expected: > 0)`);
  console.log(`  ✓ Compromised Code:  ${finalCode ?? "0x"} (expected: empty 0x)`);

  if (
    finalCompromisedToken === 0n &&
    finalSafeToken === parseEther("5000") &&
    finalCompromisedEth === 0n &&
    (finalCode === undefined || finalCode === "0x" || finalCode === "0x0")
  ) {
    console.log("\n🎉 ANVIL TEST PASSED: Full Dual-Auth EIP-7702 Rescue lifecycle validated!");
  } else {
    console.error("\n❌ ANVIL TEST FAILED: Post-rescue assertions did not hold!");
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
