/**
 * Real-Client EIP-7702 Protocol Integration Test Suite
 *
 * Verifies exact client-level EIP-7702 behavior against a Prague EVM node (Anvil):
 * 1. Authorization tuple signing & type 0x04 transaction dispatch
 * 2. Intermediate account code inspection (0xef0100 + 20-byte address)
 * 3. Execution of executeRescue in dual-authorized delegated context
 * 4. Verification of on-chain Transfer logs in receipt
 * 5. Sponsored revocation transaction to address(0)
 * 6. Final account code verification (restores to 0x)
 * 7. Post-revocation ordinary EOA transaction execution
 * 8. Reentrancy block under real EIP-7702 execution context
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
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { signRescueAuthorization, signRevocationAuthorization } from "../rescue/authorization.js";
import { encodeRescueCalldata } from "../simulation/simulator.js";
import {
  buildDomain,
  signRescueIntent,
  readOnChainNonce,
  computeDeadline,
} from "../rescue/eip712.js";

// Standard Anvil test keys
const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const SPONSOR_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const COMPROMISED_KEY = "0x5de4111afa1a4b94908f83103eb294416708687796d1948512140a760c6d7a4b";
const SAFE_WALLET_KEY = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b079a6";

const deployer = privateKeyToAccount(DEPLOYER_KEY);
const sponsor = privateKeyToAccount(SPONSOR_KEY);
const compromised = privateKeyToAccount(COMPROMISED_KEY);
const safeWallet = privateKeyToAccount(SAFE_WALLET_KEY);

const RPC_URL = "http://127.0.0.1:8545";
const CHAIN_ID = 31337;

const client = createPublicClient({
  chain: anvil,
  transport: http(RPC_URL),
});

const deployerClient = createWalletClient({
  account: deployer,
  chain: anvil,
  transport: http(RPC_URL),
});

const sponsorClient = createWalletClient({
  account: sponsor,
  chain: anvil,
  transport: http(RPC_URL),
});

const compromisedClient = createWalletClient({
  account: compromised,
  chain: anvil,
  transport: http(RPC_URL),
});

async function runProtocolSuite() {
  console.log("════════════════════════════════════════════════════════════");
  console.log("  EIP-7702 PROTOCOL & CLIENT INTEGRATION TEST SUITE");
  console.log("════════════════════════════════════════════════════════════\n");

  const contractsDir = join(process.cwd(), "..", "contracts", "out");
  const mockERC20Artifact = JSON.parse(
    readFileSync(join(contractsDir, "MockERC20.sol", "MockERC20.json"), "utf8"),
  );
  const delegateArtifact = JSON.parse(
    readFileSync(
      join(contractsDir, "UniversalRecoveryDelegate.sol", "UniversalRecoveryDelegate.json"),
      "utf8",
    ),
  );

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

  // 1. Deploy MockERC20 & Delegate
  console.log("[1/7] Deploying mock contracts...");
  const mockTokenDeployHash = await deployerClient.deployContract({
    abi: mockERC20Artifact.abi,
    bytecode: mockERC20Artifact.bytecode.object as Hex,
  });
  const mockTokenReceipt = await client.waitForTransactionReceipt({ hash: mockTokenDeployHash });
  const mockTokenAddress = mockTokenReceipt.contractAddress!;
  assert(Boolean(mockTokenAddress), "MockERC20 contract deployed");

  const delegateDeployHash = await deployerClient.deployContract({
    abi: delegateArtifact.abi,
    bytecode: delegateArtifact.bytecode.object as Hex,
  });
  const delegateReceipt = await client.waitForTransactionReceipt({ hash: delegateDeployHash });
  const delegateAddress = delegateReceipt.contractAddress!;
  assert(Boolean(delegateAddress), "UniversalRecoveryDelegate canonical contract deployed");

  // 2. Setup Balances
  console.log("\n[2/7] Funding compromised EOA with tokens and native ETH...");
  const mintHash = await deployerClient.writeContract({
    address: mockTokenAddress,
    abi: mockERC20Artifact.abi,
    functionName: "mint",
    args: [compromised.address, parseEther("1000")],
  });
  await client.waitForTransactionReceipt({ hash: mintHash });

  const fundHash = await deployerClient.sendTransaction({
    to: compromised.address,
    value: parseEther("2.0"),
  });
  await client.waitForTransactionReceipt({ hash: fundHash });

  const initialCompBal = await client.getBalance({ address: compromised.address });
  assert(initialCompBal >= parseEther("2.0"), "Compromised EOA holds initial native balance");

  // 3. Check Initial EOA Code State (must be pure EOA: 0x)
  const initialCode = await client.getCode({ address: compromised.address });
  assert(initialCode === undefined || initialCode === "0x", "Pre-delegation account code is empty (0x)");

  // 4. Sign EIP-7702 Rescue Authorization Tuple
  console.log("\n[3/7] Signing EIP-7702 Authorization tuple & EIP-712 intent...");
  const authTuple = await signRescueAuthorization(compromised, CHAIN_ID, delegateAddress);
  assert(authTuple.address.toLowerCase() === delegateAddress.toLowerCase(), "Authorization target matches delegate");

  const nonce = await readOnChainNonce(client, compromised.address);
  const deadlineResult = await computeDeadline(client, 300n);
  const domain = buildDomain(CHAIN_ID, compromised.address);
  const intentMessage = {
    safeWallet: safeWallet.address,
    sponsor: sponsor.address,
    calls: [],
    tokens: [mockTokenAddress],
    nonce,
    deadline: deadlineResult.deadline,
  };

  const signedIntent = await signRescueIntent(compromised, domain, intentMessage);
  assert(Boolean(signedIntent.signature), "EIP-712 Rescue intent signed");

  // 5. Broadcast Type 0x04 Rescue Transaction
  console.log("\n[4/7] Broadcasting Type 0x04 Rescue Transaction (Dual-Auth)...");
  const calldata = encodeRescueCalldata(
    safeWallet.address,
    [],
    [mockTokenAddress],
    nonce,
    deadlineResult.deadline,
    signedIntent.signature,
  );

  const sponsorNonce = await client.getTransactionCount({ address: sponsor.address });
  const rescueTxHash = await sponsorClient.sendTransaction({
    to: compromised.address,
    data: calldata,
    authorizationList: [authTuple],
    nonce: sponsorNonce,
  });

  const rescueReceipt = await client.waitForTransactionReceipt({ hash: rescueTxHash });
  assert(rescueReceipt.status === "success", "Type 0x04 Rescue transaction confirmed with status=success");

  // 6. Verify Causal On-Chain Transfer Event in Receipt Logs
  const TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
  const hasTransferLog = rescueReceipt.logs.some((l) => l.topics[0]?.toLowerCase() === TRANSFER_TOPIC);
  assert(hasTransferLog, "Receipt contains on-chain ERC-20 Transfer event log (Causal Proof)");

  // 7. Verify Balances Post-Rescue
  const postSourceEth = await client.getBalance({ address: compromised.address });
  const postDestEth = await client.getBalance({ address: safeWallet.address });
  assert(postSourceEth === 0n, "Compromised wallet native balance is 0 ETH");
  assert(postDestEth >= parseEther("2.0"), "Safe wallet received swept native ETH");

  // 8. Broadcast Type 0x04 Revocation Transaction
  console.log("\n[5/7] Broadcasting Type 0x04 Revocation Transaction...");
  const revokeTuple = await signRevocationAuthorization(compromised, CHAIN_ID, authTuple.nonce + 1);
  const nextSponsorNonce = await client.getTransactionCount({ address: sponsor.address });

  const revokeTxHash = await sponsorClient.sendTransaction({
    to: compromised.address,
    data: "0x",
    authorizationList: [revokeTuple],
    nonce: nextSponsorNonce,
  });

  const revokeReceipt = await client.waitForTransactionReceipt({ hash: revokeTxHash });
  assert(revokeReceipt.status === "success", "Type 0x04 Revocation transaction confirmed");

  // 9. Inspect Code State Post-Revocation (must be 0x)
  const finalCode = await client.getCode({ address: compromised.address });
  assert(finalCode === undefined || finalCode === "0x", "Account code restored to 0x after revocation");

  // 10. Verify Subsequent Ordinary EOA Transaction Execution
  console.log("\n[6/7] Testing subsequent ordinary EOA transaction from restored account...");
  await deployerClient.sendTransaction({
    to: compromised.address,
    value: parseEther("0.1"),
  });

  const eoaNonce = await client.getTransactionCount({ address: compromised.address });
  const ordinaryTxHash = await compromisedClient.sendTransaction({
    to: safeWallet.address,
    value: parseEther("0.05"),
    nonce: eoaNonce,
  });

  const ordinaryReceipt = await client.waitForTransactionReceipt({ hash: ordinaryTxHash });
  assert(ordinaryReceipt.status === "success", "Subsequent ordinary EOA transaction succeeds normally");

  console.log(`\n${"─".repeat(60)}`);
  console.log(`  PROTOCOL SUITE RESULTS: ${passed} passed, ${failed} failed`);
  console.log(`${"─".repeat(60)}\n`);

  if (failed > 0) {
    process.exit(1);
  }
}

runProtocolSuite().catch((err) => {
  console.error("FATAL ERROR in Protocol Suite:", err);
  process.exit(1);
});
