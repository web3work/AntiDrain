/**
 * CREATE2 Deterministic Deployment Module
 *
 * Handles deployment and verification of UniversalRecoveryDelegate via
 * the deterministic deployer factory at 0x4e59b44847b379578588920cA78FbF26c0B4956C.
 *
 * FACTORY PROTOCOL:
 * The factory ("Nick's Factory" / Arachnid Factory) accepts a raw transaction with:
 *   calldata = [32-byte salt] + [init code (creation bytecode)]
 * It executes CREATE2 and deploys the contract to a deterministic address:
 *   address = keccak256(0xff ++ factory ++ salt ++ keccak256(initCode))[12:]
 *
 * CANONICAL DELEGATE MODEL (Per-User Sponsor Architecture):
 * - One canonical delegate contract is deployed per chain.
 * - The delegate has NO constructor arguments and NO immutable SPONSOR state.
 * - Sponsor identity is independent of delegate identity.
 * - Sponsor authorization is cryptographically enforced via victim EIP-712 signature binding msg.sender.
 */

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  keccak256,
  concat,
  getAddress,
} from "viem";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// ─── Constants ────────────────────────────────────────────────────────────

/** Nick's Factory / Deterministic Deployment Proxy — same address on all EVM chains */
export const CREATE2_FACTORY: Address = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/** Salt for AntiDrain v2 rescue delegate deployment (keccak256("AntiDrain_Rescue_v2")) */
export const DEPLOYMENT_SALT: Hex = "0x1e3b023964cf3e3601ba97c6ba650dffa05267c991945dedba0e87733b5690e4";

/** Canonical CREATE2 delegate address across all EVM chains */
export const CANONICAL_DELEGATE_ADDRESS: Address = "0x60BAf255624BEE5629e5D86Ae8976aF19795A314";

/** Canonical runtime bytecode hash */
export const CANONICAL_BYTECODE_HASH: Hex = "0x4933ce6f42ff5ec5332c4e46e00e3f73a0e185ea03cc98418f030a05aca7a2dd";

// ─── Address Prediction ───────────────────────────────────────────────────

/**
 * Compute the CREATE2 predicted deployment address.
 *
 * Formula: address(uint160(uint256(keccak256(abi.encodePacked(
 *   bytes1(0xff), factory, salt, keccak256(initCode)
 * )))))
 */
export function predictCreate2Address(
  factory: Address = CREATE2_FACTORY,
  salt: Hex = DEPLOYMENT_SALT,
  initCodeHash?: Hex,
): Address {
  const codeHash = initCodeHash ?? keccak256(loadCreationBytecode());
  const data = concat([
    "0xff",
    factory,
    salt,
    codeHash,
  ]);
  const hash = keccak256(data);
  return getAddress(`0x${hash.slice(26)}`);
}

/**
 * Load the creation bytecode from the Foundry artifact.
 */
export function loadCreationBytecode(): Hex {
  const artifactPath = join(
    process.cwd(),
    "..",
    "contracts",
    "out",
    "UniversalRecoveryDelegate.sol",
    "UniversalRecoveryDelegate.json",
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  return artifact.bytecode.object as Hex;
}

/**
 * Load the deployed runtime bytecode from the Foundry artifact.
 */
export function loadRuntimeBytecode(): Hex {
  const artifactPath = join(
    process.cwd(),
    "..",
    "contracts",
    "out",
    "UniversalRecoveryDelegate.sol",
    "UniversalRecoveryDelegate.json",
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8"));
  return artifact.deployedBytecode.object as Hex;
}

// ─── Deployment Verification ──────────────────────────────────────────────

export interface DeploymentVerification {
  /** Whether the contract needs to be deployed */
  needsDeployment: boolean;
  /** Whether the deployed runtime bytecode matches the compiled artifact */
  codeHashMatch?: boolean;
  /** The deployed runtime bytecode hash */
  codeHash?: Hex;
  /** The expected runtime bytecode hash */
  expectedCodeHash?: Hex;
  /** The predicted CREATE2 address */
  predictedAddress?: Address;
}

/**
 * Verify the delegate deployment at a given address.
 *
 * Checks:
 * 1. Code exists at the address
 * 2. The deployed runtime bytecode hash exactly matches the canonical compiled artifact
 */
export async function verifyDelegateDeployment(
  client: PublicClient<any, any>,
  _walletClient?: WalletClient<any, any, any>,
  _expectedSponsor?: Address,
  delegateAddress?: Address,
): Promise<DeploymentVerification> {
  const targetAddress = delegateAddress ?? CANONICAL_DELEGATE_ADDRESS;
  const code = await client.getCode({ address: targetAddress }).catch(() => undefined);

  if (!code || code === "0x" || targetAddress === "0x0000000000000000000000000000000000000000") {
    return { needsDeployment: true, predictedAddress: targetAddress };
  }

  const expectedCodeHash = CANONICAL_BYTECODE_HASH;
  const codeHash = keccak256(code);

  if (codeHash !== expectedCodeHash) {
    console.error(
      `  ✗ CRITICAL: Runtime bytecode mismatch at ${targetAddress}!\n` +
      `    Actual:   ${codeHash}\n` +
      `    Expected: ${expectedCodeHash}`,
    );
    return {
      needsDeployment: false,
      codeHashMatch: false,
      codeHash,
      expectedCodeHash,
      predictedAddress: targetAddress,
    };
  }

  return {
    needsDeployment: false,
    codeHashMatch: true,
    codeHash,
    expectedCodeHash,
    predictedAddress: targetAddress,
  };
}

/**
 * Deploy the delegate contract via the CREATE2 factory.
 *
 * PROTOCOL:
 * Send a transaction to the factory with calldata = salt + creationBytecode
 * The factory executes CREATE2(salt, initCode) internally.
 */
export async function deployDelegateViaCreate2(
  client: PublicClient<any, any>,
  walletClient: WalletClient<any, any, any>,
  deployerAddress: Address,
): Promise<{ address: Address; codeHash: Hex }> {
  // 1. Build init code
  const creationBytecode = loadCreationBytecode();
  const initCodeHash = keccak256(creationBytecode);
  const expectedRuntimeHash = CANONICAL_BYTECODE_HASH;

  // 2. Predict address
  const predictedAddress = predictCreate2Address(CREATE2_FACTORY, DEPLOYMENT_SALT, initCodeHash);

  console.log(`  CREATE2 Deployment:`);
  console.log(`    Factory:               ${CREATE2_FACTORY}`);
  console.log(`    Salt:                  ${DEPLOYMENT_SALT}`);
  console.log(`    Init Code Hash:        ${initCodeHash}`);
  console.log(`    Expected Runtime Hash: ${expectedRuntimeHash}`);
  console.log(`    Predicted Address:     ${predictedAddress}`);

  // 3. Check if already deployed
  const existingCode = await client.getCode({ address: predictedAddress }).catch(() => undefined);
  if (existingCode && existingCode !== "0x") {
    const actualExistingHash = keccak256(existingCode);
    if (actualExistingHash !== expectedRuntimeHash) {
      throw new Error(
        `CRITICAL SECURITY ALERT: Code exists at predicted address ${predictedAddress} ` +
        `but its runtime bytecode hash (${actualExistingHash}) DOES NOT MATCH ` +
        `expected runtime bytecode hash (${expectedRuntimeHash}). ` +
        `The address contains untrusted/modified code. STOPPING.`,
      );
    }

    console.log(`    ✓ Already deployed with verified runtime bytecode`);
    return { address: predictedAddress, codeHash: actualExistingHash };
  }

  // 4. Deploy: send salt + creationBytecode to factory
  const deployCalldata = concat([DEPLOYMENT_SALT, creationBytecode]) as Hex;

  const deployHash = await walletClient.sendTransaction({
    account: walletClient.account ?? (deployerAddress as any),
    to: CREATE2_FACTORY,
    data: deployCalldata,
    gas: 1_000_000n,
  } as any);

  console.log(`    Deploy TX: ${deployHash}`);

  const receipt = await client.waitForTransactionReceipt({
    hash: deployHash,
    timeout: 60_000,
  });

  if (receipt.status === "reverted") {
    throw new Error(`CREATE2 deployment transaction reverted: ${deployHash}`);
  }

  // 5. Post-deployment verification with retry loop (handles RPC replica propagation delay)
  let deployedCode: Hex | undefined;
  for (let attempt = 0; attempt < 5; attempt++) {
    deployedCode = await client.getCode({ address: predictedAddress });
    if (deployedCode && deployedCode !== "0x") break;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  if (!deployedCode || deployedCode === "0x") {
    throw new Error(
      `Deployment transaction succeeded but no code at predicted address ${predictedAddress}. ` +
      `This should never happen — possible chain issue.`,
    );
  }

  const deployedCodeHash = keccak256(deployedCode);
  if (deployedCodeHash !== expectedRuntimeHash) {
    throw new Error(
      `CRITICAL DEPLOYMENT CORRUPTION: Deployed code at ${predictedAddress} ` +
      `runtime bytecode hash (${deployedCodeHash}) DOES NOT MATCH ` +
      `expected runtime bytecode hash (${expectedRuntimeHash}). ` +
      `DO NOT USE THIS DEPLOYMENT. STOPPING.`,
    );
  }

  console.log(`    ✓ Deployed at:    ${predictedAddress}`);
  console.log(`    ✓ Code Hash:      ${deployedCodeHash} (verified equal to expected artifact)`);

  return { address: predictedAddress, codeHash: deployedCodeHash };
}
