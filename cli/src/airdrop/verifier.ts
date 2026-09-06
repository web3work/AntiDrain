/**
 * Protocol Code-Identity & Proxy Implementation Verifier
 *
 * Prevents TOCTOU upgrade attacks between simulation and execution
 * by verifying the bytecode hash of both the proxy and its underlying implementation.
 */

import {
  keccak256,
  type Address,
  type Hex,
  type PublicClient,
} from "viem";

// Standard ERC-1967 storage slots
export const ERC1967_IMPLEMENTATION_SLOT: Hex =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
export const ERC1967_BEACON_SLOT: Hex =
  "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

export interface ProtocolIdentity {
  targetAddress: Address;
  isProxy: boolean;
  proxyCodeHash: Hex;
  implementationAddress?: Address;
  implementationCodeHash?: Hex;
  beaconAddress?: Address;
}

/**
 * Inspect an airdrop contract and resolve its code identity and underlying implementation.
 */
export async function verifyProtocolIdentity(
  client: PublicClient,
  targetAddress: Address,
): Promise<ProtocolIdentity> {
  const code = await client.getCode({ address: targetAddress });
  if (!code || code === "0x") {
    throw new Error(`Target address ${targetAddress} has no bytecode deployed`);
  }

  const proxyCodeHash = keccak256(code);

  // Check ERC-1967 implementation slot
  let isProxy = false;
  let implementationAddress: Address | undefined;
  let implementationCodeHash: Hex | undefined;

  try {
    const rawImplSlot = await client.getStorageAt({
      address: targetAddress,
      slot: ERC1967_IMPLEMENTATION_SLOT,
    });

    if (rawImplSlot && rawImplSlot !== "0x0000000000000000000000000000000000000000000000000000000000000000") {
      const implAddr = `0x${rawImplSlot.slice(26)}` as Address;
      if (implAddr !== "0x0000000000000000000000000000000000000000") {
        isProxy = true;
        implementationAddress = implAddr;
        const implCode = await client.getCode({ address: implAddr });
        if (implCode && implCode !== "0x") {
          implementationCodeHash = keccak256(implCode);
        }
      }
    }
  } catch {}

  return {
    targetAddress,
    isProxy,
    proxyCodeHash,
    implementationAddress,
    implementationCodeHash,
  };
}
