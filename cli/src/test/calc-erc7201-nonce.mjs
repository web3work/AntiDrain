import { keccak256, toHex, encodeAbiParameters, parseAbiParameters } from "viem";

const id = "antidrain.universalRecoveryDelegate.nonce.v1";
const h1 = keccak256(Buffer.from(id, "utf8"));
const h1BigInt = BigInt(h1);
const h1Minus1 = h1BigInt - 1n;

// ERC-7201 formula:
// keccak256(abi.encode(uint256(keccak256(id)) - 1)) & ~bytes32(uint256(0xff))
const encoded = encodeAbiParameters(parseAbiParameters("uint256"), [h1Minus1]);
const h2 = keccak256(encoded);
const h2BigInt = BigInt(h2);
const mask = ~0xffn & ((1n << 256n) - 1n);
const erc7201Slot = h2BigInt & mask;
const erc7201SlotHex = "0x" + erc7201Slot.toString(16).padStart(64, "0");

console.log("Namespace ID:           ", id);
console.log("keccak256(id):          ", h1);
console.log("uint256(h1) - 1:        ", "0x" + h1Minus1.toString(16).padStart(64, "0"));
console.log("keccak256(encoded):     ", h2);
console.log("ERC-7201 Derived Slot:  ", erc7201SlotHex);
