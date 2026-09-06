import {
  hashTypedData,
  keccak256,
  encodeAbiParameters,
  parseAbiParameters,
  encodePacked,
} from "viem";

const domain = {
  name: "AntiDrainRecovery",
  version: "1",
  chainId: 8453,
  verifyingContract: "0x333fd718F4a14d0518e4be77af68919D6BBb88F9",
};

const types = {
  Call: [
    { name: "target", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
  ],
  Rescue: [
    { name: "safeWallet", type: "address" },
    { name: "calls", type: "Call[]" },
    { name: "tokens", type: "address[]" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

const message = {
  safeWallet: "0x956Bb1434f43aBe9eAdb9564fa31e22A72b70cb5",
  calls: [
    {
      target: "0xBfc06549532E6119C4Bc0EFf167290EfdCA33fa6",
      value: 0n,
      data: "0x1d6ee8eb",
    },
  ],
  tokens: ["0x53f39e5C53EE40bbc3Da97C3B47BD2968d110a8D"],
  nonce: 0n,
  deadline: 1787238000n,
};

// 1. Viem canonical EIP-712 hash
const viemDigest = hashTypedData({
  domain,
  types,
  primaryType: "Rescue",
  message,
});

console.log("════════════════════════════════════════════════════════════");
console.log("  EIP-712 BYTE-FOR-BYTE DERIVATION & COMPARISON");
console.log("════════════════════════════════════════════════════════════\n");
console.log("Viem Canonical EIP-712 Digest: ", viemDigest);

// 2. Manual step-by-step Solidity equivalent calculation:
const CALL_TYPEHASH = keccak256(
  Buffer.from("Call(address target,uint256 value,bytes data)", "utf8")
);
const RESCUE_TYPEHASH = keccak256(
  Buffer.from(
    "Rescue(address safeWallet,Call[] calls,address[] tokens,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)",
    "utf8"
  )
);

console.log("CALL_TYPEHASH:                 ", CALL_TYPEHASH);
console.log("RESCUE_TYPEHASH:               ", RESCUE_TYPEHASH);

// Hash Call struct
const call0DataHash = keccak256(message.calls[0].data);
const call0Hash = keccak256(
  encodeAbiParameters(
    parseAbiParameters("bytes32, address, uint256, bytes32"),
    [CALL_TYPEHASH, message.calls[0].target, message.calls[0].value, call0DataHash]
  )
);
const callsHash = keccak256(call0Hash); // packed single element

// Hash tokens array: In EIP-712, array of address is keccak256(abi.encode(token0, token1...)) where each is 32-byte word
const token0Encoded = encodeAbiParameters(parseAbiParameters("address"), [message.tokens[0]]);
const tokensHash = keccak256(token0Encoded);

console.log("Calculated callsHash:          ", callsHash);
console.log("Calculated tokensHash:         ", tokensHash);

// Struct hash
const structHash = keccak256(
  encodeAbiParameters(
    parseAbiParameters("bytes32, address, bytes32, bytes32, uint256, uint256"),
    [
      RESCUE_TYPEHASH,
      message.safeWallet,
      callsHash,
      tokensHash,
      message.nonce,
      message.deadline,
    ]
  )
);

console.log("Calculated structHash:         ", structHash);

// Domain separator
const EIP712_DOMAIN_TYPEHASH = keccak256(
  Buffer.from(
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    "utf8"
  )
);
const domainSeparator = keccak256(
  encodeAbiParameters(
    parseAbiParameters("bytes32, bytes32, bytes32, uint256, address"),
    [
      EIP712_DOMAIN_TYPEHASH,
      keccak256(Buffer.from(domain.name, "utf8")),
      keccak256(Buffer.from(domain.version, "utf8")),
      BigInt(domain.chainId),
      domain.verifyingContract,
    ]
  )
);

console.log("Calculated Domain Separator:   ", domainSeparator);

// Final digest
const manualDigest = keccak256(
  encodePacked(
    ["string", "bytes32", "bytes32"],
    ["\x19\x01", domainSeparator, structHash]
  )
);

console.log("Manual Step Digest:            ", manualDigest);
console.log("Byte-for-Byte Exact Match:     ", viemDigest === manualDigest ? "YES ✅" : "NO ❌");
