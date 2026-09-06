import {
  hashTypedData,
  keccak256,
  encodeAbiParameters,
  parseAbiParameters,
  encodePacked,
  recoverAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

const account = privateKeyToAccount(
  "0x2222222222222222222222222222222222222222222222222222222222222222"
);

const baseDomain = {
  name: "AntiDrainRecovery",
  version: "1",
  chainId: 8453,
  verifyingContract: account.address,
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

const baseMessage = {
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

const baselineDigest = hashTypedData({
  domain: baseDomain,
  types,
  primaryType: "Rescue",
  message: baseMessage,
});

const baselineSig = await account.signTypedData({
  domain: baseDomain,
  types,
  primaryType: "Rescue",
  message: baseMessage,
});

console.log("════════════════════════════════════════════════════════════");
console.log("  SECTION 2: EIP-712 COMPREHENSIVE NEGATIVE TEST MATRIX");
console.log("════════════════════════════════════════════════════════════\n");
console.log("Baseline Digest: ", baselineDigest);
console.log("Signer:          ", account.address);

const mutations = [
  {
    name: "A. safeWallet",
    domain: baseDomain,
    message: {
      ...baseMessage,
      safeWallet: "0x000000000000000000000000000000000000dEaD",
    },
  },
  {
    name: "B. calls[0].target",
    domain: baseDomain,
    message: {
      ...baseMessage,
      calls: [
        {
          target: "0x000000000000000000000000000000000000dEaD",
          value: 0n,
          data: "0x1d6ee8eb",
        },
      ],
    },
  },
  {
    name: "C. calls[0].value",
    domain: baseDomain,
    message: {
      ...baseMessage,
      calls: [
        {
          target: "0xBfc06549532E6119C4Bc0EFf167290EfdCA33fa6",
          value: 1000000000000000000n, // 1 ETH
          data: "0x1d6ee8eb",
        },
      ],
    },
  },
  {
    name: "D. calls[0].data",
    domain: baseDomain,
    message: {
      ...baseMessage,
      calls: [
        {
          target: "0xBfc06549532E6119C4Bc0EFf167290EfdCA33fa6",
          value: 0n,
          data: "0xdeadbeef",
        },
      ],
    },
  },
  {
    name: "E. calls array length (added call)",
    domain: baseDomain,
    message: {
      ...baseMessage,
      calls: [
        ...baseMessage.calls,
        {
          target: "0x1111111111111111111111111111111111111111",
          value: 0n,
          data: "0x",
        },
      ],
    },
  },
  {
    name: "F. calls ordering (swapped)",
    domain: baseDomain,
    message: {
      ...baseMessage,
      calls: [
        {
          target: "0x1111111111111111111111111111111111111111",
          value: 0n,
          data: "0x",
        },
        baseMessage.calls[0],
      ],
    },
  },
  {
    name: "G. tokens[0]",
    domain: baseDomain,
    message: {
      ...baseMessage,
      tokens: ["0x000000000000000000000000000000000000dEaD"],
    },
  },
  {
    name: "H. tokens array ordering (swapped)",
    domain: baseDomain,
    message: {
      ...baseMessage,
      tokens: [
        "0x1111111111111111111111111111111111111111",
        baseMessage.tokens[0],
      ],
    },
  },
  {
    name: "I. nonce",
    domain: baseDomain,
    message: {
      ...baseMessage,
      nonce: 1n,
    },
  },
  {
    name: "J. deadline",
    domain: baseDomain,
    message: {
      ...baseMessage,
      deadline: baseMessage.deadline + 3600n,
    },
  },
  {
    name: "K. chainId",
    domain: { ...baseDomain, chainId: 1 },
    message: baseMessage,
  },
  {
    name: "L. verifyingContract",
    domain: {
      ...baseDomain,
      verifyingContract: "0x000000000000000000000000000000000000dEaD",
    },
    message: baseMessage,
  },
  {
    name: "M. domain name",
    domain: { ...baseDomain, name: "AntiDrainRecoveryV2" },
    message: baseMessage,
  },
  {
    name: "N. domain version",
    domain: { ...baseDomain, version: "2" },
    message: baseMessage,
  },
];

let allPassed = true;
for (const mut of mutations) {
  const mutDigest = hashTypedData({
    domain: mut.domain,
    types,
    primaryType: "Rescue",
    message: mut.message,
  });

  const recovered = await recoverAddress({
    hash: mutDigest,
    signature: baselineSig,
  });

  const digestChanged = mutDigest !== baselineDigest;
  const authFailed = recovered.toLowerCase() !== account.address.toLowerCase();

  const pass = digestChanged && authFailed;
  if (!pass) allPassed = false;

  console.log(
    `[${pass ? "PASS" : "FAIL"}] ${mut.name.padEnd(38)} | Digest Changed: ${digestChanged} | Auth Rejected: ${authFailed}`
  );
}

// Edge Cases:
console.log("\n─── Edge Case Assertions ───");
const edgeCases = [
  {
    name: "Empty calls[]",
    domain: baseDomain,
    message: { ...baseMessage, calls: [] },
  },
  {
    name: "Empty tokens[]",
    domain: baseDomain,
    message: { ...baseMessage, tokens: [] },
  },
  {
    name: "Multiple calls (5 calls)",
    domain: baseDomain,
    message: {
      ...baseMessage,
      calls: Array(5).fill(baseMessage.calls[0]),
    },
  },
  {
    name: "Multiple tokens (5 tokens)",
    domain: baseDomain,
    message: {
      ...baseMessage,
      tokens: Array(5).fill(baseMessage.tokens[0]),
    },
  },
  {
    name: "Dynamic bytes calldata (1024 bytes payload)",
    domain: baseDomain,
    message: {
      ...baseMessage,
      calls: [
        {
          target: baseMessage.calls[0].target,
          value: 0n,
          data: "0x" + "aa".repeat(1024),
        },
      ],
    },
  },
];

for (const ec of edgeCases) {
  const digest = hashTypedData({
    domain: ec.domain,
    types,
    primaryType: "Rescue",
    message: ec.message,
  });
  const sig = await account.signTypedData({
    domain: ec.domain,
    types,
    primaryType: "Rescue",
    message: ec.message,
  });
  const recovered = await recoverAddress({
    hash: digest,
    signature: sig,
  });
  const valid = recovered.toLowerCase() === account.address.toLowerCase();
  console.log(`[${valid ? "PASS" : "FAIL"}] ${ec.name.padEnd(45)} | Recovered: ${recovered.slice(0, 10)}... (Match: ${valid})`);
}

console.log("\nOverall Negative Matrix Result:", allPassed ? "100% PROVEN ✅" : "FAILED ❌");
