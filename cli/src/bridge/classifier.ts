/**
 * AntiDrain Web3 Claim Interceptor Bridge — Calldata Classifier
 *
 * NOTE: Calldata classification is an INPUT PARSING & POLICY FILTER,
 * NOT a cryptographic security proof.
 */

import {
  type Address,
  type Hex,
  slice,
  decodeFunctionData,
  getAddress,
} from "viem";
import type { CalldataClassification } from "./types.js";

const MERKLE_CLAIM_INDEX_ABI = [
  {
    name: "claim",
    type: "function",
    inputs: [
      { name: "index", type: "uint256" },
      { name: "account", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "merkleProof", type: "bytes32[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

const MERKLE_CLAIM_NO_INDEX_ABI = [
  {
    name: "claim",
    type: "function",
    inputs: [
      { name: "account", type: "address" },
      { name: "amount", type: "uint256" },
      { name: "merkleProof", type: "bytes32[]" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

const ERC20_APPROVE_ABI = [
  {
    name: "approve",
    type: "function",
    inputs: [
      { name: "spender", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
  },
] as const;

const ERC20_INCREASE_ALLOWANCE_ABI = [
  {
    name: "increaseAllowance",
    type: "function",
    inputs: [
      { name: "spender", type: "address" },
      { name: "addedValue", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
  },
] as const;

const ERC721_SET_APPROVAL_FOR_ALL_ABI = [
  {
    name: "setApprovalForAll",
    type: "function",
    inputs: [
      { name: "operator", type: "address" },
      { name: "approved", type: "bool" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
] as const;

const ERC20_TRANSFER_ABI = [
  {
    name: "transfer",
    type: "function",
    inputs: [
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
  },
] as const;

const ERC20_TRANSFER_FROM_ABI = [
  {
    name: "transferFrom",
    type: "function",
    inputs: [
      { name: "from", type: "address" },
      { name: "to", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bool" }],
    stateMutability: "nonpayable",
  },
] as const;

export function classifyCalldata(
  target: Address,
  calldata: Hex,
  value: bigint,
  victimEOA: Address,
): CalldataClassification {
  const warnings: string[] = [];

  if (!calldata || calldata === "0x" || calldata.length < 10) {
    if (value > 0n) {
      return {
        type: "TRANSFER",
        selector: "0x00000000" as Hex,
        functionSignature: "nativeTransfer()",
        isPersistentApproval: false,
        hazardWarnings: ["Direct native ETH transfer with empty calldata."],
        recipient: target,
        claimedAmount: value,
      };
    }
    return {
      type: "UNKNOWN",
      selector: "0x" as Hex,
      isPersistentApproval: false,
      hazardWarnings: ["Empty calldata with zero value."],
    };
  }

  const selector = slice(calldata, 0, 4);

  // 1. Approvals
  if (selector === "0x095ea7b3") {
    try {
      const decoded = decodeFunctionData({
        abi: ERC20_APPROVE_ABI,
        data: calldata,
      });
      const spender = decoded.args[0];
      const amount = decoded.args[1];
      warnings.push(
        `APPROVAL HAZARD: Token approval of ${amount.toString()} to spender ${spender}. Creates persistent authority.`
      );
      return {
        type: "APPROVAL",
        selector,
        functionSignature: "approve(address,uint256)",
        decodedArgs: { spender, amount: amount.toString() },
        isPersistentApproval: true,
        hazardWarnings: warnings,
        recipient: spender,
      };
    } catch {
      warnings.push("Malformed approve() calldata.");
    }
  }

  if (selector === "0x39509351") {
    try {
      const decoded = decodeFunctionData({
        abi: ERC20_INCREASE_ALLOWANCE_ABI,
        data: calldata,
      });
      const spender = decoded.args[0];
      const addedValue = decoded.args[1];
      warnings.push(
        `APPROVAL HAZARD: increaseAllowance of ${addedValue.toString()} to spender ${spender}.`
      );
      return {
        type: "APPROVAL",
        selector,
        functionSignature: "increaseAllowance(address,uint256)",
        decodedArgs: { spender, addedValue: addedValue.toString() },
        isPersistentApproval: true,
        hazardWarnings: warnings,
        recipient: spender,
      };
    } catch {
      warnings.push("Malformed increaseAllowance() calldata.");
    }
  }

  if (selector === "0xa22cb465") {
    try {
      const decoded = decodeFunctionData({
        abi: ERC721_SET_APPROVAL_FOR_ALL_ABI,
        data: calldata,
      });
      const operator = decoded.args[0];
      const approved = decoded.args[1];
      warnings.push(
        `APPROVAL HAZARD: setApprovalForAll(${operator}, ${approved}). Grants full asset management authority.`
      );
      return {
        type: "APPROVAL",
        selector,
        functionSignature: "setApprovalForAll(address,bool)",
        decodedArgs: { operator, approved },
        isPersistentApproval: approved,
        hazardWarnings: warnings,
        recipient: operator,
      };
    } catch {
      warnings.push("Malformed setApprovalForAll() calldata.");
    }
  }

  if (selector === "0xd505accf") {
    warnings.push("PERMIT HAZARD: Off-chain permit authorization calldata detected.");
    return {
      type: "PERMIT",
      selector,
      functionSignature: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
      isPersistentApproval: true,
      hazardWarnings: warnings,
    };
  }

  // 2. Token Transfers
  if (selector === "0xa9059cbb") {
    try {
      const decoded = decodeFunctionData({
        abi: ERC20_TRANSFER_ABI,
        data: calldata,
      });
      return {
        type: "TRANSFER",
        selector,
        functionSignature: "transfer(address,uint256)",
        decodedArgs: { to: decoded.args[0], amount: decoded.args[1].toString() },
        isPersistentApproval: false,
        hazardWarnings: ["Direct token transfer operation."],
        targetToken: target,
        recipient: decoded.args[0],
        claimedAmount: decoded.args[1],
      };
    } catch {
      warnings.push("Malformed transfer() calldata.");
    }
  }

  if (selector === "0x23b872dd") {
    try {
      const decoded = decodeFunctionData({
        abi: ERC20_TRANSFER_FROM_ABI,
        data: calldata,
      });
      return {
        type: "TRANSFER",
        selector,
        functionSignature: "transferFrom(address,address,uint256)",
        decodedArgs: {
          from: decoded.args[0],
          to: decoded.args[1],
          amount: decoded.args[2].toString(),
        },
        isPersistentApproval: false,
        hazardWarnings: ["transferFrom() operation detected."],
        targetToken: target,
        recipient: decoded.args[1],
        claimedAmount: decoded.args[2],
      };
    } catch {
      warnings.push("Malformed transferFrom() calldata.");
    }
  }

  // 3. Claims
  if (selector === "0x2e7ba6ef") {
    try {
      const decoded = decodeFunctionData({
        abi: MERKLE_CLAIM_INDEX_ABI,
        data: calldata,
      });
      const index = decoded.args[0];
      const account = decoded.args[1];
      const amount = decoded.args[2];
      const normalizedAccount = getAddress(account);
      const normalizedVictim = getAddress(victimEOA);

      if (normalizedAccount !== normalizedVictim) {
        warnings.push(
          `RECIPIENT MISMATCH: Claim recipient (${normalizedAccount}) does not match victim EOA (${normalizedVictim}).`
        );
      }

      return {
        type: "CLAIM",
        selector,
        functionSignature: "claim(uint256,address,uint256,bytes32[])",
        decodedArgs: {
          index: index.toString(),
          account: normalizedAccount,
          amount: amount.toString(),
        },
        isPersistentApproval: false,
        hazardWarnings: warnings,
        recipient: normalizedAccount,
        claimedAmount: amount,
      };
    } catch {
      warnings.push("Failed to decode Merkle claim with index.");
    }
  }

  if (selector === "0x7b6f6345" || selector === "0x893d20e8") {
    try {
      const decoded = decodeFunctionData({
        abi: MERKLE_CLAIM_NO_INDEX_ABI,
        data: calldata,
      });
      const account = decoded.args[0];
      const amount = decoded.args[1];
      const normalizedAccount = getAddress(account);
      const normalizedVictim = getAddress(victimEOA);

      if (normalizedAccount !== normalizedVictim) {
        warnings.push(
          `RECIPIENT MISMATCH: Claim recipient (${normalizedAccount}) does not match victim EOA (${normalizedVictim}).`
        );
      }

      return {
        type: "CLAIM",
        selector,
        functionSignature: "claim(address,uint256,bytes32[])",
        decodedArgs: { account: normalizedAccount, amount: amount.toString() },
        isPersistentApproval: false,
        hazardWarnings: warnings,
        recipient: normalizedAccount,
        claimedAmount: amount,
      };
    } catch {
      warnings.push("Failed to decode Merkle claim without index.");
    }
  }

  if (selector === "0x4e71d92d") {
    return {
      type: "CLAIM",
      selector,
      functionSignature: "claim()",
      isPersistentApproval: false,
      hazardWarnings: warnings,
      recipient: victimEOA,
    };
  }

  // 4. Default Unknown
  warnings.push(`Unrecognized function selector ${selector}. Strict policy confirmation required.`);
  return {
    type: "UNKNOWN",
    selector,
    isPersistentApproval: false,
    hazardWarnings: warnings,
  };
}
