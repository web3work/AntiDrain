/**
 * OneFootball 11-Point Validation & Exact Value Flow Verification Suite
 *
 * Proves that:
 * 1. The 11-point precondition validator catches all forged/stale/corrupted inputs.
 * 2. Exact value accounting is enforced (calls[0].value == liveFeeWei, outer value == calls[0].value, 0 overfunding).
 * 3. Selector encoding matches production claim(uint256,uint256,bytes) -> 0x5eddd157.
 * 4. Victim EOA != Safe wallet invariant is enforced.
 * 5. Deterministic RescuePlan is correctly constructed.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ONEFOOTBALL_DISTRIBUTOR,
  ONEFOOTBALL_OFC_TOKEN,
  ONEFOOTBALL_AUTHORIZED_SIGNER,
  ONEFOOTBALL_CHAIN_ID,
  validateOneFootballPreconditions,
  buildOneFootballRescuePlan,
  type OneFootballVoucher,
} from "../airdrop/onefootball.js";
import { type Address, type Hex } from "viem";

const MOCK_VICTIM = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as Address;
const MOCK_SPONSOR = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" as Address;
const MOCK_SAFE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as Address;
const CLAIM_AMOUNT = 1028000000000000000000n; // 1028 OFC
const LIVE_FEE = 802581101000000n; // 0.000802581101 ETH
const FUTURE_DEADLINE = BigInt(Math.floor(Date.now() / 1000) + 7200);

function createMockClient(overrides: Partial<any> = {}) {
  return {
    getBlock: async () => ({
      timestamp: BigInt(Math.floor(Date.now() / 1000)),
    }),
    getCode: async () => (overrides.code !== undefined ? overrides.code : "0x1234"),
    readContract: async ({ functionName }: { functionName: string }) => {
      if (functionName === "authorizedSigner") return overrides.authorizedSigner || ONEFOOTBALL_AUTHORIZED_SIGNER;
      if (functionName === "claimFeeWei") return overrides.claimFeeWei !== undefined ? overrides.claimFeeWei : LIVE_FEE;
      if (functionName === "getNonce") return overrides.getNonce !== undefined ? overrides.getNonce : 0n;
      if (functionName === "claimedAmount") return overrides.claimedAmount !== undefined ? overrides.claimedAmount : 0n;
      return 0n;
    },
    call: async () => ({ data: "0x" as Hex }),
    ...overrides,
  } as any;
}

const VALID_VOUCHER: OneFootballVoucher = {
  amount: CLAIM_AMOUNT.toString(),
  deadline: FUTURE_DEADLINE.toString(),
  signature: ("0x" + "aa".repeat(65)) as Hex,
  contractAddress: ONEFOOTBALL_DISTRIBUTOR,
  account: MOCK_VICTIM,
};

describe("OneFootball Precondition & Value Accounting Suite", () => {
  it("passes all 11 precondition checks with valid inputs", async () => {
    const client = createMockClient();
    const result = await validateOneFootballPreconditions(
      client,
      VALID_VOUCHER,
      MOCK_VICTIM,
      MOCK_SAFE,
    );

    assert.equal(result.valid, true, `Validation failed with: ${result.errors.join(", ")}`);
    assert.equal(result.claimFeeWei, LIVE_FEE);
    assert.equal(result.amount, CLAIM_AMOUNT);
    assert.equal(result.call.value, LIVE_FEE, "Call value must equal exact live fee");
    assert.equal(result.call.target, ONEFOOTBALL_DISTRIBUTOR);
    assert.equal(result.call.data.slice(0, 10).toLowerCase(), "0x5eddd157", "Calldata must start with 0x5eddd157");
  });

  it("builds a deterministic RescuePlan with exact fee and zero overfunding", async () => {
    const client = createMockClient();
    const result = await validateOneFootballPreconditions(
      client,
      VALID_VOUCHER,
      MOCK_VICTIM,
      MOCK_SAFE,
    );

    const plan = buildOneFootballRescuePlan(MOCK_VICTIM, MOCK_SPONSOR, MOCK_SAFE, result);

    assert.equal(plan.chainId, ONEFOOTBALL_CHAIN_ID);
    assert.equal(plan.compromisedAddress, MOCK_VICTIM);
    assert.equal(plan.sponsorAddress, MOCK_SPONSOR);
    assert.equal(plan.safeWallet, MOCK_SAFE);
    assert.equal(plan.calls.length, 1);
    assert.equal(plan.calls[0].value, LIVE_FEE, "Planner must assign exact claim fee with zero overfunding");
    assert.equal(plan.tokens.length, 1);
    assert.equal(plan.tokens[0], ONEFOOTBALL_OFC_TOKEN);
  });

  it("fails if voucher deadline is expired", async () => {
    const expiredVoucher: OneFootballVoucher = {
      ...VALID_VOUCHER,
      deadline: "1000", // Way in the past
    };
    const client = createMockClient();
    const result = await validateOneFootballPreconditions(
      client,
      expiredVoucher,
      MOCK_VICTIM,
      MOCK_SAFE,
    );

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("deadline")));
  });

  it("fails if safeWallet equals victim address (anti-self-sweep invariant)", async () => {
    const client = createMockClient();
    const result = await validateOneFootballPreconditions(
      client,
      VALID_VOUCHER,
      MOCK_VICTIM,
      MOCK_VICTIM, // Invalid: safe is same as victim
    );

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("safeWallet cannot equal")));
  });

  it("fails if voucher contractAddress does not match production distributor", async () => {
    const wrongContractVoucher: OneFootballVoucher = {
      ...VALID_VOUCHER,
      contractAddress: "0x1111111111111111111111111111111111111111" as Address,
    };
    const client = createMockClient();
    const result = await validateOneFootballPreconditions(
      client,
      wrongContractVoucher,
      MOCK_VICTIM,
      MOCK_SAFE,
    );

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("contractAddress")));
  });

  it("fails if on-chain authorizedSigner does not match expected signer", async () => {
    const client = createMockClient({
      authorizedSigner: "0x0000000000000000000000000000000000000001" as Address,
    });
    const result = await validateOneFootballPreconditions(
      client,
      VALID_VOUCHER,
      MOCK_VICTIM,
      MOCK_SAFE,
      { expectedSigner: ONEFOOTBALL_AUTHORIZED_SIGNER },
    );

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("authorizedSigner")));
  });

  it("fails if distributor contract has zero address as authorizedSigner", async () => {
    const client = createMockClient({
      authorizedSigner: "0x0000000000000000000000000000000000000000" as Address,
    });
    const result = await validateOneFootballPreconditions(
      client,
      VALID_VOUCHER,
      MOCK_VICTIM,
      MOCK_SAFE,
    );

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("no active authorizedSigner")));
  });

  it("fails if direct claim simulation reverts", async () => {
    const client = createMockClient({
      call: async () => {
        throw new Error("Execution reverted: InsufficientFee");
      },
    });
    const result = await validateOneFootballPreconditions(
      client,
      VALID_VOUCHER,
      MOCK_VICTIM,
      MOCK_SAFE,
    );

    assert.equal(result.valid, false);
    assert.ok(result.errors.some((e) => e.includes("Check 11 Failed")));
  });
});
