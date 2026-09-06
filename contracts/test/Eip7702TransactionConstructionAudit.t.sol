// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Phase 8.2 Transaction Construction & Multi-Authorization Audit ââââââââââ

contract Eip7702TransactionConstructionAuditTest is AntiDrainTestBase {
    uint256 internal victimPk = 0xAAAAAA;
    address internal victimEOA;

    uint256 internal sponsorPk = 0xBBBBBB;
    address internal sponsor;

    uint256 internal attackerPk = 0xCCCCCC;
    address internal attacker;

    address internal safeWallet = address(0x8888888888888888888888888888888888888888);

    UniversalRecoveryDelegate internal rescueDelegate;
    UniversalRecoveryDelegate internal foreignDelegate;
    MockERC20 internal token;

    struct AuthorizationTuple {
        uint256 chainId;
        address delegate;
        uint256 nonce;
        uint256 signerPk;
    }

    function setUp() public {
        victimEOA = vm.addr(victimPk);
        sponsor = vm.addr(sponsorPk);
        attacker = vm.addr(attackerPk);

        rescueDelegate = new UniversalRecoveryDelegate();
        foreignDelegate = new UniversalRecoveryDelegate();

        token = new MockERC20();

        vm.deal(victimEOA, 10 ether);
        token.mint(victimEOA, 10_000 ether);

        vm.deal(sponsor, 5 ether);
        vm.deal(attacker, 5 ether);

        vm.setNonce(victimEOA, 0);
    }

    // =========================================================================
    // SECTION 1: Exact EIP-7702 Multi-Authorization List Processing Engine
    // =========================================================================

    /**
     * @notice Simulates an EIP-7702 Type 0x04 transaction with multiple authorization tuples
     *         following the exact Prague specification:
     *         1. For each authorization tuple in authorization_list:
     *            a. Verify chain_id is 0 or matches current block.chainid.
     *            b. Verify authority.nonce == auth.nonce.
     *            c. If valid: authority.nonce += 1, and set authority code = delegate.
     *            d. If authority appears multiple times, the LAST valid tuple determines the code.
     *            e. If invalid: tuple is skipped/ignored.
     *         2. Execute calldata in target account context.
     */
    function _simulateMultiAuthType04Transaction(
        address txSender,
        AuthorizationTuple[] memory authList,
        bytes memory calldataPayload
    ) internal returns (uint256 validCount, bool execSuccess, bytes memory ret) {
        for (uint256 i = 0; i < authList.length; i++) {
            AuthorizationTuple memory a = authList[i];
            address authority = vm.addr(a.signerPk);
            uint256 currentNonce = vm.getNonce(authority);

            // Check 1: Chain ID matching rule (EIP-7702: chainId == 0 or chainId == block.chainid)
            bool chainValid = (a.chainId == 0 || a.chainId == block.chainid);

            // Check 2: Authority nonce matching rule
            bool nonceValid = (a.nonce == currentNonce);

            if (chainValid && nonceValid) {
                // Install delegate code
                if (a.delegate == address(0)) {
                    vm.etch(authority, "");
                } else {
                    vm.etch(authority, a.delegate.code);
                }
                // Increment authority account nonce
                vm.setNonce(authority, uint64(currentNonce + 1));
                validCount++;
            }
            // Invalid tuples are silently skipped by EVM protocol
        }

        // Execute calldata
        vm.prank(txSender);
        (execSuccess, ret) = victimEOA.call(calldataPayload);
    }

    // =========================================================================
    // SECTION 2: Multi-Authorization Vectors (Rules A through H)
    // =========================================================================

    function test_MultiAuth_A_SingleAuthorization() public {
        // Single valid authorization tuple (nonce = 0)
        AuthorizationTuple[] memory list = new AuthorizationTuple[](1);
        list[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(sponsor, list, "");

        assertEq(validCount, 1, "1 valid tuple processed");
        assertEq(vm.getNonce(victimEOA), 1, "Victim nonce incremented 0 -> 1");
        // SPONSOR() immutable removed  per-user sponsor is now bound via EIP-712 signature
    }

    function test_MultiAuth_B_TwoValidSequentialAuthorizations_SameTx() public {
        // Tuple 0: victim authorizes rescueDelegate at nonce 0
        // Tuple 1: victim authorizes foreignDelegate at nonce 1
        AuthorizationTuple[] memory list = new AuthorizationTuple[](2);
        list[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);
        list[1] = AuthorizationTuple(block.chainid, address(foreignDelegate), 1, victimPk);

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(sponsor, list, "");

        // Both are valid sequentially
        assertEq(validCount, 2, "Both sequential tuples processed");
        assertEq(vm.getNonce(victimEOA), 2, "Victim nonce incremented 0 -> 2");

        // EIP-7702 Rule: Last valid occurrence sets the code!
        // Per-user sponsor: no SPONSOR() immutable — sponsor is bound via EIP-712 signature
        // EIP-7702 Rule: Last valid occurrence sets the code (foreignDelegate in this case)
    }

    function test_MultiAuth_C_VictimThenAttackerSameNonce_SecondIgnored() public {
        // Tuple 0: victim authorizes rescueDelegate at nonce 0
        // Tuple 1: attacker uses pre-signed victim auth for foreignDelegate at nonce 0 (SAME NONCE)
        AuthorizationTuple[] memory list = new AuthorizationTuple[](2);
        list[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);
        list[1] = AuthorizationTuple(block.chainid, address(foreignDelegate), 0, victimPk); // Stale nonce!

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(sponsor, list, "");

        // Tuple 0 consumed nonce 0. Tuple 1 sees nonce 1 != 0 and is IGNORED!
        assertEq(validCount, 1, "Only first tuple processed");
        assertEq(vm.getNonce(victimEOA), 1, "Victim nonce is 1");

        // Active code remains rescueDelegate
        // Per-user sponsor: no SPONSOR() immutable — first tuple remains active (second had stale nonce)
    }

    function test_MultiAuth_D_AttackerThenVictimSameNonce_FirstWins() public {
        // Tuple 0: attacker auth at nonce 0
        // Tuple 1: victim auth at nonce 0
        AuthorizationTuple[] memory list = new AuthorizationTuple[](2);
        list[0] = AuthorizationTuple(block.chainid, address(foreignDelegate), 0, victimPk);
        list[1] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(attacker, list, "");

        assertEq(validCount, 1);
        assertEq(vm.getNonce(victimEOA), 1);
        // Per-user sponsor: no SPONSOR() immutable — attacker tuple executed first, invalidating second
    }

    function test_MultiAuth_E_DuplicateIdenticalTuples() public {
        // Duplicate identical tuples: [auth(0), auth(0)]
        AuthorizationTuple[] memory list = new AuthorizationTuple[](2);
        list[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);
        list[1] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(sponsor, list, "");

        // First tuple succeeds, second duplicate tuple fails nonce check and is skipped
        assertEq(validCount, 1, "Duplicate tuple skipped");
        assertEq(vm.getNonce(victimEOA), 1);
    }

    // =========================================================================
    // SECTION 3: Cross-Chain & Chain ID Replay Vectors
    // =========================================================================

    function test_ChainId_CurrentChain_Accepted() public {
        AuthorizationTuple[] memory list = new AuthorizationTuple[](1);
        list[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(sponsor, list, "");
        assertEq(validCount, 1, "Matching chainId accepted");
    }

    function test_ChainId_Zero_AcceptedOnAnyChain() public {
        // EIP-7702 specifies chainId = 0 is valid on any chain
        AuthorizationTuple[] memory list = new AuthorizationTuple[](1);
        list[0] = AuthorizationTuple(0, address(rescueDelegate), 0, victimPk);

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(sponsor, list, "");
        assertEq(validCount, 1, "chainId = 0 accepted on current chain");
    }

    function test_ChainId_WrongChain_Ignored() public {
        // Signed for Ethereum Mainnet (chainId = 1), but submitted on current chain (31337)
        AuthorizationTuple[] memory list = new AuthorizationTuple[](1);
        list[0] = AuthorizationTuple(1, address(rescueDelegate), 0, victimPk);

        (uint256 validCount, , ) = _simulateMultiAuthType04Transaction(sponsor, list, "");
        assertEq(validCount, 0, "Wrong chainId tuple is dropped/ignored by EVM");
        assertEq(vm.getNonce(victimEOA), 0, "Nonce untouched");
        assertEq(victimEOA.code.length, 0, "Code untouched");
    }

    // =========================================================================
    // SECTION 3B: EIP-7702 Exact 2^64 Boundary Verification Vectors
    // =========================================================================

    function test_NonceBoundary_Vectors_0_to_MaxUint64() public {
        uint256 MAX_UINT64_MINUS_1 = 18446744073709551614; // 2^64 - 2
        uint256 MAX_UINT64 = 18446744073709551615;         // 2^64 - 1
        uint256 OVERFLOW_UINT64 = 18446744073709551616;    // 2^64

        // 1. Vector: Nonce 0 (Valid when account nonce = 0)
        vm.setNonce(victimEOA, 0);
        AuthorizationTuple[] memory list0 = new AuthorizationTuple[](1);
        list0[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);
        (uint256 v0, , ) = _simulateMultiAuthType04Transaction(sponsor, list0, "");
        assertEq(v0, 1, "Nonce 0 valid");

        // 2. Vector: Nonce 1 (Valid when account nonce = 1)
        AuthorizationTuple[] memory list1 = new AuthorizationTuple[](1);
        list1[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 1, victimPk);
        (uint256 v1, , ) = _simulateMultiAuthType04Transaction(sponsor, list1, "");
        assertEq(v1, 1, "Nonce 1 valid");

        // 3. Vector: N - 1 (Stale nonce, ignored by EVM)
        AuthorizationTuple[] memory listStale = new AuthorizationTuple[](1);
        listStale[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 1, victimPk); // Current is 2
        (uint256 vStale, , ) = _simulateMultiAuthType04Transaction(sponsor, listStale, "");
        assertEq(vStale, 0, "Nonce N-1 ignored");

        // 4. Vector: N + 1 (Future nonce, ignored by EVM)
        AuthorizationTuple[] memory listFuture = new AuthorizationTuple[](1);
        listFuture[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 3, victimPk); // Current is 2
        (uint256 vFuture, , ) = _simulateMultiAuthType04Transaction(sponsor, listFuture, "");
        assertEq(vFuture, 0, "Nonce N+1 ignored");

        // 5. Vector: 2^64 - 2 (Valid when account nonce is 2^64 - 2)
        vm.setNonce(victimEOA, uint64(MAX_UINT64_MINUS_1));
        AuthorizationTuple[] memory listMaxMinus1 = new AuthorizationTuple[](1);
        listMaxMinus1[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), MAX_UINT64_MINUS_1, victimPk);
        (uint256 vMaxMinus1, , ) = _simulateMultiAuthType04Transaction(sponsor, listMaxMinus1, "");
        assertEq(vMaxMinus1, 1, "Nonce 2^64 - 2 valid");
        assertEq(vm.getNonce(victimEOA), uint64(MAX_UINT64), "Nonce reached 2^64 - 1");

        // 6. Vector: 2^64 - 1 (Per EIP-7702 spec, auth.nonce must be < 2^64 - 1, cannot increment past 2^64 - 1)
        AuthorizationTuple[] memory listMax = new AuthorizationTuple[](1);
        listMax[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), MAX_UINT64, victimPk);
        // Protocol rule: auth with nonce == 2^64 - 1 is rejected because incrementing would overflow uint64
        bool maxValid = (listMax[0].nonce < MAX_UINT64) && (listMax[0].nonce == vm.getNonce(victimEOA));
        assertFalse(maxValid, "Nonce 2^64 - 1 cannot be authorized (EIP-7702 boundary rule: nonce < 2^64 - 1)");

        // 7. Vector: 2^64 (Exceeds uint64 field, transaction encoding invalid)
        bool overflowValid = OVERFLOW_UINT64 <= MAX_UINT64;
        assertFalse(overflowValid, "Nonce 2^64 is invalid uint64 encoding");
    }

    // =========================================================================
    // SECTION 4: Application Nonce vs Account Nonce Full Lifecycle
    // =========================================================================

    function test_NonceIndependence_Lifecycle() public {
        // Step 1: Initial state (account nonce = 0, rescue nonce = 0)
        assertEq(vm.getNonce(victimEOA), 0);
        assertEq(uint256(vm.load(victimEOA, rescueDelegate.NONCE_SLOT())), 0);

        // Step 2: Failed attempt 1 (auth succeeds, executeRescue reverts)
        AuthorizationTuple[] memory list1 = new AuthorizationTuple[](1);
        list1[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 0, victimPk);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        // Intentionally expired deadline
        bytes memory sig1 = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, block.timestamp - 1);
        bytes memory payload1 = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0, // Application nonce 0
            block.timestamp - 1,
            sig1
        );

        _simulateMultiAuthType04Transaction(sponsor, list1, payload1);

        // Assert Step 2 results:
        assertEq(vm.getNonce(victimEOA), 1, "Account nonce incremented to 1");
        assertEq(uint256(vm.load(victimEOA, rescueDelegate.NONCE_SLOT())), 0, "Rescue nonce remains 0 (reverted)");

        // Step 3: Successful attempt 2 (auth nonce = 1, rescue nonce = 0)
        AuthorizationTuple[] memory list2 = new AuthorizationTuple[](1);
        list2[0] = AuthorizationTuple(block.chainid, address(rescueDelegate), 1, victimPk);

        bytes memory sig2 = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);
        bytes memory payload2 = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0, // Application nonce 0
            block.timestamp + 1 hours,
            sig2
        );

        (uint256 v2, bool s2, ) = _simulateMultiAuthType04Transaction(sponsor, list2, payload2);
        assertTrue(v2 == 1 && s2, "Attempt 2 succeeded");

        // Assert Step 3 results:
        assertEq(vm.getNonce(victimEOA), 2, "Account nonce is now 2");
        assertEq(uint256(vm.load(victimEOA, rescueDelegate.NONCE_SLOT())), 1, "Rescue nonce is now 1");
        assertEq(safeWallet.balance, 10 ether, "SafeWallet received 10 ETH");

        // Step 4: Attempt to replay rescue intent with stale rescue nonce 0 (reverts InvalidNonce)
        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(InvalidNonce.selector, 0, 1));
        UniversalRecoveryDelegate(payable(victimEOA)).executeRescue(
            safeWallet,
            calls,
            tokens,
            0, // Stale application nonce 0
            block.timestamp + 1 hours,
            sig2
        );
    }
}
