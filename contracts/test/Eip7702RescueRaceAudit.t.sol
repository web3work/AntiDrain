// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Supporting Mock Contracts âââââââââââââââââââââââââââââââââââââââââââââââ

contract MockRaceNFT {
    mapping(uint256 => address) public ownerOf;
    mapping(address => mapping(address => bool)) public isApprovedForAll;

    function mint(address to, uint256 tokenId) external {
        ownerOf[tokenId] = to;
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        require(ownerOf[tokenId] == from, "Not owner");
        ownerOf[tokenId] = to;
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
    }
}

contract AttackerRaceDelegate {
    function drainAll(address recipient, address token, address nft, uint256 tokenId) external payable {
        // 1. Drain Native ETH
        uint256 nativeBal = address(this).balance;
        if (nativeBal > 0) {
            (bool s, ) = recipient.call{value: nativeBal}("");
            require(s, "Native drain failed");
        }

        // 2. Drain ERC-20
        if (token != address(0)) {
            uint256 tokenBal = MockERC20(token).balanceOf(address(this));
            if (tokenBal > 0) {
                bool s = MockERC20(token).transfer(recipient, tokenBal);
                require(s, "ERC20 drain failed");
            }
        }

        // 3. Drain NFT
        if (nft != address(0)) {
            (bool s, ) = nft.call(
                abi.encodeWithSignature("transferFrom(address,address,uint256)", address(this), recipient, tokenId)
            );
            s;
        }
    }

    // Explicit fallback: reverts on unexpected calldata like executeRescue()
    fallback() external payable {
        revert("AttackerDelegate: unrecognized selector");
    }
}

contract RevertingClaimMock {
    function failClaim() external pure {
        revert("Claim failed");
    }
}

// âââ EIP-7702 Rescue Race & Nonce Semantics Audit Suite âââââââââââââââââââââââ

contract Eip7702RescueRaceAuditTest is AntiDrainTestBase {
    uint256 internal victimPk = 0x111111;
    address internal victimEOA;

    uint256 internal sponsorPk = 0x222222;
    address internal sponsor;

    uint256 internal attackerPk = 0x333333;
    address internal attacker;

    address internal safeWallet = address(0x9999999999999999999999999999999999999999);

    UniversalRecoveryDelegate internal rescueDelegate;
    AttackerRaceDelegate internal attackerDelegate;
    MockERC20 internal token;
    MockRaceNFT internal nft;

    // Simulated EIP-7702 Authorization Struct
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
        attackerDelegate = new AttackerRaceDelegate();

        token = new MockERC20();
        nft = new MockRaceNFT();

        // Initial funding
        vm.deal(victimEOA, 10 ether);
        token.mint(victimEOA, 10_000 ether);
        nft.mint(victimEOA, 1);

        vm.deal(sponsor, 5 ether);
        vm.deal(attacker, 5 ether);

        // Reset account nonce
        vm.setNonce(victimEOA, 0);
    }

    // =========================================================================
    // SECTION 1: EIP-7702 Real Account Nonce Protocol Simulation Engine
    // =========================================================================

    /**
     * @notice Simulates an EIP-7702 Type 0x04 transaction with real EVM account nonce rules.
     * @dev Step 1: Checks authority.nonce == auth.nonce.
     *             If equal: installs code and increments authority.nonce += 1.
     *             If not equal: authorization tuple is skipped/ignored; existing code remains.
     *      Step 2: Executes calldata in victim context.
     */
    function _simulateType04Transaction(
        address sender,
        EIP7702Authorization memory auth,
        bytes memory calldataPayload
    ) internal returns (bool authApplied, bool executionSuccess, bytes memory returnData) {
        uint256 currentAccountNonce = vm.getNonce(victimEOA);

        // EIP-7702 Protocol Step 1: Authorization list processing
        if (auth.nonce == currentAccountNonce) {
            // Valid authorization tuple: install delegate code & increment account nonce
            if (auth.delegate == address(0)) {
                vm.etch(victimEOA, "");
            } else {
                vm.etch(victimEOA, auth.delegate.code);
            }
            vm.setNonce(victimEOA, uint64(currentAccountNonce + 1));
            authApplied = true;
        } else {
            // Stale / invalid authorization tuple: ignored by EVM protocol
            authApplied = false;
        }

        // EIP-7702 Protocol Step 2: Calldata execution
        vm.prank(sender);
        (executionSuccess, returnData) = victimEOA.call(calldataPayload);
    }

    // =========================================================================
    // SECTION 2: Scenario A â Rescue Included First (Real Nonce)
    // =========================================================================

    function test_ScenarioA_RescueFirst_RealAccountNonce() public {
        // Initial state: victim account nonce = 0
        assertEq(vm.getNonce(victimEOA), 0);

        // Both parties create pre-signed authorizations targeting nonce 0
        EIP7702Authorization memory rescueAuth = EIP7702Authorization({
            chainId: block.chainid,
            delegate: address(rescueDelegate),
            nonce: 0
        });

        EIP7702Authorization memory attackerAuth = EIP7702Authorization({
            chainId: block.chainid,
            delegate: address(attackerDelegate),
            nonce: 0
        });

        // 1. Rescue transaction is included first
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = signRescueIntent(
            victimPk,
            victimEOA,
            safeWallet,
            sponsor,
            calls,
            tokens,
            0, // Application rescue nonce
            block.timestamp + 1 hours
        );

        bytes memory rescueCalldata = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );

        (bool rescueAuthApplied, bool rescueExecSuccess, ) = _simulateType04Transaction(
            sponsor,
            rescueAuth,
            rescueCalldata
        );

        assertTrue(rescueAuthApplied, "Rescue auth applied (nonce 0 -> 1)");
        assertTrue(rescueExecSuccess, "executeRescue succeeded");
        assertEq(vm.getNonce(victimEOA), 1, "Victim account nonce incremented to 1");
        assertEq(safeWallet.balance, 10 ether, "SafeWallet received 10 ETH");
        assertEq(token.balanceOf(safeWallet), 10_000 ether, "SafeWallet received 10k tokens");

        // 2. Attacker transaction is included second with pre-signed nonce 0
        bytes memory attackerCalldata = abi.encodeWithSelector(
            AttackerRaceDelegate.drainAll.selector,
            attacker,
            address(token),
            address(nft),
            1
        );

        (bool attackerAuthApplied, bool attackerExecSuccess, ) = _simulateType04Transaction(
            attacker,
            attackerAuth,
            attackerCalldata
        );

        // EVM rejects attacker's stale authorization (auth.nonce 0 != account nonce 1)
        assertFalse(attackerAuthApplied, "Attacker auth ignored due to stale account nonce");
        // Calldata is delivered to victimEOA which is still UniversalRecoveryDelegate
        // Calling drainAll on UniversalRecoveryDelegate triggers fallback / reverts or rejects
        assertFalse(attackerExecSuccess, "Attacker drain calldata fails against UniversalRecoveryDelegate");

        // Attacker gets zero assets
        assertEq(attacker.balance, 5 ether, "Attacker balance untouched");
        assertEq(token.balanceOf(attacker), 0, "Attacker received 0 tokens");
    }

    // =========================================================================
    // SECTION 3: Scenario B â Attacker Included First (Real Nonce)
    // =========================================================================

    function test_ScenarioB_AttackerFirst_RealAccountNonce() public {
        // Initial state: victim account nonce = 0
        assertEq(vm.getNonce(victimEOA), 0);

        EIP7702Authorization memory attackerAuth = EIP7702Authorization({
            chainId: block.chainid,
            delegate: address(attackerDelegate),
            nonce: 0
        });

        EIP7702Authorization memory rescueAuth = EIP7702Authorization({
            chainId: block.chainid,
            delegate: address(rescueDelegate),
            nonce: 0
        });

        // 1. Attacker transaction is included first
        bytes memory attackerCalldata = abi.encodeWithSelector(
            AttackerRaceDelegate.drainAll.selector,
            attacker,
            address(token),
            address(nft),
            1
        );

        (bool attackerAuthApplied, bool attackerExecSuccess, ) = _simulateType04Transaction(
            attacker,
            attackerAuth,
            attackerCalldata
        );

        assertTrue(attackerAuthApplied, "Attacker auth applied (nonce 0 -> 1)");
        assertTrue(attackerExecSuccess, "Attacker drain succeeded");
        assertEq(vm.getNonce(victimEOA), 1, "Victim account nonce incremented to 1");
        assertEq(attacker.balance, 15 ether, "Attacker drained 10 ETH");
        assertEq(token.balanceOf(attacker), 10_000 ether, "Attacker drained 10k tokens");

        // 2. Rescue transaction is included second with stale nonce 0
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = signRescueIntent(
            victimPk,
            victimEOA,
            safeWallet,
            sponsor,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours
        );

        bytes memory rescueCalldata = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );

        (bool rescueAuthApplied, bool rescueExecSuccess, bytes memory ret) = _simulateType04Transaction(
            sponsor,
            rescueAuth,
            rescueCalldata
        );

        // Crucial verification:
        // A. Rescue authorization is IGNORED by EVM (auth.nonce 0 != account nonce 1)
        assertFalse(rescueAuthApplied, "Rescue auth rejected due to stale account nonce");
        // B. Active code at victimEOA REMAINS AttackerRaceDelegate
        // C. executeRescue calldata is delivered to AttackerRaceDelegate
        // D. AttackerRaceDelegate has no executeRescue function -> fallback reverts!
        assertFalse(rescueExecSuccess, "Sponsor tx reverts when executing executeRescue on AttackerDelegate");
        assertTrue(ret.length > 0, "Returns revert data from AttackerDelegate fallback");

        // SafeWallet receives nothing
        assertEq(safeWallet.balance, 0);
    }

    // =========================================================================
    // SECTION 4: Same-Block Ordering Tests
    // =========================================================================

    function test_ScenarioA_SameBlock_RescueThenAttacker() public {
        // In the same block:
        // Tx 1: Rescue (auth.nonce = 0)
        // Tx 2: Attacker (pre-signed auth.nonce = 0)
        test_ScenarioA_RescueFirst_RealAccountNonce();
    }

    function test_ScenarioB_SameBlock_AttackerThenRescue() public {
        // In the same block:
        // Tx 1: Attacker (auth.nonce = 0)
        // Tx 2: Rescue (pre-signed auth.nonce = 0)
        test_ScenarioB_AttackerFirst_RealAccountNonce();
    }

    // =========================================================================
    // SECTION 5: Critical Test â Delegation Persistence on Execution Revert
    // =========================================================================

    function test_ScenarioC_DelegationPersistsOnExecutionRevert() public {
        // Initial state: pure EOA, nonce = 0
        assertEq(victimEOA.code.length, 0);
        assertEq(vm.getNonce(victimEOA), 0);

        EIP7702Authorization memory rescueAuth = EIP7702Authorization({
            chainId: block.chainid,
            delegate: address(rescueDelegate),
            nonce: 0
        });

        // Construct rescue payload with an EXPIRED DEADLINE to force calldata revert
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        uint256 expiredDeadline = block.timestamp - 1; // Expired!
        bytes memory sig = signRescueIntent(
            victimPk,
            victimEOA,
            safeWallet,
            sponsor,
            calls,
            tokens,
            0,
            expiredDeadline
        );

        bytes memory rescueCalldata = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            expiredDeadline,
            sig
        );

        // Execute Type 0x04 transaction
        (bool authApplied, bool execSuccess, ) = _simulateType04Transaction(
            sponsor,
            rescueAuth,
            rescueCalldata
        );

        // Proof of EIP-7702 Revert Semantics:
        // 1. Authorization list processing succeeded
        assertTrue(authApplied, "Authorization list processing succeeded");
        // 2. Account nonce was incremented 0 -> 1
        assertEq(vm.getNonce(victimEOA), 1, "Account nonce incremented to 1");
        // 3. Calldata execution reverted due to expired deadline
        assertFalse(execSuccess, "Calldata execution reverted");
        // 4. CRITICAL: Delegation code REMAINS INSTALLED on victimEOA!
        assertTrue(victimEOA.code.length > 0, "Delegation code remains installed after revert");
        // Per-user sponsor: no SPONSOR() immutable to verify — sponsor is bound via EIP-712 signature
    }

    // =========================================================================
    // SECTION 6: Comprehensive Revert Path Matrix & Delegation Persistence
    // =========================================================================

    function test_ScenarioD_RevertPath_InvalidSignature() public {
        EIP7702Authorization memory auth = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory badSig = new bytes(65); // Garbage signature

        bytes memory payload = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            badSig
        );

        (bool authApplied, bool execSuccess, ) = _simulateType04Transaction(sponsor, auth, payload);
        assertTrue(authApplied);
        assertFalse(execSuccess);
        assertEq(vm.getNonce(victimEOA), 1);
        assertTrue(victimEOA.code.length > 0, "Delegation persists on InvalidSignature revert");
    }

    function test_ScenarioD_RevertPath_UnauthorizedCaller() public {
        vm.setNonce(victimEOA, 0);
        EIP7702Authorization memory auth = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);
        bytes memory payload = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );

        // Attacker attempts to send the outer transaction
        (bool authApplied, bool execSuccess, ) = _simulateType04Transaction(attacker, auth, payload);
        assertTrue(authApplied);
        assertFalse(execSuccess, "Reverts InvalidAuthorization (wrong sponsor)");
        assertEq(vm.getNonce(victimEOA), 1);
        assertTrue(victimEOA.code.length > 0, "Delegation persists on InvalidAuthorization revert");
    }

    function test_ScenarioD_RevertPath_FailedArbitraryCall() public {
        vm.setNonce(victimEOA, 0);
        RevertingClaimMock claimMock = new RevertingClaimMock();

        EIP7702Authorization memory auth = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimMock),
            value: 0,
            data: abi.encodeWithSelector(RevertingClaimMock.failClaim.selector)
        });
        address[] memory tokens = new address[](0);

        bytes memory sig = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);
        bytes memory payload = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );

        (bool authApplied, bool execSuccess, ) = _simulateType04Transaction(sponsor, auth, payload);
        assertTrue(authApplied);
        assertFalse(execSuccess, "Reverts CallFailed");
        assertEq(vm.getNonce(victimEOA), 1);
        assertTrue(victimEOA.code.length > 0, "Delegation persists on CallFailed revert");
    }

    function test_ScenarioD_RevertPath_InvalidApplicationNonce() public {
        vm.setNonce(victimEOA, 0);
        // Stored application nonce is 0, but payload requests nonce 5
        EIP7702Authorization memory auth = EIP7702Authorization(block.chainid, address(rescueDelegate), 0);
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = signRescueIntent(victimPk, victimEOA, safeWallet, sponsor, calls, tokens, 5, block.timestamp + 1 hours);
        bytes memory payload = abi.encodeWithSelector(
            UniversalRecoveryDelegate.executeRescue.selector,
            safeWallet,
            calls,
            tokens,
            5,
            block.timestamp + 1 hours,
            sig
        );

        (bool authApplied, bool execSuccess, ) = _simulateType04Transaction(sponsor, auth, payload);
        assertTrue(authApplied);
        assertFalse(execSuccess, "Reverts InvalidNonce");
        assertEq(vm.getNonce(victimEOA), 1);
        assertTrue(victimEOA.code.length > 0, "Delegation persists on InvalidNonce revert");
    }
}
