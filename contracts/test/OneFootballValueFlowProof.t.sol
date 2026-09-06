// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

contract MockOneFootballClaim {
    uint256 public claimFeeWei = 802581101000000; // 0.000802581101 ETH
    address public immutable token;
    address public immutable feeCollector;
    address public owner;

    event Claimed(address indexed account, uint256 amount, uint256 nonce);
    event ClaimFeeUpdated(uint256 oldFee, uint256 newFee);

    constructor(address _token, address _feeCollector) {
        token = _token;
        feeCollector = _feeCollector;
        owner = msg.sender;
    }

    // selector 0x2e75ab50 matches on-chain setter
    function setClaimFee(uint256 newFee) external {
        require(msg.sender == owner, "Not owner");
        uint256 old = claimFeeWei;
        claimFeeWei = newFee;
        emit ClaimFeeUpdated(old, newFee);
    }

    // selector 0x5eddd157 matches on-chain claim
    function claim(
        uint256 amount,
        uint256 deadline,
        bytes calldata /* signature */
    ) external payable {
        require(block.timestamp <= deadline, "Expired");
        require(msg.value >= claimFeeWei, "InsufficientFee");

        // Forward fee to collector immediately
        (bool feeOk, ) = feeCollector.call{value: msg.value}("");
        require(feeOk, "Fee forward failed");

        // Send tokens to caller (msg.sender is the claiming account)
        MockERC20(token).mint(msg.sender, amount);

        emit Claimed(msg.sender, amount, 0);
    }
}

contract ForceFeeder {
    constructor(address payable target) payable {
        selfdestruct(target);
    }
}

contract OneFootballValueFlowProofTest is Test {
    UniversalRecoveryDelegate delegateContract;
    MockERC20 ofcToken;
    MockOneFootballClaim claimContract;

    uint256 sponsorPk = 0x1111;
    address sponsor;

    uint256 victimPk = 0x2222;
    address victim;

    uint256 attackerPk = 0x4444;
    address attacker;

    address safeWallet = address(0x3333);
    address feeCollector = address(0x9999);

    uint256 constant CLAIM_FEE = 802581101000000; // 0.000802581101 ETH
    uint256 constant CLAIM_AMOUNT = 1028 * 1e18;

    function setUp() public {
        sponsor = vm.addr(sponsorPk);
        victim = vm.addr(victimPk);
        attacker = vm.addr(attackerPk);

        vm.deal(sponsor, 10 ether);
        vm.deal(victim, 0 ether); // Victim starts with EXACTLY 0 ETH
        vm.deal(attacker, 10 ether);

        ofcToken = new MockERC20();
        claimContract = new MockOneFootballClaim(address(ofcToken), feeCollector);

        delegateContract = new UniversalRecoveryDelegate();

        // Simulate EIP-7702 delegation: victim EOA executes delegateContract bytecode
        vm.etch(victim, address(delegateContract).code);
    }

    function _sign(
        uint256 pk,
        address verifyingContract,
        address _safeWallet,
        address _sponsor,
        Call[] memory calls,
        address[] memory tokens,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");
        bytes32 RESCUE_TYPEHASH = keccak256(
            "Rescue(address safeWallet,address sponsor,Call[] calls,address[] tokens,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)"
        );

        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callHashes[i] = keccak256(
                abi.encode(CALL_TYPEHASH, calls[i].target, calls[i].value, keccak256(calls[i].data))
            );
        }

        bytes32[] memory tokenWords = new bytes32[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenWords[i] = bytes32(uint256(uint160(tokens[i])));
        }

        bytes32 structHash = keccak256(
            abi.encode(
                RESCUE_TYPEHASH,
                _safeWallet,
                _sponsor,
                keccak256(abi.encodePacked(callHashes)),
                keccak256(abi.encodePacked(tokenWords)),
                nonce,
                deadline
            )
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("AntiDrainRecovery")),
                keccak256(bytes("1")),
                block.chainid,
                verifyingContract
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    // =========================================================================
    // PROOF 1: SPONSORED RESCUE WITH ZERO VICTIM ETH
    // =========================================================================
    function test_Proof1_SponsoredOneFootballClaim_ZeroVictimEth_Succeeds() public {
        assertEq(victim.balance, 0, "Precondition: victim ETH must be 0");
        assertEq(sponsor.balance, 10 ether, "Precondition: sponsor has ETH");
        assertEq(feeCollector.balance, 0, "Precondition: fee collector empty");
        assertEq(ofcToken.balanceOf(safeWallet), 0, "Precondition: safe has 0 OFC");

        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        uint256 sponsorBalanceBefore = sponsor.balance;
        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            sig
        );

        assertEq(victim.balance, 0, "Victim residual ETH must be 0");
        assertEq(feeCollector.balance, CLAIM_FEE, "Fee collector must receive exact claim fee");
        assertEq(ofcToken.balanceOf(safeWallet), CLAIM_AMOUNT, "Safe wallet must receive 1028 OFC tokens");
        assertEq(ofcToken.balanceOf(victim), 0, "Victim OFC balance must be 0");
        assertEq(sponsor.balance, sponsorBalanceBefore - CLAIM_FEE, "Sponsor balance decreased by exact fee");
    }

    // =========================================================================
    // PROOF 2: VALUE ACCOUNTING — UNDERFUNDING REVERTS ATOMICALLY
    // =========================================================================
    function test_Proof2_OuterValueLessThanCallValue_RevertsAtomically() public {
        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        uint256 partialValue = CLAIM_FEE / 2;
        vm.prank(sponsor);
        vm.expectRevert(); // CallFailed
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: partialValue}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            sig
        );

        assertEq(victim.balance, 0);
        assertEq(feeCollector.balance, 0);
        assertEq(ofcToken.balanceOf(safeWallet), 0);
    }

    // =========================================================================
    // PROOF 3: VALUE ACCOUNTING — OVERFUNDING SWEPT TO SAFE WALLET
    // =========================================================================
    function test_Proof3_Overfunding_SweptToSafeWallet() public {
        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        uint256 excess = 0.005 ether;
        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE + excess}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            sig
        );

        assertEq(victim.balance, 0, "Victim residual ETH must be 0");
        assertEq(safeWallet.balance, excess, "Safe wallet received excess ETH");
        assertEq(feeCollector.balance, CLAIM_FEE, "Claim contract received exact fee");
    }

    // =========================================================================
    // PROOF 4: VALUE MUTATION BY ATTACKER REVERTS
    // =========================================================================
    function test_Proof4_ValueMutation_RevertsInvalidAuthorization() public {
        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        calls[0].value = CLAIM_FEE * 2;

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE * 2}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            sig
        );
    }

    // =========================================================================
    // PROOF 5: ATTACKER FRONTRUNNING / AUTHORIZATION NONCE CONSUMPTION
    // =========================================================================
    function test_Proof5_AttackerFrontrunsAuthorizationTuple_Reverts() public {
        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory legitimateSig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            legitimateSig
        );

        address attackerSafe = address(0x6666);
        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            attackerSafe,
            calls,
            tokens,
            0,
            deadline,
            legitimateSig
        );

        assertEq(victim.balance, 0);
        assertEq(ofcToken.balanceOf(attacker), 0);
        assertEq(ofcToken.balanceOf(safeWallet), 0);
    }

    // =========================================================================
    // PROOF 6: RESCUE SUCCEEDS ON ALREADY-DELEGATED VICTIM (NO REPLAY OF AUTH TUPLE)
    // =========================================================================
    function test_Proof6_RescueSucceedsAfterAttackerDelegatedVictim() public {
        // Attacker already broadcast a Type 0x04 tx containing the victim's authorization tuple.
        // That transaction set victim's code to UniversalRecoveryDelegate and incremented victim's auth nonce.
        // Legitimate sponsor does NOT replay the consumed auth tuple.
        // Sponsor calls victim.executeRescue(...) directly:
        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        // Sponsor calls already-delegated victim
        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            sig
        );

        assertEq(ofcToken.balanceOf(safeWallet), CLAIM_AMOUNT);
        assertEq(victim.balance, 0);
    }

    // =========================================================================
    // PROOF 7: FEE CHANGE RACE CONDITION — REVERTS SAFELY ATOMICALLY
    // =========================================================================
    function test_Proof7_FeeChangeRace_RevertsAtomically() public {
        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        uint256 higherFee = 0.001 ether;
        claimContract.setClaimFee(higherFee);

        vm.prank(sponsor);
        vm.expectRevert(); // CallFailed: OneFootball reverts with "InsufficientFee"
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            sig
        );

        assertEq(victim.balance, 0);
        assertEq(feeCollector.balance, 0);
        assertEq(ofcToken.balanceOf(safeWallet), 0);
    }

    // =========================================================================
    // PROOF 8: ATTACKER SENDS ETH TO DELEGATED VICTIM — REJECTED & SWEPT TO SAFE
    // =========================================================================
    function test_Proof8_AttackerSendsEthToDelegatedVictim_SweptToSafeWallet() public {
        // 1. Attacker attempts to send 1.0 ETH to the delegated victim EOA
        // Because UniversalRecoveryDelegate has NO receive() and NO fallback(),
        // the delegated EOA REJECTS the plain transfer immediately!
        vm.prank(attacker);
        (bool sent, ) = victim.call{value: 1.0 ether}("");
        assertFalse(sent, "Delegated victim without receive/fallback must reject plain ETH transfers");
        assertEq(victim.balance, 0, "Victim balance remains 0 after rejected transfer");

        // 2. Even if attacker force-feeds 1.0 ETH via selfdestruct or miner reward
        new ForceFeeder{value: 1.0 ether}(payable(victim));
        assertEq(victim.balance, 1.0 ether, "Victim now holds 1 ETH from force-feed");

        // 3. Attacker attempts competing execution / unauthorized rescue to steal the 1 ETH
        bytes memory claimCalldata = abi.encodeWithSelector(
            MockOneFootballClaim.claim.selector,
            CLAIM_AMOUNT,
            block.timestamp + 1 hours,
            ""
        );

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(claimContract),
            value: CLAIM_FEE,
            data: claimCalldata
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(ofcToken);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory legitimateSig = _sign(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, deadline);

        // A. Attacker replays victim signature with attacker as msg.sender -> REVERTS
        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            legitimateSig
        );

        // B. Attacker creates fake signature to attackerSafe -> REVERTS (signer != address(this))
        address attackerSafe = address(0x6666);
        bytes memory fakeSig = _sign(attackerPk, victim, attackerSafe, attacker, calls, tokens, 0, deadline);
        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            attackerSafe,
            calls,
            tokens,
            0,
            deadline,
            fakeSig
        );

        // 4. Legitimate sponsor executes rescue
        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue{value: CLAIM_FEE}(
            safeWallet,
            calls,
            tokens,
            0,
            deadline,
            legitimateSig
        );

        // 5. Outcomes:
        // - OneFootball fee was paid
        // - 1,028 OFC claimed & swept to safeWallet
        // - The force-fed 1.0 ETH was swept to safeWallet in Step 8!
        // - Victim balance is back to 0!
        assertEq(victim.balance, 0, "Victim balance back to 0");
        assertEq(safeWallet.balance, 1.0 ether, "Safe wallet swept the force-fed ETH!");
        assertEq(ofcToken.balanceOf(safeWallet), CLAIM_AMOUNT, "Safe received all OFC");
    }
}
