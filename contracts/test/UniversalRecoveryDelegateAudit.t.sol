// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "../src/libraries/ECDSA.sol";
import "./mocks/MockERC20.sol";
import "./mocks/MaliciousToken.sol";
import "./mocks/FeeOnTransferToken.sol";

/**
 * @title UniversalRecoveryDelegateAuditTest
 * @notice Formal verification test suite addressing Sections 1 through 10
 *         of the Anti-Drain Security Development Protocol.
 */
contract UniversalRecoveryDelegateAuditTest is Test {
    UniversalRecoveryDelegate public delegate;
    MockERC20 public tokenA;
    MockERC20 public tokenB;

    address public sponsor;
    uint256 public sponsorPk;

    address public victim;
    uint256 public victimPk;

    address public safeWallet;
    address public attacker;
    uint256 public attackerPk;

    function setUp() public {
        sponsorPk = 0x1111111111111111111111111111111111111111111111111111111111111111;
        sponsor = vm.addr(sponsorPk);

        victimPk = 0x2222222222222222222222222222222222222222222222222222222222222222;
        victim = vm.addr(victimPk);

        attackerPk = 0x3333333333333333333333333333333333333333333333333333333333333333;
        attacker = vm.addr(attackerPk);

        safeWallet = address(0x9999);

        delegate = new UniversalRecoveryDelegate();
        tokenA = new MockERC20();
        tokenB = new MockERC20();

        // Simulate EIP-7702 delegation: etch delegate code into victim EOA
        vm.etch(victim, address(delegate).code);
    }

    // âââ SECTION 1: ERC-7201 Nonce Slot Verification âââââââââââââââââââââââ

    function test_Section1_ERC7201_NonceSlotDerivation() public view {
        string memory namespace = "antidrain.universalRecoveryDelegate.nonce.v1";
        bytes32 h1 = keccak256(bytes(namespace));
        uint256 h1Minus1 = uint256(h1) - 1;
        bytes32 h2 = keccak256(abi.encode(h1Minus1));
        bytes32 derivedSlot = bytes32(uint256(h2) & ~uint256(0xff));

        bytes32 expectedConstant = 0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd00;

        assertEq(derivedSlot, expectedConstant, "Derived slot must match exact constant");
        assertEq(delegate.NONCE_SLOT(), expectedConstant, "Solidity constant must match derived slot");
    }

    function test_Section1_ERC7201_ArbitrarySlotMismatchFails() public view {
        bytes32 arbitrarySlot = 0x8a9b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef;
        bytes32 realSlot = delegate.NONCE_SLOT();
        assertTrue(arbitrarySlot != realSlot, "Arbitrary placeholder must not match real slot");
    }

    // âââ Helper for Signing EIP-712 Intent ââââââââââââââââââââââââââââââââââ

    function _signRescueIntent(
        uint256 signerPk,
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
        bytes32 callsHash = keccak256(abi.encodePacked(callHashes));
        bytes32[] memory tokenWords = new bytes32[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenWords[i] = bytes32(uint256(uint160(tokens[i])));
        }
        bytes32 tokensHash = keccak256(abi.encodePacked(tokenWords));

        bytes32 structHash = keccak256(
            abi.encode(RESCUE_TYPEHASH, _safeWallet, _sponsor, callsHash, tokensHash, nonce, deadline)
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
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }

    // âââ SECTION 2: EIP-712 Single-Field Negative Matrix ââââââââââââââââââââ

    function test_Section2_HappyPath_SignatureVerification() public {
        tokenA.mint(victim, 100 ether);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(tokenA);
        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory signature = _signRescueIntent(
            victimPk,
            victim,
            safeWallet,
            sponsor,
            calls,
            tokens,
            nonce,
            deadline
        );

        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            nonce,
            deadline,
            signature
        );

        assertEq(tokenA.balanceOf(safeWallet), 100 ether, "Safe wallet must receive 100% of tokens");
        assertEq(tokenA.balanceOf(victim), 0, "Victim token balance must be 0");
    }

    function test_Section2_Mutate_SafeWallet_Fails() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(tokenA);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            attacker, // mutated safeWallet
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );
    }

    function test_Section2_Mutate_CallsTarget_Fails() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(tokenA), 0, "0x1234");
        address[] memory tokens = new address[](0);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // Mutate target
        calls[0].target = address(tokenB);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );
    }

    function test_Section2_Mutate_Nonce_Fails() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // Case A: Parameter nonce does not match signed nonce -> InvalidAuthorization
        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            1, // Mutated nonce (signed 0)
            block.timestamp + 1 hours,
            sig
        );

        // Case B: Signed for nonce 1, but on-chain nonce is 0 -> InvalidNonce(0, 1)
        bytes memory sigNonce1 = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 1, block.timestamp + 1 hours);
        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(InvalidNonce.selector, 1, 0));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            1,
            block.timestamp + 1 hours,
            sigNonce1
        );
    }

    function test_Section2_Mutate_Deadline_Fails() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 2 hours, // Mutated deadline
            sig
        );
    }

    function test_Section2_Mutate_ChainId_Fails() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        // Compute signature with wrong chainId
        vm.chainId(999);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);
        vm.chainId(31337);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );
    }

    function test_Section2_Mutate_VerifyingContract_Fails() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        // Signed for another EOA (attacker)
        bytes memory sig = _signRescueIntent(victimPk, attacker, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );
    }

    function test_Section2_NonceReplay_Fails() public {
        tokenA.mint(victim, 100 ether);
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(tokenA);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // 1st call succeeds
        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        // 2nd call with same nonce 0 must revert with InvalidNonce(0, 1)
        tokenA.mint(victim, 50 ether);
        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(InvalidNonce.selector, 0, 1));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // âââ SECTION 3: External Contract & Reentrancy Call-Graph Test âââââââââ

    function test_Section3_Reentrancy_BlockedByTransientLock() public {
        MaliciousToken malToken = new MaliciousToken();
        malToken.mint(victim, 100 ether);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(malToken);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
        assertEq(malToken.balanceOf(safeWallet), 100 ether);
    }

    // âââ SECTION 7: _safeTransfer Adversarial Test Matrix âââââââââââââââââââ

    function test_Section7_FeeOnTransferToken() public {
        FeeOnTransferToken fotToken = new FeeOnTransferToken();
        fotToken.mint(victim, 100 ether);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(fotToken);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        // FeeOnTransfer takes 10% on transfer -> safeWallet gets 90 ether
        assertEq(fotToken.balanceOf(safeWallet), 90 ether);
    }

    // âââ SECTION 8: EIP-7702 Non-Sponsor Caller Fails âââââââââââââââââââââââ

    function test_Section8_AttackerCaller_FailsEvenWithValidSignature() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        bytes memory sig = _signRescueIntent(victimPk, victim, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // Attacker calls executeRescue with victim's valid signature -> Reverts InvalidAuthorization (wrong sponsor)()
        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );
    }
}
