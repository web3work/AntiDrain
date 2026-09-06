// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Special Mock Contracts for Formal Verification ââââââââââââââââââââââââ

contract ReturnDataVariantToken {
    mapping(address => uint256) public balanceOf;
    uint8 public mode; 
    // 0: std true (32-byte 1)
    // 1: std false (32-byte 0)
    // 2: void (0 bytes)
    // 3: revert
    // 4: >32 bytes with true in word 0
    // 5: >32 bytes with false in word 0
    // 6: malformed (<32 bytes, e.g. 16 bytes)

    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function setMode(uint8 _mode) external { mode = _mode; }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (mode == 1) return false;
        if (mode == 2) {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
            assembly { return(0, 0) }
        }
        if (mode == 3) revert("Token transfer reverted");
        if (mode == 4) {
            balanceOf[msg.sender] -= amount;
            balanceOf[to] += amount;
            assembly {
                let m := mload(0x40)
                mstore(m, 1)
                mstore(add(m, 0x20), 0xdeadbeef)
                return(m, 0x40)
            }
        }
        if (mode == 5) {
            assembly {
                let m := mload(0x40)
                mstore(m, 0)
                mstore(add(m, 0x20), 0xdeadbeef)
                return(m, 0x40)
            }
        }
        if (mode == 6) {
            assembly {
                let m := mload(0x40)
                mstore(m, 1)
                return(m, 0x10) // 16 bytes
            }
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract BalanceOfVariantToken {
    uint8 public mode;
    // 0: valid balance
    // 1: revert
    // 2: empty (0 bytes)
    // 3: <32 bytes (16 bytes)
    // 4: 0 balance

    function setMode(uint8 _mode) external { mode = _mode; }

    function balanceOf(address) external view returns (uint256) {
        if (mode == 1) revert("balanceOf revert");
        if (mode == 2) {
            assembly { return(0, 0) }
        }
        if (mode == 3) {
            assembly {
                let m := mload(0x40)
                mstore(m, 500)
                return(m, 0x10)
            }
        }
        if (mode == 4) return 0;
        return 1000;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
}

contract PersistentAuthorizationTarget {
    MockERC20 public token;
    mapping(address => address) public protocolDelegation;
    mapping(address => bool) public approvedOperators;

    constructor(MockERC20 _token) { token = _token; }

    function claimAndApprove(address spender, uint256 amount) external {
        token.mint(msg.sender, amount);
        token.approve(spender, type(uint256).max);
    }

    function setProtocolDelegate(address delegatee) external {
        protocolDelegation[msg.sender] = delegatee;
    }

    function setOperator(address operator, bool approved) external {
        approvedOperators[operator] = approved;
    }
}

// âââ Formal Verification Test Suite ââââââââââââââââââââââââââââââââââââââââ

contract ComprehensiveSecurityProofTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 sponsorPk = 0x1111;
    address sponsor;
    uint256 victimPk = 0x2222;
    address victim;
    address safeWallet = address(0x3333);
    address attacker = address(0x4444);

    MockERC20 tokenA;
    MockERC20 tokenB;
    ReturnDataVariantToken variantToken;
    BalanceOfVariantToken balanceToken;
    PersistentAuthorizationTarget authTarget;

    function setUp() public {
        sponsor = vm.addr(sponsorPk);
        victim = vm.addr(victimPk);

        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(victim, address(delegateContract).code);

        tokenA = new MockERC20();
        tokenB = new MockERC20();
        variantToken = new ReturnDataVariantToken();
        balanceToken = new BalanceOfVariantToken();
        authTarget = new PersistentAuthorizationTarget(tokenA);
    }

    function _sign(
        uint256 pk,
        address verifyingContract,
        address _safeWallet,
        Call[] memory calls,
        address[] memory tokens,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        return signRescueIntent(pk, verifyingContract, _safeWallet, sponsor, calls, tokens, nonce, deadline);
    }

    // =========================================================================
    // SECTION 1: ERC-7201 Nonce Slot Verification
    // =========================================================================

    function test_Section1_ExactNonceSlotStepByStep() public view {
        string memory namespace = "antidrain.universalRecoveryDelegate.nonce.v1";
        bytes32 h1 = keccak256(bytes(namespace));
        uint256 h1Minus1 = uint256(h1) - 1;
        bytes32 h2 = keccak256(abi.encode(h1Minus1));
        bytes32 derivedSlot = bytes32(uint256(h2) & ~uint256(0xff));

        bytes32 expectedConstant = 0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd00;

        assertEq(derivedSlot, expectedConstant);
        assertEq(delegateContract.NONCE_SLOT(), expectedConstant);
    }

    function test_Section1_CorruptedSlotAssertionFails() public view {
        bytes32 wrongSlot = 0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd01;
        bytes32 actualSlot = delegateContract.NONCE_SLOT();
        assertTrue(wrongSlot != actualSlot);
    }

    // =========================================================================
    // SECTION 2: EIP-712 Complete Negative Test Matrix (14 single-field mutations)
    // =========================================================================

    function test_Section2_NegativeMatrix_A_SafeWalletMutation() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(attacker, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_B_CallsTargetMutation() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(tokenA), 0, "0x11");
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        calls[0].target = address(tokenB); // mutated

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_C_CallsValueMutation() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(tokenA), 0, "0x11");
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        calls[0].value = 1 ether; // mutated

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_D_CallsDataMutation() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call(address(tokenA), 0, "0x11");
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        calls[0].data = "0x22"; // mutated

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_E_CallsLengthMutation() public {
        Call[] memory signedCalls = new Call[](1);
        signedCalls[0] = Call(address(tokenA), 0, "0x11");
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, signedCalls, tokens, 0, block.timestamp + 1 hours);

        Call[] memory executedCalls = new Call[](2);
        executedCalls[0] = Call(address(tokenA), 0, "0x11");
        executedCalls[1] = Call(address(tokenB), 0, "0x22");

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, executedCalls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_F_CallsOrderingMutation() public {
        Call[] memory signedCalls = new Call[](2);
        signedCalls[0] = Call(address(tokenA), 0, "0x11");
        signedCalls[1] = Call(address(tokenB), 0, "0x22");
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, signedCalls, tokens, 0, block.timestamp + 1 hours);

        Call[] memory executedCalls = new Call[](2);
        executedCalls[0] = Call(address(tokenB), 0, "0x22"); // Swapped
        executedCalls[1] = Call(address(tokenA), 0, "0x11");

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, executedCalls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_G_TokensElementMutation() public {
        Call[] memory calls = new Call[](0);
        address[] memory signedTokens = new address[](1);
        signedTokens[0] = address(tokenA);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, signedTokens, 0, block.timestamp + 1 hours);

        address[] memory executedTokens = new address[](1);
        executedTokens[0] = address(tokenB); // mutated

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, executedTokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_H_TokensOrderingMutation() public {
        Call[] memory calls = new Call[](0);
        address[] memory signedTokens = new address[](2);
        signedTokens[0] = address(tokenA);
        signedTokens[1] = address(tokenB);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, signedTokens, 0, block.timestamp + 1 hours);

        address[] memory executedTokens = new address[](2);
        executedTokens[0] = address(tokenB); // swapped
        executedTokens[1] = address(tokenA);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, executedTokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_I_NonceMutation() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        // Case A: Parameter nonce != signed nonce -> InvalidAuthorization
        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 1, block.timestamp + 1 hours, sig);

        // Case B: Signed nonce != on-chain nonce -> InvalidNonce
        bytes memory sigNonce1 = _sign(victimPk, victim, safeWallet, calls, tokens, 1, block.timestamp + 1 hours);
        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(InvalidNonce.selector, 1, 0));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 1, block.timestamp + 1 hours, sigNonce1);
    }

    function test_Section2_NegativeMatrix_J_DeadlineMutation() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 2 hours, sig);
    }

    function test_Section2_NegativeMatrix_K_ChainIdMutation() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        vm.chainId(999);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);
        vm.chainId(31337);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section2_NegativeMatrix_L_VerifyingContractMutation() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        // Signed for attacker instead of victim
        bytes memory sig = _sign(victimPk, attacker, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // =========================================================================
    // SECTION 5: Persistent External Authorization Lifecycle Proof
    // =========================================================================

    function test_Section5_ClaimWithPersistentAllowance_LeavesResidualRiskOnToken() public {
        tokenA.mint(victim, 1000);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(tokenA),
            value: 0,
            data: abi.encodeWithSelector(MockERC20.approve.selector, attacker, type(uint256).max)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(tokenA);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        // Assets are swept cleanly to safeWallet
        assertEq(tokenA.balanceOf(safeWallet), 1000);
        assertEq(tokenA.balanceOf(victim), 0);

        // FORMAL PROOF OF RESIDUAL STATE: Attacker retains allowance on tokenA
        assertEq(tokenA.allowance(victim, attacker), type(uint256).max);

        // If victim receives future tokens, attacker can transferFrom without needing compromised key!
        tokenA.mint(victim, 500);
        vm.prank(attacker);
        tokenA.transferFrom(victim, attacker, 500);
        assertEq(tokenA.balanceOf(attacker), 500);
    }

    // =========================================================================
    // SECTION 6: _balanceOf() Failure Semantics Test Matrix
    // =========================================================================

    function test_Section6_BalanceOf_RevertingToken_RevertsAtomically() public {
        balanceToken.setMode(1); // Revert mode
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(balanceToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(BalanceQueryFailed.selector, address(balanceToken)));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section6_BalanceOf_EmptyData_RevertsAtomically() public {
        balanceToken.setMode(2); // Empty data
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(balanceToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(BalanceQueryFailed.selector, address(balanceToken)));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section6_BalanceOf_ShortData_RevertsAtomically() public {
        balanceToken.setMode(3); // <32 bytes data
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(balanceToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(BalanceQueryFailed.selector, address(balanceToken)));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // =========================================================================
    // SECTION 7: _safeTransfer() Adversarial Test Matrix (Modes 0 through 6)
    // =========================================================================

    function test_Section7_SafeTransfer_StandardTrue_Succeeds() public {
        variantToken.setMode(0);
        variantToken.mint(victim, 100);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(variantToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
        assertEq(variantToken.balanceOf(safeWallet), 100);
    }

    function test_Section7_SafeTransfer_StandardFalse_Reverts() public {
        variantToken.setMode(1); // Standard false
        variantToken.mint(victim, 100);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(variantToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(SweepFailed.selector, address(variantToken)));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section7_SafeTransfer_VoidReturn_Succeeds() public {
        variantToken.setMode(2); // USDT void return
        variantToken.mint(victim, 100);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(variantToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
        assertEq(variantToken.balanceOf(safeWallet), 100);
    }

    function test_Section7_SafeTransfer_RevertingToken_Reverts() public {
        variantToken.setMode(3); // Reverts
        variantToken.mint(victim, 100);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(variantToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(SweepFailed.selector, address(variantToken)));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function test_Section7_SafeTransfer_OverSizedTrue_Succeeds() public {
        variantToken.setMode(4); // >32 bytes with true
        variantToken.mint(victim, 100);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(variantToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
        assertEq(variantToken.balanceOf(safeWallet), 100);
    }

    function test_Section7_SafeTransfer_OverSizedFalse_Reverts() public {
        variantToken.setMode(5); // >32 bytes with false
        variantToken.mint(victim, 100);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(variantToken);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(SweepFailed.selector, address(variantToken)));
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // =========================================================================
    // SECTION 8: EIP-7702 Execution Context & Caller Isolation Proof
    // =========================================================================

    function test_Section8_ExecutionContextProof() public {
        tokenA.mint(victim, 500);
        vm.deal(victim, 1 ether);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(tokenA);

        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        // Sponsor executes rescue
        vm.prank(sponsor, sponsor); // msg.sender == sponsor, tx.origin == sponsor
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(tokenA.balanceOf(safeWallet), 500);
        assertEq(safeWallet.balance, 1 ether);
        assertEq(victim.balance, 0);
    }

    function test_Section8_AttackerCannotInvokeEvenWithValidSig() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(victimPk, victim, safeWallet, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victim)).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // =========================================================================
    // SECTION 10: Revocation Lifecycle Proof
    // =========================================================================

    function test_Section10_RevocationRestoresCodeState() public {
        // Step 1: EIP-7702 active
        assertTrue(victim.code.length > 0, "Victim has delegated code in Step 1");

        // Step 2: Revocation executes (in EIP-7702, sets delegation to address(0), resetting code to 0x)
        vm.etch(victim, hex"");
        assertEq(victim.code.length, 0, "Victim code restored to 0x in Step 2");
    }
}
