// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

contract TargetContractWithBalanceChanges {
    MockERC20 public token;
    constructor(MockERC20 _token) {
        token = _token;
    }

    function mintCallerTokens(uint256 amount) external {
        token.mint(msg.sender, amount);
    }

    function approveSpender(address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}

contract RevertingOnConditionContract {
    uint256 public counter;

    function stepOne() external {
        counter = 1;
    }

    function stepTwoFails() external pure {
        revert("Step Two Failed");
    }
}

contract CallsCatastrophicLossTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 eoaPk = 0x789;
    address eoa;
    address sponsor = address(0x456);
    address safeWallet = address(0x123);
    address attacker = address(0xBAD);

    MockERC20 token;
    TargetContractWithBalanceChanges balanceManipulator;
    RevertingOnConditionContract multiStepTarget;

    function setUp() public {
        eoa = vm.addr(eoaPk);
        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(eoa, address(delegateContract).code);

        token = new MockERC20();
        balanceManipulator = new TargetContractWithBalanceChanges(token);
        multiStepTarget = new RevertingOnConditionContract();
    }

    function _sign(Call[] memory calls, address[] memory tokens, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return signRescueIntent(eoaPk, eoa, safeWallet, sponsor, calls, tokens, nonce, deadline);
    }

    /// @notice Call target = delegate itself (address(this)) calling executeRescue recursively
    function testCalls_TargetDelegateSelf_BlockedByReentrancyGuard() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: eoa,
            value: 0,
            data: abi.encodeWithSelector(
                UniversalRecoveryDelegate.executeRescue.selector,
                safeWallet,
                new Call[](0),
                new address[](0),
                0,
                block.timestamp + 1 hours,
                ""
            )
        });

        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector,
                0,
                abi.encodeWithSelector(ReentrancyGuardReentrantCall.selector)
            )
        );
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    /// @notice Multi-step calls: step 1 modifies state, step 2 reverts -> step 1 must rollback
    function testCalls_MultiStepSequenceFailure_RollsBackAllPriorCalls() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(multiStepTarget),
            value: 0,
            data: abi.encodeWithSelector(RevertingOnConditionContract.stepOne.selector)
        });
        calls[1] = Call({
            target: address(multiStepTarget),
            value: 0,
            data: abi.encodeWithSelector(RevertingOnConditionContract.stepTwoFails.selector)
        });

        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector,
                1,
                abi.encodeWithSignature("Error(string)", "Step Two Failed")
            )
        );
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(multiStepTarget.counter(), 0);
    }

    /// @notice Call specifies value > EOA native balance -> reverts atomically
    function testCalls_ValueGreaterThanBalance_RevertsAtomically() public {
        vm.deal(eoa, 0.5 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(0x999),
            value: 1 ether,
            data: ""
        });

        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(CallFailed.selector, 0, ""));
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(eoa.balance, 0.5 ether);
        assertEq(safeWallet.balance, 0);
    }

    /// @notice Legitimate dynamic balance generation + immediate sweep
    function testCalls_ClaimAndImmediateSweep_Succeeds() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(balanceManipulator),
            value: 0,
            data: abi.encodeWithSelector(TargetContractWithBalanceChanges.mintCallerTokens.selector, 5000)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token.balanceOf(safeWallet), 5000);
        assertEq(token.balanceOf(eoa), 0);
    }

    /// @notice Malicious call approval: test that approvals persist in token contract
    function testCalls_SponsorApprovingSpender_LeavesAllowanceOnToken() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(token),
            value: 0,
            data: abi.encodeWithSelector(MockERC20.approve.selector, attacker, 9999)
        });

        address[] memory tokens = new address[](0);
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token.allowance(eoa, attacker), 9999);
    }
}
