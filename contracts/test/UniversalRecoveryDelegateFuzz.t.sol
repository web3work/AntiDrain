// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

contract UniversalRecoveryDelegateFuzzTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 eoaPk = 0x789;
    address eoa;
    address safeWallet = address(0x123);
    address sponsor = address(0x456);

    MockERC20 token1;
    MockERC20 token2;

    function setUp() public {
        eoa = vm.addr(eoaPk);
        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(eoa, address(delegateContract).code);

        token1 = new MockERC20();
        token2 = new MockERC20();
    }

    /// @notice Fuzz test: Any unauthorized caller must always revert regardless of calldata
    function testFuzz_UnauthorizedCaller_AlwaysReverts(
        address unauthorizedCaller,
        address destination,
        uint256 ethAmount,
        uint256 tokenAmount
    ) public {
        vm.assume(unauthorizedCaller != sponsor);
        vm.assume(destination != address(0));

        token1.mint(eoa, tokenAmount);
        vm.deal(eoa, ethAmount);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token1);

        bytes memory sig = signRescueIntent(eoaPk, eoa, destination, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(unauthorizedCaller);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(destination, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token1.balanceOf(eoa), tokenAmount);
        assertEq(eoa.balance, ethAmount);
    }

    /// @notice Fuzz test: Sponsor can sweep arbitrary amounts of native and ERC20 tokens
    function testFuzz_SponsorRescue_SweepsExactBalances(
        uint128 nativeBalance,
        uint128 token1Balance,
        uint128 token2Balance
    ) public {
        token1.mint(eoa, token1Balance);
        token2.mint(eoa, token2Balance);
        vm.deal(eoa, nativeBalance);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](2);
        tokens[0] = address(token1);
        tokens[1] = address(token2);

        bytes memory sig = signRescueIntent(eoaPk, eoa, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token1.balanceOf(safeWallet), token1Balance, "Token 1 swept exactly");
        assertEq(token2.balanceOf(safeWallet), token2Balance, "Token 2 swept exactly");
        assertEq(safeWallet.balance, nativeBalance, "Native ETH swept exactly");
        assertEq(token1.balanceOf(eoa), 0, "EOA token 1 balance is 0");
        assertEq(token2.balanceOf(eoa), 0, "EOA token 2 balance is 0");
        assertEq(eoa.balance, 0, "EOA native balance is 0");
    }

    /// @notice Fuzz test: Arbitrary calls with failed subcalls revert atomically
    function testFuzz_FailedCall_RevertsAtomically(uint128 nativeBalance, uint128 tokenBalance) public {
        token1.mint(eoa, tokenBalance);
        vm.deal(eoa, nativeBalance);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(token1),
            value: 0,
            data: abi.encodeWithSignature("nonExistentFunction()")
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(token1);

        bytes memory sig = signRescueIntent(eoaPk, eoa, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert();
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token1.balanceOf(eoa), tokenBalance);
        assertEq(eoa.balance, nativeBalance);
        assertEq(token1.balanceOf(safeWallet), 0);
        assertEq(safeWallet.balance, 0);
    }
}
