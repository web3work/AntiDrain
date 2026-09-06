// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Hostile & Weird ERC-20 Mock Contracts âââââââââââââââââââââââââââââââââ

/// @notice Returns > 32 bytes on transfer (e.g. 64 bytes)
contract OverSizedReturnToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool, uint256) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return (true, 12345); // 64 bytes return data with bool true in word 0
    }
}

/// @notice Returns 1 byte on transfer (0x01)
contract SingleByteReturnToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bytes1) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return bytes1(0x01);
    }
}

/// @notice Returns true but does NOT actually transfer tokens (silent no-op)
contract TrueReturnNoTransferToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
}

/// @notice Destination contract that rejects native ETH
contract RejectingSafeWallet {
    receive() external payable {
        revert("Rejecting ETH");
    }
}

/// @notice Destination contract with high gas usage in receive()
contract HighGasSafeWallet {
    uint256 public counter;
    receive() external payable {
        for (uint256 i = 0; i < 50; i++) {
            counter += i;
        }
    }
}

/// @notice Malicious contract attempting reentrancy via arbitrary call
contract ReentrantAttackContract {
    address public victimEoa;
    constructor(address _victim) {
        victimEoa = _victim;
    }

    function triggerAttack() external {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);
        UniversalRecoveryDelegate(payable(victimEoa)).executeRescue(
            address(0x123),
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            ""
        );
    }
}

// âââ Test Suite ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

contract AdversarialStressAuditTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 eoaPk = 0x789;
    address eoa;
    address sponsor = address(0x456);
    address safeWallet = address(0x123);

    OverSizedReturnToken overSizedToken;
    SingleByteReturnToken singleByteToken;
    TrueReturnNoTransferToken trueNoTransferToken;
    RejectingSafeWallet rejectingSafeWallet;
    HighGasSafeWallet highGasSafeWallet;
    ReentrantAttackContract attackerContract;

    function setUp() public {
        eoa = vm.addr(eoaPk);
        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(eoa, address(delegateContract).code);

        overSizedToken = new OverSizedReturnToken();
        singleByteToken = new SingleByteReturnToken();
        trueNoTransferToken = new TrueReturnNoTransferToken();
        rejectingSafeWallet = new RejectingSafeWallet();
        highGasSafeWallet = new HighGasSafeWallet();
        attackerContract = new ReentrantAttackContract(eoa);
    }

    function _sign(Call[] memory calls, address[] memory tokens, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return signRescueIntent(eoaPk, eoa, safeWallet, sponsor, calls, tokens, nonce, deadline);
    }

    /// @notice Hostile ERC20: returns > 32 bytes with true in word 0 -> succeeds
    function testHostileERC20_OverSizedReturnData() public {
        overSizedToken.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(overSizedToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(overSizedToken.balanceOf(safeWallet), 1000);
    }

    /// @notice Hostile ERC20: returns 1 byte (non-standard) -> reverts
    function testHostileERC20_SingleByteReturnData_Reverts() public {
        singleByteToken.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(singleByteToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(SweepFailed.selector, address(singleByteToken)));
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    /// @notice Hostile ERC20: returns true without transferring
    function testHostileERC20_TrueReturnNoTransfer_ExecutesWithoutReverting() public {
        trueNoTransferToken.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(trueNoTransferToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(trueNoTransferToken.balanceOf(safeWallet), 0);
    }

    /// @notice Native ETH sweep: SafeWallet rejects ETH -> reverts entire transaction
    function testNativeETH_RejectingSafeWallet_RevertsEntireRescue() public {
        vm.deal(eoa, 1 ether);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        bytes memory sig = signRescueIntent(eoaPk, eoa, address(rejectingSafeWallet), sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(NativeSweepFailed.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(address(rejectingSafeWallet), calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(eoa.balance, 1 ether);
    }

    /// @notice Native ETH sweep: SafeWallet consumes high gas in receive() -> succeeds
    function testNativeETH_HighGasSafeWallet_Succeeds() public {
        vm.deal(eoa, 1 ether);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        bytes memory sig = signRescueIntent(eoaPk, eoa, address(highGasSafeWallet), sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(address(highGasSafeWallet), calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(address(highGasSafeWallet).balance, 1 ether);
        assertEq(eoa.balance, 0);
    }

    /// @notice Reentrancy: external call tries to reenter executeRescue() -> reverts
    function testReentrancy_ArbitraryCallCallback_BlockedByTransientStorage() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(attackerContract),
            value: 0,
            data: abi.encodeWithSelector(ReentrantAttackContract.triggerAttack.selector)
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

    /// @notice Input validation: safeWallet cannot be address(0)
    function testRevert_SafeWalletZeroAddress_Reverts() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        vm.prank(sponsor);
        vm.expectRevert(InvalidSafeWallet.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(address(0), calls, tokens, 0, block.timestamp + 1 hours, "");
    }

    /// @notice Input validation: safeWallet cannot be address(this)
    function testRevert_SafeWalletSelfAddress_Reverts() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        vm.prank(sponsor);
        vm.expectRevert(InvalidSafeWallet.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(eoa, calls, tokens, 0, block.timestamp + 1 hours, "");
    }
}
