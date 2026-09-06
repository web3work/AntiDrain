// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Real Airdrop Archetype Mocks ââââââââââââââââââââââââââââââââââââââââââ

/// @notice Airdrop that checks extcodesize(msg.sender) == 0 (anti-contract / anti-bot check)
contract AntiContractAirdrop {
    address public immutable token;

    constructor(address token_) {
        token = token_;
    }

    function claim(uint256 amount) external {
        uint256 size;
        address sender = msg.sender;
        assembly {
            size := extcodesize(sender)
        }
        // Under EIP-7702, the EOA has delegation code (0xef0100 + address), so extcodesize > 0!
        require(size == 0, "EOA ONLY: Contracts blocked");
        MockERC20(token).mint(msg.sender, amount);
    }
}

/// @notice Airdrop that requires tx.origin == msg.sender
contract StrictTxOriginAirdrop {
    address public immutable token;

    constructor(address token_) {
        token = token_;
    }

    function claim(uint256 amount) external {
        require(tx.origin == msg.sender, "tx.origin != msg.sender: Sponsored calls blocked");
        MockERC20(token).mint(msg.sender, amount);
    }
}

/// @notice Hostile token that emits fake Transfer event without transferring tokens
contract HostileFakeTransferToken {
    string public name = "Fake Token";
    string public symbol = "FAKE";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function transfer(address to, uint256 amount) external returns (bool) {
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function setBalance(address account, uint256 amount) external {
        balanceOf[account] = amount;
    }
}

/// @notice Rebasing token where balance changes between steps
contract RebasingTokenMock {
    string public name = "Rebasing Token";
    string public symbol = "REBASE";
    uint8 public decimals = 18;
    mapping(address => uint256) public rawBalance;
    uint256 public multiplier = 1;

    function mint(address to, uint256 amount) external {
        rawBalance[to] += amount;
    }

    function rebase(uint256 newMultiplier) external {
        multiplier = newMultiplier;
    }

    function balanceOf(address account) external view returns (uint256) {
        return rawBalance[account] * multiplier;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 rawAmount = amount / multiplier;
        require(rawBalance[msg.sender] >= rawAmount, "insufficient");
        rawBalance[msg.sender] -= rawAmount;
        rawBalance[to] += rawAmount;
        return true;
    }
}

/// @notice Fee on transfer token (takes 10% fee on every transfer)
contract FeeOnTransferTokenBreak {
    string public name = "Fee Token";
    string public symbol = "FEE";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = amount / 10; // 10% burn/tax
        uint256 received = amount - fee;
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += received;
        return true;
    }
}

// âââ Test Suite ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

contract RealAirdropBreakCampaignTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 eoaPk = 0x789;
    address eoa;
    address sponsor = address(0x456);
    address safeWallet = address(0x123);

    MockERC20 standardToken;
    AntiContractAirdrop antiContractAirdrop;
    StrictTxOriginAirdrop strictOriginAirdrop;
    HostileFakeTransferToken hostileToken;
    RebasingTokenMock rebasingToken;
    FeeOnTransferTokenBreak feeToken;

    function setUp() public {
        eoa = vm.addr(eoaPk);
        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(eoa, address(delegateContract).code);

        standardToken = new MockERC20();
        antiContractAirdrop = new AntiContractAirdrop(address(standardToken));
        strictOriginAirdrop = new StrictTxOriginAirdrop(address(standardToken));
        hostileToken = new HostileFakeTransferToken();
        rebasingToken = new RebasingTokenMock();
        feeToken = new FeeOnTransferTokenBreak();
    }

    function _sign(Call[] memory calls, address[] memory tokens, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return signRescueIntent(eoaPk, eoa, safeWallet, sponsor, calls, tokens, nonce, deadline);
    }

    /// @notice Attack Archetype 1: Anti-contract check `extcodesize(msg.sender) == 0`
    function testBreak_AntiContractExtcodesize_RevertsUnderEIP7702() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(antiContractAirdrop),
            value: 0,
            data: abi.encodeWithSelector(AntiContractAirdrop.claim.selector, 1000)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(standardToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor, sponsor);
        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector,
                0,
                abi.encodeWithSignature("Error(string)", "EOA ONLY: Contracts blocked")
            )
        );
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    /// @notice Attack Archetype 2: Strict `tx.origin == msg.sender`
    function testBreak_StrictTxOrigin_RevertsUnderSponsorship() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(strictOriginAirdrop),
            value: 0,
            data: abi.encodeWithSelector(StrictTxOriginAirdrop.claim.selector, 1000)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(standardToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor, sponsor);
        vm.expectRevert(
            abi.encodeWithSelector(
                CallFailed.selector,
                0,
                abi.encodeWithSignature("Error(string)", "tx.origin != msg.sender: Sponsored calls blocked")
            )
        );
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    /// @notice Attack Archetype 3: Hostile Fake Transfer Token
    function testBreak_HostileFakeTransfer_TransactionSucceeds_BalanceZero() public {
        hostileToken.setBalance(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(hostileToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor, sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(hostileToken.balanceOf(safeWallet), 0);
    }

    /// @notice Attack Archetype 4: Rebasing Token
    function testBreak_RebasingToken_BalanceChangesDynamically() public {
        rebasingToken.mint(eoa, 1000);
        rebasingToken.rebase(2);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(rebasingToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor, sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(rebasingToken.balanceOf(safeWallet), 2000);
    }

    /// @notice Attack Archetype 5: Fee-On-Transfer Token
    function testBreak_FeeOnTransferToken_SweepsActualReceivedAmount() public {
        feeToken.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(feeToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor, sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(feeToken.balanceOf(safeWallet), 900);
    }
}
