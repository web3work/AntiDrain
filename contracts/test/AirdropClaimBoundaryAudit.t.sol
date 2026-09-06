// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ ERC-1967 Mock Proxy & Implementations âââââââââââââââââââââââââââââââââ

contract AirdropImplementationV1 {
    address public immutable token;

    constructor(address token_) {
        token = token_;
    }

    function claim(address recipient, uint256 amount) external {
        MockERC20(token).mint(recipient, amount);
    }
}

contract AirdropImplementationV2Malicious {
    function claim(address, uint256) external pure {
        revert("Upgraded implementation rejects claim");
    }
}

contract ERC1967ProxyMock {
    bytes32 internal constant _IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    address public admin;

    constructor(address logic, address admin_) {
        admin = admin_;
        _setImplementation(logic);
    }

    function upgradeTo(address newImplementation) external {
        require(msg.sender == admin, "Only admin");
        _setImplementation(newImplementation);
    }

    function _setImplementation(address newImplementation) private {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    fallback() external payable {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        address impl;
        assembly {
            impl := sload(slot)
        }
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

// âââ Execution Context Checking Airdrops âââââââââââââââââââââââââââââââââââ

contract ContextCheckingAirdrop {
    address public immutable token;

    constructor(address token_) {
        token = token_;
    }

    function claimSender(address recipient, uint256 amount) external {
        require(msg.sender == recipient, "msg.sender != recipient");
        MockERC20(token).mint(recipient, amount);
    }

    function claimStrictOrigin(address recipient, uint256 amount) external {
        require(tx.origin == msg.sender, "tx.origin != msg.sender");
        require(msg.sender == recipient, "msg.sender != recipient");
        MockERC20(token).mint(recipient, amount);
    }
}

// âââ Boundary Audit Test Suite âââââââââââââââââââââââââââââââââââââââââââââ

contract AirdropClaimBoundaryAuditTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 eoaPk = 0x789;
    address eoa;
    address sponsor = address(0x456);
    address safeWallet = address(0x123);
    address proxyAdmin = address(0xAA);
    address attacker = address(0xBAD);

    MockERC20 airdropToken;
    AirdropImplementationV1 v1Impl;
    AirdropImplementationV2Malicious v2Impl;
    ERC1967ProxyMock proxy;
    ContextCheckingAirdrop contextAirdrop;

    function setUp() public {
        eoa = vm.addr(eoaPk);
        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(eoa, address(delegateContract).code);

        airdropToken = new MockERC20();
        v1Impl = new AirdropImplementationV1(address(airdropToken));
        v2Impl = new AirdropImplementationV2Malicious();
        proxy = new ERC1967ProxyMock(address(v1Impl), proxyAdmin);
        contextAirdrop = new ContextCheckingAirdrop(address(airdropToken));
    }

    function _sign(Call[] memory calls, address[] memory tokens, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return signRescueIntent(eoaPk, eoa, safeWallet, sponsor, calls, tokens, nonce, deadline);
    }

    // =========================================================================
    // 1. PROXY-BASED AIRDROP UPGRADE RE-ENTRANCY / MUTATION AUDIT
    // =========================================================================

    function testProxy_V1Implementation_Succeeds() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(proxy),
            value: 0,
            data: abi.encodeWithSelector(AirdropImplementationV1.claim.selector, eoa, 5000)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(airdropToken.balanceOf(safeWallet), 5000);
    }

    function testProxy_UpgradeToV2_RevertsAtomically() public {
        vm.prank(proxyAdmin);
        proxy.upgradeTo(address(v2Impl));

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(proxy),
            value: 0,
            data: abi.encodeWithSelector(AirdropImplementationV1.claim.selector, eoa, 5000)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert();
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(airdropToken.balanceOf(safeWallet), 0);
    }

    // =========================================================================
    // 2. EIP-7702 EXECUTION CONTEXT AUDIT (msg.sender vs tx.origin)
    // =========================================================================

    function testContext_MsgSenderCheck_SucceedsInDelegatedEOA() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(contextAirdrop),
            value: 0,
            data: abi.encodeWithSelector(ContextCheckingAirdrop.claimSender.selector, eoa, 3000)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(airdropToken.balanceOf(safeWallet), 3000);
    }

    function testContext_StrictTxOriginCheck_SafelyReverts() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(contextAirdrop),
            value: 0,
            data: abi.encodeWithSelector(ContextCheckingAirdrop.claimStrictOrigin.selector, eoa, 3000)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert();
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(airdropToken.balanceOf(safeWallet), 0);
    }

    // =========================================================================
    // 3. STEALTH ALLOWANCE & AUTHORITY RESIDUAL INFECTION AUDIT
    // =========================================================================

    function testStealthAllowance_LeavesPersistentAuthorityOnToken() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call({
            target: address(proxy),
            value: 0,
            data: abi.encodeWithSelector(AirdropImplementationV1.claim.selector, eoa, 4000)
        });
        calls[1] = Call({
            target: address(airdropToken),
            value: 0,
            data: abi.encodeWithSelector(MockERC20.approve.selector, attacker, type(uint256).max)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(airdropToken.balanceOf(safeWallet), 4000);
        assertEq(airdropToken.balanceOf(eoa), 0);

        assertEq(
            airdropToken.allowance(eoa, attacker),
            type(uint256).max
        );
    }
}
