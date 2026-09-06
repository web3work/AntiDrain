// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";
import "./mocks/MaliciousToken.sol";
import "./mocks/FeeOnTransferToken.sol";
import "./mocks/FalseReturnToken.sol";
import "./mocks/NoDataToken.sol";
import "./mocks/RevertingClaim.sol";
import "./mocks/SuccessfulClaim.sol";

contract BrokenBalanceToken {
    function balanceOf(address) external pure returns (bytes16) {
        return bytes16(uint128(999));
    }
    function transfer(address, uint256) external pure returns (bool) {
        return true;
    }
}

contract BatchExecutorTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 eoaPk = 0x789;
    address eoa;
    address safeWallet = address(0x123);
    address sponsor = address(0x456);
    address attacker = address(0xBAD);

    MockERC20 token;
    MockERC20 tokenB;
    MaliciousToken maliciousToken;
    FeeOnTransferToken feeToken;
    FalseReturnToken falseReturnToken;
    NoDataToken noDataToken;
    RevertingClaim revertingClaim;
    SuccessfulClaim successfulClaim;

    function setUp() public {
        eoa = vm.addr(eoaPk);
        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(eoa, address(delegateContract).code);

        token = new MockERC20();
        tokenB = new MockERC20();
        maliciousToken = new MaliciousToken();
        feeToken = new FeeOnTransferToken();
        falseReturnToken = new FalseReturnToken();
        noDataToken = new NoDataToken();
        revertingClaim = new RevertingClaim();
        successfulClaim = new SuccessfulClaim(token);
    }

    function _sign(address _sponsor, Call[] memory calls, address[] memory tokens, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return signRescueIntent(eoaPk, eoa, safeWallet, _sponsor, calls, tokens, nonce, deadline);
    }

    // âââ Happy Path ââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    function testHappyPath_SponsorExecutesRescue_Success() public {
        token.mint(eoa, 1000);
        vm.deal(eoa, 1 ether);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(successfulClaim),
            value: 0,
            data: abi.encodeWithSelector(SuccessfulClaim.claim.selector)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token.balanceOf(safeWallet), 2000);
        assertEq(token.balanceOf(eoa), 0);
        assertEq(safeWallet.balance, 1 ether);
        assertEq(eoa.balance, 0);
    }

    // âââ Per-User Sponsor Authorization Tests ââââââââââââââââââââââââââââââââ

    function testRevert_WrongSponsor_InvalidAuthorization() public {
        // Victim authorizes Sponsor A. Sponsor B executes. â REVERT
        token.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        // Sign with sponsor A
        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // Execute from attacker (Sponsor B) â signature binds msg.sender, so digest differs
        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        // Assets untouched
        assertEq(token.balanceOf(eoa), 1000);
    }

    function testRevert_RandomCallerWithValidSignature_InvalidAuthorization() public {
        // Victim authorizes Sponsor A. Random caller executes. â REVERT
        token.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        address randomCaller = address(0xCAFE);
        vm.prank(randomCaller);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function testRevert_CompromisedSponsorNoVictimSig_InvalidAuthorization() public {
        // Sponsor A is compromised. Attacker has Sponsor A key but no victim signature. â REVERT
        token.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        // Attacker crafts their own "signature" â not from victim
        uint256 attackerPk = 0xDEAD;
        bytes memory fakeSig = signRescueIntent(attackerPk, eoa, safeWallet, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, fakeSig);
    }

    function testSuccess_CompromisedSponsorWithValidVictimSig() public {
        // Attacker has valid victim signature for Sponsor A AND controls Sponsor A. â EXPECTED SUCCESS
        // This establishes the trust model: sponsor key = execution capability, victim sig = asset authorization
        token.mint(eoa, 1000);
        vm.deal(eoa, 1 ether);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // Even an attacker controlling sponsor + having the valid sig can execute â assets go to victim-signed safeWallet
        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        // Assets went to the victim-signed safeWallet, not to the attacker
        assertEq(token.balanceOf(safeWallet), 1000);
        assertEq(safeWallet.balance, 1 ether);
    }

    function testRevert_CrossUserReplay_InvalidAuthorization() public {
        // User B tries to reuse User A's signed intent with User B's sponsor. â REVERT
        // Different verifyingContract (different victim EOA) = different domain = different digest
        uint256 victimBPk = 0xABC;
        address victimB = vm.addr(victimBPk);
        UniversalRecoveryDelegate delegateB = new UniversalRecoveryDelegate();
        vm.etch(victimB, address(delegateB).code);

        token.mint(victimB, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        // Signature from victim A's key, for victim A's domain
        bytes memory sigA = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // Try to use victim A's signature on victim B's contract
        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(victimB).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sigA);
    }

    function testRevert_SafeSubstitution_InvalidAuthorization() public {
        // Intent signed for Safe A. Attempt execution to Safe B. â REVERT
        token.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        address safeB = address(0x999);
        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(safeB, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // âââ Existing Security Tests (preserved) âââââââââââââââââââââââââââââââââ

    function testAtomicity_ClaimFailure_RevertsEntireTx() public {
        token.mint(eoa, 500);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(revertingClaim),
            value: 0,
            data: abi.encodeWithSelector(RevertingClaim.claim.selector)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(CallFailed.selector, 0, abi.encodeWithSignature("Error(string)", "Always revert")));
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token.balanceOf(eoa), 500);
        assertEq(token.balanceOf(safeWallet), 0);
    }

    function testMaliciousToken_ReentrancyProtection() public {
        maliciousToken.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(maliciousToken);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(maliciousToken.balanceOf(safeWallet), 1000);
        assertEq(maliciousToken.balanceOf(eoa), 0);
    }

    function testFeeOnTransferToken() public {
        feeToken.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(feeToken);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(feeToken.balanceOf(safeWallet), 900);
        assertEq(feeToken.balanceOf(eoa), 0);
    }

    function testBrokenBalanceOfToken_GracefullySkipped() public {
        BrokenBalanceToken broken = new BrokenBalanceToken();

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(broken);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function testZeroBalances_NoOp() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(token.balanceOf(safeWallet), 0);
    }

    function testSweep_USDT_NoDataToken_Succeeds() public {
        noDataToken.mint(eoa, 500);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(noDataToken);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(noDataToken.balanceOf(safeWallet), 500);
        assertEq(noDataToken.balanceOf(eoa), 0);
    }

    function testRevert_FalseReturnToken_Reverts() public {
        falseReturnToken.mint(eoa, 500);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(falseReturnToken);

        bytes memory sig = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(SweepFailed.selector, address(falseReturnToken)));
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // âââ Nonce Replay Protection âââââââââââââââââââââââââââââââââââââââââââââ

    function testRevert_NonceReplay_SecondExecutionFails() public {
        token.mint(eoa, 2000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig0 = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig0);

        // Mint more tokens and try to replay with same nonce
        token.mint(eoa, 1000);
        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(InvalidNonce.selector, 0, 1));
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig0);
    }

    // âââ Deadline Protection âââââââââââââââââââââââââââââââââââââââââââââââââ

    function testRevert_ExpiredDeadline() public {
        token.mint(eoa, 1000);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        uint256 expiredDeadline = block.timestamp - 1;
        bytes memory sig = _sign(sponsor, calls, tokens, 0, expiredDeadline);

        vm.prank(sponsor);
        vm.expectRevert(ExpiredSignature.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, expiredDeadline, sig);
    }

    // âââ Input Hygiene âââââââââââââââââââââââââââââââââââââââââââââââââââââââ

    function testRevert_SafeWalletZeroAddress() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        bytes memory sig = signRescueIntent(eoaPk, eoa, address(0), sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidSafeWallet.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(address(0), calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    function testRevert_SafeWalletIsSelf() public {
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](0);

        bytes memory sig = signRescueIntent(eoaPk, eoa, eoa, sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        vm.prank(sponsor);
        vm.expectRevert(InvalidSafeWallet.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(eoa, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // ─── Cross-Chain Replay Protection ───────────────────────────────────────

    function testRevert_CrossChainReplay_InvalidAuthorization() public {
        // Sign intent on Chain 1
        vm.chainId(1);
        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sigChain1 = _sign(sponsor, calls, tokens, 0, block.timestamp + 1 hours);

        // Attempt to execute on Chain 8453 (Base)
        vm.chainId(8453);
        vm.prank(sponsor);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sigChain1);
    }
}
