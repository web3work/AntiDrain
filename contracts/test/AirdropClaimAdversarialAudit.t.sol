// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";
import "./mocks/MockERC20.sol";

// âââ Mock Merkle Distributor (OpenZeppelin Archetype) ââââââââââââââââââââââ

contract MockMerkleDistributor {
    address public immutable token;
    bytes32 public immutable merkleRoot;
    mapping(uint256 => uint256) private claimedBitMap;

    event Claimed(uint256 index, address account, uint256 amount);

    constructor(address token_, bytes32 merkleRoot_) {
        token = token_;
        merkleRoot = merkleRoot_;
    }

    function isClaimed(uint256 index) public view returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function _setClaimed(uint256 index) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMap[claimedWordIndex] = claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);
    }

    function claim(
        uint256 index,
        address account,
        uint256 amount,
        bytes32[] calldata merkleProof
    ) external {
        require(!isClaimed(index), "Already claimed");

        // Verify the Merkle proof
        bytes32 node = keccak256(bytes.concat(keccak256(abi.encode(index, account, amount))));
        require(_verify(merkleProof, merkleRoot, node), "Invalid proof");

        _setClaimed(index);
        require(MockERC20(token).transfer(account, amount), "Transfer failed");

        emit Claimed(index, account, amount);
    }

    function _verify(
        bytes32[] memory proof,
        bytes32 root,
        bytes32 leaf
    ) internal pure returns (bool) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        return computedHash == root;
    }
}

// âââ Mock Signature-Based Airdrop (EIP-712 Archetype) ââââââââââââââââââââââ

contract MockSignatureAirdrop {
    address public immutable token;
    address public immutable authorizerSigner;
    bytes32 public immutable DOMAIN_SEPARATOR;
    mapping(address => mapping(uint256 => bool)) public nonceUsed;

    bytes32 public constant CLAIM_TYPEHASH =
        keccak256("Claim(address claimant,address recipient,uint256 amount,uint256 nonce,uint256 deadline)");

    constructor(address token_, address authorizerSigner_) {
        token = token_;
        authorizerSigner = authorizerSigner_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("MockAirdrop")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function claimWithSignature(
        address recipient,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "Expired signature");
        require(!nonceUsed[msg.sender][nonce], "Nonce already used");

        bytes32 structHash = keccak256(
            abi.encode(CLAIM_TYPEHASH, msg.sender, recipient, amount, nonce, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        address recovered = _recover(digest, signature);
        require(recovered == authorizerSigner, "Invalid signer");

        nonceUsed[msg.sender][nonce] = true;
        require(MockERC20(token).transfer(recipient, amount), "Transfer failed");
    }

    function _recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(digest, v, r, s);
    }
}

// âââ Hostile Reentrant Airdrop âââââââââââââââââââââââââââââââââââââââââââââ

contract HostileReentrantAirdrop {
    address public immutable token;
    bool public reentrancyBlocked;

    constructor(address token_) {
        token = token_;
    }

    function claim() external {
        // Attempt to call executeRescue on the caller (the delegated EOA)
        (bool success, ) = msg.sender.call(
            abi.encodeWithSelector(
                UniversalRecoveryDelegate.executeRescue.selector,
                address(0x123),
                new Call[](0),
                new address[](0)
            )
        );
        if (!success) {
            reentrancyBlocked = true;
        }
        // Send tokens anyway
        MockERC20(token).transfer(msg.sender, 1000);
    }
}

// âââ Hostile Fake Airdrop (Emits Transfer Event without Moving Balances) âââ

contract HostileFakeEventAirdrop {
    event Transfer(address indexed from, address indexed to, uint256 value);

    function claim(address recipient, uint256 amount) external {
        // Fabricates a Transfer event without actually transferring any tokens!
        emit Transfer(address(this), recipient, amount);
    }
}

contract RevertingTransferToken {
    function balanceOf(address) external pure returns (uint256) {
        return 1000;
    }
    function transfer(address, uint256) external pure returns (bool) {
        revert("Transfer failed");
    }
}

// âââ Adversarial Test Suite for Airdrop Protocols ââââââââââââââââââââââââââ

contract AirdropClaimAdversarialAuditTest is AntiDrainTestBase {
    UniversalRecoveryDelegate delegateContract;
    uint256 eoaPk = 0x789;
    address eoa;
    address sponsor = address(0x456);
    address safeWallet = address(0x123);
    address attacker = address(0xBAD);

    uint256 signerPrivateKey = 0xA11CE;
    address authorizerSigner;

    MockERC20 airdropToken;
    MockMerkleDistributor merkleDistributor;
    MockSignatureAirdrop signatureAirdrop;
    HostileReentrantAirdrop reentrantAirdrop;
    HostileFakeEventAirdrop fakeEventAirdrop;

    // Merkle tree parameters for leaf 0: index=0, account=eoa, amount=5000
    bytes32 leaf0;
    bytes32 leaf1;
    bytes32 merkleRoot;
    bytes32[] proof0;

    function setUp() public {
        eoa = vm.addr(eoaPk);
        authorizerSigner = vm.addr(signerPrivateKey);

        delegateContract = new UniversalRecoveryDelegate();
        vm.etch(eoa, address(delegateContract).code);

        airdropToken = new MockERC20();

        // 1. Build a 2-leaf Merkle Tree:
        // Leaf 0: index 0, eoa, 5000 tokens
        // Leaf 1: index 1, address(0x999), 3000 tokens
        leaf0 = keccak256(bytes.concat(keccak256(abi.encode(uint256(0), eoa, uint256(5000)))));
        leaf1 = keccak256(bytes.concat(keccak256(abi.encode(uint256(1), address(0x999), uint256(3000)))));

        if (leaf0 <= leaf1) {
            merkleRoot = keccak256(abi.encodePacked(leaf0, leaf1));
        } else {
            merkleRoot = keccak256(abi.encodePacked(leaf1, leaf0));
        }

        proof0 = new bytes32[](1);
        proof0[0] = leaf1;

        merkleDistributor = new MockMerkleDistributor(address(airdropToken), merkleRoot);
        signatureAirdrop = new MockSignatureAirdrop(address(airdropToken), authorizerSigner);
        reentrantAirdrop = new HostileReentrantAirdrop(address(airdropToken));
        fakeEventAirdrop = new HostileFakeEventAirdrop();

        // Fund airdrop contracts with tokens
        airdropToken.mint(address(merkleDistributor), 100_000);
        airdropToken.mint(address(signatureAirdrop), 100_000);
        airdropToken.mint(address(reentrantAirdrop), 100_000);
    }

    function _sign(Call[] memory calls, address[] memory tokens, uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        return signRescueIntent(eoaPk, eoa, safeWallet, sponsor, calls, tokens, nonce, deadline);
    }

    // =========================================================================
    // 1. MERKLE AIRDROP ADVERSARIAL AUDIT
    // =========================================================================

    /// @notice Happy path: Merkle claim executes from delegated EOA and sweeps atomically to safeWallet
    function testMerkle_HappyPath_ClaimAndAtomicSweep() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(merkleDistributor),
            value: 0,
            data: abi.encodeWithSelector(
                MockMerkleDistributor.claim.selector,
                0,
                eoa,
                5000,
                proof0
            )
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        vm.prank(sponsor);
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(airdropToken.balanceOf(safeWallet), 5000, "Safe wallet received 5000 claimed airdrop tokens");
        assertEq(airdropToken.balanceOf(eoa), 0, "EOA token balance is 0");
        assertTrue(merkleDistributor.isClaimed(0), "Leaf 0 marked claimed on Merkle distributor");
    }

    /// @notice Adversarial: Proof manipulation (tampered sibling hash) reverts entire rescue atomically
    function testMerkle_ProofManipulation_RevertsAtomically() public {
        bytes32[] memory badProof = new bytes32[](1);
        badProof[0] = bytes32(uint256(0xDEADBEEF));

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(merkleDistributor),
            value: 0,
            data: abi.encodeWithSelector(
                MockMerkleDistributor.claim.selector,
                0,
                eoa,
                5000,
                badProof
            )
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        vm.prank(sponsor);
        vm.expectRevert();
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertFalse(merkleDistributor.isClaimed(0), "Claim did not execute");
        assertEq(airdropToken.balanceOf(safeWallet), 0, "No tokens moved to safe wallet");
    }

    /// @notice Adversarial: Merkle claim replay attempt must revert
    function testMerkle_ClaimReplay_RevertsOnSecondAttempt() public {
        // First claim succeeds
        testMerkle_HappyPath_ClaimAndAtomicSweep();

        // Second claim attempt with same proof
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(merkleDistributor),
            value: 0,
            data: abi.encodeWithSelector(
                MockMerkleDistributor.claim.selector,
                0,
                eoa,
                5000,
                proof0
            )
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        vm.prank(sponsor);
        vm.expectRevert();
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // =========================================================================
    // 2. SIGNATURE-BASED AIRDROP ADVERSARIAL AUDIT
    // =========================================================================

    /// @notice Happy path: EIP-712 signature claim executes and sweeps directly
    function testSignatureAirdrop_HappyPath_ClaimAndSweep() public {
        uint256 nonce = 0;
        uint256 deadline = block.timestamp + 3600;
        uint256 amount = 8000;

        bytes32 structHash = keccak256(
            abi.encode(
                signatureAirdrop.CLAIM_TYPEHASH(),
                eoa,
                eoa,
                amount,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", signatureAirdrop.DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory airdropSig = abi.encodePacked(r, s, v);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(signatureAirdrop),
            value: 0,
            data: abi.encodeWithSelector(
                MockSignatureAirdrop.claimWithSignature.selector,
                eoa,
                amount,
                nonce,
                deadline,
                airdropSig
            )
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        vm.prank(sponsor);
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertEq(airdropToken.balanceOf(safeWallet), 8000, "Safe wallet received 8000 signature-claimed tokens");
        assertEq(airdropToken.balanceOf(eoa), 0);
    }

    /// @notice Adversarial: Expired signature deadline reverts atomically
    function testSignatureAirdrop_ExpiredDeadline_RevertsAtomically() public {
        uint256 nonce = 0;
        uint256 deadline = block.timestamp - 1; // Expired
        uint256 amount = 8000;

        bytes32 structHash = keccak256(
            abi.encode(
                signatureAirdrop.CLAIM_TYPEHASH(),
                eoa,
                eoa,
                amount,
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", signatureAirdrop.DOMAIN_SEPARATOR(), structHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, digest);
        bytes memory airdropSig = abi.encodePacked(r, s, v);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(signatureAirdrop),
            value: 0,
            data: abi.encodeWithSelector(
                MockSignatureAirdrop.claimWithSignature.selector,
                eoa,
                amount,
                nonce,
                deadline,
                airdropSig
            )
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        vm.prank(sponsor);
        vm.expectRevert();
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);
    }

    // =========================================================================
    // 3. REENTRANCY & HOSTILE CALLBACK AUDIT
    // =========================================================================

    /// @notice Airdrop contract attempting callback reentrancy into executeRescue is strictly blocked
    function testAirdrop_HostileCallbackReentrancy_Blocked() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(reentrantAirdrop),
            value: 0,
            data: abi.encodeWithSelector(HostileReentrantAirdrop.claim.selector)
        });

        address[] memory tokens = new address[](1);
        tokens[0] = address(airdropToken);

        vm.prank(sponsor);
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        assertTrue(reentrantAirdrop.reentrancyBlocked(), "Reentrancy callback was intercepted and blocked by transient guard");
        assertEq(airdropToken.balanceOf(safeWallet), 1000, "Tokens swept cleanly after blocked reentrancy attempt");
    }

    // =========================================================================
    // 4. CLAIM + SWEEP ATOMICITY GUARANTEE
    // =========================================================================

    /// @notice If claim succeeds but sweep encounters a failing token, the entire claim is rolled back
    function testAtomicity_ClaimSucceeds_SweepFails_EntireTxReverts() public {
        RevertingTransferToken badToken = new RevertingTransferToken();

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: address(merkleDistributor),
            value: 0,
            data: abi.encodeWithSelector(
                MockMerkleDistributor.claim.selector,
                0,
                eoa,
                5000,
                proof0
            )
        });

        // Add a token that will fail during transfer
        address[] memory tokens = new address[](1);
        tokens[0] = address(badToken);

        vm.prank(sponsor);
        vm.expectRevert();
        bytes memory sig = _sign(calls, tokens, 0, block.timestamp + 1 hours);
        UniversalRecoveryDelegate(eoa).executeRescue(safeWallet, calls, tokens, 0, block.timestamp + 1 hours, sig);

        // Entire transaction reverted: Merkle distributor leaf 0 was NOT consumed!
        assertFalse(merkleDistributor.isClaimed(0), "Merkle leaf claim was cleanly rolled back on EVM revert");
    }
}
