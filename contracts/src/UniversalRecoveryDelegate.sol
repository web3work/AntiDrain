// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./libraries/ECDSA.sol";

/**
 * @title UniversalRecoveryDelegate
 * @notice EIP-7702 rescue delegate with per-user sponsor authorization via EIP-712,
 *         ERC-7201 unstructured nonces, and EIP-1153 transient-storage reentrancy protection.
 * @dev Intended to be delegated to by compromised EOAs under EIP-7702.
 *      When called through the delegated EOA, `address(this)` is the EOA itself.
 *
 * THREAT MODEL & DUAL-AUTHORIZATION:
 * - Layer 1 (Per-User Sponsor Gate): The victim signs an EIP-712 intent that binds a specific
 *   `sponsor` address. The contract derives the sponsor from `msg.sender` and verifies that
 *   the victim authorized exactly that caller. Any other caller is rejected.
 * - Layer 2 (Anti-Poisoning Gate): The compromised EOA (`address(this)`) must have signed an EIP-712
 *   typed intent containing the exact `safeWallet`, `sponsor`, `calls`, `tokens`, `nonce`, and `deadline`.
 *   A rogue sponsor cannot modify the payload, redirect assets, or inject unapproved calls.
 *
 * SPONSOR MODEL:
 *   Every user controls their own dedicated sponsor wallet. There is no global AntiDrain treasury.
 *   The victim explicitly authorizes which sponsor may submit their rescue by including the sponsor
 *   address in the signed EIP-712 intent. The contract enforces msg.sender == signed sponsor.
 */

struct Call {
    address target;
    uint256 value;
    bytes data;
}

error UnauthorizedCaller();
error InvalidSafeWallet();
error InvalidNonce(uint256 expected, uint256 actual);
error ExpiredSignature();
error InvalidAuthorization();
error ReentrancyGuardReentrantCall();
error CallFailed(uint256 index, bytes returnData);
error SweepFailed(address token);
error BalanceQueryFailed(address token);
error NativeSweepFailed();

contract UniversalRecoveryDelegate {
    using ECDSA for bytes32;

    /// @dev EIP-712 TypeHashes
    /// IMPORTANT: `sponsor` is the second field in the Rescue struct.
    /// The contract derives the sponsor value from msg.sender — it is NOT a calldata parameter.
    bytes32 public constant CALL_TYPEHASH =
        keccak256("Call(address target,uint256 value,bytes data)");
    bytes32 public constant RESCUE_TYPEHASH =
        keccak256("Rescue(address safeWallet,address sponsor,Call[] calls,address[] tokens,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)");

    /// @dev ERC-7201 Unstructured storage slot derived mathematically from:
    /// keccak256(abi.encode(uint256(keccak256("antidrain.universalRecoveryDelegate.nonce.v1")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 public constant NONCE_SLOT =
        0x20c4ef2d64438754904902e0d18b9fd08eff972df857676712e43a442e87bd00;

    /// @dev Transient storage slot for reentrancy lock (EIP-1153)
    bytes32 private constant _REENTRANCY_SLOT =
        keccak256("antidrain.universalRecoveryDelegate.reentrancy.v1");

    modifier nonReentrant() {
        bytes32 slot = _REENTRANCY_SLOT;
        uint256 status;
        assembly ("memory-safe") {
            status := tload(slot)
        }
        if (status != 0) {
            revert ReentrancyGuardReentrantCall();
        }
        assembly ("memory-safe") {
            tstore(slot, 1)
        }
        _;
        assembly ("memory-safe") {
            tstore(slot, 0)
        }
    }

    /**
     * @notice Execute an authorized rescue operation on behalf of the delegated EOA.
     * @dev Gated by EIP-712 signature that binds msg.sender as the authorized sponsor.
     *      The sponsor is derived from msg.sender — NOT from calldata — eliminating any
     *      parameter-substitution attack surface.
     *
     * Authorization flow:
     *   1. sponsor = msg.sender (derived, not user-supplied)
     *   2. structHash = hash(safeWallet, sponsor, calls, tokens, nonce, deadline)
     *   3. digest = EIP-712 digest with domain(chainId, address(this))
     *   4. signer = ecrecover(digest, signature)
     *   5. require(signer == address(this))  ← victim EOA must have signed THIS exact intent
     *
     * @param safeWallet The safe destination wallet to receive swept assets.
     * @param calls Array of arbitrary pre-sweep calls (claims, unstakes, approvals).
     * @param tokens Array of ERC-20 token addresses to sweep.
     * @param nonce Sequential rescue nonce stored in ERC-7201 unstructured slot.
     * @param deadline Unix timestamp after which the signature expires.
     * @param signature EIP-712 typed signature from the delegating EOA (`address(this)`).
     */
    function executeRescue(
        address safeWallet,
        Call[] calldata calls,
        address[] calldata tokens,
        uint256 nonce,
        uint256 deadline,
        bytes calldata signature
    ) external payable nonReentrant {
        // 1. Derive sponsor from actual transaction sender (NOT from calldata)
        address sponsor = msg.sender;

        // 2. Deadline check
        if (block.timestamp > deadline) {
            revert ExpiredSignature();
        }

        // 3. Input Hygiene: safeWallet cannot be zero address or self
        if (safeWallet == address(0) || safeWallet == address(this)) {
            revert InvalidSafeWallet();
        }

        // 4. EIP-712 Authorization: Verify victim signed THIS exact intent including THIS sponsor
        bytes32 structHash = keccak256(
            abi.encode(
                RESCUE_TYPEHASH,
                safeWallet,
                sponsor,         // msg.sender bound into signed data
                _hashCalls(calls),
                _hashTokens(tokens),
                nonce,
                deadline
            )
        );
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", _domainSeparatorV4(), structHash)
        );
        address signer = digest.recover(signature);
        if (signer != address(this)) {
            revert InvalidAuthorization();
        }

        // 5. Replay Protection: Check & increment ERC-7201 nonce
        _useNonce(nonce);

        // 6. Execute pre-sweep calls (claims, unstakes)
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory returnData) = calls[i].target.call{
                value: calls[i].value
            }(calls[i].data);
            if (!success) {
                revert CallFailed(i, returnData);
            }
        }

        // 7. Sweep 100% of ERC-20 tokens to safeWallet (0% commission, completely free)
        for (uint256 i = 0; i < tokens.length; i++) {
            address token = tokens[i];
            uint256 balance = _balanceOf(token, address(this));
            if (balance > 0) {
                _safeTransfer(token, safeWallet, balance);
            }
        }

        // 8. Sweep 100% of native balance to safeWallet
        uint256 nativeBalance = address(this).balance;
        if (nativeBalance > 0) {
            (bool success, ) = safeWallet.call{value: nativeBalance}("");
            if (!success) {
                revert NativeSweepFailed();
            }
        }
    }

    // ─── EIP-712 Spec-Compliant Array Hashing ──────────────────────────────

    function _hashCalls(Call[] calldata calls) internal pure returns (bytes32) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callHashes[i] = keccak256(
                abi.encode(
                    CALL_TYPEHASH,
                    calls[i].target,
                    calls[i].value,
                    keccak256(calls[i].data)
                )
            );
        }
        return keccak256(abi.encodePacked(callHashes));
    }

    function _hashTokens(address[] calldata tokens) internal pure returns (bytes32) {
        bytes32[] memory tokenWords = new bytes32[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenWords[i] = bytes32(uint256(uint160(tokens[i])));
        }
        return keccak256(abi.encodePacked(tokenWords));
    }

    function _domainSeparatorV4() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("AntiDrainRecovery")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function _useNonce(uint256 expectedNonce) internal {
        bytes32 slot = NONCE_SLOT;
        uint256 currentNonce;
        assembly ("memory-safe") {
            currentNonce := sload(slot)
        }
        if (expectedNonce != currentNonce) {
            revert InvalidNonce(expectedNonce, currentNonce);
        }
        assembly ("memory-safe") {
            sstore(slot, add(currentNonce, 1))
        }
    }

    // ─── Internal Token Helpers ───────────────────────────────────────────

    function _safeTransfer(address token, address to, uint256 amount) internal {
        if (token.code.length == 0) {
            revert SweepFailed(token);
        }
        bool success;
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 0xa9059cbb00000000000000000000000000000000000000000000000000000000)
            mstore(add(m, 0x04), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(m, 0x24), amount)

            let out := add(m, 0x44)
            mstore(out, 0)
            success := call(gas(), token, 0, m, 0x44, out, 0x20)
            let rds := returndatasize()
            // returndatasize == 0 -> success (e.g. USDT)
            // returndatasize >= 32 -> first word must be 1 (standard boolean true)
            // 1 <= returndatasize < 32 -> revert (malformed token return)
            let returnOk := or(
                iszero(rds),
                and(iszero(lt(rds, 32)), eq(mload(out), 1))
            )
            success := and(success, returnOk)
        }

        if (!success) {
            revert SweepFailed(token);
        }
    }

    function _balanceOf(address token, address owner) internal view returns (uint256 balance) {
        if (token.code.length == 0) {
            revert BalanceQueryFailed(token);
        }
        (bool success, bytes memory data) = token.staticcall(
            abi.encodeWithSelector(0x70a08231, owner)
        );
        if (!success || data.length < 32) {
            revert BalanceQueryFailed(token);
        }
        balance = abi.decode(data, (uint256));
    }
}
