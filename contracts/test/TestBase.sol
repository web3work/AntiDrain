// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Test.sol";
import "../src/UniversalRecoveryDelegate.sol";

contract AntiDrainTestBase is Test {
    bytes32 internal constant CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");
    bytes32 internal constant RESCUE_TYPEHASH =
        keccak256("Rescue(address safeWallet,address sponsor,Call[] calls,address[] tokens,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)");

    function signRescueIntent(
        uint256 signerPk,
        address verifyingContract,
        address safeWallet,
        address sponsor,
        Call[] memory calls,
        address[] memory tokens,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32[] memory callHashes = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; i++) {
            callHashes[i] = keccak256(
                abi.encode(CALL_TYPEHASH, calls[i].target, calls[i].value, keccak256(calls[i].data))
            );
        }
        bytes32 callsHash = keccak256(abi.encodePacked(callHashes));
        bytes32[] memory tokenWords = new bytes32[](tokens.length);
        for (uint256 i = 0; i < tokens.length; i++) {
            tokenWords[i] = bytes32(uint256(uint160(tokens[i])));
        }
        bytes32 tokensHash = keccak256(abi.encodePacked(tokenWords));

        bytes32 structHash = keccak256(
            abi.encode(RESCUE_TYPEHASH, safeWallet, sponsor, callsHash, tokensHash, nonce, deadline)
        );

        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("AntiDrainRecovery")),
                keccak256(bytes("1")),
                block.chainid,
                verifyingContract
            )
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, digest);
        return abi.encodePacked(r, s, v);
    }
}
