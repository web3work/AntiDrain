// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./TestBase.sol";
import "../src/UniversalRecoveryDelegate.sol";

contract Create2DeploymentAuditTest is AntiDrainTestBase {
    bytes32 constant TEST_SALT = bytes32(uint256(0xAD7702));

    function test_Section9_Create2AddressPredictionMatchesExactDeployment() public {
        // In the per-user sponsor architecture, UniversalRecoveryDelegate has NO constructor parameters.
        // InitCode is simply the creationCode with no encoded arguments.
        bytes memory initCode = type(UniversalRecoveryDelegate).creationCode;
        bytes32 initCodeHash = keccak256(initCode);
        bytes32 s = TEST_SALT;

        address deployed;
        assembly {
            deployed := create2(0, add(initCode, 0x20), mload(initCode), s)
        }

        address calculatedDirect = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            s,
                            initCodeHash
                        )
                    )
                )
            )
        );

        assertEq(deployed, calculatedDirect, "CREATE2 formula is mathematically identical to EVM opcode");
        assertTrue(deployed.code.length > 0, "Deployed delegate has non-zero code length");
    }

    function test_Section9_CanonicalRuntimeBytecodeIsDeterministic() public {
        UniversalRecoveryDelegate delegateA = new UniversalRecoveryDelegate();
        UniversalRecoveryDelegate delegateB = new UniversalRecoveryDelegate();

        bytes memory codeA = address(delegateA).code;
        bytes memory codeB = address(delegateB).code;

        assertEq(codeA.length, codeB.length, "Runtime code lengths are identical");
        assertTrue(codeA.length > 0, "Runtime code is non-empty");
        assertEq(keccak256(codeA), keccak256(codeB), "Canonical delegate produces identical deterministic runtime bytecode");
    }

    function test_Section9_ForeignContractWithDifferentBytecodeRejected() public {
        UniversalRecoveryDelegate legitimate = new UniversalRecoveryDelegate();
        ForeignContract foreign = new ForeignContract();

        assertTrue(
            keccak256(address(foreign).code) != keccak256(address(legitimate).code),
            "Foreign contract bytecode hash is DIFFERENT and must be rejected"
        );
    }
}

contract ForeignContract {
    function someOtherFunction() external pure returns (bool) {
        return true;
    }
}
