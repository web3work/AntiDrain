// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "forge-std/Script.sol";
import "../src/BatchExecutor.sol";

contract Deploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);
        
        // One canonical delegate per chain — sponsor identity is independent of delegate identity.
        // Sponsor authorization is now handled via EIP-712 signature binding, not constructor state.
        bytes32 salt = keccak256(abi.encodePacked("AntiDrain_Rescue_v2"));
        BatchExecutor executor = new BatchExecutor{salt: salt}();
        
        vm.stopBroadcast();
    }
}
