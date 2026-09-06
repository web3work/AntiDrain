// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../../src/UniversalRecoveryDelegate.sol";

contract MaliciousToken {
    mapping(address => uint256) public balanceOf;
    bool public reentrancyAttempted;
    bool public reentrancySucceeded;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (!reentrancyAttempted) {
            reentrancyAttempted = true;
            // Attempt to re-enter executeRescue on the caller (the delegated EOA)
            (bool success, ) = msg.sender.call(
                abi.encodeWithSelector(
                    UniversalRecoveryDelegate.executeRescue.selector,
                    address(0x123),
                    new Call[](0),
                    new address[](0)
                )
            );
            if (success) {
                reentrancySucceeded = true;
            }
        }
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
