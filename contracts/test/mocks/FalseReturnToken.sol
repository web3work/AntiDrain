// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @dev Token that returns false on transfer instead of reverting
contract FalseReturnToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false; // Return false instead of revert
    }
}
