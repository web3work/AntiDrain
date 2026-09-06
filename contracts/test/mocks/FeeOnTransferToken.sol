// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FeeOnTransferToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = amount / 10;
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += (amount - fee);
        return true;
    }
}
