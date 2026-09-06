// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @dev Token that returns no data on transfer (like USDT)
contract NoDataToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "low balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        // returns void (0 bytes return data)
    }
}
