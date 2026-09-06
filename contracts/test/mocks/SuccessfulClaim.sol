// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./MockERC20.sol";

contract SuccessfulClaim {
    MockERC20 public token;

    constructor(MockERC20 _token) {
        token = _token;
    }

    function claim() external {
        token.mint(msg.sender, 1000);
    }
}
