// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RevertingClaim {
    function claim() external {
        revert("Always revert");
    }
}
