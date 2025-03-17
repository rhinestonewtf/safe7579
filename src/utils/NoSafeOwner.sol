// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

contract NoSafeOwner {
    // legacy ERC-1271 used by Safe 1.4.1 and lower
    function isValidSignature(bytes calldata, bytes calldata) public pure returns (bytes4) {
        return 0xffffffff;
    }

    // up-to-date ERC-1271
    function isValidSignature(bytes32, bytes calldata) public pure returns (bytes4) {
        return 0xffffffff;
    }
}
