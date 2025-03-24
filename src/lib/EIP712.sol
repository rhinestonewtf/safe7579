// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

library EIP712 {
    function encodeMessageData(
        bytes32 domainSeparator,
        bytes32 typeHash,
        bytes memory message
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            domainSeparator,
            keccak256(abi.encodePacked(typeHash, message))
        );
    }
}
