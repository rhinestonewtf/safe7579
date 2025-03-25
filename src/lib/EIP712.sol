// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import { EmergencyUninstall } from "../DataTypes.sol";

library EIP712 {
    // keccak256("SafeMessage(bytes message)");
    bytes32 internal constant SAFE_MSG_TYPEHASH =
        0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    // forgefmt: disable-next-line
    // keccak256("EmergencyUninstall(address hook,uint256 hookType,bytes deInitData,uint256 nonce)");
    bytes32 internal constant EMERGENCY_UNINSTALL_TYPE_HASH =
        0xd3ddfc12654178cc44d4a7b6b969cfdce7ffe6342326ba37825314cffa0fba9c;

    function encodeMessageData(
        bytes32 domainSeparator,
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
            keccak256(abi.encode(SAFE_MSG_TYPEHASH, message))
        );
    }

    function encodeEmergencyUninstallData(
        bytes32 domainSeparator,
        EmergencyUninstall calldata data
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            domainSeparator,
            keccak256(
                abi.encode(
                    EMERGENCY_UNINSTALL_TYPE_HASH,
                    data.hook,
                    data.hookType,
                    keccak256(data.deInitData),
                    data.nonce
                )
            )
        );
    }
}
