// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { IModule } from "src/interfaces/IERC7579Module.sol";
import {
    PackedUserOperation,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
    IPreValidationHookERC1271,
    IPreValidationHookERC4337
} from "erc7579/interfaces/IERC7579Module.sol";

contract MockPreValidationHook is IPreValidationHookERC1271, IPreValidationHookERC4337 {
    bytes32 public returnedHash;
    bytes public returnedSignature;
    bool public hookCalled;
    bool public willModify;

    function onInstall(bytes calldata data) external override { }

    function onUninstall(bytes calldata) external override { }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
            || moduleTypeId == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271;
    }

    function isInitialized(address) external pure returns (bool) {
        return true;
    }

    function setWillModify(bool _willModify) external {
        willModify = _willModify;
    }

    function setReturnValues(bytes32 _hash, bytes calldata _signature) external {
        returnedHash = _hash;
        returnedSignature = _signature;
    }

    function preValidationHookERC1271(
        address,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes32 hookHash, bytes memory hookSignature)
    {
        if (willModify) {
            return (returnedHash, returnedSignature);
        } else {
            return (hash, data);
        }
    }

    function preValidationHookERC4337(
        PackedUserOperation calldata userOp,
        uint256,
        bytes32 userOpHash
    )
        external
        view
        returns (bytes32 hookHash, bytes memory hookSignature)
    {
        if (willModify) {
            return (returnedHash, returnedSignature);
        } else {
            return (userOpHash, userOp.signature);
        }
    }
}
