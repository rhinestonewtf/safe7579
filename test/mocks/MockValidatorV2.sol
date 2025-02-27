// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { PackedUserOperation } from "erc7579/interfaces/IERC7579Module.sol";
import { MockValidator as MockValidatorBase } from "module-bases/mocks/MockValidator.sol";

contract MockValidatorV2 is MockValidatorBase {
    bytes4 public constant MAGIC_VALUE = 0x1626ba7e;
    bool public returnValidSignature;
    uint256 public validateUserOpReturnValue;

    function onInstall(bytes calldata) external override { }
    function onUninstall(bytes calldata) external override { }

    function setReturnValidSignature(bool _returnValidSignature) external {
        returnValidSignature = _returnValidSignature;
    }

    function setValidateUserOpReturnValue(uint256 _returnValue) external {
        validateUserOpReturnValue = _returnValue;
    }

    function validateUserOp(
        PackedUserOperation calldata,
        bytes32
    )
        external
        override
        returns (ValidationData)
    {
        return ValidationData.wrap(validateUserOpReturnValue);
    }

    function isValidSignatureWithSender(
        address,
        bytes32,
        bytes calldata
    )
        external
        view
        override
        returns (bytes4)
    {
        return returnValidSignature ? MAGIC_VALUE : bytes4(0);
    }
}
