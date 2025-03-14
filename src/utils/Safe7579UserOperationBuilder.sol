// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    IUserOperationBuilder, PackedUserOperation
} from "src/interfaces/IUserOperationBuilder.sol";
import { ModeLib } from "src/lib/ModeLib.sol";
import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { IEntryPoint } from "@ERC4337/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { ISafe7579 } from "src/ISafe7579.sol";

contract Safe7579UserOperationBuilder is IUserOperationBuilder {
    IEntryPoint internal immutable _entryPoint;

    constructor(address _entryPointAddress) {
        _entryPoint = IEntryPoint(_entryPointAddress);
    }

    function entryPoint() external view returns (address) {
        return address(_entryPoint);
    }

    function getNonce(
        address smartAccount,
        bytes calldata context
    )
        external
        view
        returns (uint256)
    {
        address validator = address(bytes20(context[0:20]));
        uint192 key = uint192(bytes24(bytes20(address(validator))));
        return _entryPoint.getNonce(address(smartAccount), key);
    }

    function getCallData(
        address smartAccount,
        Execution[] calldata executions,
        bytes calldata context
    )
        external
        pure
        returns (bytes memory)
    {
        if (executions.length == 0) {
            revert("No executions provided");
        }
        if (executions.length == 1) {
            return abi.encodeCall(
                ISafe7579.execute,
                (
                    ModeLib.encodeSimpleSingle(),
                    ExecutionLib.encodeSingle(
                        executions[0].target, executions[0].value, executions[0].callData
                    )
                )
            );
        } else {
            return abi.encodeCall(
                ISafe7579.execute,
                (ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(executions))
            );
        }
        // TODO: add delegatecall, tryExecute and other execution modes handling
    }

    function getDummySignature(
        address smartAccount,
        Execution[] calldata executions,
        bytes calldata context
    )
        external
        pure
        returns (bytes memory signature)
    {
        bytes32 signerId = bytes32(context);
        signature = abi.encodePacked(
            bytes1(0x00),
            context,
            abi.encode(
                hex"e8b94748580ca0b4993c9a1b86b5be851bfc076ff5ce3a1ff65bf16392acfcb800f9b4f1aef1555c7fce5599fffb17e7c635502154a0333ba21f3ae491839af51c",
                hex"07855b46a623a8ecabac76ed697aa4e13631e3b6718c8a0d342860c13c30d2fc00000000000000000000000000000000000000000000000000000000000000e0010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000024456b4f30bac4a8994b010d127650e6f22669f7f7aec4475f80f8c2a8d2ed02872b0aca713e929d8a28596b42f325fa9587a16a8eb2bc07e4b3a3e9c14a7b988100000000000000000000000000000000000000000000000000000000000000251584482fdf7a4d0b7eb9d45cf835288cb59e55b8249fff356e33be88ecc546d11d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000957b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a22307831383138356261383531633032383032323035366564396634326261313434396532613138663739323932326238383939363937313962616665373861653563222c226f726967696e223a2268747470733a2f2f646576656c6f706d656e742e666f72756d64616f732e636f6d227d0000000000000000000000"
            )
        );
    }

    function getSignature(
        address smartAccount,
        PackedUserOperation calldata userOperation,
        bytes calldata context
    )
        external
        pure
        returns (bytes memory signature)
    {
        if (context[0] == 0x01) {
            // enable module
            (
                uint8 permissionIndex,
                bytes memory permissionEnableData,
                bytes memory permissionEnableDataSignature,
                bytes memory permissionData
            ) = abi.decode(context[1:], (uint8, bytes, bytes, bytes));

            signature = abi.encodePacked(
                context[0],
                permissionIndex,
                abi.encode(
                    permissionEnableData,
                    permissionEnableDataSignature,
                    permissionData,
                    userOperation.signature
                )
            );
        } else {
            // use existing signerId
            bytes32 signerId = bytes32(context[1:33]);
            (bytes memory sig1, bytes memory sig2) =
                abi.decode(userOperation.signature, (bytes, bytes));
            signature = abi.encodePacked(context, abi.encode(sig1, sig2));
        }
    }
}
