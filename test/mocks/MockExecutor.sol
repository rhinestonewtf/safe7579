// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import {
    ExecType,
    ModeCode,
    ModeLib,
    ModePayload,
    MODE_DEFAULT,
    CallType,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL
} from "src/lib/ModeLib.sol";
import { MockExecutor as MockExecutorBase } from "module-bases/mocks/MockExecutor.sol";
import { ISafe7579 } from "src/ISafe7579.sol";

contract MockExecutor is MockExecutorBase {
    function executeViaAccount(
        ISafe7579 account,
        address target,
        uint256 value,
        bytes calldata callData
    )
        external
        returns (bytes[] memory returnData)
    {
        return account.executeFromExecutor(
            ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(target, value, callData)
        );
    }

    function execBatch(
        ISafe7579 account,
        Execution[] calldata execs
    )
        external
        returns (bytes[] memory returnData)
    {
        return account.executeFromExecutor(
            ModeLib.encodeSimpleBatch(), ExecutionLib.encodeBatch(execs)
        );
    }

    function executeDelegateCallViaAccount(
        ISafe7579 account,
        address target,
        bytes calldata callData
    )
        external
        returns (bytes[] memory returnData)
    {
        bytes memory delegateCallData = abi.encodePacked(target, callData);

        return account.executeFromExecutor(
            ModeLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            delegateCallData
        );
    }

    function tryExecuteDelegateCallViaAccount(
        ISafe7579 account,
        address target,
        bytes calldata callData
    )
        external
        returns (bytes[] memory returnData)
    {
        bytes memory delegateCallData = abi.encodePacked(target, callData);

        return account.executeFromExecutor(
            ModeLib.encode(
                CALLTYPE_DELEGATECALL, EXECTYPE_TRY, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            delegateCallData
        );
    }

    function executeUnsupportedCallType(
        ISafe7579 account,
        address target,
        bytes calldata callData
    )
        external
        returns (bytes[] memory returnData)
    {
        return account.executeFromExecutor(
            ModeLib.encode(
                CallType.wrap(0x04), EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(bytes22(0))
            ),
            abi.encodePacked(target, callData)
        );
    }

    function executeUnsupportedExecType(
        ISafe7579 account,
        address target,
        bytes calldata callData
    )
        external
        returns (bytes[] memory returnData)
    {
        return account.executeFromExecutor(
            ModeLib.encode(
                CALLTYPE_DELEGATECALL,
                ExecType.wrap(0x02),
                MODE_DEFAULT,
                ModePayload.wrap(bytes22(0))
            ),
            abi.encodePacked(target, callData)
        );
    }
}
