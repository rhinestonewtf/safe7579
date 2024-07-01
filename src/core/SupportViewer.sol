// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {
    CallType,
    ExecType,
    ModeCode,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL
} from "../lib/ModeLib.sol";
import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK
} from "erc7579/interfaces/IERC7579Module.sol";
import { IERC7579AccountView } from "src/interfaces/IERC7579Account.sol";

abstract contract SupportViewer is IERC7579AccountView {
    function accountId() external pure returns (string memory accountImplementationId) {
        return "rhinestone.safe7579.v1.0.0";
    }

    function supportsExecutionMode(ModeCode encodedMode) external pure returns (bool supported) {
        CallType callType;
        ExecType execType;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            callType := encodedMode
            execType := shl(8, encodedMode)
        }
        if (callType == CALLTYPE_BATCH) supported = true;
        else if (callType == CALLTYPE_SINGLE) supported = true;
        else if (callType == CALLTYPE_DELEGATECALL) supported = true;
        else return false;

        if (supported && execType == EXECTYPE_DEFAULT) return supported;
        else if (supported && execType == EXECTYPE_TRY) return supported;
        else return false;
    }

    function supportsModule(uint256 moduleTypeId) external pure returns (bool) {
        if (moduleTypeId == MODULE_TYPE_VALIDATOR) return true;
        else if (moduleTypeId == MODULE_TYPE_EXECUTOR) return true;
        else if (moduleTypeId == MODULE_TYPE_FALLBACK) return true;
        else if (moduleTypeId == MODULE_TYPE_HOOK) return true;
        else return false;
    }
}
