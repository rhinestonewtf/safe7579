// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import { IERC7579Account, Execution } from "./interfaces/IERC7579Account.sol";
import {
    CallType,
    ExecType,
    ModeCode,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY,
    CALLTYPE_SINGLE,
    CALLTYPE_BATCH,
    CALLTYPE_DELEGATECALL
} from "./lib/ModeLib.sol";
import { ExecutionLib } from "./lib/ExecutionLib.sol";
import {
    IValidator,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK
} from "erc7579/interfaces/IERC7579Module.sol";
import { ModuleInstallUtil } from "./utils/DCUtil.sol";
import { AccessControl } from "./core/AccessControl.sol";
import { Initializer } from "./core/Initializer.sol";
import { SafeOp } from "./core/SafeOp.sol";
import { ISafe } from "./interfaces/ISafe.sol";
import { ISafe7579 } from "./ISafe7579.sol";
import {
    PackedUserOperation,
    UserOperationLib
} from "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";
import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import { IEntryPoint } from "@ERC4337/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { IERC1271 } from "./interfaces/IERC1271.sol";
import { SupportViewer } from "./core/SupportViewer.sol";

uint256 constant MULTITYPE_MODULE = 0;

/**
 * @title ERC7579 Adapter for Safe accounts.
 * creates full ERC7579 compliance to Safe accounts
 * @author rhinestone | zeroknots.eth, Konrad Kopp (@kopy-kat)
 * @dev This contract is a Safe account implementation that supports ERC7579 operations.
 *    In order to facilitate full ERC7579 compliance, the contract implements the IERC7579Account
 *    interface.
 * This contract is an implementation of a Safe account supporting ERC7579 operations and complying
 * with the IERC7579Account interface. It serves as a Safe FallbackHandler and module for Safe
 * accounts, incorporating complex hacks to ensure ERC7579 compliance and requiring interactions and
 * event emissions to be done via the SafeProxy as msg.sender using Safe's
 * "executeTransactionFromModule" features.
 */
contract Safe7579 is ISafe7579, SafeOp, SupportViewer, AccessControl, Initializer {
    using ExecutionLib for bytes;

    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256("SafeMessage(bytes message)");
    bytes32 private constant SAFE_MSG_TYPEHASH =
        0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;
    // keccak256("safeSignature(bytes32,bytes32,bytes,bytes)");
    bytes4 private constant SAFE_SIGNATURE_MAGIC_VALUE = 0x5fd7e97d;

    /**
     * @inheritdoc ISafe7579
     */
    function execute(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        withHook(IERC7579Account.execute.selector)
        onlyEntryPointOrSelf
    {
        CallType callType;
        ExecType execType;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            callType := mode
            execType := shl(8, mode)
        }
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                   REVERT ON FAILED EXEC                    */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        ISafe safe = ISafe(msg.sender);
        if (execType == EXECTYPE_DEFAULT) {
            // DEFAULT EXEC & BATCH CALL
            if (callType == CALLTYPE_BATCH) {
                Execution[] calldata executions = executionCalldata.decodeBatch();
                _exec(safe, executions);
            }
            // DEFAULT EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) =
                    executionCalldata.decodeSingle();
                _exec(safe, target, value, callData);
            }
            // DEFAULT EXEC & DELEGATECALL
            else if (callType == CALLTYPE_DELEGATECALL) {
                address target = address(bytes20(executionCalldata[:20]));
                bytes calldata callData = executionCalldata[20:];
                _delegatecall(safe, target, callData);
            }
            // handle unsupported calltype
            else {
                revert UnsupportedCallType(callType);
            }
        }
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                           TRY EXEC                         */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        else if (execType == EXECTYPE_TRY) {
            // TRY EXEC & BATCH CALL
            if (callType == CALLTYPE_BATCH) {
                Execution[] calldata executions = executionCalldata.decodeBatch();
                _tryExec(safe, executions);
            }
            // TRY EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) =
                    executionCalldata.decodeSingle();
                _tryExec(safe, target, value, callData);
            }
            // TRY EXEC & DELEGATECALL
            else if (callType == CALLTYPE_DELEGATECALL) {
                address target = address(bytes20(executionCalldata[:20]));
                bytes calldata callData = executionCalldata[20:];
                _tryDelegatecall(safe, target, callData);
            }
            // handle unsupported calltype
            else {
                revert UnsupportedCallType(callType);
            }
        }
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*               HANDLE UNSUPPORTED EXEC TYPE                 */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        else {
            revert UnsupportedExecType(execType);
        }
    }

    /**
     * @inheritdoc ISafe7579
     */
    function executeFromExecutor(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        override
        onlyExecutorModule
        withHook(IERC7579Account.executeFromExecutor.selector)
        withRegistry(_msgSender(), MODULE_TYPE_EXECUTOR)
        returns (bytes[] memory returnDatas)
    {
        CallType callType;
        ExecType execType;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            callType := mode
            execType := shl(8, mode)
        }
        // using JUMPI to avoid stack too deep
        return _executeReturn(execType, callType, executionCalldata);
    }

    /**
     * Internal function that will be solely called by executeFromExecutor. Not super uniform code,
     * but we need the JUMPI to avoid stack too deep, due to the modifiers in the
     * executeFromExecutor function
     */
    function _executeReturn(
        ExecType execType,
        CallType callType,
        bytes calldata executionCalldata
    )
        private
        returns (bytes[] memory returnDatas)
    {
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                   REVERT ON FAILED EXEC                    */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

        if (execType == EXECTYPE_DEFAULT) {
            // DEFAULT EXEC & BATCH CALL
            if (callType == CALLTYPE_BATCH) {
                Execution[] calldata executions = executionCalldata.decodeBatch();
                returnDatas = _execReturn(ISafe(msg.sender), executions);
            }
            // DEFAULT EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) =
                    executionCalldata.decodeSingle();
                returnDatas = new bytes[](1);
                returnDatas[0] = _execReturn(ISafe(msg.sender), target, value, callData);
            }
            // DEFAULT EXEC & DELEGATECALL
            else if (callType == CALLTYPE_DELEGATECALL) {
                address target = address(bytes20(executionCalldata[:20]));
                bytes calldata callData = executionCalldata[20:];
                returnDatas = new bytes[](1);
                returnDatas[0] = _delegatecallReturn(ISafe(msg.sender), target, callData);
            }
            // handle unsupported calltype
            else {
                revert UnsupportedCallType(callType);
            }
        }
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                           TRY EXEC                         */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        else if (execType == EXECTYPE_TRY) {
            // TRY EXEC & BATCH CALL
            if (callType == CALLTYPE_BATCH) {
                Execution[] calldata executions = executionCalldata.decodeBatch();
                (, returnDatas) = _tryExecReturn(ISafe(msg.sender), executions);
            }
            // TRY EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) =
                    executionCalldata.decodeSingle();
                returnDatas = new bytes[](1);
                returnDatas[0] = _tryExecReturn(ISafe(msg.sender), target, value, callData);
            }
            // TRY EXEC & DELEGATECALL
            else if (callType == CALLTYPE_DELEGATECALL) {
                address target = address(bytes20(executionCalldata[:20]));
                bytes calldata callData = executionCalldata[20:];
                returnDatas = new bytes[](1);
                returnDatas[0] = _tryDelegatecallReturn(ISafe(msg.sender), target, callData);
            }
            // handle unsupported calltype
            else {
                revert UnsupportedCallType(callType);
            }
        }
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*               HANDLE UNSUPPORTED EXEC TYPE                 */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        else {
            revert UnsupportedExecType(execType);
        }
    }

    /**
     * @inheritdoc ISafe7579
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        onlyEntryPoint
        returns (uint256 validSignature)
    {
        address validator;
        uint256 nonce = userOp.nonce;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            validator := shr(96, nonce)
        }

        // check if validator is enabled. If not, use Safe's checkSignatures()
        if (validator == address(0) || !_isValidatorInstalled(validator)) {
            validSignature = _validateSignatures(userOp);
        } else {
            // bubble up the return value of the validator module
            bytes memory retData = _execReturn({
                safe: ISafe(msg.sender),
                target: validator,
                value: 0,
                callData: abi.encodeCall(IValidator.validateUserOp, (userOp, userOpHash))
            });
            validSignature = abi.decode(retData, (uint256));
        }

        // pay prefund
        if (missingAccountFunds != 0) {
            _exec({
                safe: ISafe(msg.sender),
                target: entryPoint(),
                value: missingAccountFunds,
                callData: ""
            });
        }
    }

    /**
     * Function used as signature check fallback, if no valid validation module was selected.
     * will use safe's ECDSA multisig. This code was copied of Safe's ERC4337 module
     */
    function _validateSignatures(PackedUserOperation calldata userOp)
        internal
        view
        returns (uint256 validationData)
    {
        (bytes memory operationData, uint48 validAfter, uint48 validUntil, bytes memory signatures)
        = getSafeOp(userOp, entryPoint());
        try ISafe((msg.sender)).checkSignatures(keccak256(operationData), operationData, signatures)
        {
            // The timestamps are validated by the entry point,
            // therefore we will not check them again
            validationData = _packValidationData({
                sigFailed: false,
                validUntil: validUntil,
                validAfter: validAfter
            });
        } catch {
            validationData = _packValidationData({
                sigFailed: true,
                validUntil: validUntil,
                validAfter: validAfter
            });
        }
    }

    /**
     * @inheritdoc ISafe7579
     */
    function isValidSignature(
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes4 magicValue)
    {
        ISafe safe = ISafe(msg.sender);

        // check for safe's approved hashes
        if (data.length == 0) {
            bytes32 messageHash = keccak256(
                EIP712.encodeMessageData(
                    safe.domainSeparator(),
                    SAFE_MSG_TYPEHASH,
                    abi.encode(keccak256(abi.encode(hash)))
                )
            );

            require(safe.signedMessages(messageHash) != 0, "Hash not approved");
            // return magic value
            return IERC1271.isValidSignature.selector;
        }
        address validationModule = address(bytes20(data[:20]));

        // If validation module with address(0) or no valid validator was provided,
        // The signature validation mechanism falls back to Safe's checkSignatures() function
        if (validationModule == address(0) || !_isValidatorInstalled(validationModule)) {
            bytes memory messageData = EIP712.encodeMessageData(
                safe.domainSeparator(), SAFE_MSG_TYPEHASH, abi.encode(keccak256(abi.encode(hash)))
            );

            bytes32 messageHash = keccak256(messageData);

            safe.checkSignatures(messageHash, messageData, data[20:]);
            return IERC1271.isValidSignature.selector;
        }

        // if a installed validator module was selected, use 7579 validation module
        bytes memory ret = _staticcallReturn({
            safe: ISafe(msg.sender),
            target: validationModule,
            callData: abi.encodeCall(
                IValidator.isValidSignatureWithSender, (_msgSender(), hash, data[20:])
            )
        });
        magicValue = abi.decode(ret, (bytes4));
    }

    /**
     * @inheritdoc ISafe7579
     */
    function installModule(
        uint256 moduleType,
        address module,
        bytes calldata initData
    )
        external
        override
        withHook(IERC7579Account.installModule.selector)
        onlyEntryPointOrSelf
    {
        // internal install functions will decode the initData param, and return sanitized
        // moduleInitData. This is the initData that will be passed to Module.onInstall()
        bytes memory moduleInitData;
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            moduleInitData = _installValidator(module, initData);
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            moduleInitData = _installExecutor(module, initData);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            moduleInitData = _installFallbackHandler(module, initData);
        } else if (moduleType == MODULE_TYPE_HOOK) {
            moduleInitData = _installHook(module, initData);
        } else if (moduleType == MULTITYPE_MODULE) {
            moduleInitData = _multiTypeInstall(module, initData);
        } else {
            revert UnsupportedModuleType(moduleType);
        }

        // Initialize Module via Safe
        _delegatecall({
            safe: ISafe(msg.sender),
            target: UTIL,
            callData: abi.encodeCall(
                ModuleInstallUtil.installModule, (moduleType, module, moduleInitData)
            )
        });
    }

    /**
     * @inheritdoc ISafe7579
     */
    function uninstallModule(
        uint256 moduleType,
        address module,
        bytes calldata deInitData
    )
        external
        override
        tryWithHook(module, IERC7579Account.uninstallModule.selector)
        onlyEntryPointOrSelf
    {
        // internal uninstall functions will decode the deInitData param, and return sanitized
        // moduleDeInitData. This is the initData that will be passed to Module.onUninstall()
        bytes memory moduleDeInitData;
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            moduleDeInitData = _uninstallValidator(module, deInitData);
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            moduleDeInitData = _uninstallExecutor(module, deInitData);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            moduleDeInitData = _uninstallFallbackHandler(module, deInitData);
        } else if (moduleType == MODULE_TYPE_HOOK) {
            moduleDeInitData = _uninstallHook(module, deInitData);
        } else if (moduleType == MULTITYPE_MODULE) {
            moduleDeInitData = _multiTypeUninstall(module, deInitData);
        } else {
            revert UnsupportedModuleType(moduleType);
        }

        // Deinitialize Module via Safe.
        // We are using "try" here, to avoid DoS. A module could revert in 'onUninstall' and prevent
        // the account from removing the module
        _tryDelegatecall({
            safe: ISafe(msg.sender),
            target: UTIL,
            callData: abi.encodeCall(
                ModuleInstallUtil.unInstallModule, (moduleType, module, moduleDeInitData)
            )
        });
    }

    /**
     * @inheritdoc ISafe7579
     */
    function isModuleInstalled(
        uint256 moduleType,
        address module,
        bytes calldata additionalContext
    )
        external
        view
        returns (bool)
    {
        if (moduleType == MODULE_TYPE_VALIDATOR) {
            // Safe7579 adapter allows for validator fallback to Safe's checkSignatures().
            // It can thus be considered a valid validator module
            if (module == msg.sender) return true;
            return _isValidatorInstalled(module);
        } else if (moduleType == MODULE_TYPE_EXECUTOR) {
            return _isExecutorInstalled(module);
        } else if (moduleType == MODULE_TYPE_FALLBACK) {
            return _isFallbackHandlerInstalled(module, additionalContext);
        } else if (moduleType == MODULE_TYPE_HOOK) {
            return _isHookInstalled(module, additionalContext);
        } else {
            return false;
        }
    }

    /**
     * @inheritdoc ISafe7579
     */
    function getNonce(address safe, address validator) external view returns (uint256 nonce) {
        uint192 key = uint192(bytes24(bytes20(address(validator))));
        nonce = IEntryPoint(entryPoint()).getNonce(safe, key);
    }
}

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
