// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { SentinelListLib } from "sentinellist/SentinelList.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { IModule, IHook } from "../interfaces/IERC7579Module.sol";
import { ISafe } from "../interfaces/ISafe.sol";
import { ISafe7579 } from "../ISafe7579.sol";
import "../DataTypes.sol";

import { RegistryAdapter } from "./RegistryAdapter.sol";
import { AccessControl } from "./AccessControl.sol";
import { CallType, CALLTYPE_STATIC, CALLTYPE_SINGLE } from "../lib/ModeLib.sol";
import {
    IValidator,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
    IPreValidationHookERC1271,
    IPreValidationHookERC4337
} from "erc7579/interfaces/IERC7579Module.sol";
import { PackedUserOperation } from
    "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";
import { EIP712 } from "../lib/EIP712.sol";
import { IERC1271 } from "../interfaces/IERC1271.sol";

/**
 * @title ModuleManager
 * Contract that implements ERC7579 Module compatibility for Safe accounts
 * @author zeroknots.eth | rhinestone.wtf
 * @dev All Module types  are handled within this
 * contract. To make it a bit easier to read, the contract is split into different sections:
 * - Validator Modules
 * - Executor Modules
 * - Fallback Modules
 * - Hook Modules
 * Note: the Storage mappings for each section, are not listed on the very top, but in the
 * respective section
 */
abstract contract ModuleManager is ISafe7579, AccessControl, RegistryAdapter {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;

    /// @dev Nonces used for signature replay protection
    mapping(uint256 nonce => mapping(address smartAccount => bool isUsed)) internal $nonces;

    /// @dev The timelock period for emergency hook uninstallation.
    uint256 internal constant _EMERGENCY_TIMELOCK = 1 days;

    // Magic value for ERC-1271 valid signature
    bytes4 constant ERC1271_MAGICVALUE = 0x1626ba7e;

    // keccak256("SafeMessage(bytes message)");
    bytes32 internal constant SAFE_MSG_TYPEHASH =
        0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    // forgefmt: disable-next-line
    // keccak256("EmergencyUninstall(address hook,uint256 hookType,bytes deInitData,uint256 nonce)");
    bytes32 internal constant EMERGENCY_UNINSTALL_TYPE_HASH =
        0xd3ddfc12654178cc44d4a7b6b969cfdce7ffe6342326ba37825314cffa0fba9c;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     VALIDATOR MODULES                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
    // No mapping account => list necessary. this sentinellist flavour handles associated storage to
    // smart account itself to comply with 4337 storage restrictions
    SentinelList4337Lib.SentinelList internal $validators;

    /**
     * install and initialize validator module
     * @dev This function will install a validator module and return the moduleInitData
     * @param validator address of the validator module
     * @param data initialization data for the validator module
     */
    function _installValidator(
        address validator,
        bytes calldata data
    )
        internal
        withRegistry(validator, MODULE_TYPE_VALIDATOR)
        withCorrectModuleType(validator, MODULE_TYPE_VALIDATOR)
        returns (bytes memory moduleInitData)
    {
        $validators.push({ account: msg.sender, newEntry: validator });
        return data;
    }

    /**
     * Uninstall validator module
     * @dev This function does not prevent the user from uninstalling all validator modules.
     * Since the Safe7579 signature validation can fallback to Safe's checkSignature()
     * function, it is okay, if all validator modules are removed.
     * This does not brick the account
     */
    function _uninstallValidator(
        address validator,
        bytes calldata data
    )
        internal
        returns (bytes memory moduleInitData)
    {
        address prev;
        (prev, moduleInitData) = abi.decode(data, (address, bytes));
        $validators.pop({ account: msg.sender, prevEntry: prev, popEntry: validator });
    }

    /**
     * Helper function that will calculate storage slot for
     * validator address within the linked list in ValidatorStorageHelper
     * and use Safe's getStorageAt() to read 32bytes from Safe's storage
     */
    function _isValidatorInstalled(address validator)
        internal
        view
        virtual
        returns (bool isInstalled)
    {
        isInstalled = $validators.contains({ account: msg.sender, entry: validator });
    }

    /**
     * Get paginated list of installed validators
     */
    function getValidatorsPaginated(
        address cursor,
        uint256 pageSize
    )
        external
        view
        virtual
        returns (address[] memory array, address next)
    {
        return $validators.getEntriesPaginated({
            account: msg.sender,
            start: cursor,
            pageSize: pageSize
        });
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      EXECUTOR MODULES                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    SentinelList4337Lib.SentinelList internal $executors;

    modifier onlyExecutorModule() {
        if (!_isExecutorInstalled(_msgSender())) revert InvalidModule(_msgSender());
        _;
    }

    /**
     * Install and initialize executor module
     * @dev This function will install an executor module and return the moduleInitData
     * @param executor address of the executor module
     * @param data initialization data for the executor module
     */
    function _installExecutor(
        address executor,
        bytes calldata data
    )
        internal
        withRegistry(executor, MODULE_TYPE_EXECUTOR)
        withCorrectModuleType(executor, MODULE_TYPE_EXECUTOR)
        returns (bytes memory moduleInitData)
    {
        $executors.push({ account: msg.sender, newEntry: executor });
        return data;
    }

    /**
     * Uninstall executor module
     * @dev This function will uninstall an executor module
     * @param executor address of executor module to be uninstalled
     * @param data abi encoded previous address and deinit data
     */
    function _uninstallExecutor(
        address executor,
        bytes calldata data
    )
        internal
        returns (bytes memory moduleDeInitData)
    {
        address prev;
        (prev, moduleDeInitData) = abi.decode(data, (address, bytes));
        $executors.pop({ account: msg.sender, prevEntry: prev, popEntry: executor });
    }

    function _isExecutorInstalled(address executor)
        internal
        view
        virtual
        returns (bool isInstalled)
    {
        isInstalled = $executors.contains({ account: msg.sender, entry: executor });
    }

    /**
     * Get paginated list of installed executors
     */
    function getExecutorsPaginated(
        address cursor,
        uint256 pageSize
    )
        external
        view
        virtual
        returns (address[] memory array, address next)
    {
        return $executors.getEntriesPaginated({
            account: msg.sender,
            start: cursor,
            pageSize: pageSize
        });
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      FALLBACK MODULES                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    mapping(bytes4 selector => mapping(address smartAccount => FallbackHandler handlerConfig))
        internal $fallbackStorage;

    function _installFallbackHandler(
        address handler,
        bytes calldata params
    )
        internal
        virtual
        withRegistry(handler, MODULE_TYPE_FALLBACK)
        withCorrectModuleType(handler, MODULE_TYPE_FALLBACK)
        returns (bytes memory moduleInitData)
    {
        bytes4 functionSig;
        CallType calltype;
        (functionSig, calltype, moduleInitData) = abi.decode(params, (bytes4, CallType, bytes));

        // disallow calls to onInstall or onUninstall.
        // this could create a security issue
        if (
            functionSig == IModule.onInstall.selector || functionSig == IModule.onUninstall.selector
        ) revert InvalidFallbackHandler(functionSig);

        // disallow unsupported calltypes
        if (calltype != CALLTYPE_SINGLE && calltype != CALLTYPE_STATIC) {
            revert InvalidCallType(calltype);
        }

        if (_isFallbackHandlerInstalled(functionSig)) revert FallbackInstalled(functionSig);

        FallbackHandler storage $fallbacks = $fallbackStorage[functionSig][msg.sender];
        $fallbacks.calltype = calltype;
        $fallbacks.handler = handler;
    }

    function _isFallbackHandlerInstalled(bytes4 functionSig) internal view virtual returns (bool) {
        FallbackHandler storage $fallbacks = $fallbackStorage[functionSig][msg.sender];
        return $fallbacks.handler != address(0);
    }

    function _uninstallFallbackHandler(
        address, /*handler*/
        bytes calldata context
    )
        internal
        virtual
        returns (bytes memory moduleDeInitData)
    {
        bytes4 functionSig;
        (functionSig, moduleDeInitData) = abi.decode(context, (bytes4, bytes));

        FallbackHandler storage $fallbacks = $fallbackStorage[functionSig][msg.sender];
        delete $fallbacks.handler;
    }

    function _isFallbackHandlerInstalled(
        address _handler,
        bytes calldata additionalContext
    )
        internal
        view
        virtual
        returns (bool)
    {
        bytes4 functionSig = abi.decode(additionalContext, (bytes4));

        FallbackHandler storage $fallbacks = $fallbackStorage[functionSig][msg.sender];
        return $fallbacks.handler == _handler;
    }

    function getFallbackHandlerBySelector(bytes4 selector)
        external
        view
        returns (CallType, address)
    {
        FallbackHandler memory handler = $fallbackStorage[selector][msg.sender];
        return (handler.calltype, handler.handler);
    }

    /**
     * @dev AccessControl: any external contract / EOA may call this function
     * Safe7579 Fallback supports the following feature set:
     *    CallTypes:
     *             - CALLTYPE_SINGLE
     *             - CALLTYPE_BATCH
     * @dev If a global hook and/or selector hook is set, it will be called
     */
    // solhint-disable-next-line no-complex-fallback
    fallback(bytes calldata callData)
        external
        payable
        virtual
        withHook
        returns (bytes memory fallbackRet)
    {
        // using JUMPI to avoid stack too deep
        return _callFallbackHandler(callData);
    }

    receive() external payable { }

    function _callFallbackHandler(bytes calldata callData)
        private
        returns (bytes memory fallbackRet)
    {
        // get handler for specific function selector
        FallbackHandler storage $fallbacks = $fallbackStorage[msg.sig][msg.sender];
        address handler = $fallbacks.handler;
        CallType calltype = $fallbacks.calltype;
        // if no handler is set for the msg.sig, return msg.sig for erc721/1155 selectors,
        // otherwise revert
        if (handler == address(0)) {
            /// @solidity memory-safe-assembly
            assembly {
                let s := shr(224, calldataload(0))
                // 0x150b7a02: `onERC721Received(address,address,uint256,bytes)`.
                // 0xf23a6e61: `onERC1155Received(address,address,uint256,uint256,bytes)`.
                // 0xbc197c81: `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.
                if or(eq(s, 0x150b7a02), or(eq(s, 0xf23a6e61), eq(s, 0xbc197c81))) {
                    mstore(0x20, s) // Store `msg.sig`.
                    return(0x3c, 0x20) // Return `msg.sig`.
                }
            }
            revert NoFallbackHandler(msg.sig);
        }
        // according to ERC7579, when calling to fallback modules, ERC2771 msg.sender has to be
        // appended to the calldata, this allows fallback modules to implement
        // authorization control
        if (calltype == CALLTYPE_STATIC) {
            return _staticcallReturn({
                safe: ISafe(msg.sender),
                target: handler,
                callData: abi.encodePacked(callData, _msgSender()) // append ERC2771
             });
        }
        if (calltype == CALLTYPE_SINGLE) {
            return _execReturn({
                safe: ISafe(msg.sender),
                target: handler,
                value: 0,
                callData: abi.encodePacked(callData, _msgSender()) // append ERC2771
             });
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        HOOK MODULES                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    mapping(address smartAccount => address globalHook) internal $globalHook;
    mapping(address hook => mapping(address smartAccount => uint256 emergencyUninstallTime))
        internal $emergencyUninstallTime;

    /**
     * Run precheck for global hook
     */
    function _preHooks(address globalHook) internal returns (bytes memory global) {
        if (globalHook != address(0)) {
            global = _execReturn({
                safe: ISafe(msg.sender),
                target: globalHook,
                value: 0,
                callData: abi.encodeCall(IHook.preCheck, (_msgSender(), msg.value, msg.data))
            });
            global = abi.decode(global, (bytes));
        }
    }

    /**
     * Run post hooks
     */
    function _postHooks(address globalHook, bytes memory global) internal {
        if (globalHook != address(0)) {
            _exec({
                safe: ISafe(msg.sender),
                target: globalHook,
                value: 0,
                callData: abi.encodeCall(IHook.postCheck, (global))
            });
        }
    }

    /**
     * modifier that executes global hook, and function signature specific hook if enabled
     */
    modifier withHook() {
        address globalHook = $globalHook[msg.sender];
        (bytes memory global) = _preHooks(globalHook);
        _;
        _postHooks(globalHook, global);
    }

    /**
     * Install and initialize hook module
     * @dev This function will install a hook module and return the moduleInitData
     * @param hook address of the hook module
     * @param data initialization data for the hook module
     */
    function _installHook(
        address hook,
        bytes calldata data
    )
        internal
        virtual
        withRegistry(hook, MODULE_TYPE_HOOK)
        withCorrectModuleType(hook, MODULE_TYPE_HOOK)
        returns (bytes memory moduleInitData)
    {
        // check if any hook is already installed
        address currentHook = $globalHook[msg.sender];
        // Dont allow hooks to be overwritten. If a hook is currently installed, it must be
        // uninstalled first
        if (currentHook != address(0)) {
            revert HookAlreadyInstalled(currentHook);
        }
        $globalHook[msg.sender] = hook;
        return data;
    }

    function _uninstallHook(
        address, /*hook*/
        bytes calldata data
    )
        internal
        virtual
        returns (bytes memory moduleDeInitData)
    {
        delete $globalHook[msg.sender];
        return data;
    }

    function _isHookInstalled(address module) internal view returns (bool) {
        address hook = getActiveHook();
        return module != address(0) && hook == module;
    }

    function getActiveHook() public view returns (address hook) {
        return $globalHook[msg.sender];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 PREVALIDATION HOOK MODULES                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    mapping(address smartAccount => address preValidationHook4337) internal $preValidationHook4337;
    mapping(address smartAccount => address preValidationHook1271) internal $preValidationHook1271;

    function _withPreValidationHook(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        returns (bytes32 postHash, bytes memory postSig)
    {
        address preValidationHook = getPrevalidationHook(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271);
        if (preValidationHook == address(0)) {
            return (hash, signature);
        } else {
            bytes memory ret = _staticcallReturn({
                safe: ISafe(msg.sender),
                target: preValidationHook,
                callData: abi.encodeCall(
                    IPreValidationHookERC1271.preValidationHookERC1271, (sender, hash, signature)
                )
            });
            return abi.decode(ret, (bytes32, bytes));
        }
    }

    function _withPreValidationHook(
        bytes32 hash,
        PackedUserOperation memory userOp,
        uint256 missingAccountFunds
    )
        internal
        returns (bytes32 postHash, bytes memory postSig)
    {
        address preValidationHook = getPrevalidationHook(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337);
        if (preValidationHook == address(0)) {
            return (hash, userOp.signature);
        } else {
            bytes memory ret = _execReturn({
                safe: ISafe(msg.sender),
                target: preValidationHook,
                value: 0,
                callData: abi.encodeCall(
                    IPreValidationHookERC4337.preValidationHookERC4337,
                    (userOp, missingAccountFunds, hash)
                )
            });
            return abi.decode(ret, (bytes32, bytes));
        }
    }

    function _installPreValidationHook(
        address hook,
        bytes calldata data
    )
        internal
        returns (bytes memory moduleInitData)
    {
        uint256 moduleType;
        (moduleType, moduleInitData) = abi.decode(data, (uint256, bytes));
        if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337) {
            _installPreValidationHook4337(hook);
        } else if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271) {
            _installPreValidationHook1271(hook);
        }
    }

    function _installPreValidationHook4337(address hook)
        internal
        virtual
        withRegistry(hook, MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
        withCorrectModuleType(hook, MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
    {
        address currentHook = $preValidationHook4337[msg.sender];
        if (currentHook != address(0)) {
            revert PreValidationHookAlreadyInstalled(
                currentHook, MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
            );
        }
        $preValidationHook4337[msg.sender] = hook;
    }

    function _installPreValidationHook1271(address hook)
        internal
        virtual
        withRegistry(hook, MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
        withCorrectModuleType(hook, MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
    {
        address currentHook = $preValidationHook1271[msg.sender];
        if (currentHook != address(0)) {
            revert PreValidationHookAlreadyInstalled(
                currentHook, MODULE_TYPE_PREVALIDATION_HOOK_ERC1271
            );
        }
        $preValidationHook1271[msg.sender] = hook;
    }

    function _uninstallPreValidationHook(
        address, /*hook*/
        bytes calldata data
    )
        internal
        returns (bytes memory moduleDeInitData)
    {
        uint256 moduleType;
        (moduleType, moduleDeInitData) = abi.decode(data, (uint256, bytes));
        if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337) {
            delete $preValidationHook4337[msg.sender];
        } else if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271) {
            delete $preValidationHook1271[msg.sender];
        }
    }

    function _checkEmergencyUninstallSignature(
        EmergencyUninstall calldata data,
        bytes calldata signature
    )
        internal
    {
        address validator = address(bytes20(signature[0:20]));
        ISafe safe = ISafe(msg.sender);
        // Hash the data
        bytes32 hash = _getEmergencyUninstallDataHash(
            safe, data.hook, data.hookType, data.deInitData, data.nonce
        );
        // Check if nonce is valid
        require(!$nonces[data.nonce][msg.sender], InvalidNonce());
        // Mark nonce as used
        $nonces[data.nonce][msg.sender] = true;

        // check if validator is enabled. If not, use Safe's checkSignatures()
        if (validator == address(0) || !_isValidatorInstalled(validator)) {
            bytes memory messageData = EIP712.encodeMessageData(
                safe.domainSeparator(), SAFE_MSG_TYPEHASH, abi.encode(keccak256(abi.encode(hash)))
            );
            bytes32 messageHash = keccak256(messageData);
            safe.checkSignatures(messageHash, messageData, abi.encode(data));
        }
        // if a installed validator module was selected, use 7579 validation module
        else {
            bytes memory ret = _staticcallReturn({
                safe: ISafe(msg.sender),
                target: validator,
                callData: abi.encodeCall(
                    IValidator.isValidSignatureWithSender, (_msgSender(), hash, abi.encode(data))
                )
            });
            require(abi.decode(ret, (bytes4)) == ERC1271_MAGICVALUE, EmergencyUninstallSigError());
        }
    }

    function _getEmergencyUninstallDataHash(
        ISafe safe,
        address hook,
        uint256 hookType,
        bytes calldata data,
        uint256 nonce
    )
        internal
        view
        returns (bytes32)
    {
        return keccak256(
            EIP712.encodeMessageData(
                safe.domainSeparator(),
                EMERGENCY_UNINSTALL_TYPE_HASH,
                abi.encode(hook, hookType, keccak256(data), nonce)
            )
        );
    }

    function getPrevalidationHook(uint256 moduleType) public view returns (address hook) {
        if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337) {
            return $preValidationHook4337[msg.sender];
        } else if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271) {
            return $preValidationHook1271[msg.sender];
        } else {
            revert InvalidHookType();
        }
    }

    function _isPreValidationHookInstalled(
        address module,
        bytes calldata context
    )
        internal
        view
        returns (bool isInstalled)
    {
        uint256 moduleType = abi.decode(context, (uint256));
        if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337) {
            return $preValidationHook4337[msg.sender] == module;
        } else if (moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271) {
            return $preValidationHook1271[msg.sender] == module;
        }
    }

    // solhint-disable-next-line code-complexity
    /**
     * To make it easier to install multiple modules at once, this function will
     * install multiple modules at once. The init data is expected to be a abi encoded tuple
     * of (uint[] types, bytes[] contexts, bytes moduleInitData)
     * @dev Install multiple modules at once
     * @param module address of the module
     * @param initData initialization data for the module
     */
    function _multiTypeInstall(
        address module,
        bytes calldata initData
    )
        internal
        returns (bytes memory _moduleInitData)
    {
        uint256[] calldata types;
        bytes[] calldata contexts;
        bytes calldata moduleInitData;

        // equivalent of:
        // (types, contexs, moduleInitData) = abi.decode(initData,(uint[],bytes[],bytes)
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let offset := initData.offset
            let baseOffset := offset
            let dataPointer := add(baseOffset, calldataload(offset))

            types.offset := add(dataPointer, 32)
            types.length := calldataload(dataPointer)
            offset := add(offset, 32)

            dataPointer := add(baseOffset, calldataload(offset))
            contexts.offset := add(dataPointer, 32)
            contexts.length := calldataload(dataPointer)
            offset := add(offset, 32)

            dataPointer := add(baseOffset, calldataload(offset))
            moduleInitData.offset := add(dataPointer, 32)
            moduleInitData.length := calldataload(dataPointer)
        }

        uint256 length = types.length;
        if (contexts.length != length) revert InvalidInput();

        // iterate over all module types and install the module as a type accordingly
        for (uint256 i; i < length; i++) {
            uint256 _type = types[i];

            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*                      INSTALL VALIDATORS                    */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            if (_type == MODULE_TYPE_VALIDATOR) {
                _installValidator(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*                       INSTALL EXECUTORS                    */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_EXECUTOR) {
                _installExecutor(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*                       INSTALL FALLBACK                     */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_FALLBACK) {
                _installFallbackHandler(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*          INSTALL HOOK            */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_HOOK) {
                _installHook(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*      INSTALL PREVALIDATION HOOK (ERC1271 or ERC4337)       */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (
                _type == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271
                    || _type == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
            ) {
                _installPreValidationHook(module, contexts[i]);
            } else {
                revert InvalidModuleType(module, _type);
            }
        }
        // memory allocate the moduleInitData to return. This data should be used by the caller to
        // initialize the module
        _moduleInitData = moduleInitData;
    }

    function _multiTypeUninstall(
        address module,
        bytes calldata initData
    )
        internal
        returns (bytes memory _moduleDeInitData)
    {
        uint256[] calldata types;
        bytes[] calldata contexts;
        bytes calldata moduleDeInitData;

        // equivalent of:
        // (types, contexs, moduleInitData) = abi.decode(initData,(uint[],bytes[],bytes)
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            let offset := initData.offset
            let baseOffset := offset
            let dataPointer := add(baseOffset, calldataload(offset))

            types.offset := add(dataPointer, 32)
            types.length := calldataload(dataPointer)
            offset := add(offset, 32)

            dataPointer := add(baseOffset, calldataload(offset))
            contexts.offset := add(dataPointer, 32)
            contexts.length := calldataload(dataPointer)
            offset := add(offset, 32)

            dataPointer := add(baseOffset, calldataload(offset))
            moduleDeInitData.offset := add(dataPointer, 32)
            moduleDeInitData.length := calldataload(dataPointer)
        }

        uint256 length = types.length;
        if (contexts.length != length) revert InvalidInput();

        // iterate over all module types and install the module as a type accordingly
        for (uint256 i; i < length; i++) {
            uint256 _type = types[i];

            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*                      INSTALL VALIDATORS                    */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            if (_type == MODULE_TYPE_VALIDATOR) {
                _uninstallValidator(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*                       INSTALL EXECUTORS                    */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_EXECUTOR) {
                _uninstallExecutor(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*                       INSTALL FALLBACK                     */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_FALLBACK) {
                _uninstallFallbackHandler(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*          INSTALL HOOK            */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_HOOK) {
                _uninstallHook(module, contexts[i]);
            }
            /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
            /*      INSTALL PREVALIDATION HOOK (ERC1271 or ERC4337)       */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (
                _type == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271
                    || _type == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
            ) {
                _uninstallPreValidationHook(module, contexts[i]);
            } else {
                revert InvalidModuleType(module, _type);
            }
        }
        // memory allocate the moduleInitData to return. This data should be used by the caller to
        // initialize the module
        _moduleDeInitData = moduleDeInitData;
    }

    /*
     * @Dev Check's if a module is of a specific type, reverts if not
     */
    modifier withCorrectModuleType(address module, uint256 moduleType) {
        if (!IModule(module).isModuleType(moduleType)) {
            revert InvalidModuleType(module, moduleType);
        }
        _;
    }
}
