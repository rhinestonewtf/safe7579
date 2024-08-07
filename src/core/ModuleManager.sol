// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { SentinelListLib } from "sentinellist/SentinelList.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { IModule, IHook } from "../interfaces/IERC7579Module.sol";
import { ISafe } from "../interfaces/ISafe.sol";
import { ISafe7579 } from "../ISafe7579.sol";
import "../DataTypes.sol";

import { RegistryAdapter } from "./RegistryAdapter.sol";
import { Receiver } from "erc7579/core/Receiver.sol";
import { AccessControl } from "./AccessControl.sol";
import { CallType, CALLTYPE_STATIC, CALLTYPE_SINGLE } from "../lib/ModeLib.sol";
import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_HOOK
} from "erc7579/interfaces/IERC7579Module.sol";

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
abstract contract ModuleManager is ISafe7579, AccessControl, Receiver, RegistryAdapter {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;

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
        returns (bytes memory moduleInitData)
    {
        (bytes4 functionSig, CallType calltype, bytes memory initData) =
            abi.decode(params, (bytes4, CallType, bytes));

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

        return initData;
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
        override(Receiver)
        receiverFallback
        withHook(msg.sig)
        returns (bytes memory fallbackRet)
    {
        // using JUMPI to avoid stack too deep
        return _callFallbackHandler(callData);
    }

    function _callFallbackHandler(bytes calldata callData)
        private
        returns (bytes memory fallbackRet)
    {
        // get handler for specific function selector
        FallbackHandler storage $fallbacks = $fallbackStorage[msg.sig][msg.sender];
        address handler = $fallbacks.handler;
        CallType calltype = $fallbacks.calltype;
        // if no handler is set for the msg.sig, revert
        if (handler == address(0)) revert NoFallbackHandler(msg.sig);

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
    mapping(bytes4 selector => mapping(address smartAccount => address hook)) internal $hookManager;

    /**
     * Run precheck hook for global and function selector specific
     */
    function _preHooks(
        address globalHook,
        address sigHook
    )
        internal
        returns (bytes memory global, bytes memory sig)
    {
        if (globalHook != address(0)) {
            global = _execReturn({
                safe: ISafe(msg.sender),
                target: globalHook,
                value: 0,
                callData: abi.encodeCall(IHook.preCheck, (_msgSender(), msg.value, msg.data))
            });
            global = abi.decode(global, (bytes));
        }
        if (sigHook != address(0)) {
            sig = _execReturn({
                safe: ISafe(msg.sender),
                target: sigHook,
                value: 0,
                callData: abi.encodeCall(IHook.preCheck, (_msgSender(), msg.value, msg.data))
            });
            sig = abi.decode(sig, (bytes));
        }
    }

    /**
     * Run post hooks (global and function sig)
     */
    function _postHooks(
        address globalHook,
        address sigHook,
        bytes memory global,
        bytes memory sig
    )
        internal
    {
        if (globalHook != address(0)) {
            _exec({
                safe: ISafe(msg.sender),
                target: globalHook,
                value: 0,
                callData: abi.encodeCall(IHook.postCheck, (global))
            });
        }
        if (sigHook != address(0)) {
            _exec({
                safe: ISafe(msg.sender),
                target: sigHook,
                value: 0,
                callData: abi.encodeCall(IHook.postCheck, (sig))
            });
        }
    }

    /**
     * modifier that executes global hook, and function signature specific hook if enabled
     */
    modifier withHook(bytes4 selector) {
        address globalHook = $globalHook[msg.sender];
        address sigHook = $hookManager[selector][msg.sender];
        (bytes memory global, bytes memory sig) = _preHooks(globalHook, sigHook);
        _;
        _postHooks(globalHook, sigHook, global, sig);
    }

    modifier tryWithHook(address module, bytes4 selector) {
        address globalHook = $globalHook[msg.sender];
        address sigHook = $hookManager[selector][msg.sender];

        if (module != globalHook && module != sigHook) {
            (bytes memory global, bytes memory sig) = _preHooks(globalHook, sigHook);
            _;
            _postHooks(globalHook, sigHook, global, sig);
        } else {
            _;
        }
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
        returns (bytes memory moduleInitData)
    {
        (HookType hookType, bytes4 selector, bytes memory initData) =
            abi.decode(data, (HookType, bytes4, bytes));
        address currentHook;

        // handle global hooks
        if (hookType == HookType.GLOBAL && selector == 0x0) {
            currentHook = $globalHook[msg.sender];
            // Dont allow hooks to be overwritten. If a hook is currently installed, it must be
            // uninstalled first
            if (currentHook != address(0)) {
                revert HookAlreadyInstalled(currentHook);
            }
            $globalHook[msg.sender] = hook;
        } else if (hookType == HookType.SIG) {
            currentHook = $hookManager[selector][msg.sender];
            // Dont allow hooks to be overwritten. If a hook is currently installed, it must be
            // uninstalled first
            if (currentHook != address(0)) {
                revert HookAlreadyInstalled(currentHook);
            }
            $hookManager[selector][msg.sender] = hook;
        } else {
            revert InvalidHookType();
        }

        return initData;
    }

    function _uninstallHook(
        address, /*hook*/
        bytes calldata data
    )
        internal
        virtual
        returns (bytes memory moduleDeInitData)
    {
        HookType hookType;
        bytes4 selector;
        (hookType, selector, moduleDeInitData) = abi.decode(data, (HookType, bytes4, bytes));
        if (hookType == HookType.GLOBAL && selector == 0x0) {
            delete $globalHook[msg.sender];
        } else if (hookType == HookType.SIG) {
            delete $hookManager[selector][msg.sender];
        } else {
            revert InvalidHookType();
        }
    }

    function _getCurrentHook(
        HookType hookType,
        bytes4 selector
    )
        internal
        view
        returns (address hook)
    {
        // handle global hooks
        if (hookType == HookType.GLOBAL && selector == 0x0) {
            hook = $globalHook[msg.sender];
        }
        if (hookType == HookType.SIG) {
            hook = $hookManager[selector][msg.sender];
        }
    }

    function _isHookInstalled(
        address module,
        bytes calldata context
    )
        internal
        view
        returns (bool)
    {
        (HookType hookType, bytes4 selector) = abi.decode(context, (HookType, bytes4));
        address hook = _getCurrentHook({ hookType: hookType, selector: selector });
        return hook == module;
    }

    function getActiveHook(bytes4 selector) public view returns (address hook) {
        return $hookManager[selector][msg.sender];
    }

    function getActiveHook() public view returns (address hook) {
        return $globalHook[msg.sender];
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
            /*          INSTALL HOOK (global or sig specific)             */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_HOOK) {
                _installHook(module, contexts[i]);
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
            /*          INSTALL HOOK (global or sig specific)             */
            /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
            else if (_type == MODULE_TYPE_HOOK) {
                _uninstallHook(module, contexts[i]);
            } else {
                revert InvalidModuleType(module, _type);
            }
        }
        // memory allocate the moduleInitData to return. This data should be used by the caller to
        // initialize the module
        _moduleDeInitData = moduleDeInitData;
    }
}
