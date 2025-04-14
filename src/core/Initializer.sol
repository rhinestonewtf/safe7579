// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ISafe7579 } from "../ISafe7579.sol";
import { ISafe } from "../interfaces/ISafe.sol";
import "../DataTypes.sol";
import { ModuleInstallUtil } from "../utils/DCUtil.sol";
import { ModuleManager } from "./ModuleManager.sol";

import {
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_EXECUTOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
} from "erc7579/interfaces/IERC7579Module.sol";
import { IERC7484 } from "../interfaces/IERC7484.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { SentinelListLib } from "sentinellist/SentinelList.sol";

/**
 * Functions that can be used to initialze Safe7579 for a Safe Account
 * @author zeroknots.eth | rhinestone.wtf
 */
abstract contract Initializer is ISafe7579, ModuleManager {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;

    event Safe7579Initialized(address indexed safe);

    error InvalidInitData(address safe);

    /**
     * @inheritdoc ISafe7579
     */
    function initializeAccountWithValidators(ModuleInit[] calldata validators)
        external
        override
        onlyEntryPointOrSelf
    {
        if (!$validators.alreadyInitialized({ account: msg.sender })) {
            // this will revert if already initialized
            $validators.init({ account: msg.sender });
            uint256 length = validators.length;
            for (uint256 i; i < length; i++) {
                ModuleInit calldata validator = validators[i];
                // Ensure the module type is validator
                if (validator.moduleType != MODULE_TYPE_VALIDATOR) {
                    revert InvalidModuleType(validator.module, validator.moduleType);
                }
                $validators.push({ account: msg.sender, newEntry: validator.module });
                // @dev No events emitted here. Launchpad is expected to do this.
                // at this point, the safeproxy singleton is not yet updated to the SafeSingleton
                // calling execTransactionFromModule is not available yet.
            }
            emit Safe7579Initialized(msg.sender);
        }
    }

    /**
     * @inheritdoc ISafe7579
     */
    function initializeAccount(
        ModuleInit[] calldata modules,
        RegistryInit calldata registryInit
    )
        external
        onlyEntryPointOrSelf
    {
        _configureRegistry(registryInit.registry, registryInit.attesters, registryInit.threshold);
        // this will revert if already initialized
        _initModules(modules);
    }

    /**
     * _initModules may be used via launchpad deploymet or directly by already deployed Safe
     * accounts
     */
    function _initModules(ModuleInit[] calldata modules) internal {
        bytes memory moduleInitData;
        uint256 length = modules.length;
        bool validatorsInitialized = $validators.alreadyInitialized({ account: msg.sender });

        // Initialize validators list if needed
        if (!validatorsInitialized) {
            $validators.init({ account: msg.sender });
        }

        // This will revert if already initialized.
        $executors.init({ account: msg.sender });

        for (uint256 i; i < length; i++) {
            ModuleInit calldata module = modules[i];
            uint256 moduleType = module.moduleType;

            if (module.moduleType == MODULE_TYPE_VALIDATOR) {
                if (validatorsInitialized) {
                    revert InvalidInitData(msg.sender);
                }
                // enable module on Safe7579, initialize module via Safe, emit events
                moduleInitData = _installValidator(module.module, module.initData);
            } else if (module.moduleType == MODULE_TYPE_EXECUTOR) {
                // enable module on Safe7579, initialize module via Safe, emit events
                moduleInitData = _installExecutor(module.module, module.initData);
            } else if (module.moduleType == MODULE_TYPE_FALLBACK) {
                // enable module on Safe7579, initialize module via Safe, emit events
                moduleInitData = _installFallbackHandler(module.module, module.initData);
            } else if (module.moduleType == MODULE_TYPE_HOOK) {
                // enable module on Safe7579, initialize module via Safe, emit events
                moduleInitData = _installHook(module.module, module.initData);
            } else if (
                module.moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC1271
                    || module.moduleType == MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
            ) {
                // Handle pre-validation hooks or other module types
                moduleInitData = _installPreValidationHook(module.module, module.initData);
            } else {
                revert InvalidModuleType(module.module, moduleType);
            }

            // Initialize Module via Safe for standard module types
            _delegatecall({
                safe: ISafe(msg.sender),
                target: UTIL,
                callData: abi.encodeCall(
                    ModuleInstallUtil.installModule, (moduleType, module.module, moduleInitData)
                )
            });
        }

        emit Safe7579Initialized(msg.sender);
    }

    /**
     * @inheritdoc ISafe7579
     */
    function setRegistry(
        IERC7484 registry,
        address[] calldata attesters,
        uint8 threshold
    )
        external
        onlySelf
    {
        _configureRegistry(registry, attesters, threshold);
    }
}
