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
    MODULE_TYPE_FALLBACK
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
    using SentinelListLib for SentinelListLib.SentinelList;

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
        // this will revert if already initialized
        $validators.init({ account: msg.sender });
        uint256 length = validators.length;
        for (uint256 i; i < length; i++) {
            ModuleInit calldata validator = validators[i];
            $validators.push({ account: msg.sender, newEntry: validator.module });
            // @dev No events emitted here. Launchpad is expected to do this.
            // at this point, the safeproxy singleton is not yet updated to the SafeSingleton
            // calling execTransactionFromModule is not available yet.
        }
    }

    /**
     * @inheritdoc ISafe7579
     */
    function initializeAccount(
        ModuleInit[] calldata validators,
        ModuleInit[] calldata executors,
        ModuleInit[] calldata fallbacks,
        ModuleInit[] calldata hooks,
        RegistryInit calldata registryInit
    )
        external
        onlyEntryPointOrSelf
    {
        _configureRegistry(registryInit.registry, registryInit.attesters, registryInit.threshold);
        // this will revert if already initialized
        _initModules(validators, executors, fallbacks, hooks);
    }

    /**
     * _initModules may be used via launchpad deploymet or directly by already deployed Safe
     * accounts
     */
    function _initModules(
        ModuleInit[] calldata validators,
        ModuleInit[] calldata executors,
        ModuleInit[] calldata fallbacks,
        ModuleInit[] calldata hooks
    )
        internal
    {
        bytes memory moduleInitData;
        uint256 length = validators.length;
        // if this function is called by the launchpad, validators will be initialized via
        // launchpadValidators()
        // to avoid double initialization, we check if the validators are already initialized
        if (!$validators.alreadyInitialized({ account: msg.sender })) {
            $validators.init({ account: msg.sender });
            for (uint256 i; i < length; i++) {
                ModuleInit calldata validator = validators[i];
                // enable module on Safe7579,  initialize module via Safe, emit events
                moduleInitData = _installValidator(validator.module, validator.initData);

                // Initialize Module via Safe
                _delegatecall({
                    safe: ISafe(msg.sender),
                    target: UTIL,
                    callData: abi.encodeCall(
                        ModuleInstallUtil.installModule,
                        (MODULE_TYPE_VALIDATOR, validator.module, moduleInitData)
                    )
                });
            }
        } else if (length != 0) {
            revert InvalidInitData(msg.sender);
        }

        // this will revert if already initialized.
        $executors.init({ account: msg.sender });

        length = executors.length;
        for (uint256 i; i < length; i++) {
            ModuleInit calldata executor = executors[i];
            // enable module on Safe7579,  initialize module via Safe, emit events
            moduleInitData = _installExecutor(executor.module, executor.initData);

            // Initialize Module via Safe
            _delegatecall({
                safe: ISafe(msg.sender),
                target: UTIL,
                callData: abi.encodeCall(
                    ModuleInstallUtil.installModule,
                    (MODULE_TYPE_EXECUTOR, executor.module, moduleInitData)
                )
            });
        }

        length = fallbacks.length;
        for (uint256 i; i < length; i++) {
            ModuleInit calldata _fallback = fallbacks[i];
            // enable module on Safe7579,  initialize module via Safe, emit events
            moduleInitData = _installFallbackHandler(_fallback.module, _fallback.initData);

            // Initialize Module via Safe
            _delegatecall({
                safe: ISafe(msg.sender),
                target: UTIL,
                callData: abi.encodeCall(
                    ModuleInstallUtil.installModule,
                    (MODULE_TYPE_FALLBACK, _fallback.module, moduleInitData)
                )
            });
        }

        length = hooks.length;
        for (uint256 i; i < length; i++) {
            ModuleInit calldata hook = hooks[i];
            // enable module on Safe7579,  initialize module via Safe, emit events
            moduleInitData = _installHook(hook.module, hook.initData);

            // Initialize Module via Safe
            _delegatecall({
                safe: ISafe(msg.sender),
                target: UTIL,
                callData: abi.encodeCall(
                    ModuleInstallUtil.installModule, (MODULE_TYPE_HOOK, hook.module, moduleInitData)
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
        onlyEntryPointOrSelf
    {
        _configureRegistry(registry, attesters, threshold);
    }
}
