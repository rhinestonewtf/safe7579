// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import { SafeOp } from "./core/SafeOp.sol";

import {
    IAccount,
    PackedUserOperation
} from "@ERC4337/account-abstraction/contracts/interfaces/IAccount.sol";
import { ISafe } from "./interfaces/ISafe.sol";
import { ISafeOp } from "./interfaces/ISafeOp.sol";
import { ISafe7579 } from "./ISafe7579.sol";
import { IERC7484 } from "./interfaces/IERC7484.sol";
import "./DataTypes.sol";

import { UserOperationLib } from "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";

import { IValidator } from "erc7579/interfaces/IERC7579Module.sol";

import { SafeStorage } from "@safe-global/safe-contracts/contracts/libraries/SafeStorage.sol";

import { MODULE_TYPE_VALIDATOR } from "erc7579/interfaces/IERC7579Module.sol";
import { CheckSignatures } from "@rhinestone/checknsignatures/src/CheckNSignatures.sol";
import { LibSort } from "solady/utils/LibSort.sol";
import { SupportViewer } from "./core/SupportViewer.sol";
import { IERC7579AccountEvents } from "./interfaces/IERC7579Account.sol";

/**
 * Launchpad to deploy a Safe account and connect the Safe7579 adapter.
 * Check Readme.md for more information.
 * Note that (unlike some other smart accounts) the Safe7579 will only finish initializing the
 * account during the execution phase of the first UserOperation in order to comply with ERC-4337.
 * This means that if the exection of the first UserOperation fails, the account could be
 * permanently bricked. To avoid this, make sure that all the initialization and call data are
 * correctly set up and do not cause a revert on any chain that the account should be deployed on.
 * Special thanks to [nlordell (Safe)](https://github.com/nlordell), who came up with [this
 * technique](https://github.com/safe-global/safe-modules/pull/184)
 * @author rhinestone | zeroknots.eth
 */
contract Safe7579Launchpad is
    IAccount,
    SafeStorage,
    SafeOp,
    SupportViewer,
    IERC7579AccountEvents
{
    using LibSort for address[];
    using CheckSignatures for bytes32;

    // keccak256("Safe7579Launchpad.initHash") - 1
    uint256 private constant INIT_HASH_SLOT =
        0x982e06ee6a56dfc0f1ac189a5d23506361ca0a3ce45a9c7b8d33d65d43746a24;

    /**
     * @notice The keccak256 hash of the EIP-712 InitData struct, representing the structure
     */
    struct InitData {
        address singleton;
        address[] owners;
        uint256 threshold;
        address setupTo;
        bytes setupData;
        ISafe7579 safe7579;
        ModuleInit[] validators;
        bytes callData;
    }

    address private immutable SELF;
    address public immutable SUPPORTED_ENTRYPOINT;
    IERC7484 public immutable REGISTRY;

    error InvalidEntryPoint();
    error InvalidSetup();
    error Safe7579LaunchpadAlreadyInitialized();
    error OnlyDelegatecall();
    error OnlyProxy();
    error PreValidationSetupFailed();
    error InvalidUserOperationData();
    error InvalidInitHash();

    constructor(address entryPoint, IERC7484 registry) {
        if (entryPoint == address(0)) revert InvalidEntryPoint();

        SELF = address(this);
        SUPPORTED_ENTRYPOINT = entryPoint;
        REGISTRY = registry;
    }

    modifier onlySelfDelegatecall() {
        if (msg.sender != address(this)) revert OnlyDelegatecall();
        _;
    }

    modifier onlyProxy() {
        if (singleton != SELF) revert OnlyProxy();
        _;
    }

    modifier onlySupportedEntryPoint() {
        if (msg.sender != SUPPORTED_ENTRYPOINT) revert InvalidEntryPoint();
        _;
    }

    receive() external payable onlyProxy { }

    /**
     * This function is intended to be delegatecalled by the ISafe.setup function. It configures the
     * Safe7579 for the user for all module types except validators, which were initialized in the
     * validateUserOp function.
     */
    function initSafe7579(
        address safe7579,
        ModuleInit[] calldata modules,
        address[] calldata attesters,
        uint8 threshold
    )
        public
        onlySelfDelegatecall
    {
        ISafe(address(this)).enableModule(safe7579);
        ISafe7579(payable(this)).initializeAccount({
            modules: modules,
            registryInit: RegistryInit({ registry: REGISTRY, attesters: attesters, threshold: threshold })
        });
    }

    /**
     * This function allows existing safe accounts to add the Safe7579 adapter to their account
     */
    function addSafe7579(
        address safe7579,
        ModuleInit[] calldata modules,
        address[] calldata attesters,
        uint8 threshold
    )
        external
    {
        ISafe(address(this)).enableModule(safe7579);
        ISafe(address(this)).setFallbackHandler(safe7579);
        ISafe7579(payable(this)).initializeAccount({
            modules: modules,
            registryInit: RegistryInit({ registry: REGISTRY, attesters: attesters, threshold: threshold })
        });
    }

    /**
     * SafeProxyFactory will create a SafeProxy and using this contract as the singleton
     * implementation and call this function to initialize the account.
     * will write initHash into SafeProxy storage
     * @param initHash will be calculated offchain using this.hash(InitData)
     * @param to optional parameter for a delegatecall
     * @param preInit optional parameter for a delegatecall
     */
    function preValidationSetup(
        bytes32 initHash,
        address to,
        bytes calldata preInit
    )
        external
        onlyProxy
    {
        if (getInitHash() != bytes32(0)) revert Safe7579LaunchpadAlreadyInitialized();

        // sstore inithash
        _setInitHash(initHash);

        // if a delegatecall target is provided, SafeProxy will execute a delegatecall
        if (to != address(0)) {
            (bool success,) = to.delegatecall(preInit);
            if (!success) revert PreValidationSetupFailed();
        }
    }

    /**
     * Upon creation of SafeProxy by SafeProxyFactory, EntryPoint invokes this function to verify
     * the transaction. It ensures that only this.setupSafe() can be called by EntryPoint during
     * execution. The function validates the hash of InitData in userOp.callData against the hash
     * stored in preValidationSetup. This function abides by ERC4337 storage restrictions, allowing
     * Safe7579 adapter initialization only in Validation Modules compliant with 4337. It installs
     * validators from InitData onto the Safe7579 adapter for the account. When called by EP, the
     * SafeProxy singleton address remains unupgraded to SafeSingleton, preventing
     * execTransactionFromModule by Safe7579 Adapter. Initialization of Validator Modules is
     * achieved through a direct call to onInstall(). This delegatecalled function initializes the
     * Validator Module with the correct msg.sender. Once all validator modules are set up, they can
     * be used to validate the userOp. Parameters include userOp (EntryPoint v0.7 userOp),
     * userOpHash, and missingAccountFunds representing the gas payment required.
     *
     * @param userOp EntryPoint v0.7 userOp.
     * @param userOpHash hash of userOp
     * @param missingAccountFunds amount of gas that has to be paid
     * @return validationData 4337 packed validation data returned by the validator module
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        onlyProxy // ensure SafeProxy called this
        onlySupportedEntryPoint
        returns (uint256 validationData)
    {
        if (this.setupSafe.selector != bytes4(userOp.callData[:4])) {
            revert InvalidUserOperationData();
        }

        InitData memory initData = abi.decode(userOp.callData[4:], (InitData));
        // read stored initHash from SafeProxy storage. only proceed if the InitData hash matches
        if (hash(initData) != getInitHash()) revert InvalidInitHash();

        // get validator from nonce encoding
        address validator;
        uint256 nonce = userOp.nonce;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            validator := shr(96, nonce)
        }

        // initialize validator on behalf of the safe account
        // the call below is equivalent to:
        // ISafe7579(initData.safe7579).initializeAccountWithValidators(initData.validators);
        // but we need to append msg.sender (entrypoint) to ERC2771 style access control, to protect
        // the launchpadValidator function
        (bool success,) = address(initData.safe7579).call(
            abi.encodePacked(
                abi.encodeCall(ISafe7579.initializeAccountWithValidators, (initData.validators)), // validators
                msg.sender // ERC2771 access control
            )
        );

        // ensure that the call was successful
        if (!success) revert InvalidUserOperationData();

        // Call onInstall on each validator module to set up the validators.
        // Since this function is delegatecalled by the SafeProxy, the Validator Module is
        // called
        // with msg.sender == SafeProxy.
        bool userOpValidatorInstalled;
        uint256 validatorsLength = initData.validators.length;
        for (uint256 i; i < validatorsLength; i++) {
            address validatorModule = initData.validators[i].module;
            IValidator(validatorModule).onInstall(initData.validators[i].initData);
            emit ModuleInstalled(MODULE_TYPE_VALIDATOR, validatorModule);

            if (validatorModule == validator) userOpValidatorInstalled = true;
        }

        // Ensure that the validator module selected in the userOp was
        // part of the validators in InitData
        if (userOpValidatorInstalled) {
            // validate userOp with selected validation module.
            validationData = IValidator(validator).validateUserOp(userOp, userOpHash);
        } else {
            // otherwise we fall back to safe-style validation, like in the safe7579
            (bool validSig, uint48 validUntil, uint48 validAfter) =
                _isValidSafeSigners(initData, userOp);

            validationData = _packValidationData({
                sigFailed: !validSig,
                validUntil: validUntil,
                validAfter: validAfter
            });
        }

        // pay back gas to EntryPoint
        if (missingAccountFunds > 0) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    function _isValidSafeSigners(
        InitData memory safeSetupCallData,
        PackedUserOperation calldata userOp
    )
        internal
        view
        returns (bool validSig, uint48 validUntil, uint48 validAfter)
    {
        bytes memory operationData;
        bytes memory signatures;
        // decode ERC4337 userOp into Safe operation.
        (operationData, validAfter, validUntil, signatures) =
            ISafeOp(safeSetupCallData.safe7579).getSafeOp(userOp, SUPPORTED_ENTRYPOINT);
        bytes32 _hash = keccak256(operationData);

        address[] memory signers = _hash.recoverNSignatures(signatures, safeSetupCallData.threshold);
        signers.insertionSort();

        address[] memory owners = safeSetupCallData.owners;

        // sorting owners here instead of requiring sorted list for improved UX
        owners.insertionSort();
        owners.uniquifySorted();

        uint256 ownersLength = owners.length;

        uint256 validSigs;
        for (uint256 i; i < ownersLength; i++) {
            (bool found,) = signers.searchSorted(owners[i]);
            if (found) {
                validSigs++;
                if (validSigs >= safeSetupCallData.threshold) {
                    return (true, validUntil, validAfter);
                }
            }
        }
        return (false, validUntil, validAfter);
    }

    /**
     * During the execution phase of ERC4337, this function upgrades the SafeProxy to the actual
     * SafeSingleton implementation. Subsequently, it invokes the ISafe.setup() function to
     * initialize the Safe Account. The setup() function should ensure the completion of Safe7579
     * Adapter initialization with InitData.setupTo as address(this) and InitData.setupData encoding
     * the call to this.initSafe7579(). SafeProxy.setup() delegatecalls this function to install
     * executors, fallbacks, hooks, and registry configurations on the Safe7579 adapter. As this
     * occurs in the ERC4337 execution phase, storage restrictions are not applicable.
     *
     * @param initData initData to initialize the Safe and Safe7579 Adapter
     */
    function setupSafe(InitData calldata initData) external onlySupportedEntryPoint {
        // update singleton to Safe account implementation
        // from now on, ISafe can be used to interact with the SafeProxy
        SafeStorage.singleton = initData.singleton;

        // setupTo should be this launchpad
        if (initData.setupTo != SELF) revert InvalidSetup();
        // // setupData should be a call to this.initSafe7579()
        if (bytes4(initData.setupData[:4]) != this.initSafe7579.selector) revert InvalidSetup();
        // setup SafeAccount
        ISafe(address(this)).setup({
            _owners: initData.owners,
            _threshold: initData.threshold,
            to: initData.setupTo,
            data: initData.setupData,
            fallbackHandler: address(initData.safe7579),
            paymentToken: address(0),
            payment: 0,
            paymentReceiver: payable(address(0))
        });

        // reset initHash
        _setInitHash(0);
        // in order to allow launchpad users to perform 7579 account operations like execute(), in
        // the safe transaction context of the launchpad setup, any call can be encoded in
        // initData.callData
        (bool success, bytes memory returnData) = address(initData.safe7579).call(
            abi.encodePacked(
                initData.callData, // encode arbitrary execution here. i.e. IERC7579.execute()
                address(this) // ERC2771 access control
            )
        );
        if (!success) {
            // solhint-disable-next-line no-inline-assembly
            assembly ("memory-safe") {
                revert(add(returnData, 0x20), mload(returnData))
            }
        }
    }

    // sload inithash from SafeProxy storage
    function getInitHash() public view returns (bytes32 value) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            value := sload(INIT_HASH_SLOT)
        }
    }

    // store inithash in SafeProxy storage
    function _setInitHash(bytes32 value) internal {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            sstore(INIT_HASH_SLOT, value)
        }
    }

    /**
     * Helper function that can be used offchain to predict the counterfactual Safe address.
     * @dev factoryInitializer is expected to be:
     * abi.encodeCall(Safe7579Launchpad.preValidationSetup, (initHash, to, callData));
     */
    function predictSafeAddress(
        address singleton,
        address safeProxyFactory,
        bytes memory creationCode,
        bytes32 salt,
        bytes memory factoryInitializer
    )
        external
        pure
        returns (address safeProxy)
    {
        salt = keccak256(abi.encodePacked(keccak256(factoryInitializer), salt));

        safeProxy = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(safeProxyFactory),
                            salt,
                            keccak256(
                                abi.encodePacked(creationCode, uint256(uint160(address(singleton))))
                            )
                        )
                    )
                )
            )
        );
    }

    /**
     * Create unique InitData hash. Using all params but excluding data.callData from hash
     */
    function hash(InitData memory data) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                data.singleton,
                data.owners,
                data.threshold,
                data.setupTo,
                data.setupData,
                data.safe7579,
                data.validators
            )
        );
    }
}
