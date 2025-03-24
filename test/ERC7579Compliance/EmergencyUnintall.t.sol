// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Base.t.sol";
import { ModuleManager } from "src/core/ModuleManager.sol";
import { EmergencyUninstall } from "src/DataTypes.sol";
import { MockPreValidationHook } from "test/mocks/MockPrevalidationHook.sol";
import { ISafe7579 } from "src/ISafe7579.sol";
import { ISafe } from "src/interfaces/ISafe.sol";
import {
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
    MODULE_TYPE_HOOK
} from "erc7579/interfaces/IERC7579Module.sol";
import { EIP712 } from "src/lib/EIP712.sol";
import "forge-std/console2.sol";

contract EmergencyUninstallTest is BaseTest {
    bytes _data;
    MockPreValidationHook _preValidationHook4337;
    MockPreValidationHook _preValidationHook1271;
    MockModule _regularHook;

    error EmergencyTimeLockNotExpired();
    error InvalidNonce();
    error EmergencyUninstallSigError();
    error ModuleNotInstalled(address hook, uint256 hookType);

    event EmergencyHookUninstallRequest(address hook, uint256 time);
    event EmergencyHookUninstallRequestReset(address hook, uint256 hookType);
    event ModuleUninstalled(uint256 indexed moduleType, address indexed module);

    function setUp() public virtual override {
        super.setUp();
        _preValidationHook4337 = new MockPreValidationHook();
        _preValidationHook1271 = new MockPreValidationHook();
        _regularHook = new MockModule();
        _data = hex"";
    }

    function _installHook() internal {
        vm.prank(address(entrypoint));
        account.installModule(MODULE_TYPE_HOOK, address(_regularHook), _data);
        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(_regularHook), ""));
    }

    function _installPreValidationHook1271() internal {
        vm.prank(address(entrypoint));
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
            address(_preValidationHook1271),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data)
        );
        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                address(_preValidationHook1271),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );
    }

    function _installPreValidationHook4337() internal {
        vm.prank(address(entrypoint));
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            address(_preValidationHook4337),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );
        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                address(_preValidationHook4337),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );
    }

    function _createEmergencyUninstallData(
        address hook,
        uint256 hookType,
        bytes memory deInitData,
        uint256 nonce
    )
        internal
        pure
        returns (EmergencyUninstall memory)
    {
        return EmergencyUninstall({
            hook: hook,
            hookType: hookType,
            deInitData: deInitData,
            nonce: nonce
        });
    }

    // Create a simpler approach using the validator
    function _createValidatorSignature() internal view returns (bytes memory) {
        return abi.encodePacked(address(defaultValidator));
    }

    // Tests using validator-based signatures for simplicity

    function test_EmergencyUninstallRequestInitiation() external {
        _installHook();

        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        bytes memory signature = _createValidatorSignature();

        vm.expectEmit(true, true, true, true);
        emit EmergencyHookUninstallRequest(address(_regularHook), block.timestamp);

        account.emergencyUninstallHook(data, signature);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(_regularHook), ""));
    }

    function test_EmergencyUninstallTimelockNotExpired() external {
        _installHook();

        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        bytes memory signature = _createValidatorSignature();

        account.emergencyUninstallHook(data, signature);

        vm.warp(block.timestamp + 12 hours);

        // Update nonce
        data.nonce = 2;

        vm.expectRevert(EmergencyTimeLockNotExpired.selector);
        account.emergencyUninstallHook(data, signature);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(_regularHook), ""));
    }

    function test_EmergencyUninstallSuccessful() external {
        _installHook();

        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        bytes memory signature = _createValidatorSignature();

        account.emergencyUninstallHook(data, signature);

        vm.warp(block.timestamp + 1 days + 1);

        // Update nonce
        data.nonce = 2;

        account.emergencyUninstallHook(data, signature);

        assertFalse(account.isModuleInstalled(MODULE_TYPE_HOOK, address(_regularHook), ""));
    }

    function test_EmergencyUninstallRequestReset() external {
        _installHook();

        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        bytes memory signature = _createValidatorSignature();

        account.emergencyUninstallHook(data, signature);

        vm.warp(block.timestamp + 3 days + 1);

        vm.expectEmit(true, true, true, true);
        emit EmergencyHookUninstallRequestReset(address(_regularHook), block.timestamp);
        // Update nonce
        data.nonce = 2;

        account.emergencyUninstallHook(data, signature);

        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, address(_regularHook), ""));
    }

    function test_EmergencyUninstallPrevalidationHook1271() external {
        _installPreValidationHook1271();

        EmergencyUninstall memory data = _createEmergencyUninstallData(
            address(_preValidationHook1271),
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data),
            1
        );

        bytes memory signature = _createValidatorSignature();

        account.emergencyUninstallHook(data, signature);

        vm.warp(block.timestamp + 1 days + 1);

        // Update nonce
        data.nonce = 2;

        account.emergencyUninstallHook(data, signature);

        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                address(_preValidationHook1271),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );
    }

    function test_EmergencyUninstallPrevalidationHook4337() external {
        _installPreValidationHook4337();

        EmergencyUninstall memory data = _createEmergencyUninstallData(
            address(_preValidationHook4337),
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data),
            1
        );

        bytes memory signature = _createValidatorSignature();

        account.emergencyUninstallHook(data, signature);

        vm.warp(block.timestamp + 1 days + 1);

        // Update nonce
        data.nonce = 2;

        account.emergencyUninstallHook(data, signature);

        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                address(_preValidationHook4337),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );
    }

    function test_EmergencyUninstallUnsupportedModuleType() external {
        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), 99, _data, 1);

        bytes memory signature = _createValidatorSignature();

        vm.expectRevert();
        account.emergencyUninstallHook(data, signature);
    }

    function test_EmergencyUninstallHookNotInstalled() external {
        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        bytes memory signature = _createValidatorSignature();

        vm.expectRevert(
            abi.encodeWithSelector(
                ModuleNotInstalled.selector, address(_regularHook), MODULE_TYPE_HOOK
            )
        );
        account.emergencyUninstallHook(data, signature);
    }

    function test_EmergencyUninstallNonceReuse() external {
        _installHook();

        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        bytes memory signature = _createValidatorSignature();

        account.emergencyUninstallHook(data, signature);

        vm.warp(block.timestamp + 1 days + 1);

        vm.expectRevert(InvalidNonce.selector);

        account.emergencyUninstallHook(data, signature);
    }

    function test_EmergencyUninstallInvalidSignature() external {
        _installHook();

        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        // Create an invalid signature by using random bytes
        bytes memory invalidSignature = hex"123456";

        vm.expectRevert();
        account.emergencyUninstallHook(data, invalidSignature);
    }

    function test_EmergencyUninstallWithSafeSignature() external {
        _installHook();

        bytes32 EMERGENCY_UNINSTALL_TYPE_HASH =
            0xd3ddfc12654178cc44d4a7b6b969cfdce7ffe6342326ba37825314cffa0fba9c;

        // Get the Safe's domain separator
        bytes32 domainSeparator = ISafe(address(safe)).domainSeparator();

        // Create the emergency uninstall data
        EmergencyUninstall memory data =
            _createEmergencyUninstallData(address(_regularHook), MODULE_TYPE_HOOK, _data, 1);

        // Generate the hash that will be signed
        bytes32 dataHash = keccak256(
            EIP712.encodeMessageData(
                domainSeparator,
                EMERGENCY_UNINSTALL_TYPE_HASH,
                abi.encode(data.hook, data.hookType, keccak256(data.deInitData), data.nonce)
            )
        );

        // Create the message hash that owners will sign (using Safe's standard approach)
        bytes32 safeMessageHash = keccak256(
            EIP712.encodeMessageData(
                domainSeparator,
                0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca, // SAFE_MSG_TYPEHASH
                abi.encode(keccak256(abi.encode(dataHash)))
            )
        );

        // Sign with the owner's private key
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signer1.key, safeMessageHash);
        bytes memory ownerSignature = abi.encodePacked(r, s, v);

        // Add the address(0) prefix for Safe signature validation
        bytes memory signature = abi.encodePacked(address(0), ownerSignature);

        // Initiate the emergency uninstall
        account.emergencyUninstallHook(data, signature);

        // Verify request was initiated
        // Advance time to pass the timelock (1 day)
        vm.warp(block.timestamp + 1 days + 1);

        // Update nonce for the second operation
        data.nonce = 2;

        // Create a new signature for the updated nonce
        dataHash = keccak256(
            EIP712.encodeMessageData(
                domainSeparator,
                EMERGENCY_UNINSTALL_TYPE_HASH,
                abi.encode(data.hook, data.hookType, keccak256(data.deInitData), data.nonce)
            )
        );

        safeMessageHash = keccak256(
            EIP712.encodeMessageData(
                domainSeparator,
                0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca, // SAFE_MSG_TYPEHASH
                abi.encode(keccak256(abi.encode(dataHash)))
            )
        );

        (v, r, s) = vm.sign(signer1.key, safeMessageHash);
        ownerSignature = abi.encodePacked(r, s, v);
        signature = abi.encodePacked(address(0), ownerSignature);

        // Complete the uninstall
        account.emergencyUninstallHook(data, signature);

        // Hook should be uninstalled
        assertFalse(account.isModuleInstalled(MODULE_TYPE_HOOK, address(_regularHook), ""));
    }
}
