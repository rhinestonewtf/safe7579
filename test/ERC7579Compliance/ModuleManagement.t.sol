// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Base.t.sol";
// import "src/lib/ModeLib.sol";
import { ModuleManager } from "src/core/ModuleManager.sol";
import {
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
    MODULE_TYPE_HOOK,
    MODULE_TYPE_VALIDATOR,
    MODULE_TYPE_FALLBACK,
    MODULE_TYPE_EXECUTOR
} from "erc7579/interfaces/IERC7579Module.sol";
import { MockPreValidationHook } from "test/mocks/MockPrevalidationHook.sol";
import { ISafe7579 } from "src/ISafe7579.sol";

import { CALLTYPE_SINGLE, CALLTYPE_BATCH, CALLTYPE_DELEGATECALL } from "src/lib/ModeLib.sol";

contract ModuleManagementTest is BaseTest {
    bytes _data;
    MockPreValidationHook preValidationHook;

    error UnsupportedModuleType(uint256 moduleType);
    error InvalidModule(address module);
    error InvalidModuleType(address module, uint256 moduleType);

    // fallback handlers
    error InvalidInput();
    error InvalidCallType(CallType callType);
    error NoFallbackHandler(bytes4 msgSig);
    error InvalidFallbackHandler(bytes4 msgSig);
    error FallbackInstalled(bytes4 msgSig);

    // Hooks
    error HookAlreadyInstalled(address hook);
    error InvalidHookType();
    error PreValidationHookAlreadyInstalled(address currentHook, uint256 moduleType);

    function setUp() public virtual override {
        super.setUp();
        preValidationHook = new MockPreValidationHook();
    }

    function onInstall(bytes calldata data) public virtual override {
        assertEq(_data, data);
        assertEq(msg.sender, address(account));
    }

    function onUninstall(bytes calldata data) public override {
        assertEq(_data, data);
        assertEq(msg.sender, address(account));
    }

    function test_WhenInstallingExecutors() external asEntryPoint {
        _data = hex"4141414141414141";
        assertFalse(account.isModuleInstalled(2, SELF, ""));
        account.installModule(2, SELF, _data);
        assertTrue(account.isModuleInstalled(2, SELF, ""));
        account.uninstallModule(2, SELF, abi.encode(address(1), _data));
        assertFalse(account.isModuleInstalled(2, SELF, ""));
    }

    function test_WhenInstallingValidators() external asEntryPoint {
        // It should call onInstall on module
        _data = hex"4141414141414141";
        assertFalse(account.isModuleInstalled(1, SELF, ""));
        account.installModule(1, SELF, _data);
        assertTrue(account.isModuleInstalled(1, SELF, ""));
        account.uninstallModule(1, SELF, abi.encode(address(1), _data));
        assertFalse(account.isModuleInstalled(1, SELF, ""));
    }

    function test_WhenInstallingFallbackModules() external asEntryPoint {
        bytes4 selector = MockTarget.set.selector;
        _data = hex"4141414141414141";

        assertFalse(account.isModuleInstalled(3, SELF, abi.encode(selector)));
        account.installModule(3, SELF, abi.encode(selector, CALLTYPE_SINGLE, _data));
        assertTrue(account.isModuleInstalled(3, SELF, abi.encode(selector)));
        account.uninstallModule(3, SELF, abi.encode(selector, _data));
        assertFalse(account.isModuleInstalled(3, SELF, abi.encode(selector)));
    }

    function test_WhenInstallingPreValidationHookERC1271() external asEntryPoint {
        _data = hex"4141414141414141";

        // Verify hook is not installed initially
        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );

        // Install the hook
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data)
        );

        // Verify it's installed
        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );

        // Check it's accessible through getPrevalidationHook
        assertEq(
            ISafe7579(address(account)).getPrevalidationHook(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271),
            address(preValidationHook)
        );

        // Uninstall the hook
        account.uninstallModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data)
        );

        // Verify it's no longer installed
        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );
    }

    function test_WhenInstallingPreValidationHookERC4337() external asEntryPoint {
        _data = hex"4141414141414141";

        // Verify hook is not installed initially
        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );

        // Install the hook
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        // Verify it's installed
        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );

        // Check it's accessible through getPrevalidationHook
        assertEq(
            ISafe7579(address(account)).getPrevalidationHook(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337),
            address(preValidationHook)
        );

        // Uninstall the hook
        account.uninstallModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        // Verify it's no longer installed
        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );
    }

    function test_WhenInstallingMultiplePreValidationHooks() external asEntryPoint {
        _data = hex"4141414141414141";
        MockPreValidationHook secondHook = new MockPreValidationHook();

        // Install the first hook type
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data)
        );

        // Try to install a second hook of the same type (should revert)
        vm.expectRevert(); // This should revert with PreValidationHookAlreadyInstalled
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
            address(secondHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data)
        );

        // Should be able to install a different type of hook
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        // Verify both hooks are installed
        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );

        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                address(preValidationHook),
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );
    }

    function _installHook(bytes memory initData) public {
        bytes memory data = abi.encode(initData);
        account.installModule(4, SELF, data);
        assertTrue(account.isModuleInstalled(4, SELF, bytes("")));
    }

    function _uninstallHook(bytes memory initData) public {
        account.uninstallModule(4, SELF, "");
        assertFalse(account.isModuleInstalled(4, SELF, bytes("")));
    }

    function test_WhenInstallingHooks_GLOBAL() external asEntryPoint {
        _data = hex"4141414141414141";
        account.installModule(4, SELF, _data);

        account.uninstallModule(4, SELF, _data);
    }

    function test_multiTypeInstall() public asEntryPoint {
        uint256[] memory types = Solarray.uint256s(1, 2);
        bytes[] memory contexts = Solarray.bytess(hex"41", hex"41");
        _data = hex"4141414141414141";
        bytes memory moduleInitData = _data;

        bytes memory initData = abi.encode(types, contexts, moduleInitData);
        account.installModule(0, SELF, initData);

        assertTrue(account.isModuleInstalled(1, SELF, ""));
        assertTrue(account.isModuleInstalled(2, SELF, ""));
    }

    function test_multiTypeUninstall() public {
        test_multiTypeInstall();

        uint256[] memory types = Solarray.uint256s(1, 2);

        bytes memory data = abi.encode(address(1), hex"41");
        bytes[] memory contexts = Solarray.bytess(data, data);
        _data = hex"4141414141414141";
        bytes memory moduleInitData = _data;

        bytes memory initData = abi.encode(types, contexts, moduleInitData);
        vm.prank(address(entrypoint));
        account.uninstallModule(0, SELF, initData);

        assertFalse(account.isModuleInstalled(1, SELF, ""));
        assertFalse(account.isModuleInstalled(2, SELF, ""));
    }

    function test_multiTypeInstallWithPreValidationHooks() public asEntryPoint {
        uint256[] memory types = Solarray.uint256s(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
        );

        _data = hex"4141414141414141";

        bytes[] memory contexts = Solarray.bytess(
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        bytes memory moduleInitData = _data;
        bytes memory initData = abi.encode(types, contexts, moduleInitData);

        account.installModule(0, SELF, initData);

        // Verify both hook types were installed
        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                SELF,
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );

        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                SELF,
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );
    }

    function test_multiTypeUninstallWithPreValidationHooks() public asEntryPoint {
        // Install
        uint256[] memory types = Solarray.uint256s(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
        );

        _data = hex"4141414141414141";

        bytes[] memory contexts = Solarray.bytess(
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        bytes memory moduleInitData = _data;
        bytes memory initData = abi.encode(types, contexts, moduleInitData);

        account.installModule(0, SELF, initData);

        // Verify both hook types were installed
        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                SELF,
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );

        assertTrue(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                SELF,
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );

        // Create uninstall data
        types = Solarray.uint256s(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
        );

        _data = hex"4141414141414141";

        contexts = Solarray.bytess(
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, _data),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        moduleInitData = _data;
        bytes memory uninstallData = abi.encode(types, contexts, moduleInitData);

        // Uninstall both hooks
        account.uninstallModule(0, SELF, uninstallData);

        // Verify both hook types were uninstalled
        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
                SELF,
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271)
            )
        );

        assertFalse(
            account.isModuleInstalled(
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
                SELF,
                abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337)
            )
        );
    }

    function test_IsHookInstalled() external asEntryPoint {
        // First install a hook module
        _data = hex"4141414141414141";
        account.installModule(MODULE_TYPE_HOOK, SELF, _data);

        // Verify the hook is installed with isModuleInstalled
        bool result = account.isModuleInstalled(MODULE_TYPE_HOOK, SELF, "");
        assertTrue(result);

        // Clean up
        account.uninstallModule(MODULE_TYPE_HOOK, SELF, _data);
    }

    function test_UnsupportedModuleTypeInstall() external asEntryPoint {
        // Use an invalid module type (e.g., 99) that doesn't match any of the defined types
        uint256 invalidModuleType = 99;

        // Expect revert with UnsupportedModuleType error
        vm.expectRevert(abi.encodeWithSelector(UnsupportedModuleType.selector, invalidModuleType));

        account.installModule(invalidModuleType, address(0x123), "");
    }

    function test_UnsupportedModuleTypeUninstall() external asEntryPoint {
        // Use an invalid module type (e.g., 99) that doesn't match any of the defined types
        uint256 invalidModuleType = 99;

        // Expect revert with UnsupportedModuleType error
        vm.expectRevert(abi.encodeWithSelector(UnsupportedModuleType.selector, invalidModuleType));

        account.uninstallModule(invalidModuleType, address(0x123), "");
    }

    function test_checkVersion() public {
        string memory version = account.accountId();

        string memory versionExpected = "rhinestone.safe7579.v1.0.0";
        assertEq(version, versionExpected);
    }

    function test_IsModuleInstalledInvalidType() external asEntryPoint {
        // Use an invalid module type (e.g., 99) that doesn't match any of the defined types
        uint256 invalidModuleType = 99;

        // Check result - should return false for invalid module types
        bool result = account.isModuleInstalled(invalidModuleType, address(0x123), "");
        assertFalse(result);
    }

    function test_multiTypeUninstallWithHooksAndFallbacks() public asEntryPoint {
        // First install modules of different types
        _data = hex"4141414141414141";

        // Install hook
        account.installModule(MODULE_TYPE_HOOK, SELF, _data);

        // Install fallback - need selector for fallback
        bytes4 selector = MockTarget.set.selector;
        account.installModule(
            MODULE_TYPE_FALLBACK, SELF, abi.encode(selector, CALLTYPE_SINGLE, _data)
        );

        // Install validator and executor for completeness
        account.installModule(MODULE_TYPE_VALIDATOR, SELF, _data);
        account.installModule(MODULE_TYPE_EXECUTOR, SELF, _data);

        // Verify all modules are installed
        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, SELF, ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_FALLBACK, SELF, abi.encode(selector)));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, SELF, ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, SELF, ""));

        // Create uninstall data including all types
        uint256[] memory types = Solarray.uint256s(
            MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, MODULE_TYPE_FALLBACK, MODULE_TYPE_HOOK
        );

        bytes memory fallbackContext = abi.encode(selector, _data);
        bytes memory data = abi.encode(address(1), _data); // For validator and executor

        bytes[] memory contexts = Solarray.bytess(
            data, // validator
            data, // executor
            fallbackContext, // fallback
            _data // hook
        );

        bytes memory moduleDeInitData = _data;
        bytes memory uninstallData = abi.encode(types, contexts, moduleDeInitData);

        // Uninstall all module types
        account.uninstallModule(0, SELF, uninstallData);

        // Verify all modules were uninstalled
        assertFalse(account.isModuleInstalled(MODULE_TYPE_HOOK, SELF, ""));
        assertFalse(account.isModuleInstalled(MODULE_TYPE_FALLBACK, SELF, abi.encode(selector)));
        assertFalse(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, SELF, ""));
        assertFalse(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, SELF, ""));
    }

    function test_multiTypeUninstallInvalidInput() public asEntryPoint {
        // Create uninstall data with mismatched array lengths
        uint256[] memory types = Solarray.uint256s(MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR);
        bytes[] memory contexts = Solarray.bytess(hex"41"); // Only one context for two types

        bytes memory moduleDeInitData = hex"4141414141414141";
        bytes memory uninstallData = abi.encode(types, contexts, moduleDeInitData);

        // Should revert with InvalidInput
        vm.expectRevert(InvalidInput.selector);
        account.uninstallModule(0, SELF, uninstallData);
    }

    function test_multiTypeUninstallInvalidModuleType() public asEntryPoint {
        // Create uninstall data with an invalid module type
        uint256 invalidModuleType = 99;
        uint256[] memory types = Solarray.uint256s(invalidModuleType);
        bytes[] memory contexts = Solarray.bytess(hex"41");

        bytes memory moduleDeInitData = hex"4141414141414141";
        bytes memory uninstallData = abi.encode(types, contexts, moduleDeInitData);

        // Should revert with InvalidModuleType
        vm.expectRevert(abi.encodeWithSelector(InvalidModuleType.selector, SELF, invalidModuleType));
        account.uninstallModule(0, SELF, uninstallData);
    }

    function test_multiTypeInstallWithHooksAndFallbacks() public asEntryPoint {
        // Create installation data for multiple module types including hook and fallback
        uint256[] memory types = Solarray.uint256s(
            MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, MODULE_TYPE_FALLBACK, MODULE_TYPE_HOOK
        );

        _data = hex"4141414141414141";
        bytes4 selector = MockTarget.set.selector;

        // Create contexts for each module type
        bytes[] memory contexts = Solarray.bytess(
            _data, // validator
            _data, // executor
            abi.encode(selector, CALLTYPE_SINGLE, _data), // fallback
            _data // hook
        );

        bytes memory moduleInitData = _data;
        bytes memory installData = abi.encode(types, contexts, moduleInitData);

        // Install all module types at once
        account.installModule(0, SELF, installData);

        // Verify all modules were installed
        assertTrue(account.isModuleInstalled(MODULE_TYPE_VALIDATOR, SELF, ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_EXECUTOR, SELF, ""));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_FALLBACK, SELF, abi.encode(selector)));
        assertTrue(account.isModuleInstalled(MODULE_TYPE_HOOK, SELF, ""));

        // Clean up
        uint256[] memory uninstallTypes = Solarray.uint256s(
            MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, MODULE_TYPE_FALLBACK, MODULE_TYPE_HOOK
        );

        bytes[] memory uninstallContexts = Solarray.bytess(
            abi.encode(address(1), _data), // validator
            abi.encode(address(1), _data), // executor
            abi.encode(selector, _data), // fallback
            _data // hook
        );

        bytes memory uninstallData = abi.encode(uninstallTypes, uninstallContexts, _data);
        account.uninstallModule(0, SELF, uninstallData);
    }

    function test_multiTypeInstallInvalidInput() public asEntryPoint {
        // Create install data with mismatched array lengths
        uint256[] memory types = Solarray.uint256s(MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR);
        bytes[] memory contexts = Solarray.bytess(hex"41"); // Only one context for two types

        bytes memory moduleInitData = hex"4141414141414141";
        bytes memory installData = abi.encode(types, contexts, moduleInitData);

        // Should revert with InvalidInput
        vm.expectRevert(InvalidInput.selector);
        account.installModule(0, SELF, installData);
    }

    function test_multiTypeInstallInvalidModuleType() public asEntryPoint {
        // Create install data with an invalid module type
        uint256 invalidModuleType = 99;
        uint256[] memory types = Solarray.uint256s(invalidModuleType);
        bytes[] memory contexts = Solarray.bytess(hex"41");

        bytes memory moduleInitData = hex"4141414141414141";
        bytes memory installData = abi.encode(types, contexts, moduleInitData);

        // Should revert with InvalidModuleType
        vm.expectRevert(abi.encodeWithSelector(InvalidModuleType.selector, SELF, invalidModuleType));
        account.installModule(0, SELF, installData);
    }

    function test_InstallHookAlreadyInstalled() external asEntryPoint {
        // First install a hook
        _data = hex"4141414141414141";
        account.installModule(MODULE_TYPE_HOOK, SELF, _data);

        // Try to install another hook - should revert with HookAlreadyInstalled
        MockModule newHook = new MockModule();
        vm.expectRevert(abi.encodeWithSelector(HookAlreadyInstalled.selector, SELF));
        account.installModule(MODULE_TYPE_HOOK, address(newHook), _data);

        // Clean up
        account.uninstallModule(MODULE_TYPE_HOOK, SELF, _data);
    }

    function test_InstallPreValidationHook4337AlreadyInstalled() external asEntryPoint {
        // First install a prevalidation hook
        _data = hex"4141414141414141";
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            SELF,
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        // Try to install another prevalidation hook - should revert with
        // PreValidationHookAlreadyInstalled
        MockModule newHook = new MockModule();
        vm.expectRevert(
            abi.encodeWithSelector(
                PreValidationHookAlreadyInstalled.selector,
                SELF,
                MODULE_TYPE_PREVALIDATION_HOOK_ERC4337
            )
        );
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            address(newHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );

        // Clean up
        account.uninstallModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            SELF,
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data)
        );
    }

    function test_GetPrevalidationHookInvalidType() external {
        // Try to get a prevalidation hook with an invalid type
        uint256 invalidHookType = 99;

        vm.expectRevert(InvalidHookType.selector);
        ISafe7579(address(account)).getPrevalidationHook(invalidHookType);
    }

    function test_PreValidationHookReturnData() external asEntryPoint {
        // Test that _installPreValidationHook returns the moduleInitData properly
        _data = hex"4141414141414141";

        bytes memory initData = abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, _data);
        bytes memory returnData;

        account.installModule(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, SELF, initData);

        // Verify the hook is installed
        address installedHook =
            ISafe7579(address(account)).getPrevalidationHook(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337);
        assertEq(installedHook, SELF);

        // Now uninstall and verify
        account.uninstallModule(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, SELF, initData);

        address uninstalledHook =
            ISafe7579(address(account)).getPrevalidationHook(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337);
        assertEq(uninstalledHook, address(0));
    }

    function test_GetValidatorsPaginated() external asEntryPoint {
        // First install a few validators
        _data = hex"4141414141414141";

        // Create multiple validators
        MockModule validator1 = new MockModule();
        MockModule validator2 = new MockModule();
        MockModule validator3 = new MockModule();

        // Install them
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator1), _data);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator2), _data);
        account.installModule(MODULE_TYPE_VALIDATOR, address(validator3), _data);

        // Test pagination with different page sizes
        (address[] memory validators, address next) =
            account.getValidatorsPaginated(address(0x0000000000000000000000000000000000000001), 2);

        // Verify we got the expected results
        assertEq(validators.length, 2);
        assertTrue(next != address(0)); // Should have more validators

        // Get next page
        (address[] memory nextValidators, address nextCursor) =
            account.getValidatorsPaginated(next, 2);

        // Verify we got the remaining validators
        assertEq(nextValidators.length, 2);
        assertEq(nextCursor, address(0x0000000000000000000000000000000000000001)); // No more
            // validators
    }

    function test_GetExecutorsPaginated() external asEntryPoint {
        // First install a few executors
        _data = hex"4141414141414141";

        // Create multiple executors
        MockModule executor1 = new MockModule();
        MockModule executor2 = new MockModule();
        MockModule executor3 = new MockModule();

        // Install them
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor1), _data);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor2), _data);
        account.installModule(MODULE_TYPE_EXECUTOR, address(executor3), _data);

        // Test pagination with different page sizes
        (address[] memory executors, address next) =
            account.getExecutorsPaginated(address(0x0000000000000000000000000000000000000001), 2);

        // Verify we got the expected results
        assertEq(executors.length, 2);
        assertTrue(next != address(0)); // Should have more executors

        // Get next page
        (address[] memory nextExecutors, address nextCursor) =
            account.getExecutorsPaginated(next, 2);

        // Verify we got the remaining executors
        assertEq(nextExecutors.length, 2);
        assertEq(nextCursor, address(0x0000000000000000000000000000000000000001)); // No more
            // executors
    }

    function test_InstallFallbackHandlerWithInvalidFunctionSig() external asEntryPoint {
        // Try to install a fallback handler with onInstall selector
        bytes4 invalidSig = IModule.onInstall.selector;

        vm.expectRevert(abi.encodeWithSelector(InvalidFallbackHandler.selector, invalidSig));

        account.installModule(
            MODULE_TYPE_FALLBACK,
            SELF,
            abi.encode(invalidSig, CALLTYPE_SINGLE, hex"4141414141414141")
        );

        // Try with onUninstall selector
        invalidSig = IModule.onUninstall.selector;

        vm.expectRevert(abi.encodeWithSelector(InvalidFallbackHandler.selector, invalidSig));

        account.installModule(
            MODULE_TYPE_FALLBACK,
            SELF,
            abi.encode(invalidSig, CALLTYPE_SINGLE, hex"4141414141414141")
        );
    }

    function test_InstallFallbackHandlerWithInvalidCallType() external asEntryPoint {
        // Try to install a fallback handler with invalid call type (not SINGLE or STATIC)
        bytes4 funcSig = bytes4(keccak256("someFunction()"));
        CallType invalidCallType = CALLTYPE_DELEGATECALL; // Using delegatecall as invalid type

        vm.expectRevert(abi.encodeWithSelector(InvalidCallType.selector, invalidCallType));

        account.installModule(
            MODULE_TYPE_FALLBACK, SELF, abi.encode(funcSig, invalidCallType, hex"4141414141414141")
        );
    }

    function test_InstallFallbackHandlerAlreadyInstalled() external asEntryPoint {
        // First install a fallback handler
        bytes4 funcSig = bytes4(keccak256("someFunction()"));
        _data = hex"4141414141414141";

        account.installModule(
            MODULE_TYPE_FALLBACK, SELF, abi.encode(funcSig, CALLTYPE_SINGLE, _data)
        );

        // Try to install another fallback handler for the same function
        vm.expectRevert(abi.encodeWithSelector(FallbackInstalled.selector, funcSig));

        account.installModule(
            MODULE_TYPE_FALLBACK, address(this), abi.encode(funcSig, CALLTYPE_SINGLE, _data)
        );

        // Clean up
        account.uninstallModule(MODULE_TYPE_FALLBACK, SELF, abi.encode(funcSig, _data));
    }

    function test_InvalidExecutorModule() external {
        // Call a function with the onlyExecutorModule modifier from a non-executor
        address nonExecutor = address(0x123);

        vm.startPrank(nonExecutor);
        vm.expectRevert(abi.encodeWithSelector(InvalidModule.selector, nonExecutor));

        // Call executeFromExecutor which has the onlyExecutorModule modifier
        account.executeFromExecutor(
            ModeLib.encodeSimpleSingle(), ExecutionLib.encodeSingle(address(target), 0, "")
        );

        vm.stopPrank();
    }
}
