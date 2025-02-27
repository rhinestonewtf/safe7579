// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Base.t.sol";
// import "src/lib/ModeLib.sol";
import { ModuleManager } from "src/core/ModuleManager.sol";
import {
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271
} from "erc7579/interfaces/IERC7579Module.sol";
import { MockPreValidationHook } from "test/mocks/MockPrevalidationHook.sol";
import { ISafe7579 } from "src/ISafe7579.sol";

import { CALLTYPE_SINGLE, CALLTYPE_BATCH, CALLTYPE_DELEGATECALL } from "erc7579/lib/ModeLib.sol";

contract ModuleManagementTest is BaseTest {
    bytes _data;
    MockPreValidationHook preValidationHook;

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

    function _installHook(HookType hookType, bytes4 selector, bytes memory initData) public {
        bytes memory data = abi.encode(hookType, selector, initData);
        account.installModule(4, SELF, data);
        assertTrue(account.isModuleInstalled(4, SELF, abi.encode(hookType, selector)));
    }

    function _uninstallHook(HookType hookType, bytes4 selector, bytes memory initData) public {
        bytes memory data = abi.encode(hookType, selector, initData);
        account.uninstallModule(4, SELF, data);
        assertFalse(account.isModuleInstalled(4, SELF, abi.encode(hookType, selector)));
    }

    function test_WhenInstallingHooks_SIG() external asEntryPoint {
        HookType hookType = HookType.SIG;
        bytes4 selector = MockTarget.set.selector;
        _data = hex"4141414141414141";

        _installHook(hookType, selector, _data);
        _uninstallHook(hookType, selector, _data);
    }

    function test_WhenInstallingHooks_GLOBAL() external asEntryPoint {
        HookType hookType = HookType.GLOBAL;
        bytes4 selector = 0x00000000;
        _data = hex"4141414141414141";

        bytes memory data = abi.encode(hookType, selector, _data);
        account.installModule(4, SELF, data);

        account.uninstallModule(4, SELF, data);
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

    function test_checkVersion() public {
        string memory version = account.accountId();

        string memory versionExpected = "rhinestone.safe7579.v1.0.0";
        assertEq(version, versionExpected);
    }
}
