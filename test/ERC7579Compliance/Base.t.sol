// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "../Launchpad.t.sol";
import { ISafe7579 } from "src/ISafe7579.sol";
import { ModeLib } from "src/lib/ModeLib.sol";
import { IModule } from "erc7579/interfaces/IERC7579Module.sol";

contract MockModule is IModule {
    bool initialized;

    function onInstall(bytes calldata data) public virtual { }

    function onUninstall(bytes calldata data) external virtual { }

    function isModuleType(uint256 moduleTypeId) external view returns (bool) {
        return true;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return initialized;
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        virtual
        returns (uint256)
    {
        return 1;
    }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        virtual
        returns (bytes4)
    {
        return IERC7579Account.isValidSignature.selector;
    }

    function preCheck(
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        external
        virtual
        returns (bytes memory hookData)
    { }

    function postCheck(bytes calldata hookData) external virtual { }
}

contract BaseTest is LaunchpadBase, MockModule {
    ISafe7579 account;

    address SELF;

    modifier asEntryPoint() {
        vm.startPrank(address(entrypoint));
        _;
        vm.stopPrank();
    }

    function setUp() public virtual override {
        super.setUp();
        target = new MockTarget();

        initFirstExec();
        account = ISafe7579(address(safe));
        SELF = address(this);
    }

    function installUnitTestAsModule() public asEntryPoint {
        account.installModule(1, SELF, "");
        account.installModule(2, SELF, "");
        // account.installModule(3, SELF, "");
        // account.installModule(4, SELF,"");
    }

    function initFirstExec() public {
        // Create calldata for the account to execute
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.set, 1337);

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata = abi.encodeCall(
            ISafe7579.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(address(target), uint256(0), setValueOnTarget)
            )
        );

        PackedUserOperation memory userOp =
            getDefaultUserOp(address(safe), address(defaultValidator));
        userOp.initCode = userOpInitCode;
        userOp.callData = userOpCalldata;

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        // Assert that the value was set ie that execution was successful
        assertTrue(target.value() == 1337);
    }
}
