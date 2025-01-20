// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { Script } from "forge-std/Script.sol";
import { Safe7579 } from "src/Safe7579.sol";
import { Safe7579Launchpad } from "src/Safe7579Launchpad.sol";
import { IERC7484 } from "src/interfaces/IERC7484.sol";
import { Safe7579 } from "src/Safe7579.sol";
import { ISafe7579 } from "src/ISafe7579.sol";
import { IERC7484 } from "src/interfaces/IERC7484.sol";
import "src/DataTypes.sol";
import { ModuleManager } from "src/core/ModuleManager.sol";
import { MockValidator } from "module-bases/mocks/MockValidator.sol";
import { MockRegistry } from "test/mocks/MockRegistry.sol";
import { MockExecutor } from "test/mocks/MockExecutor.sol";
import { MockFallback } from "test/mocks/MockFallback.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { MockTarget } from "test/mocks/MockTarget.sol";

import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import {
    SafeProxy,
    SafeProxyFactory
} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { LibClone } from "solady/utils/LibClone.sol";
import { Safe7579Launchpad } from "src/Safe7579Launchpad.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { Solarray } from "solarray/Solarray.sol";
import "test/dependencies/EntryPoint.sol";

import "forge-std/console2.sol";

/**
 * @title DeployAccount
 * @author @kopy-kat
 */
contract DeployAccountScript is Script {
    function run() public {
        IERC7484 registry = IERC7484(0x000000000069E2a187AEFFb852bF3cCdC95151B2);
        address payable safe7579 = payable(address(0x7579EE8307284F293B1927136486880611F20002));
        address singleton = address(0x29fcB43b46531BcA003ddC8FCB67FFE91900C762);
        address payable launchpad = payable(address(0x7579011aB74c46090561ea277Ba79D510c6C00ff));
        address validator = address(0x2483DA3A338895199E5e538530213157e931Bf06);
        address safeProxyFactory = address(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);

        ModuleInit[] memory validators = new ModuleInit[](1);
        ModuleInit[] memory executors = new ModuleInit[](0);
        ModuleInit[] memory fallbacks = new ModuleInit[](0);
        ModuleInit[] memory hooks = new ModuleInit[](0);

        {
            // we love stack too deep
            address[] memory owners = new address[](1);
            owners[0] = address(0x5027918E940125c63C262e22D1E7FF71e61f67b5);

            validators[0] =
                ModuleInit({ module: validator, initData: abi.encode(uint256(1), owners) });
        }

        Safe7579Launchpad.InitData memory initData = Safe7579Launchpad.InitData({
            singleton: singleton,
            owners: Solarray.addresses(address(0x7484d43c22461C34DAA7C5Ee4e26e3F3D8Acf944)),
            threshold: 1,
            setupTo: launchpad,
            setupData: abi.encodeCall(
                Safe7579Launchpad.initSafe7579,
                (
                    safe7579,
                    executors,
                    fallbacks,
                    hooks,
                    Solarray.addresses(
                        address(0x000000333034E9f539ce08819E12c1b8Cb29084d),
                        address(0xA4C777199658a41688E9488c4EcbD7a2925Cc23A)
                    ),
                    1
                )
            ),
            safe7579: ISafe7579(safe7579),
            validators: validators,
            callData: abi.encodeCall(
                IERC7579Account.execute,
                (
                    ModeLib.encodeSimpleSingle(),
                    ExecutionLib.encodeSingle({
                        target: address(0xF7C012789aac54B5E33EA5b88064ca1F1172De05),
                        value: 1,
                        callData: ""
                    })
                )
            )
        });

        bytes32 initHash = Safe7579Launchpad(launchpad).hash(initData);

        bytes memory factoryInitializer =
            abi.encodeCall(Safe7579Launchpad.preValidationSetup, (initHash, address(0), ""));

        PackedUserOperation memory userOp =
            getDefaultUserOp(address(0), validator, Safe7579(safe7579));

        bytes32 salt = bytes32(uint256(1));

        userOp.callData = abi.encodeCall(Safe7579Launchpad.setupSafe, (initData));
        userOp.initCode = _initCode(factoryInitializer, salt, safeProxyFactory, launchpad);

        address predict = Safe7579Launchpad(launchpad).predictSafeAddress({
            singleton: launchpad,
            safeProxyFactory: safeProxyFactory,
            creationCode: SafeProxyFactory(safeProxyFactory).proxyCreationCode(),
            salt: salt,
            factoryInitializer: factoryInitializer
        });
        userOp.sender = predict;
        IEntryPoint entryPoint = IEntryPoint(address(0x0000000071727De22E5E9d8BAf0edAc6f37da032));

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            0x7d244a960a545eb62ab7fe2412a5892e608dba4fe5c142dbe6d7141ec082183f,
            ECDSA.toEthSignedMessageHash(userOpHash)
        );
        userOp.signature = abi.encodePacked(r, s, v);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        console2.log(predict);

        vm.startBroadcast(vm.envUint("PK"));

        // send eth to userOp sender

        entryPoint.handleOps(userOps, payable(address(0xF7C012789aac54B5E33EA5b88064ca1F1172De05)));

        vm.stopBroadcast();
    }

    function _initCode(
        bytes memory initializer,
        bytes32 salt,
        address safeProxyFactory,
        address launchpad
    )
        internal
        view
        returns (bytes memory _initCode)
    {
        _initCode = abi.encodePacked(
            address(safeProxyFactory),
            abi.encodeCall(
                SafeProxyFactory.createProxyWithNonce,
                (address(launchpad), initializer, uint256(salt))
            )
        );
    }

    function getDefaultUserOp(
        address account,
        address validator,
        Safe7579 safe7579
    )
        internal
        view
        returns (PackedUserOperation memory userOp)
    {
        userOp = PackedUserOperation({
            sender: account,
            nonce: safe7579.getNonce(account, validator),
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            preVerificationGas: 2e2,
            gasFees: bytes32(abi.encodePacked(uint128(1), uint128(1))),
            paymasterAndData: bytes(""),
            signature: abi.encodePacked(hex"41414141")
        });
    }
}
