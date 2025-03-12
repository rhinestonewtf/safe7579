// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { MultiSend } from "@safe-global/safe-contracts/contracts/libraries/MultiSend.sol";
import "../SafeERC7579.t.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";

import "forge-std/console2.sol";

contract NoLaunchpad is Safe7579Test {
    function setUp() public override {
        super.setUp();
        target = new MockTarget();
    }

    function makeSafeWithoutLaunchpad() public returns (address, bytes memory) {
        address[] memory owners = Solarray.addresses(signer1.addr, signer2.addr);

        ModuleInit[] memory validators = new ModuleInit[](1);
        validators[0] = ModuleInit({ module: address(defaultValidator), initData: bytes("") });

        bytes memory initializer = abi.encodeCall(
            Safe.setup,
            (
                owners,
                2,
                address(launchpad),
                abi.encodeCall(
                    Safe7579Launchpad.addSafe7579,
                    (
                        address(safe7579),
                        validators,
                        new ModuleInit[](0),
                        new ModuleInit[](0),
                        new ModuleInit[](0),
                        Solarray.addresses(makeAddr("attester1"), makeAddr("attester2")),
                        2
                    )
                ),
                address(safe7579),
                address(0),
                0,
                payable(address(0))
            )
        );

        uint256 saltNonce = 222;

        // bytes memory deploymentData = abi.encodePacked(
        //     safeProxyFactory.proxyCreationCode(), uint256(uint160(address(singleton)))
        // );
        //
        // bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        //
        // bytes32 hash = keccak256(
        //     abi.encodePacked(
        //         bytes1(0xff), // prefix
        //         address(0x104fBc016F4bb334D775a19E8A6510109AC63E00), // deployer address
        //         salt, // salt
        //         keccak256(deploymentData) // bytecode hash
        //     )
        // );
        //
        // address account = payable(address(uint160(uint256(hash))));
        address account = address(0xB2BD76082593E35532472287D725bED7090De763);
        vm.deal(address(account), 1 ether);
        return (
            account,
            abi.encodePacked(
                safeProxyFactory,
                abi.encodeCall(
                    SafeProxyFactory.createProxyWithNonce,
                    (address(singleton), initializer, saltNonce)
                )
            )
        );
    }

    function test_with4337() public {
        // Create calldata for the account to execute
        bytes memory setValueOnTarget = abi.encodeCall(MockTarget.set, 1337);

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(address(target), uint256(0), setValueOnTarget)
            )
        );

        (address account, bytes memory userOpInitCode) = makeSafeWithoutLaunchpad();

        PackedUserOperation memory userOp =
            getDefaultUserOp(address(account), address(defaultValidator));
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

    function test_execViaExecutor() public override { }
    function test_execBatchFromExecutor() public override { }
}
