// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { MultiSend } from "@safe-global/safe-contracts/contracts/libraries/MultiSend.sol";
import "../SafeERC7579.t.sol";
import { ModeLib } from "src/lib/ModeLib.sol";

import "forge-std/console2.sol";

contract NoLaunchpad is Safe7579Test {
    function setUp() public override {
        super.setUp();
        target = new MockTarget();
        makeSafeWithoutLaunchpad();
    }

    function makeSafeWithoutLaunchpad() public {
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
        safe = Safe(
            payable(
                address(safeProxyFactory.createProxyWithNonce(address(singleton), initializer, 1))
            )
        );
        vm.deal(address(safe), 1 ether);
    }

    function test_execViaExecutor() public override { }
    function test_execBatchFromExecutor() public override { }
}
