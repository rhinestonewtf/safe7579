// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Enum } from "@safe-global/safe-contracts/contracts/common/Enum.sol";
import { Safe7579Test, Solarray, Safe, ModuleInit, Safe7579Launchpad } from "../SafeERC7579.t.sol";

contract ExistingSafe is Safe7579Test {
    function setUp() public override {
        super.setUp();

        makeExistingSafe();
    }

    function makeExistingSafe() public {
        address[] memory owners = Solarray.addresses(signer1.addr, signer2.addr);

        bytes memory initializer = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
        );

        safe = Safe(
            payable(
                address(safeProxyFactory.createProxyWithNonce(address(singleton), initializer, 1))
            )
        );
        vm.deal(address(safe), 1 ether);

        ModuleInit[] memory validators = new ModuleInit[](1);
        validators[0] = ModuleInit({ module: address(defaultValidator), initData: bytes("") });

        ModuleInit[] memory executors = new ModuleInit[](1);
        executors[0] = ModuleInit({ module: address(defaultExecutor), initData: bytes("") });

        address to = address(launchpad);
        uint256 value = 0;
        bytes memory data = abi.encodeCall(
            Safe7579Launchpad.addSafe7579,
            (
                address(safe7579),
                validators,
                executors,
                new ModuleInit[](0),
                new ModuleInit[](0),
                Solarray.addresses(makeAddr("attester1"), makeAddr("attester2")),
                2
            )
        );
        Enum.Operation operation = Enum.Operation.DelegateCall;
        uint256 safeTxGas = 10_000_000;
        uint256 baseGas = 1000;
        uint256 gasPrice = 10;
        address gasToken = address(0);
        address payable refundReceiver = payable(address(0));

        bytes memory txData = safe.encodeTransactionData({
            to: to,
            value: value,
            data: data,
            operation: operation,
            safeTxGas: safeTxGas,
            baseGas: baseGas,
            gasPrice: gasPrice,
            gasToken: gasToken,
            refundReceiver: refundReceiver,
            _nonce: 0
        });

        bytes32 txDataHash = keccak256(txData);
        bytes memory sig = signHash(signer1.key, txDataHash);

        safe.execTransaction({
            to: to,
            value: value,
            data: data,
            operation: operation,
            safeTxGas: safeTxGas,
            baseGas: baseGas,
            gasPrice: gasPrice,
            gasToken: gasToken,
            refundReceiver: refundReceiver,
            signatures: sig
        });
    }

    // function test_execViaExecutor() public override { }
    // function test_execBatchFromExecutor() public override { }

    function signHash(uint256 privKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);

        // Sanity checks
        address signer = ecrecover(digest, v, r, s);
        require(signer == vm.addr(privKey), "Invalid signature");

        return abi.encodePacked(r, s, v);
    }
}
