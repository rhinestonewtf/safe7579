// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// import "erc7579/lib/ModeLib.sol";
// import "erc7579/lib/ExecutionLib.sol";
import "./Launchpad.t.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { ISafeOp, SAFE_OP_TYPEHASH } from "src/interfaces/ISafeOp.sol";
import {
    UserOperationLib,
    PackedUserOperation
} from "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";

import "forge-std/console2.sol";

contract NativeSafe is LaunchpadBase {
    using UserOperationLib for *;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
    }

    function signHash(uint256 privKey, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, digest);

        // Sanity checks
        address signer = ecrecover(digest, v, r, s);
        require(signer == vm.addr(privKey), "Invalid signature");

        return abi.encodePacked(r, s, v);
    }

    function getSafeOp(
        PackedUserOperation calldata userOp,
        uint48 validAfter,
        uint48 validUntil
    )
        external
        returns (bytes memory operationData)
    {
        ISafeOp.EncodedSafeOpStruct memory encodedSafeOp = ISafeOp.EncodedSafeOpStruct({
            typeHash: SAFE_OP_TYPEHASH,
            safe: userOp.sender,
            nonce: userOp.nonce,
            initCodeHash: keccak256(userOp.initCode),
            callDataHash: keccak256(userOp.callData),
            verificationGasLimit: uint128(userOp.unpackVerificationGasLimit()),
            callGasLimit: uint128(userOp.unpackCallGasLimit()),
            preVerificationGas: userOp.preVerificationGas,
            maxPriorityFeePerGas: uint128(userOp.unpackMaxPriorityFeePerGas()),
            maxFeePerGas: uint128(userOp.unpackMaxFeePerGas()),
            paymasterAndDataHash: keccak256(userOp.paymasterAndData),
            validAfter: validAfter,
            validUntil: validUntil,
            entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032
        });

        bytes32 safeOpStructHash;
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            // Since the `encodedSafeOp` value's memory layout is identical to the result of
            // `abi.encode`-ing the
            // individual `SafeOp` fields, we can pass it directly to `keccak256`. Additionally,
            // there are 14
            // 32-byte fields to hash, for a length of `14 * 32 = 448` bytes.
            safeOpStructHash := keccak256(encodedSafeOp, 448)
        }

        operationData = abi.encodePacked(
            bytes1(0x19), bytes1(0x01), safe7579.domainSeparator(), safeOpStructHash
        );
    }

    function test_execSingle() public {
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

        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(0));
        userOp.initCode = userOpInitCode;
        userOp.callData = userOpCalldata;

        uint48 validAfter = 0;
        uint48 validUntil = type(uint48).max;

        bytes memory operationData = this.getSafeOp(userOp, validAfter, validUntil);
        bytes32 opHash = keccak256(operationData);

        bytes memory sig = signHash(signer1.key, opHash);

        userOp.signature = abi.encodePacked(validAfter, validUntil, sig);

        // Create userOps array
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Send the userOp to the entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));

        // Assert that the value was set ie that execution was successful
        assertTrue(target.value() == 1337);
    }
}
