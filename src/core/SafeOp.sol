// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import {
    PackedUserOperation,
    UserOperationLib
} from "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";
import { SAFE_OP_TYPEHASH, ISafeOp } from "../interfaces/ISafeOp.sol";

abstract contract SafeOp is ISafeOp {
    using UserOperationLib for PackedUserOperation;

    bytes32 private constant DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    /**
     * @dev Decodes an ERC-4337 user operation into a Safe operation.
     * @param userOp The ERC-4337 user operation.
     * @return operationData Encoded EIP-712 Safe operation data bytes used for signature
     * verification.
     * @return validAfter The timestamp the user operation is valid from.
     * @return validUntil The timestamp the user operation is valid until.
     * @return signatures The Safe owner signatures extracted from the user operation.
     */
    function getSafeOp(
        PackedUserOperation memory userOp,
        address entryPoint
    )
        public
        view
        returns (
            bytes memory operationData,
            uint48 validAfter,
            uint48 validUntil,
            bytes memory signatures
        )
    {
        // Extract additional Safe operation fields from the user operation signature which is
        // encoded as:
        // `abi.encodePacked(validAfter, validUntil, signatures)`
        // This is how we can extract signature components from memory
        bytes memory sig = userOp.signature;
        uint256 sigLength = sig.length;

        assembly {
            // Get the signature data pointer (skip the length word)
            let sigDataPtr := add(sig, 0x20)

            // Load first 12 bytes (as a uint96) then split into two uint48
            let timeData := mload(sigDataPtr)
            // Shift right by 48 bits (6 bytes) and mask to get validAfter
            validAfter := and(shr(48, timeData), 0xFFFFFFFFFFFF)
            // Mask to get validUntil
            validUntil := and(timeData, 0xFFFFFFFFFFFF)

            // Handle signatures - allocate new memory and copy remaining bytes
            let signaturesLength := sub(sigLength, 12)
            signatures := mload(0x40) // get free memory pointer
            mstore(signatures, signaturesLength) // store length

            // Update free memory pointer
            let nextMemPtr := add(add(signatures, 0x20), signaturesLength)
            // Round up to 32-byte boundary
            nextMemPtr := and(add(nextMemPtr, 31), not(31))
            mstore(0x40, nextMemPtr)

            // Copy signature data
            let sourcePtr := add(sigDataPtr, 12)
            let destPtr := add(signatures, 0x20)

            // Copy 32 bytes at a time
            for { let i := 0 } lt(i, signaturesLength) { i := add(i, 32) } {
                mstore(add(destPtr, i), mload(add(sourcePtr, i)))
            }
        }

        // It is important that **all** user operation fields are represented in the `SafeOp` data
        // somehow, to prevent
        // user operations from being submitted that do not fully respect the user preferences. The
        // only exception is
        // the `signature` bytes. Note that even `initCode` needs to be represented in the operation
        // data, otherwise
        // it can be replaced with a more expensive initialization that would charge the user
        // additional fees.
        {
            // In order to work around Solidity "stack too deep" errors related to too many stack
            // variables, manually
            // encode the `SafeOp` fields into a memory `struct` for computing the EIP-712
            // struct-hash. This works
            // because the `EncodedSafeOpStruct` struct has no "dynamic" fields so its memory layout
            // is identical to the
            // result of `abi.encode`-ing the individual fields.
            EncodedSafeOpStruct memory encodedSafeOp = EncodedSafeOpStruct({
                typeHash: SAFE_OP_TYPEHASH,
                safe: userOp.sender,
                nonce: userOp.nonce,
                initCodeHash: keccak256(userOp.initCode),
                callDataHash: keccak256(userOp.callData),
                verificationGasLimit: uint128(unpackVerificationGasLimit(userOp)),
                callGasLimit: uint128(unpackCallGasLimit(userOp)),
                preVerificationGas: userOp.preVerificationGas,
                maxPriorityFeePerGas: uint128(unpackMaxPriorityFeePerGas(userOp)),
                maxFeePerGas: uint128(unpackMaxFeePerGas(userOp)),
                paymasterAndDataHash: keccak256(userOp.paymasterAndData),
                validAfter: validAfter,
                validUntil: validUntil,
                entryPoint: entryPoint
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

            operationData =
                abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator(), safeOpStructHash);
        }
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, block.chainid, this));
    }

    function unpackVerificationGasLimit(PackedUserOperation memory userOp)
        private
        pure
        returns (uint256)
    {
        return UserOperationLib.unpackHigh128(userOp.accountGasLimits);
    }

    function unpackCallGasLimit(PackedUserOperation memory userOp) private pure returns (uint256) {
        return UserOperationLib.unpackLow128(userOp.accountGasLimits);
    }

    function unpackMaxPriorityFeePerGas(PackedUserOperation memory userOp)
        private
        pure
        returns (uint256)
    {
        return UserOperationLib.unpackHigh128(userOp.gasFees);
    }

    function unpackMaxFeePerGas(PackedUserOperation memory userOp) private pure returns (uint256) {
        return UserOperationLib.unpackLow128(userOp.gasFees);
    }
}
