// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "./Base.t.sol";
import {
    PackedUserOperation,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
    MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
    IValidator,
    IPreValidationHookERC1271,
    IPreValidationHookERC4337
} from "erc7579/interfaces/IERC7579Module.sol";
import { IERC1271 } from "src/interfaces/IERC1271.sol";
import { MockPreValidationHook } from "test/mocks/MockPrevalidationHook.sol";
import { ISafe7579 } from "src/ISafe7579.sol";
import { MockValidatorV2 } from "test/mocks/MockValidatorV2.sol";

interface IERC4337 {
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        payable
        returns (uint256 validSignature);
}

contract PreValidationHookTest is BaseTest {
    // Test constants
    bytes32 public constant TEST_HASH = bytes32(hex"deadbeef");
    bytes public constant TEST_SIGNATURE = hex"cafebabe";
    bytes32 public constant MODIFIED_HASH = bytes32(hex"beefdead");
    bytes public constant MODIFIED_SIGNATURE = hex"babecafe";

    MockPreValidationHook public preValidationHook;
    MockValidatorV2 public mockValidator;

    function setUp() public virtual override {
        super.setUp();
        installUnitTestAsModule();
        preValidationHook = new MockPreValidationHook();
        mockValidator = new MockValidatorV2();
        // Install modules with EntryPoint privileges
        vm.startPrank(address(entrypoint));

        // Install prevalidation hooks
        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC1271,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC1271, "")
        );

        account.installModule(
            MODULE_TYPE_PREVALIDATION_HOOK_ERC4337,
            address(preValidationHook),
            abi.encode(MODULE_TYPE_PREVALIDATION_HOOK_ERC4337, "")
        );

        // Install validator module
        account.installModule(
            1, // MODULE_TYPE_VALIDATOR
            address(mockValidator),
            ""
        );

        vm.stopPrank();

        // Configure the mock prevalidation hook
        preValidationHook.setWillModify(true);
        preValidationHook.setReturnValues(MODIFIED_HASH, MODIFIED_SIGNATURE);
    }

    /*//////////////////////////////////////////////////////////////
                        ERC1271 PREVALIDATION TESTS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Tests the case where data.length == 0 in isValidSignature.
     * Flow:
     * 1. Call preValidationHook with empty data
     * 2. Check if the hash is in Safe's signedMessages mapping
     * 3. If successful, return magic value
     */
    function test_ERC1271PreValidationHook_EmptyData() external {
        // Mock Safe's signedMessages to return a non-zero value
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("signedMessages(bytes32)"))),
            abi.encode(1) // Non-zero value
        );

        // Mock Safe's domainSeparator
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("domainSeparator()"))),
            abi.encode(bytes32(0))
        );

        // Expect call to the ERC1271 hook
        vm.expectCall(
            address(preValidationHook),
            abi.encodeCall(
                IPreValidationHookERC1271.preValidationHookERC1271,
                (address(this), TEST_HASH, bytes(""))
            )
        );

        // Call isValidSignature with empty data
        bytes4 magicValue = IERC1271(address(account)).isValidSignature(
            TEST_HASH,
            bytes("") // Empty data
        );

        assertEq(magicValue, IERC1271.isValidSignature.selector);
    }

    /**
     * @notice Tests the case where validation module is address(0).
     * Flow:
     * 1. Extract validation module from data (address(0))
     * 2. Call preValidationHook with remaining data
     * 3. Since validator is address(0), fall back to Safe's checkSignatures
     * 4. Return magic value
     */
    function test_ERC1271PreValidationHook_NoValidValidator() external {
        // Mock Safe's checkSignatures
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("checkSignatures(bytes32,bytes,bytes)"))),
            abi.encode()
        );

        // Mock Safe's domainSeparator
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("domainSeparator()"))),
            abi.encode(bytes32(0))
        );

        // Prepare data with address(0) as the validator
        bytes memory data = abi.encodePacked(address(0), TEST_SIGNATURE);

        // Expect call to the ERC1271 hook
        vm.expectCall(
            address(preValidationHook),
            abi.encodeWithSelector(
                IPreValidationHookERC1271.preValidationHookERC1271.selector,
                address(this), // The caller in this context
                TEST_HASH,
                TEST_SIGNATURE // Remaining data after address(0)
            )
        );

        // Call isValidSignature with address(0) validator
        bytes4 magicValue = IERC1271(address(account)).isValidSignature(TEST_HASH, data);

        assertEq(magicValue, IERC1271.isValidSignature.selector);
    }

    /**
     * @notice Tests the case where validation module is not installed.
     * Flow:
     * 1. Extract validation module from data (non-installed validator)
     * 2. Call preValidationHook with remaining data
     * 3. Check if validator is installed (_isValidatorInstalled returns false)
     * 4. Fall back to Safe's checkSignatures
     * 5. Return magic value
     */
    function test_ERC1271PreValidationHook_WithNonInstalledValidator() external {
        // First uninstall the validator so we can test with a non-installed validator
        vm.startPrank(address(entrypoint));
        account.uninstallModule(1, address(mockValidator), abi.encode(address(1), ""));
        vm.stopPrank();

        // Mock Safe's checkSignatures
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("checkSignatures(bytes32,bytes,bytes)"))),
            abi.encode()
        );

        // Mock Safe's domainSeparator
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("domainSeparator()"))),
            abi.encode(bytes32(0))
        );

        // Prepare data with non-installed validator
        bytes memory data = abi.encodePacked(address(mockValidator), TEST_SIGNATURE);

        // Expect call to the ERC1271 hook
        vm.expectCall(
            address(preValidationHook),
            abi.encodeWithSelector(
                IPreValidationHookERC1271.preValidationHookERC1271.selector,
                address(this), // The caller in this context
                TEST_HASH,
                TEST_SIGNATURE // Remaining data after validator address
            )
        );

        // Call isValidSignature with non-installed validator
        bytes4 magicValue = IERC1271(address(account)).isValidSignature(TEST_HASH, data);

        // Should fall back to Safe's signature check
        assertEq(magicValue, IERC1271.isValidSignature.selector);
    }

    /**
     * @notice Tests the case where a valid validator module is provided.
     * Flow:
     * 1. Extract validation module from data (installed validator)
     * 2. Call preValidationHook with remaining data
     * 3. Check if validator is installed (_isValidatorInstalled returns true)
     * 4. Call validator's isValidSignatureWithSender with modified values from hook
     * 5. Return the validator's response
     */
    function test_ERC1271PreValidationHook_WithInstalledValidator() external {
        // Configure validator to return valid signature
        mockValidator.setReturnValidSignature(true);

        // Prepare data with mockValidator address
        bytes memory data = abi.encodePacked(address(mockValidator), TEST_SIGNATURE);

        // Expect call to the ERC1271 hook
        vm.expectCall(
            address(preValidationHook),
            abi.encodeWithSelector(
                IPreValidationHookERC1271.preValidationHookERC1271.selector,
                address(this), // The caller in this context
                TEST_HASH,
                TEST_SIGNATURE // Remaining data after validator address
            )
        );

        // Expect call to the validator
        vm.expectCall(
            address(mockValidator),
            abi.encodeWithSelector(
                IValidator.isValidSignatureWithSender.selector,
                address(this), // The caller
                MODIFIED_HASH, // The modified hash from the hook
                MODIFIED_SIGNATURE // The modified signature from the hook
            )
        );

        // Call isValidSignature with validator
        bytes4 magicValue = IERC1271(address(account)).isValidSignature(TEST_HASH, data);

        assertEq(magicValue, bytes4(0x1626ba7e)); // Should return the validator's magic value
    }

    /**
     * @notice Tests the case where a valid validator returns an invalid signature.
     * Flow:
     * 1. Extract validation module from data (installed validator)
     * 2. Call preValidationHook with remaining data
     * 3. Check if validator is installed (_isValidatorInstalled returns true)
     * 4. Call validator's isValidSignatureWithSender with modified values from hook
     * 5. Validator returns an invalid response (bytes4(0))
     * 6. Return the validator's invalid response
     */
    function test_ERC1271PreValidationHook_WithInvalidValidatorResponse() external {
        // Configure validator to return INVALID signature
        mockValidator.setReturnValidSignature(false);

        // Prepare data with mockValidator address
        bytes memory data = abi.encodePacked(address(mockValidator), TEST_SIGNATURE);

        // Call isValidSignature with validator
        bytes4 magicValue = IERC1271(address(account)).isValidSignature(TEST_HASH, data);

        assertEq(magicValue, bytes4(0)); // Should return the validator's invalid response
    }

    /*//////////////////////////////////////////////////////////////
                        ERC4337 PREVALIDATION TESTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Tests the basic ERC4337 prevalidation hook functionality with no validator.
     * Flow:
     * 1. Call preValidationHook with userOp, missingAccountFunds, and userOpHash
     * 2. Hook modifies the hash and signature
     * 3. Extract validator from nonce (address(0))
     * 4. Fall back to _validateSignatures since validator is address(0)
     */
    function test_ERC4337PreValidationHook_NoValidator() external asEntryPoint {
        // Set up the user operation with no validator in nonce
        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(0));
        userOp.signature = TEST_SIGNATURE;
        bytes32 userOpHash = TEST_HASH;
        uint256 missingAccountFunds = 0;

        // Mock the Safe's checkSignatures behavior
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("checkSignatures(bytes32,bytes,bytes)"))),
            abi.encode()
        );

        // Expect call to the ERC4337 hook
        vm.expectCall(
            address(preValidationHook),
            abi.encodeWithSelector(
                IPreValidationHookERC4337.preValidationHookERC4337.selector,
                userOp,
                missingAccountFunds,
                userOpHash
            )
        );

        // Call validateUserOp
        uint256 validSignature =
            IERC4337(address(account)).validateUserOp(userOp, userOpHash, missingAccountFunds);
    }

    /**
     * @notice Tests when the validator encoded in nonce is not installed.
     * Flow:
     * 1. Call preValidationHook with userOp, missingAccountFunds, and userOpHash
     * 2. Extract validator from nonce (non-installed validator)
     * 3. Fall back to _validateSignatures since validator is not installed
     */
    function test_ERC4337PreValidationHook_NonInstalledValidator() external asEntryPoint {
        // Set up user operation with a random (non-installed) validator in nonce
        address randomValidator = address(0x123456789);
        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), randomValidator);
        userOp.signature = TEST_SIGNATURE;
        bytes32 userOpHash = TEST_HASH;
        uint256 missingAccountFunds = 0;

        // Mock the Safe's checkSignatures behavior
        vm.mockCall(
            address(safe),
            abi.encodeWithSelector(bytes4(keccak256("checkSignatures(bytes32,bytes,bytes)"))),
            abi.encode()
        );

        // Expect call to the ERC4337 hook
        vm.expectCall(
            address(preValidationHook),
            abi.encodeWithSelector(
                IPreValidationHookERC4337.preValidationHookERC4337.selector,
                userOp,
                missingAccountFunds,
                userOpHash
            )
        );

        // Call validateUserOp
        uint256 validSignature =
            IERC4337(address(account)).validateUserOp(userOp, userOpHash, missingAccountFunds);
    }

    /**
     * @notice Tests ERC4337 prevalidation hook with a valid installed validator.
     * Flow:
     * 1. Call preValidationHook with userOp, missingAccountFunds, and userOpHash
     * 2. Hook modifies the hash and signature
     * 3. Extract validator from nonce (installed validator)
     * 4. Call validator with modified values
     * 5. Return validator response
     */
    function test_ERC4337PreValidationHook_WithValidator() external asEntryPoint {
        // Set up user operation with our installed validator in nonce
        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(mockValidator));
        userOp.signature = TEST_SIGNATURE;
        bytes32 userOpHash = TEST_HASH;
        uint256 missingAccountFunds = 0;

        // Set validator to return a specific value
        mockValidator.setValidateUserOpReturnValue(42);

        // Expect call to the ERC4337 hook
        vm.expectCall(
            address(preValidationHook),
            abi.encodeWithSelector(
                IPreValidationHookERC4337.preValidationHookERC4337.selector,
                userOp,
                missingAccountFunds,
                userOpHash
            )
        );

        // The hook modifies the hash and signature
        PackedUserOperation memory modifiedUserOp = userOp;
        modifiedUserOp.signature = MODIFIED_SIGNATURE;

        // Expect call to validator
        vm.expectCall(
            address(mockValidator),
            abi.encodeWithSelector(
                IValidator.validateUserOp.selector,
                modifiedUserOp, // The modified user operation from the hook
                MODIFIED_HASH // The modified hash from the hook
            )
        );

        // Use original signature
        userOp.signature = TEST_SIGNATURE;

        // Call validateUserOp
        uint256 validSignature =
            IERC4337(address(account)).validateUserOp(userOp, userOpHash, missingAccountFunds);

        // Verify validator's return value was passed through
        assertEq(validSignature, 42);
    }

    /**
     * @notice Tests when missingAccountFunds is non-zero to test prefund payment.
     * Flow:
     * 1. Call preValidationHook with userOp, missingAccountFunds, and userOpHash
     * 2. Process validation
     * 3. Transfer missingAccountFunds to EntryPoint
     */
    function test_ERC4337PreValidationHook_WithMissingFunds() external asEntryPoint {
        // Set up user operation
        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(mockValidator));
        userOp.signature = TEST_SIGNATURE;
        bytes32 userOpHash = TEST_HASH;
        uint256 missingAccountFunds = 100; // Non-zero missing funds

        // Set validator to return a specific value
        mockValidator.setValidateUserOpReturnValue(0);

        // Prepare Safe with funds
        vm.deal(address(safe), 1000);

        // Check entrypoint balance before
        uint256 entrypointBalanceBefore = address(entrypoint).balance;

        // Call validateUserOp with missing funds
        IERC4337(address(account)).validateUserOp(userOp, userOpHash, missingAccountFunds);

        // Check entrypoint balance after
        assertEq(address(entrypoint).balance, entrypointBalanceBefore + missingAccountFunds);
    }
}
