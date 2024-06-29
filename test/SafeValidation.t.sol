// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "./Launchpad.t.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { ISafeOp, SAFE_OP_TYPEHASH } from "src/interfaces/ISafeOp.sol";
import {
    UserOperationLib,
    PackedUserOperation
} from "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";
import { Simulator } from "@rhinestone/erc4337-validation/src/Simulator.sol";
import "./Launchpad.t.sol";

contract SafeValidationTest is LaunchpadBase {
    using Simulator for PackedUserOperation;
    using UserOperationLib for PackedUserOperation;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    address activeAccount;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public override {
        super.setUp();
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      TESTS
    //////////////////////////////////////////////////////////////////////////*/

    function test_deployAccount() public {
        bytes32 salt = keccak256("newAccount");

        ModuleInit[] memory validators = new ModuleInit[](1);
        validators[0] = ModuleInit({ module: address(defaultValidator), initData: bytes("") });
        ModuleInit[] memory executors = new ModuleInit[](1);
        executors[0] = ModuleInit({ module: address(defaultExecutor), initData: bytes("") });
        ModuleInit[] memory fallbacks = new ModuleInit[](0);
        ModuleInit[] memory hooks = new ModuleInit[](0);

        Safe7579Launchpad.InitData memory initData = Safe7579Launchpad.InitData({
            singleton: address(singleton),
            owners: Solarray.addresses(signer1.addr),
            threshold: 1,
            setupTo: address(launchpad),
            setupData: abi.encodeCall(
                Safe7579Launchpad.initSafe7579,
                (
                    address(safe7579),
                    executors,
                    fallbacks,
                    hooks,
                    Solarray.addresses(makeAddr("attester1"), makeAddr("attester2")),
                    2
                )
            ),
            safe7579: ISafe7579(safe7579),
            validators: validators,
            callData: abi.encodeCall(
                IERC7579Account.execute,
                (
                    ModeLib.encodeSimpleSingle(),
                    ExecutionLib.encodeSingle({
                        target: address(target),
                        value: 0,
                        callData: abi.encodeCall(MockTarget.set, (1337))
                    })
                )
            )
        });
        bytes32 initHash = launchpad.hash(initData);

        bytes memory factoryInitializer =
            abi.encodeCall(Safe7579Launchpad.preValidationSetup, (initHash, address(0), ""));

        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(0));

        {
            userOp.callData = abi.encodeCall(Safe7579Launchpad.setupSafe, (initData));
            userOp.initCode = _initCode(factoryInitializer, salt);
        }

        address predict = launchpad.predictSafeAddress({
            singleton: address(launchpad),
            safeProxyFactory: address(safeProxyFactory),
            creationCode: type(SafeProxy).creationCode,
            salt: salt,
            factoryInitializer: factoryInitializer
        });
        userOp.sender = predict;
        activeAccount = predict;

        uint48 validAfter = 0;
        uint48 validUntil = type(uint48).max;

        bytes memory operationData = this.getSafeOp(userOp, validAfter, validUntil, address(this));
        bytes32 opHash = keccak256(operationData);
        bytes memory sig = signHash(signer1.key, opHash);
        userOp.signature = abi.encodePacked(validAfter, validUntil, sig);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        deal(address(userOp.sender), 1 ether);

        userOp.simulateUserOp(address(entrypoint));
        entrypoint.handleOps(userOps, payable(address(0x69)));

        safe = Safe(payable(predict));

        assertEq(target.value(), 1337);
    }

    function test_execSingle() public {
        test_deployAccount();

        // Encode the call into the calldata for the userOp
        bytes memory userOpCalldata = abi.encodeCall(
            IERC7579Account.execute,
            (
                ModeLib.encodeSimpleSingle(),
                ExecutionLib.encodeSingle(
                    address(target), uint256(0), abi.encodeCall(MockTarget.set, 420)
                )
            )
        );

        PackedUserOperation memory userOp = getDefaultUserOp(address(safe), address(0));
        userOp.callData = userOpCalldata;

        uint48 validAfter = 0;
        uint48 validUntil = type(uint48).max;

        bytes memory operationData =
            this.getSafeOp(userOp, validAfter, validUntil, address(safe7579));
        bytes32 opHash = keccak256(operationData);
        bytes memory sig = signHash(signer1.key, opHash);
        userOp.signature = abi.encodePacked(validAfter, validUntil, sig);

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        entrypoint.handleOps(userOps, payable(address(0x69)));

        assertTrue(target.value() == 420);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                      INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

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
        uint48 validUntil,
        address domainSeparator
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
            safeOpStructHash := keccak256(encodedSafeOp, 448)
        }

        operationData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            IDomainSeparator(domainSeparator).domainSeparator(),
            safeOpStructHash
        );
    }

    function domainSeparator() public returns (bytes32) {
        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }

        return keccak256(
            abi.encode(
                0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218,
                id,
                activeAccount
            )
        );
    }
}

interface IDomainSeparator {
    function domainSeparator() external returns (bytes32);
}
