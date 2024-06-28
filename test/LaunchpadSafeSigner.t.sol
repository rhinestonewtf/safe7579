// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import { ISafeOp, SAFE_OP_TYPEHASH } from "src/interfaces/ISafeOp.sol";
import { UserOperationLib } from "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";
import { Safe7579 } from "src/Safe7579.sol";
import { ISafe7579 } from "src/ISafe7579.sol";
import { IERC7484 } from "src/interfaces/IERC7484.sol";
import "src/DataTypes.sol";
import { ModuleManager } from "src/core/ModuleManager.sol";
import { MockValidator } from "module-bases/mocks/MockValidator.sol";
import { MockRegistry } from "./mocks/MockRegistry.sol";
import { MockExecutor } from "./mocks/MockExecutor.sol";
import { MockFallback } from "./mocks/MockFallback.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ModeLib } from "erc7579/lib/ModeLib.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { MockTarget } from "./mocks/MockTarget.sol";

import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import {
    SafeProxy,
    SafeProxyFactory
} from "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { LibClone } from "solady/utils/LibClone.sol";
import { Safe7579Launchpad } from "src/Safe7579Launchpad.sol";

import { Solarray } from "solarray/Solarray.sol";
import "./dependencies/EntryPoint.sol";

import { Simulator } from "@rhinestone/erc4337-validation/src/Simulator.sol";

contract LaunchpadSafeSignerBase is Test {
    using Simulator for PackedUserOperation; // or UserOperation
    using UserOperationLib for PackedUserOperation;

    Safe7579 safe7579;
    Safe singleton;
    Safe safe;
    SafeProxyFactory safeProxyFactory;
    Safe7579Launchpad launchpad;

    MockValidator defaultValidator;
    MockExecutor defaultExecutor;
    MockTarget target;

    Account signer1 = makeAccount("signer1");
    Account signer2 = makeAccount("signer2");

    IEntryPoint entrypoint;
    bytes userOpInitCode;
    IERC7484 registry;

    struct Setup {
        address singleton;
        address signerFactory;
        bytes signerData;
        address setupTo;
        bytes setupData;
        address fallbackHandler;
    }

    function setUp() public virtual {
        // Set up EntryPoint
        entrypoint = etchEntrypoint();
        singleton = new Safe();
        safeProxyFactory = new SafeProxyFactory();
        registry = new MockRegistry();
        safe7579 = new Safe7579();
        launchpad = new Safe7579Launchpad(address(entrypoint), registry);

        // Set up Modules
        defaultValidator = new MockValidator();
        defaultExecutor = new MockExecutor();
        target = new MockTarget();

        bytes32 salt;

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
        console2.log("Predicted address: ", predict);
        userOp.sender = predict;
        assertEq(userOp.sender, predict);

        uint48 validAfter = 0;
        uint48 validUntil = type(uint48).max;

        userOp.signature =
            abi.encodePacked(validAfter, validUntil, hex"4141414141414141414141414141414141");

        bytes memory operationData = this.getSafeOp(userOp, validAfter, validUntil);
        bytes32 opHash = keccak256(operationData);

        bytes memory sig = signHash(signer1.key, opHash);
        sig = abi.encodePacked(sig, signHash(signer1.key, opHash));

        userOp.signature = abi.encodePacked(validAfter, validUntil, sig);

        (
            bytes memory _operationData,
            uint48 _validAfter,
            uint48 _validUntil,
            bytes memory _signatures
        ) = launchpad._getSafeOp(userOp);

        // assertEq(opHash, keccak256(_operationData));

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;
        deal(address(userOp.sender), 1 ether);

        userOp.simulateUserOp(address(entrypoint));
        entrypoint.handleOps(userOps, payable(address(0x69)));

        safe = Safe(payable(predict));

        assertEq(target.value(), 1337);
    }

    function _initCode(
        bytes memory initializer,
        bytes32 salt
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

    function test_foo() public {
        assertTrue(true);
    }

    function getDefaultUserOp(
        address account,
        address validator
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
            preVerificationGas: 2e6,
            gasFees: bytes32(abi.encodePacked(uint128(2e6), uint128(2e6))),
            paymasterAndData: bytes(""),
            signature: abi.encodePacked(hex"41414141")
        });
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

        uint256 id;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            id := chainid()
        }

        operationData = abi.encodePacked(
            bytes1(0x19),
            bytes1(0x01),
            keccak256(
                abi.encode(
                    0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218,
                    id,
                    userOp.sender
                )
            ),
            safeOpStructHash
        );
    }

    // function getSafeOp(
    //     PackedUserOperation calldata userOp,
    //     uint48 validAfter,
    //     uint48 validUntil
    // )
    //     external
    //     returns (bytes memory operationData)
    // {
    //     ISafeOp.EncodedSafeOpStruct memory encodedSafeOp = ISafeOp.EncodedSafeOpStruct({
    //         typeHash: SAFE_OP_TYPEHASH,
    //         safe: msg.sender,
    //         nonce: userOp.nonce,
    //         initCodeHash: keccak256(userOp.initCode),
    //         callDataHash: keccak256(userOp.callData),
    //         callGasLimit: userOp.unpackCallGasLimit(),
    //         verificationGasLimit: userOp.unpackVerificationGasLimit(),
    //         preVerificationGas: userOp.preVerificationGas,
    //         maxFeePerGas: userOp.unpackMaxFeePerGas(),
    //         maxPriorityFeePerGas: userOp.unpackMaxPriorityFeePerGas(),
    //         paymasterAndDataHash: keccak256(userOp.paymasterAndData),
    //         validAfter: validAfter,
    //         validUntil: validUntil,
    //         entryPoint: 0x0000000071727De22E5E9d8BAf0edAc6f37da032
    //     });

    //     bytes32 safeOpStructHash;
    //     // solhint-disable-next-line no-inline-assembly
    //     assembly ("memory-safe") {
    //         // Since the `encodedSafeOp` value's memory layout is identical to the result of
    //         // `abi.encode`-ing the
    //         // individual `SafeOp` fields, we can pass it directly to `keccak256`. Additionally,
    //         // there are 14
    //         // 32-byte fields to hash, for a length of `14 * 32 = 448` bytes.
    //         safeOpStructHash := keccak256(encodedSafeOp, 448)
    //     }

    //     operationData = abi.encodePacked(
    //         bytes1(0x19), bytes1(0x01), launchpad.domainSeparator(), safeOpStructHash
    //     );
    // }
}
