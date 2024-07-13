// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Script, console2 } from "forge-std/Script.sol";
import { SafeSingletonDeployer } from "safe-singleton-deployer/SafeSingletonDeployer.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

import { Safe7579 } from "src/Safe7579.sol";
import { Safe7579Launchpad } from "src/Safe7579Launchpad.sol";
import { TransparentUpgradeableProxy } from
    "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

struct EnvironmentSingletons {
    address deployer;
    address safe7579;
    address safe7579Launchpad;
}

interface ISafeProxyFactory {
    function createProxyWithNonce(
        address _singleton,
        bytes memory initializer,
        uint256 saltNonce
    )
        external
        returns (address proxy);
}

contract DeployAll is Script {
    address constant SAFE_PROXY_FACTORY = address(0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67);
    address constant SAFE_SINGLETON = address(0x29fcB43b46531BcA003ddC8FCB67FFE91900C762);
    address constant MULTI_SEND = address(0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526);
    address constant ENTRYPOINT = address(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
    address constant registry = address(0x0000000000E1AA5927a7B55DDD5D21BeD5E482a7);

    function run() public virtual {
        console2.log("Deployment on chainId:", block.chainid);

        uint256 privKey = vm.envUint("PRIVATE_KEY");
        console2.log("Deployer Addr: ", vm.addr(privKey));

        EnvironmentSingletons memory env;

        env.deployer = vm.addr(privKey);
        (env.safe7579, env.safe7579Launchpad) = _safe7579(privKey, registry);

        _print(env);
        _logJson(env);
    }

    function _safe7579(
        uint256 pKey,
        address registry
    )
        internal
        returns (address safe7579, address safe7579Launchpad)
    {
        safe7579 = SafeSingletonDeployer.broadcastDeploy({
            deployerPrivateKey: pKey,
            creationCode: type(Safe7579).creationCode,
            args: "",
            salt: vm.envBytes32("SAFE7579_SALT")
        });
        _initCode("safe7579", type(Safe7579).creationCode, "");

        safe7579Launchpad = SafeSingletonDeployer.broadcastDeploy({
            deployerPrivateKey: pKey,
            creationCode: type(Safe7579Launchpad).creationCode,
            args: abi.encode(ENTRYPOINT, registry),
            salt: vm.envBytes32("SAFE7579LAUNCHPAD_SALT")
        });
        _initCode(
            "safe7579Launchpad",
            type(Safe7579Launchpad).creationCode,
            abi.encode(ENTRYPOINT, registry)
        );
    }

    function _print(EnvironmentSingletons memory env) internal pure {
        console2.log("-------------------------------------------------------");
        console2.log("safe7579:", env.safe7579);
        console2.log("safe7579Launchpad:", env.safe7579Launchpad);
        console2.log("-------------------------------------------------------");
    }

    function _logJson(EnvironmentSingletons memory env) internal {
        string memory root = "some key";
        vm.serializeUint(root, "chainId", block.chainid);
        vm.serializeAddress(root, "broadcastEOA", env.deployer);

        string memory deployments = "deployments";

        string memory item;

        item = "safe7579";
        vm.serializeAddress(item, "address", env.safe7579);
        vm.serializeBytes32(item, "salt", vm.envBytes32("SAFE7579_SALT"));
        vm.serializeAddress(item, "deployer", env.deployer);
        item = vm.serializeAddress(item, "factory", SafeSingletonDeployer.SAFE_SINGLETON_FACTORY);
        vm.serializeString(deployments, "safe7579", item);

        string memory safe7579Launchpad = "safe7579Launchpad";
        vm.serializeAddress(safe7579Launchpad, "address", env.safe7579Launchpad);
        vm.serializeBytes32(safe7579Launchpad, "salt", vm.envBytes32("SAFE7579LAUNCHPAD_SALT"));
        vm.serializeAddress(safe7579Launchpad, "deployer", env.deployer);
        safe7579Launchpad = vm.serializeAddress(
            safe7579Launchpad, "factory", SafeSingletonDeployer.SAFE_SINGLETON_FACTORY
        );
        vm.serializeString(deployments, "safe7579Launchpad", safe7579Launchpad);

        string memory output = vm.serializeUint(deployments, "timestamp", block.timestamp);
        string memory finalJson = vm.serializeString(root, "deployments", output);

        string memory fileName =
            string(abi.encodePacked("./deployments/", Strings.toString(block.chainid), ".json"));
        console2.log("Writing to file: ", fileName);

        vm.writeJson(finalJson, fileName);
    }

    function _initCode(
        string memory component,
        bytes memory creationCode,
        bytes memory args
    )
        private
        pure
    {
        console2.log("InitCodeHash: ", component);
        console2.logBytes32(keccak256(abi.encodePacked(creationCode, args)));
        console2.log("\n");
    }
}
