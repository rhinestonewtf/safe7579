// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { Script } from "forge-std/Script.sol";
import { Safe7579UserOperationBuilder } from "src/utils/Safe7579UserOperationBuilder.sol";

/**
 * @title Deploy
 * @author @kopy-kat
 */
contract DeployBuilderScript is Script {
    function run() public {
        address entryPoint = address(0x0000000071727De22E5E9d8BAf0edAc6f37da032);

        bytes32 salt = bytes32(uint256(0));

        vm.startBroadcast(vm.envUint("PK"));

        new Safe7579UserOperationBuilder{ salt: salt }(entryPoint);

        vm.stopBroadcast();
    }
}
