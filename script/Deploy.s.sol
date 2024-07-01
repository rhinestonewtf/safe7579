// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import { Script } from "forge-std/Script.sol";
import { Safe7579 } from "src/Safe7579.sol";
import { Safe7579Launchpad } from "src/Safe7579Launchpad.sol";
import { IERC7484 } from "src/interfaces/IERC7484.sol";
import { MockRegistry } from "test/mocks/MockRegistry.sol";
import { Safe } from "@safe-global/safe-contracts/contracts/Safe.sol";
import { SafeProxyFactory } from
    "@safe-global/safe-contracts/contracts/proxies/SafeProxyFactory.sol";
import { MockValidator } from "test/mocks/MockValidator.sol";

/**
 * @title Deploy
 * @author @kopy-kat
 */
contract DeployScript is Script {
    function run() public {
        bytes32 salt = bytes32(uint256(0));

        address entryPoint = address(0x0000000071727De22E5E9d8BAf0edAc6f37da032);
        IERC7484 registry = IERC7484(0x25A4b2F363678E13A0A5DB79b712dE00347a593E);

        vm.startBroadcast(vm.envUint("PK"));

        // new MockValidator{ salt: salt }();

        // new Safe{ salt: salt }();
        // new SafeProxyFactory{ salt: salt }();

        // IERC7484 registry = new MockRegistry{ salt: salt }();
        new Safe7579{ salt: salt }();
        new Safe7579Launchpad{ salt: salt }(entryPoint, registry);

        vm.stopBroadcast();
    }
}
