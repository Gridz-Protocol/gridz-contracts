// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {GridzResolver} from "../src/GridzResolver.sol";

/**
 * @notice Upgrades an existing GridzResolver proxy to a new implementation.
 *
 * Env:
 *   PROXY_ADDRESS  — the ERC1967 proxy ENS points at
 *
 * Caller must hold UPGRADER_ROLE on the proxy (or DEFAULT_ADMIN_ROLE).
 */
contract Upgrade is Script {
    function run() external {
        address proxy = vm.envAddress("PROXY_ADDRESS");
        vm.startBroadcast();
        GridzResolver newImpl = new GridzResolver();
        GridzResolver(proxy).upgradeToAndCall(address(newImpl), "");
        vm.stopBroadcast();
    }
}
