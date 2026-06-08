// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {GridzResolver} from "../src/GridzResolver.sol";
import {IEAS} from "../src/IEAS.sol";

/**
 * @notice Deploys GridzResolver behind an ERC1967 (UUPS) proxy. ENS should point at
 *         the **proxy** address — it stays stable across implementation upgrades.
 *
 * EAS per network:
 *   Mainnet          0xC03e4De6924389f6Dfc89A41Eda71C41cd063315
 *   Sepolia          0xC2679fBD37d54388Ce493F1DB75320D236e1815e
 *   Base mainnet     0x4200000000000000000000000000000000000021
 *   Base Sepolia     0x4200000000000000000000000000000000000021
 *
 * Env:
 *   EAS_ADDRESS      — network EAS contract
 *   CELL_SCHEMA      — registered gridz.cell.v1 schema UID
 *   ADMIN_ADDRESS    — optional; defaults to broadcaster (tx.origin)
 *
 *   forge script script/Deploy.s.sol --rpc-url <rpc> --broadcast --private-key <key>
 */
contract Deploy is Script {
    function run() external returns (GridzResolver resolver) {
        address eas = vm.envAddress("EAS_ADDRESS");
        bytes32 cellSchema = vm.envBytes32("CELL_SCHEMA");

        vm.startBroadcast();
        address admin = vm.envOr("ADMIN_ADDRESS", msg.sender);

        GridzResolver impl = new GridzResolver();
        bytes memory initData =
            abi.encodeCall(GridzResolver.initialize, (IEAS(eas), cellSchema, admin));
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        resolver = GridzResolver(address(proxy));
        vm.stopBroadcast();
    }
}
