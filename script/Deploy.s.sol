// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {GridzResolver} from "../src/GridzResolver.sol";
import {IEAS} from "../src/IEAS.sol";

/**
 * @notice Deploys GridzResolver to a testnet. EAS address per network:
 *   Sepolia          0xC2679fBD37d54388Ce493F1DB75320D236e1815e
 *   Base Sepolia     0x4200000000000000000000000000000000000021
 *   Optimism Sepolia 0x4200000000000000000000000000000000000021
 *
 * Set EAS_ADDRESS in the environment, then:
 *   forge script script/Deploy.s.sol --rpc-url <testnet> --broadcast
 *
 * No mainnet config is shipped — that is the operator's call (BRIEF §13).
 */
contract Deploy is Script {
    function run() external returns (GridzResolver resolver) {
        // Addresses/schemas are supplied by the operator, never hardcoded here
        // (ethskills: verify addresses, don't hallucinate them).
        address eas = vm.envAddress("EAS_ADDRESS");
        bytes32 cellSchema = vm.envBytes32("CELL_SCHEMA"); // the registered gridz.cell.v1 schema UID
        vm.startBroadcast();
        resolver = new GridzResolver(IEAS(eas), cellSchema);
        vm.stopBroadcast();
    }
}
