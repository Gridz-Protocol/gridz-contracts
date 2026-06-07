// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal EAS attestation record (subset of the official struct).
struct Attestation {
    bytes32 uid;
    bytes32 schema;
    uint64 time;
    uint64 expirationTime;
    uint64 revocationTime;
    bytes32 refUID;
    address recipient;
    address attester;
    bool revocable;
    bytes data;
}

/// @notice The slice of the Ethereum Attestation Service the resolver depends on.
interface IEAS {
    function getAttestation(bytes32 uid) external view returns (Attestation memory);
}
