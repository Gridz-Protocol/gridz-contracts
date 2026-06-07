// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEAS, Attestation} from "./IEAS.sol";

/// @notice ENSIP-10 extended resolver interface.
interface IExtendedResolver {
    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory);
}

/**
 * @title GridzResolver
 * @notice An ENSIP-10 wildcard resolver that backs `gridz.*` text records with
 *         EAS attestations. The node owner registers a cell's attestation UID;
 *         `text(node, key)` reads the attestation from EAS and returns the
 *         on-chain commitment (valueHashHex). Revoked or expired attestations
 *         resolve to the empty string. Off-chain consumers fetch the cleartext
 *         value and check it against this commitment.
 *
 * @dev Self-contained ownership (no external deps) for auditability. For
 *      production, deploy behind an OpenZeppelin UUPS proxy (see script/Deploy).
 */
contract GridzResolver is IExtendedResolver {
    /// @dev EAS schema for gridz.cell.v1.
    /// (bytes32 gridId, string key, string valueHashHex, uint64 expiresAt, bytes32 widgetTypeHash)

    address public owner;
    IEAS public immutable eas;
    /// @dev The registered EAS schema UID for gridz.cell.v1. Attestations under
    ///      any other schema are ignored (defensive — prevents abi.decode reverts
    ///      and stops a wrong-schema UID from being read as a cell).
    bytes32 public immutable cellSchema;

    // node => keccak256(key) => attestation uid
    mapping(bytes32 => mapping(bytes32 => bytes32)) private _cellUid;

    bytes4 private constant TEXT_SELECTOR = 0x59d1d43c; // text(bytes32,string)
    bytes4 private constant ERC165_ID = 0x01ffc9a7;
    bytes4 private constant EXTENDED_RESOLVER_ID = 0x9061b923;

    event CellRegistered(bytes32 indexed node, string key, bytes32 uid);
    event OwnershipTransferred(address indexed from, address indexed to);

    error NotOwner();
    error UnsupportedResolverFunction();
    error ZeroAddress();

    constructor(IEAS _eas, bytes32 _cellSchema) {
        owner = msg.sender;
        eas = _eas;
        cellSchema = _cellSchema;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Register (or clear, with uid == 0) the EAS attestation for a cell.
    function setCellAttestation(bytes32 node, string calldata key, bytes32 uid) external onlyOwner {
        _cellUid[node][keccak256(bytes(key))] = uid;
        emit CellRegistered(node, key, uid);
    }

    function cellAttestation(bytes32 node, string calldata key) external view returns (bytes32) {
        return _cellUid[node][keccak256(bytes(key))];
    }

    /// @notice ENSIP-5 text record read, backed by EAS.
    function text(bytes32 node, string calldata key) external view returns (string memory) {
        return _text(node, key);
    }

    function _text(bytes32 node, string memory key) internal view returns (string memory) {
        bytes32 uid = _cellUid[node][keccak256(bytes(key))];
        if (uid == bytes32(0)) return "";

        Attestation memory a = eas.getAttestation(uid);
        if (a.uid == bytes32(0)) return ""; // unknown attestation
        if (a.schema != cellSchema) return ""; // wrong schema — refuse to decode untrusted layout
        if (a.revocationTime != 0) return ""; // revoked
        if (a.expirationTime != 0 && a.expirationTime < block.timestamp) return ""; // expired

        (,, string memory valueHashHex,,) =
            abi.decode(a.data, (bytes32, string, string, uint64, bytes32));
        return valueHashHex;
    }

    /// @notice ENSIP-10 wildcard resolution. Only `text(bytes32,string)` is supported.
    function resolve(bytes calldata, bytes calldata data) external view override returns (bytes memory) {
        if (bytes4(data[:4]) != TEXT_SELECTOR) revert UnsupportedResolverFunction();
        (bytes32 node, string memory key) = abi.decode(data[4:], (bytes32, string));
        return abi.encode(_text(node, key));
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == ERC165_ID || interfaceId == TEXT_SELECTOR
            || interfaceId == EXTENDED_RESOLVER_ID;
    }
}
