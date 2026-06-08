// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {
    AccessControlUpgradeable
} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IEAS, Attestation} from "./IEAS.sol";

/// @notice ENSIP-10 extended resolver interface.
interface IExtendedResolver {
    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory);
}

/**
 * @title GridzResolver
 * @notice UUPS-upgradeable ENSIP-10 wildcard resolver backing `gridz.*` text records
 *         with EAS attestations. Role-gated writes; proxy address is stable for ENS.
 *
 * @dev Follows ethskills proxy + access-control guidance: initializer (no constructor
 *      state), disabled implementation init, role separation, storage gap for upgrades.
 *      Transfer UPGRADER_ROLE to a multisig before mainnet (never a lone EOA).
 */
contract GridzResolver is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    IExtendedResolver
{
    /// @dev Registers or clears EAS attestation UIDs for ENS nodes.
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");
    /// @dev Authorizes UUPS implementation upgrades.
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");

    IEAS public eas;
    bytes32 public cellSchema;

    // node => keccak256(key) => attestation uid
    mapping(bytes32 => mapping(bytes32 => bytes32)) private _cellUid;

    bytes4 private constant TEXT_SELECTOR = 0x59d1d43c; // text(bytes32,string)
    bytes4 private constant ERC165_ID = 0x01ffc9a7;
    bytes4 private constant EXTENDED_RESOLVER_ID = 0x9061b923;

    /// @dev Reserved storage for future upgrades — append-only layout (ethskills).
    uint256[48] private __gap;

    event CellRegistered(bytes32 indexed node, string key, bytes32 uid);

    error UnsupportedResolverFunction();
    error ZeroAddress();
    error ZeroSchema();
    error EmptyKey();
    error CalldataTooShort();
    error InvalidAttestation();
    error NotAttestationAttester();
    error KeyMismatch();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @param _eas        EAS contract for the target network (must be non-zero).
     * @param _cellSchema Registered `gridz.cell.v1` schema UID (must be non-zero).
     * @param admin       Receives DEFAULT_ADMIN_ROLE, UPGRADER_ROLE, and REGISTRAR_ROLE.
     */
    function initialize(IEAS _eas, bytes32 _cellSchema, address admin) external initializer {
        if (address(_eas) == address(0) || admin == address(0)) revert ZeroAddress();
        if (_cellSchema == bytes32(0)) revert ZeroSchema();

        __AccessControl_init();

        eas = _eas;
        cellSchema = _cellSchema;

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(UPGRADER_ROLE, admin);
        _grantRole(REGISTRAR_ROLE, admin);
    }

    /// @notice Point the resolver at the canonical EAS deployment (admin-only fixup).
    function setEas(IEAS _eas) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (address(_eas) == address(0)) revert ZeroAddress();
        eas = _eas;
    }

    /// @notice Update the registered gridz.cell.v1 schema UID (admin-only fixup).
    function setCellSchema(bytes32 _cellSchema) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_cellSchema == bytes32(0)) revert ZeroSchema();
        cellSchema = _cellSchema;
    }

    /// @notice Register (or clear, with uid == 0) the EAS attestation for a cell.
    function setCellAttestation(bytes32 node, string calldata key, bytes32 uid)
        external
        onlyRole(REGISTRAR_ROLE)
    {
        if (bytes(key).length == 0) revert EmptyKey();
        _cellUid[node][keccak256(bytes(key))] = uid;
        emit CellRegistered(node, key, uid);
    }

    /// @notice Link a cell when the caller is the EAS attester (user-paid publish).
    /// @dev Verifies schema, key, and attester; gridz.bio editors attest + link from the wallet.
    function linkCellAttestation(bytes32 node, string calldata key, bytes32 uid) external {
        if (bytes(key).length == 0) revert EmptyKey();
        if (uid == bytes32(0)) revert InvalidAttestation();

        Attestation memory a = eas.getAttestation(uid);
        if (a.uid == bytes32(0)) revert InvalidAttestation();
        if (a.schema != cellSchema) revert InvalidAttestation();
        if (a.revocationTime != 0) revert InvalidAttestation();
        if (a.expirationTime != 0 && a.expirationTime < block.timestamp) revert InvalidAttestation();
        if (a.attester != msg.sender) revert NotAttestationAttester();

        string memory attKey;
        try this.decodeCellKey(a.data) returns (string memory k) {
            attKey = k;
        } catch {
            revert InvalidAttestation();
        }
        if (keccak256(bytes(attKey)) != keccak256(bytes(key))) revert KeyMismatch();

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
        if (a.uid == bytes32(0)) return "";
        if (a.schema != cellSchema) return "";
        if (a.revocationTime != 0) return "";
        if (a.expirationTime != 0 && a.expirationTime < block.timestamp) return "";

        // Untrusted EAS payloads: decode via external try/catch so malformed data → "".
        try this.decodeCellValueHash(a.data) returns (string memory valueHashHex) {
            return valueHashHex;
        } catch {
            return "";
        }
    }

    /// @dev External entry for try/catch decoding of untrusted attestation bytes.
    function decodeCellValueHash(bytes memory data)
        external
        pure
        returns (string memory valueHashHex)
    {
        (,, valueHashHex,,) = abi.decode(data, (bytes32, string, string, uint64, bytes32));
    }

    /// @dev External entry for try/catch key extraction from attestation bytes.
    function decodeCellKey(bytes memory data) external pure returns (string memory key) {
        (, key,,,) = abi.decode(data, (bytes32, string, string, uint64, bytes32));
    }

    /// @notice ENSIP-10 wildcard resolution. Only `text(bytes32,string)` is supported.
    function resolve(bytes calldata, bytes calldata data)
        external
        view
        override
        returns (bytes memory)
    {
        if (data.length < 4) revert CalldataTooShort();
        if (bytes4(data[:4]) != TEXT_SELECTOR) revert UnsupportedResolverFunction();
        (bytes32 node, string memory key) = abi.decode(data[4:], (bytes32, string));
        return abi.encode(_text(node, key));
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControlUpgradeable)
        returns (bool)
    {
        return interfaceId == ERC165_ID || interfaceId == TEXT_SELECTOR
            || interfaceId == EXTENDED_RESOLVER_ID || super.supportsInterface(interfaceId);
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        view
        override
        onlyRole(UPGRADER_ROLE)
    {
        if (newImplementation == address(0)) revert ZeroAddress();
    }
}
