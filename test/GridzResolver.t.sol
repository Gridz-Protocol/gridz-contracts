// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {GridzResolver, IExtendedResolver} from "../src/GridzResolver.sol";
import {IEAS, Attestation} from "../src/IEAS.sol";

contract MockEAS is IEAS {
    mapping(bytes32 => Attestation) internal _atts;

    function set(bytes32 uid, Attestation memory a) external {
        _atts[uid] = a;
    }

    function getAttestation(bytes32 uid) external view returns (Attestation memory) {
        return _atts[uid];
    }
}

contract GridzResolverTest is Test {
    MockEAS internal eas;
    GridzResolver internal resolver;

    bytes32 internal constant NODE = keccak256("mygrid.eth");
    bytes32 internal constant UID = keccak256("uid-1");
    bytes32 internal constant CELL_SCHEMA = keccak256("gridz.cell.v1");
    address internal constant ALICE = address(0xA11CE);

    function setUp() public {
        eas = new MockEAS();
        resolver = new GridzResolver(eas, CELL_SCHEMA);
    }

    function _cellData(string memory valueHashHex) internal pure returns (bytes memory) {
        return abi.encode(bytes32("grid"), "com.github", valueHashHex, uint64(0), bytes32(0));
    }

    function _att(uint64 expiration, uint64 revocation, bytes memory data)
        internal
        view
        returns (Attestation memory a)
    {
        a.uid = UID;
        a.schema = CELL_SCHEMA;
        a.time = uint64(block.timestamp);
        a.expirationTime = expiration;
        a.revocationTime = revocation;
        a.attester = address(this);
        a.recipient = address(this);
        a.revocable = true;
        a.data = data;
    }

    function test_setAndReadCell() public {
        eas.set(UID, _att(0, 0, _cellData("0xabc")));
        resolver.setCellAttestation(NODE, "com.github", UID);
        assertEq(resolver.text(NODE, "com.github"), "0xabc");
        assertEq(resolver.cellAttestation(NODE, "com.github"), UID);
    }

    function test_unsetReturnsEmpty() public view {
        assertEq(resolver.text(NODE, "com.github"), "");
    }

    function test_unknownAttestationReturnsEmpty() public {
        resolver.setCellAttestation(NODE, "com.github", UID); // UID never set in EAS
        assertEq(resolver.text(NODE, "com.github"), "");
    }

    function test_revokedReturnsEmpty() public {
        eas.set(UID, _att(0, uint64(block.timestamp), _cellData("0xabc")));
        resolver.setCellAttestation(NODE, "com.github", UID);
        assertEq(resolver.text(NODE, "com.github"), "");
    }

    function test_expiredReturnsEmpty() public {
        eas.set(UID, _att(uint64(block.timestamp + 10), 0, _cellData("0xabc")));
        resolver.setCellAttestation(NODE, "com.github", UID);
        vm.warp(block.timestamp + 100);
        assertEq(resolver.text(NODE, "com.github"), "");
    }

    function test_notYetExpiredReturnsValue() public {
        eas.set(UID, _att(uint64(block.timestamp + 1000), 0, _cellData("0xlive")));
        resolver.setCellAttestation(NODE, "com.github", UID);
        assertEq(resolver.text(NODE, "com.github"), "0xlive");
    }

    function test_onlyOwnerCanSet() public {
        vm.prank(ALICE);
        vm.expectRevert(GridzResolver.NotOwner.selector);
        resolver.setCellAttestation(NODE, "com.github", UID);
    }

    function test_transferOwnership() public {
        resolver.transferOwnership(ALICE);
        assertEq(resolver.owner(), ALICE);
        vm.prank(ALICE);
        resolver.setCellAttestation(NODE, "alias", UID);
    }

    function test_transferOwnershipZeroReverts() public {
        vm.expectRevert(GridzResolver.ZeroAddress.selector);
        resolver.transferOwnership(address(0));
    }

    function test_resolveWildcard() public {
        eas.set(UID, _att(0, 0, _cellData("0xwild")));
        resolver.setCellAttestation(NODE, "com.github", UID);
        bytes memory data = abi.encodeWithSelector(0x59d1d43c, NODE, "com.github");
        bytes memory out = resolver.resolve(hex"00", data);
        assertEq(abi.decode(out, (string)), "0xwild");
    }

    function test_resolveUnsupportedSelectorReverts() public {
        bytes memory data = abi.encodeWithSelector(bytes4(0xdeadbeef), NODE);
        vm.expectRevert(GridzResolver.UnsupportedResolverFunction.selector);
        resolver.resolve(hex"00", data);
    }

    function test_supportsInterface() public view {
        assertTrue(resolver.supportsInterface(0x01ffc9a7)); // ERC165
        assertTrue(resolver.supportsInterface(0x59d1d43c)); // ITextResolver
        assertTrue(resolver.supportsInterface(0x9061b923)); // IExtendedResolver
        assertFalse(resolver.supportsInterface(0xffffffff));
    }

    /// @dev Defensive (ethskills Security): a UID under a different schema must
    ///      not be decoded as a cell — it resolves to "" instead of reverting.
    function test_wrongSchemaReturnsEmpty() public {
        Attestation memory a = _att(0, 0, _cellData("0xabc"));
        a.schema = keccak256("some.other.schema");
        eas.set(UID, a);
        resolver.setCellAttestation(NODE, "com.github", UID);
        assertEq(resolver.text(NODE, "com.github"), "");
    }

    // --- fuzz (ethskills Testing) ---

    function testFuzz_roundTrip(string calldata key, string calldata value) public {
        vm.assume(bytes(key).length > 0);
        bytes memory data = abi.encode(bytes32("g"), key, value, uint64(0), bytes32(0));
        eas.set(UID, _att(0, 0, data));
        resolver.setCellAttestation(NODE, key, UID);
        assertEq(resolver.text(NODE, key), value);
    }

    function testFuzz_unsetKeyAlwaysEmpty(bytes32 node, string calldata key) public view {
        assertEq(resolver.text(node, key), "");
    }

    function testFuzz_onlyOwnerCanSet(address caller) public {
        vm.assume(caller != address(this));
        vm.prank(caller);
        vm.expectRevert(GridzResolver.NotOwner.selector);
        resolver.setCellAttestation(NODE, "com.github", UID);
    }
}
