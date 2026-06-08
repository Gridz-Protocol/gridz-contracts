// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
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
    GridzResolver internal implementation;

    bytes32 internal constant NODE = keccak256("mygrid.eth");
    bytes32 internal constant UID = keccak256("uid-1");
    bytes32 internal constant CELL_SCHEMA = keccak256("gridz.cell.v1");
    address internal admin;
    address internal constant ALICE = address(0xA11CE);

    function setUp() public {
        admin = address(this);
        eas = new MockEAS();
        implementation = new GridzResolver();
        bytes memory initData =
            abi.encodeCall(GridzResolver.initialize, (IEAS(eas), CELL_SCHEMA, admin));
        ERC1967Proxy proxy = new ERC1967Proxy(address(implementation), initData);
        resolver = GridzResolver(address(proxy));
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
        resolver.setCellAttestation(NODE, "com.github", UID);
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

    function test_onlyRegistrarCanSet() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                ALICE,
                resolver.REGISTRAR_ROLE()
            )
        );
        vm.prank(ALICE);
        resolver.setCellAttestation(NODE, "com.github", UID);
    }

    function test_adminGrantsRegistrar() public {
        eas.set(UID, _att(0, 0, _cellData("0xabc")));
        resolver.grantRole(resolver.REGISTRAR_ROLE(), ALICE);
        vm.prank(ALICE);
        resolver.setCellAttestation(NODE, "alias", UID);
        assertEq(resolver.cellAttestation(NODE, "alias"), UID);
    }

    function test_initializeZeroAdminReverts() public {
        GridzResolver impl = new GridzResolver();
        bytes memory badInit =
            abi.encodeCall(GridzResolver.initialize, (IEAS(eas), CELL_SCHEMA, address(0)));
        vm.expectRevert(GridzResolver.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), badInit);
    }

    function test_initializeZeroEasReverts() public {
        GridzResolver impl = new GridzResolver();
        bytes memory badInit =
            abi.encodeCall(GridzResolver.initialize, (IEAS(address(0)), CELL_SCHEMA, admin));
        vm.expectRevert(GridzResolver.ZeroAddress.selector);
        new ERC1967Proxy(address(impl), badInit);
    }

    function test_initializeZeroSchemaReverts() public {
        GridzResolver impl = new GridzResolver();
        bytes memory badInit =
            abi.encodeCall(GridzResolver.initialize, (IEAS(eas), bytes32(0), admin));
        vm.expectRevert(GridzResolver.ZeroSchema.selector);
        new ERC1967Proxy(address(impl), badInit);
    }

    function test_cannotInitializeImplementation() public {
        GridzResolver impl = new GridzResolver();
        vm.expectRevert();
        impl.initialize(IEAS(eas), CELL_SCHEMA, admin);
    }

    function test_cannotReinitializeProxy() public {
        vm.expectRevert();
        resolver.initialize(IEAS(eas), CELL_SCHEMA, admin);
    }

    function test_emptyKeyReverts() public {
        vm.expectRevert(GridzResolver.EmptyKey.selector);
        resolver.setCellAttestation(NODE, "", UID);
    }

    function test_clearAttestationWithZeroUid() public {
        eas.set(UID, _att(0, 0, _cellData("0xabc")));
        resolver.setCellAttestation(NODE, "alias", UID);
        resolver.setCellAttestation(NODE, "alias", bytes32(0));
        assertEq(resolver.cellAttestation(NODE, "alias"), bytes32(0));
        assertEq(resolver.text(NODE, "alias"), "");
    }

    function test_setCellAttestationEmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit GridzResolver.CellRegistered(NODE, "alias", UID);
        resolver.setCellAttestation(NODE, "alias", UID);
    }

    function test_malformedEasDataReturnsEmpty() public {
        Attestation memory a = _att(0, 0, hex"deadbeef");
        eas.set(UID, a);
        resolver.setCellAttestation(NODE, "alias", UID);
        assertEq(resolver.text(NODE, "alias"), "");
    }

    function test_resolveCalldataTooShort() public {
        vm.expectRevert(GridzResolver.CalldataTooShort.selector);
        resolver.resolve(hex"00", hex"0102");
    }

    function test_upgradePreservesStorage() public {
        eas.set(UID, _att(0, 0, _cellData("0xabc")));
        resolver.setCellAttestation(NODE, "com.github", UID);

        GridzResolver newImpl = new GridzResolver();
        resolver.upgradeToAndCall(address(newImpl), "");

        assertEq(resolver.text(NODE, "com.github"), "0xabc");
        assertEq(resolver.cellAttestation(NODE, "com.github"), UID);
    }

    function test_nonUpgraderCannotUpgrade() public {
        GridzResolver newImpl = new GridzResolver();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                ALICE,
                resolver.UPGRADER_ROLE()
            )
        );
        vm.prank(ALICE);
        resolver.upgradeToAndCall(address(newImpl), "");
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
        assertTrue(resolver.supportsInterface(0x01ffc9a7));
        assertTrue(resolver.supportsInterface(0x59d1d43c));
        assertTrue(resolver.supportsInterface(0x9061b923));
        assertTrue(resolver.supportsInterface(type(IAccessControl).interfaceId));
        assertFalse(resolver.supportsInterface(0xffffffff));
    }

    function test_wrongSchemaReturnsEmpty() public {
        Attestation memory a = _att(0, 0, _cellData("0xabc"));
        a.schema = keccak256("some.other.schema");
        eas.set(UID, a);
        resolver.setCellAttestation(NODE, "com.github", UID);
        assertEq(resolver.text(NODE, "com.github"), "");
    }

    function testFuzz_roundTrip(string calldata key, string calldata value) public {
        vm.assume(bytes(key).length > 0 && bytes(key).length < 256);
        bytes memory data = abi.encode(bytes32("g"), key, value, uint64(0), bytes32(0));
        eas.set(UID, _att(0, 0, data));
        resolver.setCellAttestation(NODE, key, UID);
        assertEq(resolver.text(NODE, key), value);
    }

    function testFuzz_unsetKeyAlwaysEmpty(bytes32 node, string calldata key) public view {
        assertEq(resolver.text(node, key), "");
    }

    function testFuzz_onlyRegistrarCanSet(address caller) public {
        vm.assume(caller != admin && !resolver.hasRole(resolver.REGISTRAR_ROLE(), caller));
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                caller,
                resolver.REGISTRAR_ROLE()
            )
        );
        vm.prank(caller);
        resolver.setCellAttestation(NODE, "com.github", UID);
    }

    function test_linkCellAttestation_byAttester() public {
        eas.set(UID, _att(0, 0, _cellData("0xabc")));
        resolver.linkCellAttestation(NODE, "com.github", UID);
        assertEq(resolver.text(NODE, "com.github"), "0xabc");
    }

    function test_linkCellAttestation_wrongAttesterReverts() public {
        eas.set(UID, _att(0, 0, _cellData("0xabc")));
        vm.expectRevert(GridzResolver.NotAttestationAttester.selector);
        vm.prank(ALICE);
        resolver.linkCellAttestation(NODE, "com.github", UID);
    }

    function test_linkCellAttestation_keyMismatchReverts() public {
        eas.set(UID, _att(0, 0, _cellData("0xabc")));
        vm.expectRevert(GridzResolver.KeyMismatch.selector);
        resolver.linkCellAttestation(NODE, "alias", UID);
    }

    function test_linkCellAttestation_wrongSchemaReverts() public {
        Attestation memory a = _att(0, 0, _cellData("0xabc"));
        a.schema = keccak256("other");
        eas.set(UID, a);
        vm.expectRevert(GridzResolver.InvalidAttestation.selector);
        resolver.linkCellAttestation(NODE, "com.github", UID);
    }
}
