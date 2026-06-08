# Gridz contracts

`GridzResolver.sol` — a **UUPS-upgradeable**, **role-gated** ENSIP-10 wildcard resolver that
backs `gridz.*` text records with EAS attestations. Deploy via `ERC1967Proxy`; point ENS at
the **proxy** address so implementation upgrades do not require an ENS migration.

Reviewed against [ethskills Security](https://ethskills.com/security/SKILL.md) and
[ethskills Testing](https://ethskills.com/testing/SKILL.md).

## Roles

| Role | Purpose |
|------|---------|
| `DEFAULT_ADMIN_ROLE` | Grant/revoke roles |
| `REGISTRAR_ROLE` | `setCellAttestation` — register EAS UIDs per ENS node/key |
| `UPGRADER_ROLE` | Authorize UUPS implementation upgrades |

The deploy script grants all three to `ADMIN_ADDRESS` (defaults to the broadcaster).
**Before mainnet:** transfer `UPGRADER_ROLE` (and ideally `DEFAULT_ADMIN_ROLE`) to a
multisig — never leave upgrade authority on a single hot EOA ([ethskills proxy guidance](https://ethskills.com/security/SKILL.md)).

## Security properties

- UUPS with `_disableInitializers()` on the implementation
- `48`-slot storage gap for safe future upgrades (append-only layout)
- Input validation: non-zero EAS/schema/admin, non-empty keys, non-zero upgrade target
- Untrusted EAS attestation bytes decoded via try/catch — malformed data resolves to `""`
- No external calls on write paths (no reentrancy surface); reads are `view`

## Deploy

```bash
EAS_ADDRESS=<network EAS> \
CELL_SCHEMA=<gridz.cell.v1 schema UID> \
forge script script/Deploy.s.sol --rpc-url <rpc> --broadcast --private-key <key>
```

Use the **proxy** address from the broadcast as `GRIDZ_RESOLVER`.

| Network | Chain ID | EAS | SchemaRegistry |
|---------|----------|-----|----------------|
| **Base (gridz.bio prod)** | `8453` | `0x4200000000000000000000000000000000000021` | `0x4200000000000000000000000000000000000020` |
| Ethereum mainnet (legacy) | `1` | `0xA1207F3BBa224E2c9c3c6D5aF63D0eb1582Ce587` | `0xA7b39296258348C78294F95B872b282326A97BDF` |
| Sepolia | `11155111` | `0xC2679fBD37d54388Ce493F1DB75320D236e1815e` | `0x0a7E2Ff54e576B096E04665717A6C3B2a33b9e4a` |
| Base Sepolia | `84532` | `0x4200000000000000000000000000000000000021` | `0x4200000000000000000000000000000000000020` |

Production **GridzResolver proxy** (Base): `0x73c5e3944B780D4927c403d351A4F94875DC57B3`. See [specs/deployments.md](../specs/deployments.md).

## Upgrade

```bash
PROXY_ADDRESS=<proxy> \
forge script script/Upgrade.s.sol --rpc-url <rpc> --broadcast --private-key <key>
```

Caller must hold `UPGRADER_ROLE` on the proxy.

## Test & analyze

```bash
forge test                    # fuzz: 1000 runs (foundry.toml)
forge coverage --report summary
slither src/GridzResolver.sol # recommended pre-deploy (ethskills)
```
