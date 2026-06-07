# Gridz contracts

`GridzResolver.sol` — an ENSIP-10 wildcard resolver that backs `gridz.*` text
records with EAS attestations. The node owner registers a cell's attestation UID;
`text(node, key)` reads it from EAS and returns the on-chain commitment
(`valueHashHex`). Revoked, expired, or wrong-schema attestations resolve to `""`.

Written following [ethskills](https://ethskills.com/) (Security + Testing skills):
defensive handling of untrusted attestation data (schema-guarded decode so a
wrong-schema UID can't revert or be misread), fuzz tests alongside unit tests, and
addresses supplied by the operator at deploy time rather than hardcoded. The
constructor takes the registered `gridz.cell.v1` schema UID, so only genuine cell
attestations are ever decoded.

```bash
forge install foundry-rs/forge-std --no-git   # first time
forge test
forge coverage   # GridzResolver.sol: 100% lines/statements/branches/functions
slither src/GridzResolver.sol                 # CI gate (run with slither installed)
```

Deploy to a testnet (no mainnet config ships — operator's call, BRIEF §13):

```bash
EAS_ADDRESS=<network EAS> forge script script/Deploy.s.sol --rpc-url <rpc> --broadcast
```

| Network | EAS |
|---|---|
| Sepolia | `0xC2679fBD37d54388Ce493F1DB75320D236e1815e` |
| Base Sepolia | `0x4200000000000000000000000000000000000021` |
| Optimism Sepolia | `0x4200000000000000000000000000000000000021` |

For production, deploy behind an OpenZeppelin UUPS proxy.
