# Post-Soak Report (Template)

To be completed **after** a future soak execution. **Not filled in Phase 39 (no soak executed).** This
report does not by itself authorize any launch.

## 1. Topology
- Hosts / roles: `[A/B/C(/D)]`
- Ports + storage roots: `[summary]`
- Cross-host P2P used? `[no / source-restricted, approved]`

## 2. Branch / commit
- Soak build: `[branch] / [commit]`
- `origin/main` unchanged: `[confirm 19c496d…]`

## 3. Scenarios executed
- `[S1..S15 — which ran, which skipped and why]`

## 4. Tests passed / failed
- Pass: `[list]`
- Fail / partial: `[list + detail]`

## 5. Evidence summary
- Convergence (height/tip/root match): `[summary]`
- Fresh-wipe sync: `[result]` · Cold replay: `[result]`
- Reorg-below-finalized rejection: `[result + log line]`
- Feature state consistency (double-sign / ticket / dominance / adaptive): `[summary]`
- Evidence archive path(s): `[...]`

## 6. Issues found
- `[none | list; file via Phase 38 finding templates if real defects]`

## 7. Cleanup confirmation
- Devnet nodes stopped by exact pidfile: `[confirm]`
- Phase 39 storage roots removed (logs archived first): `[confirm]`
- Temporary firewall rules removed (if any created): `[confirm]`

## 8. Mainnet / prod safety confirmation
- Mainnet processes inventoried + untouched + still running after soak: `[confirm with PIDs]`
- No default storage used; no public ports exposed: `[confirm]`

## 9. Recommendation
- For the **independent audit**: `[evidence to hand over]`
- For **public-testnet planning** (still owner-gated, not a launch): `[proceed to planning / fix first]`
- Status remains: not audited, not production-ready, not mainnet-ready, public-testnet planning-ready
  only — unless this report explicitly and accurately states otherwise within scope.
