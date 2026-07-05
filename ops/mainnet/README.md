# Mainnet PoAW-X receipt-producer (operational bridge)

This directory tracks the mainnet PoAW-X pending-receipt producer that is
currently sustaining block production after the block-50000 activation. The
files are copied verbatim from the live VPS with no behaviour changes; this
commit exists to make the running system reviewable and reproducible instead of
a bespoke, undocumented root-level daemon.

## Files

- `poawx-receipt-producer.sh` — the loop that generates a PoAW-X pending receipt
  via `irium-miner --poawx` (with `IRIUM_POAWX_EXPORT_RECEIPT_JSON=1`), posts it
  to the node's `/poawx/receipt` endpoint, and restarts the four `irium-stratum*`
  services so the pool rebuilds its template with the pending receipt.
  Deployed at: `/home/irium/mainnet/bin/poawx-receipt-producer.sh`
  sha256: `556d16b6e702310c6e4423ffc569f150ebca12f408d5ea469ad847b287df2176`
- `irium-poawx-receipt-producer.service` — the systemd unit that runs it.
  Deployed at: `/etc/systemd/system/irium-poawx-receipt-producer.service`

## Operational notes

Load-bearing: as of this commit this daemon is the SOLE mainnet block-production
path (every block is `source=pool_stratum`, 1:1 with a posted receipt). Stopping
it halts block production; there is no organic fallback currently. It depends on:

- the deployed node (`bb75913` / `12b76c0`) accepting and persisting mainnet
  pending receipts and exposing `/poawx/receipt`, and
- an `irium-miner` binary carrying the `IRIUM_POAWX_EXPORT_RECEIPT_JSON` export.
  That capability is present in tracked `main` via `12b76c0`, byte-identical to
  the local build the daemon currently points at.

The daemon currently sets `MINER_BIN=/home/irium/irium/target/release/irium-miner`,
a build of an unmerged local branch (`6b71366`). Because the identical export
capability is in tracked source, the daemon can be cut over to a binary built
from tracked source without behaviour change; the runtime receipt path
(`run_poawx_solo`, `irium-miner.rs`, `poawx_ticket.rs`) is identical between the
two, and the only divergence (`poawx_mining_harness.rs`) is a single test
assertion. Cut over with the same pause/verify/resume care as a stratum deploy,
after empirically confirming the tracked binary produces a node-accepted receipt.
