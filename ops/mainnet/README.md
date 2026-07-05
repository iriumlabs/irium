# Mainnet PoAW-X receipt-producer (operational bridge)

This directory tracks the mainnet PoAW-X pending-receipt producer that is
currently sustaining block production after the block-50000 activation. The
files are copied verbatim from the live VPS with no behaviour changes; this
exists to make the running system reviewable and reproducible instead of a
bespoke, undocumented root-level daemon.

## Files

- `poawx-receipt-producer.sh` — the loop that generates a PoAW-X pending receipt
  via `irium-miner --poawx` (with `IRIUM_POAWX_EXPORT_RECEIPT_JSON=1`), posts it
  to the node's `/poawx/receipt` endpoint, and restarts the four `irium-stratum*`
  services so the pool rebuilds its template with the pending receipt.
  Deployed at: `/home/irium/mainnet/bin/poawx-receipt-producer.sh`
  sha256: `3af94dc9aecf8de0240292ab87b9c18d7afaf90b0b82bca5551e689a50bda738`
- `irium-poawx-receipt-producer.service` — the systemd unit that runs it.
  Deployed at: `/etc/systemd/system/irium-poawx-receipt-producer.service`

## Operational notes

Load-bearing: this daemon is currently the SOLE mainnet block-production path
(every block is `source=pool_stratum`, 1:1 with a posted receipt). Stopping it
halts block production; there is no organic fallback currently. It depends on:

- the deployed node (`bb75913` / `12b76c0`) accepting and persisting mainnet
  pending receipts and exposing `/poawx/receipt`, and
- an `irium-miner` binary carrying the `IRIUM_POAWX_EXPORT_RECEIPT_JSON` export
  (present in tracked `main` via `12b76c0`).

`MINER_BIN` points at `/home/irium/mainnet/bin/irium-miner-poawx`, a binary built
from tracked source (`testing-codes-before-merging`; sha256 of that build
`768c565fa63afe4b5522a9118c995aaff71865165e91a7aeff9b0f9ea5b74de2`) and installed
to a stable, clear-provenance path. This replaced the earlier
`MINER_BIN=/home/irium/irium/target/release/irium-miner`, which was a build of an
unmerged local branch (`6b71366`); the runtime receipt path (`run_poawx_solo`,
`irium-miner.rs`, `poawx_ticket.rs`) is identical between the two, the only source
difference being a single `#[cfg(test)]` assertion in `poawx_mining_harness.rs`.
The prior binary is retained untouched for rollback.
