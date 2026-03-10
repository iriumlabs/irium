# Pilot Issue Reporting

## Include this in every report
- `swap_id`
- `irium_htlc_txid` / `irium_claim_txid` / `irium_refund_txid` (if present)
- `btc_htlc_txid` / `btc_claim_txid` / `btc_refund_txid` (if present)
- UTC timestamps (start, failure, last retry)
- host/service involved (VPS node, EU node, coordinator, BTC RPC)
- expected result vs actual result
- severity (`sev1`, `sev2`, `sev3`)

## Logs to attach
- `journalctl -u irium-pilot-node --since "<time>"`
- `journalctl -u irium-pilot-coordinator --since "<time>"` (VPS)
- relevant BTC RPC error output
- coordinator API request/response snippets

## Severity guide
- `sev1`: safety/integrity risk, widespread pilot impact
- `sev2`: swap-path blocked, workaround exists
- `sev3`: minor issue/documentation mismatch
