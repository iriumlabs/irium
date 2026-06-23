# Final Owner Approval (Template)

Copy this page, fill it, and sign to authorize the internal devnet soak execution phase. **Unsigned —
nothing approved, nothing executed.**

```
PoAW-X Pre-Audit Internal Devnet Soak — Owner Approval

Approved topology:        [A local-only | B Win+VPS1+VPS2 | C staged]
Approved hosts:           [list]
Approved ports:           [A: p2p/rpc/status; B: ...; C: ...]
Approved firewall rules:  [none | source-restricted TCP rules, exact ports + source IPs]
Approved storage roots:   [Windows phase40-devnet\... ; VPS-1 /home/irium/phase40-devnet/... ; VPS-2 ...]
Approved scenarios:       [from SCENARIO_SELECTION.md, e.g. S1,S2,S3,S4,S5,S8,S9,S10,S15]
Controlled reorg (S6):    [approved | skipped]
Approved duration:        [short smoke | medium | long | extended]
Approved abort rules:     [per Phase 39 ABORT_AND_ROLLBACK.md]
Approved cleanup:         [exact-pidfile stop + exact-path delete + logs archived first]
Evidence retention:       [duration + archive path; redaction confirmed]

Mainnet safety reviewed:  [yes — MAINNET_SAFETY_PRECHECK.md complete]
Go/No-Go:                 [GO | NO-GO]

Signed: ______________________   Date: __________

This approval authorizes only internal devnet soak execution, not public testnet or mainnet.
```

## After signing

- Hand off to the (separate) execution phase, which runs the Phase 39 `RUNBOOK_DRAFT.md` under these
  approved parameters, captures evidence (`EVIDENCE_LOG_TEMPLATE.md`), and produces
  `POST_SOAK_REPORT_TEMPLATE.md`.
- A signed approval + a passing soak feed the audit and the public-testnet **planning** decision; they do
  not authorize a public testnet or mainnet (those remain separate, later, owner-gated decisions).
