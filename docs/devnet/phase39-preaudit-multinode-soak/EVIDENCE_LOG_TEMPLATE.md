# Evidence Log (Template)

One entry per scenario run during the (future) soak. **Empty template — no soak executed.** Never record
private keys/seeds/credentials.

```
Date / time:        [YYYY-MM-DD HH:MM TZ]
Branch / commit:    [branch] / [commit]
Hosts:              [Node A host, Node B host, Node C host, ...]
Ports:              [A: p2p/rpc/status; B: ...; C: ...]
Storage roots:      [A path; B path; C path]
Scenario:           [S1..S15 — name]

Commands run:       [exact commands actually executed]
Result:             [pass | fail | partial]

Node heights:       [A: h; B: h; C: h]
Node tip hashes:    [A: ...; B: ...; C: ...]
irx1 / root:        [per relevant block]
Feature state:      [finalized ckpt; ticket count; penalty count; dominance digest; adaptive pre/post]

Logs / artifacts:   [archive path(s)]
Pass/fail:          [against PASS_FAIL_CRITERIA.md]
Notes:              [anomalies, deviations, follow-ups]
```

## Usage

- Fill one block per scenario; keep them in execution order.
- Archive referenced logs/artifacts to an explicit path **before** cleanup.
- Roll the entries up into `POST_SOAK_REPORT_TEMPLATE.md` at the end.
