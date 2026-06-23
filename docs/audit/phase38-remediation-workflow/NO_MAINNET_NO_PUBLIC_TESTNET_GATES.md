# No-Mainnet / No-Public-Testnet Gates

What audit and remediation activity does — and does **not** — authorize. These gates stand regardless of
findings, fixes, or retests. Testnet/devnet only; mainnet hard-off.

## Explicit statements

- **Audit findings do not authorize a launch.** Receiving (or having zero) findings changes nothing
  about launch authorization.
- **Remediation does not authorize a launch.** Fixing findings on remediation branches does not open
  any gate.
- **Retest completion does not automatically authorize a launch.** A clean retest closes a finding; it
  does not open the public-testnet or mainnet gate.
- **Public testnet still requires an owner-approved plan.** See
  `docs/poaw-x-phase35-public-testnet-readiness.md` (staged plan; planning-ready only) and
  `OWNER_APPROVAL_CHECKPOINTS.md` (checkpoint 9).
- **Mainnet still requires a governance / activation program.** PoAW-X is hard-off on mainnet
  (`network_id == 0`); mainnet activation is a separate, not-started program (checkpoint 10).
- **Production-ready: no** until a separate, explicit owner sign-off after all gates — and even then,
  scoped and caveated.

## Gate sequence (none open)

```
audit done + Critical/High/Medium findings Closed-retested or owner-accepted
   └─> public-testnet PLANNING (owner-approved)         [still not a launch]
         └─> staged public testnet (separate approvals)
               └─> ... (much later) mainnet governance/activation program
```

Each arrow is an owner-gated decision; none is implied by the previous step.

## Claim discipline

- Do not say "audited," "secure," "production-ready," "mainnet-ready," or "public-testnet-ready" because
  of any remediation activity.
- Allowed now: "remediation workflow prepared," "no findings received," "not audited," "not
  mainnet-ready," "public-testnet planning-ready only."
