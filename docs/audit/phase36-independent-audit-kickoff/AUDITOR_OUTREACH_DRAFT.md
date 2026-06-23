# Auditor Outreach (DRAFT — NOT SENT)

> **This is a draft only.** It has **not** been sent. No auditor has been contacted. Do not send without
> the project owner's explicit approval. Fill the placeholders first.

---

**To:** `[AUDITOR_NAME]`, `[COMPANY]` — `[EMAIL]`
**From:** `[OWNER_NAME]`, Irium Labs
**Subject:** Independent security review — PoAW-X consensus overlay (testnet/devnet, Phases 28–34)

Hello `[AUDITOR_NAME]`,

We'd like to engage `[COMPANY]` for an **independent security review** of PoAW-X, a multi-role consensus
overlay on our Bitcoin-style PoW chain (Irium). The overlay is **testnet/devnet only** and **hard-off on
mainnet** (`network_id == 0`); we are **not** seeking a mainnet or public-testnet sign-off — only an
independent review of the consensus additions made in Phases 28–34.

**Scope (in):** finalized-checkpoint reorg rejection, block-carried double-sign evidence + penalties,
reward manifest caps/fallback, on-chain ticket store, dominance-state commitment, and adaptive-mode
consensus integration — plus the trailing block wire sections (`DSE1`/`TKT1`/`DMC1`/`ADM1`) and the
`connect_block`/`reorg_to_tip` integration.

**Scope (out):** mainnet activation, public-testnet launch, wallet UX, exchange/liquidity, production
ops, and unchanged base consensus (PoW/LWMA/anchor/base reward).

**Materials:** a complete kickoff package is ready at
`docs/audit/phase36-independent-audit-kickoff/` (scope, source ranges, review guide, invariants
checklist, repro commands, test evidence, findings template, questions, expected deliverables). The code
is at `https://github.com/iriumlabs/irium` on the `testnet/poawx-phase34-…` branch
(HEAD `78d5ca3`); `main` is unchanged and does not contain PoAW-X.

**Expected deliverables:** see `AUDIT_DELIVERABLES_EXPECTED.md` (threat model, consensus correctness,
replay/reorg, wire compatibility, state transitions, economic/incentive, test coverage, final report +
remediation retest).

**Commercials:** budget `[BUDGET]`; preferred timeline `[TIMELINE]`; NDA `[NDA_DECISION]`.

Could you confirm availability, scope fit, and an estimate? Happy to walk through the package on a call.

Thanks,
`[OWNER_NAME]`
Irium Labs — `[OWNER_EMAIL]`

---

### Placeholders to fill before sending
- `[AUDITOR_NAME]`, `[COMPANY]`, `[EMAIL]`
- `[OWNER_NAME]`, `[OWNER_EMAIL]`
- `[BUDGET]`, `[TIMELINE]`, `[NDA_DECISION]`

### Pre-send checklist (owner)
- [ ] Auditor selected and conflict-of-interest checked
- [ ] NDA decision made
- [ ] Budget + timeline agreed internally
- [ ] Send explicitly approved by the project owner
- [ ] Archive the sent copy after sending

**Reminder: not audited, not mainnet-ready; this message must not imply otherwise.**
