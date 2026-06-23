# Outreach Message Variants (DRAFTS — NOT SENT)

> **Drafts only. Nothing here has been sent. No auditor has been contacted.** The owner sends outreach
> **manually** after completing `ENGAGEMENT_READINESS_CHECKLIST.md`. Fill all `[placeholders]` first.
> Never imply the software is audited or mainnet-ready.

---

## Variant 1 — Short first contact

> Subject: Independent review — PoAW-X consensus overlay (testnet/devnet)
>
> Hi `[Auditor Name]`,
>
> We're looking for an independent security review of PoAW-X, a testnet/devnet-only consensus overlay on
> our Rust PoW chain (mainnet hard-off). Scope is the Phases 28–34 additions (finality/reorg,
> double-sign penalties, reward caps, on-chain tickets, dominance commitment, adaptive modes). A full
> auditor kickoff package is ready. Would `[Company]` be available and interested? Happy to share details.
>
> Thanks, `[Owner Name]`, Irium Labs — `[Owner Email]`

## Variant 2 — Detailed technical audit request

> Subject: Audit engagement request — PoAW-X Phases 28–34 (Rust, consensus)
>
> Hi `[Auditor Name]`,
>
> We'd like to engage `[Company]` for an independent review of PoAW-X (testnet/devnet only; hard-off on
> mainnet). In scope: `connect_block`/`reorg_to_tip` integration and the trailing block sections
> `DSE1`/`TKT1`/`DMC1`/`ADM1` across Phases 28–34. Materials: a kickoff package
> (scope, source ranges, review guide, invariants checklist, repro commands, test evidence, findings
> template, questions, expected deliverables). Code is on public `testnet/poawx-…` branches; `main` does
> not contain PoAW-X.
>
> Preferred scope: `[A/B/C/D]`. Budget range: `[Budget Range]`. Timeline: `[Timeline]`. NDA:
> `[NDA Decision]`. Could you confirm availability, scope fit, and a quote?
>
> Thanks, `[Owner Name]` — `[Owner Email]`

## Variant 3 — Follow-up

> Subject: Re: PoAW-X independent review
>
> Hi `[Auditor Name]`, following up on my note about the PoAW-X Phases 28–34 review. Is `[Company]`
> available within `[Timeline]`, and would the kickoff package be enough to scope a quote? Happy to do a
> short call. Thanks, `[Owner Name]`.

## Variant 4 — NDA / scope clarification

> Subject: PoAW-X audit — scope & NDA
>
> Hi `[Auditor Name]`, to firm up the engagement: proposed scope is `[A/B/C/D]` (deliverables per our
> package), NDA posture `[NDA Decision]` (we won't suppress genuine findings beyond a responsible-
> disclosure window), and compensation is fixed-fee / outcome-neutral. Does that work, and what's your
> retest process? Thanks, `[Owner Name]`.

---

### Placeholders
`[Auditor Name]`, `[Company]`, `[Email]`, `[Owner Name]`, `[Owner Email]`, `[Budget Range]`,
`[Timeline]`, `[NDA Decision]`, `[A/B/C/D]`.

### Before sending
Complete `ENGAGEMENT_READINESS_CHECKLIST.md`; log the send approval in `OWNER_DECISION_LOG.md`; keep all
claims factual (testnet/devnet only, not audited, not mainnet-ready).
