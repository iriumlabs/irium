# Audit Response Templates (DRAFTS — NOT SENT)

Reusable draft responses for communicating with the auditor about a finding. **Drafts only — nothing is
sent from here.** Keep all claims factual; never assert "audited"/"safe"/"mainnet-ready". Fill
`[placeholders]`.

## 1. Acknowledge finding

> Thanks for finding `[F-NNN] [title]`. We've logged it as `[severity]` and assigned `[F-NNN]`. We'll
> reproduce and follow up with a remediation plan (or questions) by `[date]`.

## 2. Request clarification

> On `[F-NNN]`: could you clarify `[specific question]` — e.g., the exact preconditions / which gates
> were active / the chain state used? We want to reproduce precisely before remediating.

## 3. Provide reproduction evidence

> Re `[F-NNN]`: reproduced at commit `[hash]` with `[steps/command]`. Observed `[behavior]`. Logs/diff
> attached. Proceeding to remediation on branch `[branch]`.

## 4. Provide remediation plan

> Re `[F-NNN]`: proposed fix — `[approach]`. Branch `[branch]` off base `[commit]`. Expected tests:
> `[focused + full lib + sim + build]`. Risk/notes: `[...]`. ETA `[date]`. Please confirm the approach
> addresses the root cause.

## 5. Send retest evidence

> Re `[F-NNN]`: fixed on `[branch]` at `[fix-hash]` (base `[base-hash]`). Diff attached. Tests: focused
> `[X/0]`, full lib `[Y/0]`, poawx-sim `[Z/0]`, release build OK. Added regression test `[name]`.
> Requesting retest.

## 6. Accept risk with rationale

> Re `[F-NNN]` (`[severity]`): we propose to **accept** this residual risk because `[rationale]`, under
> conditions `[conditions]`. We'd appreciate your note on the residual risk. (Owner sign-off recorded in
> our decision log.) This does not change our public status: not audited / not mainnet-ready.

## 7. Dispute finding (respectfully, with evidence)

> Re `[F-NNN]`: we respectfully disagree that `[claim]`, because `[evidence: code ref / test / invariant
> ]`. We may be missing context — could you confirm or point to the exact path? Happy to align on
> severity.

---

**Before sending any of these:** the owner approves the communication (see
`OWNER_APPROVAL_CHECKPOINTS.md`); follow `docs/audit/phase37-auditor-selection-engagement/COMMUNICATION_RULES.md`
(never share keys/credentials/production access; testnet/devnet only).
