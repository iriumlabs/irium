# Topology Decision

Choose the soak topology. Decision pending. Devnet only; mainnet hard-off; nothing executed.

## Option A — Local-only loopback multi-node soak
- **What:** 2–3 `iriumd` instances on the Windows host only, loopback P2P + loopback RPC.
- **Pros:** zero firewall changes; no cross-host exposure; fastest to set up; safest.
- **Cons:** doesn't exercise real cross-host network sync timing / NAT; weaker evidence for multi-machine
  behavior.
- **Risk:** lowest. **Firewall needs:** none. **Evidence quality:** good for consensus/replay/reorg;
  limited for network realism.

## Option B — Windows + VPS-1 + VPS-2 internal devnet
- **What:** three hosts, source-restricted cross-host P2P, loopback RPC each.
- **Pros:** real multi-machine convergence, fresh-wipe, cold-resync evidence (closest to the prior
  26C/26D/26E soaks).
- **Cons:** requires owner-approved source-restricted firewall rules; Windows dynamic IP must be
  re-checked immediately before execution; more moving parts.
- **Risk:** moderate (network exposure if misconfigured). **Firewall needs:** source-restricted TCP,
  single port, removed at cleanup. **Evidence quality:** strongest.

## Option C — Staged: local-only first, then Windows/VPS-1/VPS-2
- **What:** run Option A first (validate consensus/replay/reorg loopback-only), then expand to Option B
  for the multi-machine scenarios, each behind its own approval.
- **Pros:** catches issues cheaply before any cross-host exposure; incremental approvals; best
  risk/evidence balance.
- **Cons:** longer overall; two approval steps.
- **Risk:** low→moderate, incrementally. **Firewall needs:** none for stage 1; source-restricted for
  stage 2. **Evidence quality:** strong and incremental.

## Recommended default

**Option C (staged).** Do not go cross-host (Option B) first unless the owner explicitly approves it.
Record the choice in `EXECUTION_READINESS_SIGNOFF.md` (items 1–2) and
`FINAL_OWNER_APPROVAL_TEMPLATE.md`.
