# DR-0001: Single-operator process accepted for IdentityShield Phase 1

**Status:** Accepted
**Decided by:** Repository owner (labsvictorious@duck.com), 2026-10-09
**Context:** `docs/phase1/ownership-map.md` (M0) found that none of the
roles the uploaded Phase 1 delivery model requires (Technical lead,
Security lead, QA lead, Platform/data engineer, Orchestration lead,
DevOps/CI owner, Reporting owner, 7 layer owners, repository maintainer)
were assigned to a distinct human/team. Presented with the choice of (a)
naming real people for at least Security lead and QA lead, or (b)
explicitly accepting a single-operator process and adjusting the model's
criteria, the repository owner chose **(b)**.

## Decision

IdentityShield Phase 1 is run as a **single-operator process**: one
person (the repository owner) holds every role in the delivery model,
working with an AI coding session that has no independent authority to
approve its own work. This decision is recorded here rather than left
implicit, per the repository owner's own instruction.

## What this changes in the delivery model

Every milestone requirement of the form "X lead approves / signs off /
confirms" is reinterpreted as: **the repository owner reviews and
explicitly approves**, recorded as a commit, a note in this decisions
directory, or an explicit instruction in the conversation that produced
the work. A separate named Security lead or QA lead is not required to
exit M1–M6 under this decision.

| Delivery-model requirement (original) | Adjusted requirement (single-operator) |
|---|---|
| "Security lead approves policy behavior" (M1 handoff) | Repository owner reviews and explicitly approves the safety/execution contract (allowlist, ScopeEntry, capability gating, fail-closed paths) before M1 is marked exited. |
| "QA lead confirms each policy rule has a planned test" (M1 handoff) | Repository owner confirms, or the AI session states and the owner does not dispute, that each policy rule in `scope.py`/`runner.py` has a corresponding test in `backend/tests/`. |
| "Each layer owner signs off on interface compatibility" (M3 handoff) | Repository owner reviews the layer registrations in a given delivery and either approves or requests changes; no separate per-layer owner is required. |
| "Security lead, QA lead, repository maintainer" approvers (M6) | Repository owner alone signs the release decision. This is recorded as a reduced-assurance release model, not a release with the same independent-review guarantees multi-person sign-off would give - see "What this does NOT change" below. |

## What this does NOT change

- **Separation of duties is still absent.** The same party (owner +
  AI session) implements and approves. This is a real, accepted
  reduction in assurance relative to the delivery model's original
  intent, not a paperwork fix. It is accepted here explicitly rather
  than silently assumed.
- **Scope/safety enforcement controls are unaffected.** The hostname
  allowlist, explicit `ScopeEntry` requirement, and capability gating in
  `orchestrator/scope.py` / `runner.py` do not depend on any human role
  and continue to apply exactly as built and tested.
- **Deferred/unsupported work is still deferred/unsupported.** This
  decision does not retroactively mark Layer 4 (Android), CI (M5), or
  any other `not-run`/`unavailable`/`deferred` item in
  `traceability.csv` as done. It only resolves who is allowed to say
  "approved."
- **A future return to multi-person review remains open.** If the
  repository owner later brings in a separate reviewer for security or
  QA, this decision should be superseded by a new one (e.g. DR-0002),
  not silently ignored.

## Resulting risk-register update

`SCHED-1` ("No human owners assigned...") moves from `open` to
`accepted`: the gap is real and acknowledged, the repository owner has
explicitly accepted it rather than asked for it to be closed, and no
further escalation is needed unless the owner reopens the question.

## Effect on milestone status going forward

With this decision recorded, **M1 can now be formally exited** on its
substantive criteria (safety contract implemented and tested, schemas
present, fail-closed behavior tested) without being blocked on a
nonexistent Security-lead sign-off. See `traceability.csv` (`GOV-1`) and
`risk-register.csv` (`SCHED-1`) for the updated statuses.
