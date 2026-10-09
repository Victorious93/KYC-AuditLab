# Ownership Map (M0)

## Honest status

No human has been assigned to any of the roles the Phase 1 delivery model
requires (Technical lead, Security lead, QA lead, Platform/data engineer,
Orchestration lead, DevOps/CI owner, Reporting owner, 7 layer owners,
repository maintainer). This repository has so far been built by a single
operator (the user) working with a single AI coding session, with no
separate review, security, or QA function. That is a real gap against the
delivery model's entry/exit criteria for M1 ("Security lead approves
policy behavior"), M3 ("Each layer owner signs off"), M5/M6 (named
approvers), etc. - those steps cannot be truthfully marked complete until
real people are named and actually review the work.

## What this means for the release-gate checklist

Every checklist item that depends on a named approver's sign-off
(`security-review.md`, `qa-review.md`, `release-decision.md` under the
evidence package spec) is **not satisfiable** until roles are assigned.
This is tracked as `SCHED-1` in the risk register.

## Interim mapping (proposed, not a substitute for real assignment)

Until the user assigns real owners, the table below records who has
*touched* each area so far, for traceability purposes only - it does not
satisfy the model's separation-of-duties intent (e.g. the same party
cannot credibly both implement and approve a security control).

| Role | Interim holder | Real assignment status |
|---|---|---|
| Repository maintainer | labsvictorious@duck.com (repo owner) | Confirmed (owns the GitHub repo) |
| Technical lead | Not assigned | **Open** |
| Security lead | Not assigned | **Open** - critical for M1 sign-off |
| QA lead | Not assigned | **Open** |
| Platform/data engineer | Not assigned | **Open** |
| Orchestration lead | Not assigned | **Open** |
| DevOps/CI owner | Not assigned | **Open** - blocks M5 entirely (no CI exists) |
| Reporting owner | Not assigned | **Open** |
| Layer 1-3, 5-7 owner(s) | Implemented by the AI session; no human owner recorded | **Open** |
| Layer 4 (Android) owner | Not assigned; no device/emulator available to this session either | **Open**, also blocked on infrastructure (see `DEP-1`) |

## Action required before M1 can be formally exited

Per the delivery model's own M1 handoff criteria, a Security lead must
approve the safety/execution contract and a QA lead must confirm each
policy rule has a planned test. Neither can happen until those roles are
named. Recommend the user either (a) name real people/teams for at least
Security lead and QA lead before treating any milestone beyond M0 as
formally exited, or (b) explicitly accept, in writing in this repo, that a
single-operator process is being used instead and adjust the delivery
model's entry/exit criteria accordingly - silently proceeding without
either choice would make every later "approved by X" claim false.
