+++
title = "Verification and convergence"
description = "How AttackTree verifies security controls with evidence: verdicts, evidence levels, micro attack simulations and bypass rates, status roll-up, and the definition of converged."
weight = 13
[extra]
group = "Concepts"
nav_title = "Verification"
+++

A control in a tree is a claim until something proves it works. `/speckit-attacktree-converge` turns claims into evidence after implementation and recomputes risk from what was proven.

## Claims are not evidence

A checked task, a comment saying "input is validated", or `status: implemented` in the tree proves nothing. A test that only mentions the requirement ID, or asserts a constant, proves nothing either. Evidence is one of these:

- a **test** whose assertions exercise the requirement's Given/When/Then scenario;
- a **micro attack simulation** record that executed the control's validation steps against the running system;
- a **review** of the code at the control's touchpoint, showing the control is wired into the path the attack takes;
- a **scan** result that covers the requirement.

## Verdicts

The agent judges each `CR-###` requirement from evidence it opened, stopping at the first verdict it can justify:

| Verdict | Means | Recorded result |
|---|---|---|
| `verified` | every acceptance scenario is exercised and passes | pass |
| `implemented-unverified` | the control is present and wired, but nothing tests it | inconclusive |
| `partial` | a scenario, a path, or the wiring is missing | partial |
| `missing` | no implementation found | fail |

The engine rejects `verified` without an evidence pointer, such as `path::test_name`, `path:line`, or a record file. Every verdict is appended to `verification[]` with a timestamp and a commit. History is never rewritten.

## Roll-up

After recording, the engine updates the tree:

- A control becomes **verified** when all its requirements are verified. Its `evidence` level follows the method: `lab-validated` for tests, scans, and simulations, `design-reviewed` for reviews, and `end-to-end-validated` for manual drills.
- A `proposed` or `planned` control becomes **implemented** when any of its requirements shows code at the touchpoint.
- A `verified` claim without a passing verification falls back to **implemented**.
- A goal becomes **mitigated** when it has feasible paths, every one carries a verified control, its residual risk with verified controls is below `risk.block_on`, and it is not unknown. `accepted` and `transferred` follow an unexpired decision.

Residual risk is then recomputed with the `verified` scenario: only proven controls count.

## Probabilistic controls and bypass rates

Guardrails, classifiers, and human approval do not block; they reduce. Mark them `probabilistic: true`. Their real effect is a **bypass rate**, the share of attacks that get through, and only a measurement can establish it. A **micro attack simulation** is a small, targeted exercise that runs a control's validation steps with enough probes to state a rate. Christian Schneider suggests 30 or more probes for a leaf-level control, and hundreds, with a confidence interval, for a control on a critical goal's choke point.

Record the rate with the verdict. The engine stores it on the requirement's probabilistic controls, and from then on the simulation uses the measured value instead of the effect level. A goal-lock classifier assumed at "medium" (50 %) but measured at 15 % bypass lowers risk more than assumed; one measured at 60 % raises it. Either way, the tree now reports what the control does.

## Remediation tasks

Every requirement that is not verified becomes a task in a `## Phase N: Control Convergence` section appended to `tasks.md`. The task is tagged `[CR-###]`, names the touchpoints, and states the verdict and why. So does every goal still at blocking risk. Existing tasks are never changed. A gap that already has an open task is not duplicated, and a converged run leaves `tasks.md` byte-for-byte unchanged.

## Definition of converged

A feature is **converged** when all four hold:

1. No goal is at or above `risk.block_on` residual risk with verified controls only, unless an unexpired decision covers it.
2. Every `CR-###` is verified, or all its controls are rejected.
3. No risk decision has expired.
4. `spec.md`, `plan.md`, and the configured OTM file have not changed since the tree was generated.

The converge command exits with code 0 when converged and 1 otherwise, so it can run in CI after implementation.
