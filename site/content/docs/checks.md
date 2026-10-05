+++
title = "Checks"
description = "Reference for AttackTree's sixteen deterministic checks A1 to A16 with severities and fixes, and the ten semantic passes the check command adds."
weight = 33
[extra]
group = "Reference"
+++

`attacktree.sh check` runs sixteen deterministic checks over the tree, `tasks.md`, the sources, and the configured OTM file. `/speckit-attacktree-check` prints them and adds ten semantic passes that need judgement. Findings cite a location, such as `attack-tree.yaml#goal.forge-ticket` or `spec.md`, and a recommendation.

## Deterministic checks

| ID | Finds | Severity | Fix |
|---|---|---|---|
| A1 | Schema violations, or a missing `attack-tree.yaml` | CRITICAL | Correct the field the message names. |
| A2 | Dangling references, parent cycles, an `attack` block on a node with children, `effects` for a node the control is not attached to, unknown `requires` tags | CRITICAL | Point the reference at an existing id, or add the entity. |
| A3 | A goal without any node | MEDIUM | Model its paths, or retire it. |
| A4 | A leaf without `attack`, actors, or complexity | HIGH | Rate the attack vector. |
| A5 | An AND or OR node, or an AND goal, with a single child | LOW | Add the missing alternative or step, or merge the node into its child. |
| A6 | A feasible path to a goal with no control on any of its nodes and no decision | HIGH, CRITICAL for critical-impact goals | Attach a control on the path (a choke point covers every path), or record a decision. |
| A7 | A control without a `CR-###` requirement | HIGH | Derive a requirement with acceptance scenarios. |
| A8 | A requirement without a task in `tasks.md` | HIGH | Add a task tagged `[CR-###]`. |
| A9 | A requirement without verification | LOW before implementation, MEDIUM in progress, MEDIUM or HIGH once its tasks are done | Run converge after implementation. |
| A10 | A decision missing owner, rationale, or expiry, or already expired (HIGH); an expiry beyond `max_duration_days` (MEDIUM) | HIGH or MEDIUM | Complete, renew, or shorten the decision. |
| A11 | `spec.md`, `plan.md`, or the OTM file changed since the tree was generated (MEDIUM), or was never hashed (LOW) | MEDIUM or LOW | Re-run the model command. |
| A12 | A control marked `verified` without a passing verification for all its requirements | HIGH | Run converge; statuses follow evidence. |
| A13 | A link to a threat or mitigation that is not in the OTM file | MEDIUM | Fix the link, or refresh the tree after the OTM file changed. |
| A14 | A node that needs clarification | MEDIUM | Answer the question with `/speckit-clarify`, then re-run the model command. |
| A15 | An actor without some of skill, resources, access, or risk appetite | MEDIUM | Rate the missing capabilities. |
| A16 | Path enumeration truncated at `risk.max_paths` | LOW | Raise the limit, or split the goal. |

Expired decisions protect nothing: A6 and the simulation ignore them. More than three pre-implementation A9 findings are aggregated into one line.

### Exit codes and enforcement

| Worst finding | `warn` | `strict` |
|---|---|---|
| CRITICAL | 2 | 2 |
| HIGH | 1 | 1 |
| MEDIUM | 0 | 1 |
| LOW or none | 0 | 0 |

Set `enforcement` in the [configuration](@/docs/configuration.md#enforcement), or pass `--strict` for one run. Under `strict`, the agent also refuses to proceed to `/speckit-implement` while a CRITICAL finding is open.

### Output formats

`md` (the default) is the report table. `json` contains findings, metrics, the worst severity, and the effective enforcement. `sarif` is SARIF 2.1.0 for GitHub code scanning, with one rule per check ID.

## Semantic passes

The check command's agent adds these after reading the tree, the spec, the plan, the tasks, the OTM file, the profiles, and the constitution:

| Pass | Looks for |
|---|---|
| S1 Drift content | what changed in the sources that the tree does not reflect yet |
| S2 Missing paths | entry points, goals, or actors the artifacts imply but the tree lacks |
| S3 Duplicates | nodes or controls that describe the same step or safeguard |
| S4 Control fit | controls that do not address their node, controls far from a choke point, single points of failure on critical goals |
| S5 Rating plausibility | ratings the artifacts contradict, missing `requires` tags |
| S6 Requirement and task fit | untestable requirements, acceptance that skips the validation steps, tasks that cannot implement the control |
| S7 Constitution | MUST principles about security without a goal or control |
| S8 Decisions | decisions whose rationale no longer holds |
| S9 Probabilistic controls | guardrails not marked probabilistic, human approval without context |
| S10 Wording | goals phrased as weaknesses, controls without touchpoints or validation steps |
