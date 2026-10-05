+++
title = "Commands"
description = "Reference for the four AttackTree agent commands: model, simulate, check, and converge. Arguments, what each command reads and writes, and when to run it."
weight = 30
[extra]
group = "Reference"
+++

Spec Kit renders each command for your agent. Claude Code, Copilot, Cursor, and most others use the hyphenated form, as in `/speckit-attacktree-model`. opencode, Gemini, and Qwen use the dotted form, as in `/speckit.attacktree.model`. Arguments are free text after the command. They only narrow scope and are never executed.

Every command resolves the feature directory the same way: from `--feature-dir specs/<name>` if given, then `SPECIFY_FEATURE`, the current git branch, and finally the newest `specs/*/spec.md`. Every command also treats the content of the spec, plan, OTM file, code, and tests as untrusted data. Instruction-like text found there is quoted under **Unverified** and never followed.

## `/speckit-attacktree-model`

Builds or incrementally updates the attack tree.

| | |
|---|---|
| **Run after** | `/speckit-specify`, `/speckit-clarify`, and `/speckit-plan` (with `--from-plan`) |
| **Arguments** | `--feature-dir`, `--from-plan`, `--profiles default,agentic`, `--goal <text>`, `--focus <text>` |
| **Reads** | `spec.md`, `plan.md`, the constitution, the configured OTM file, the existing tree, the profiles |
| **Writes** | `attack-tree.yaml`, `attack-tree.md`, the `CR-###` block in `spec.md`, working files in `security/` |

The agent defines actors, goals, paths, controls, and requirements, and writes the whole tree to `security/incoming-attack-tree.yaml`. The engine then merges it into `attack-tree.yaml`: it validates the tree, keeps ids and human-owned fields, retires what disappeared, and records source hashes. Where the spec is silent, the agent adds a `needs-clarification` node instead of inventing architecture. The report lists open questions, proposed risk decisions, and the structural simulation.

## `/speckit-attacktree-simulate`

Evaluates the tree and interprets the result for the team.

| | |
|---|---|
| **Run after** | the model pass over the plan, before `/speckit-tasks`; also as the `before_implement` hook |
| **Arguments** | `--feature-dir`, `--scenario none\|current\|verified\|planned\|all`, `--apply ids`, `--remove ids`, `--iterations N`, `--seed N`, `--goal <id>` (focuses the report) |
| **Writes** | `security/attacktree-simulation.{md,json}` |

The command runs the configured scenario and the `planned` scenario, then answers six questions: where are we exposed, where is the leverage, what are we betting on, what should we build first, how sure are we, and what does the model not know. It changes no statuses. See [Simulation](@/docs/simulation.md).

## `/speckit-attacktree-check`

Finds gaps in the chain from goal to verified control.

| | |
|---|---|
| **Run after** | `/speckit-tasks`, and before `/speckit-implement` |
| **Arguments** | `--feature-dir`, `--strict`, `--format md\|json\|sarif` |
| **Writes** | `security/attacktree-check-report.md` |

The engine runs the [sixteen deterministic checks](@/docs/checks.md). The agent then adds ten semantic passes: drift content, missing paths, duplicates, control fit, rating plausibility, requirement and task fit, constitution, decisions, probabilistic controls, and wording. Under `enforcement: strict`, a CRITICAL finding means `/speckit-implement` must not run.

## `/speckit-attacktree-converge`

Verifies control requirements with evidence after implementation.

| | |
|---|---|
| **Run after** | `/speckit-implement`; also as the `before_converge` hook |
| **Arguments** | `--feature-dir`, `--only CR-003,CR-007`, `--run-tests` |
| **Writes** | `attack-tree.yaml` (verification, statuses, bypass rates), `attack-tree.md`, `security/attacktree-*`, an appended phase in `tasks.md` |

The engine collects facts per requirement: tasks, test files that mention the ID, touchpoints, and validation steps. The agent judges each requirement from evidence it opened. The engine records the verdicts, rolls statuses up, recomputes residual risk with verified controls only, and appends remediation tasks. `--run-tests` runs `verification.test_command` once, if one is configured. See [Verification and convergence](@/docs/evidence.md).
