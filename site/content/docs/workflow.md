+++
title = "Workflow"
description = "Use AttackTree across the Spec Kit lifecycle: two modelling passes, simulation before tasks, checks before implementation, convergence after, plus hooks, the companion preset, and the workflow."
weight = 20
[extra]
group = "Guides"
+++

AttackTree adds four commands to Spec Kit. Nothing changes until you run one or enable a hook.

```text
/speckit-specify                        spec.md
/speckit-attacktree-model               attack-tree.yaml, attack-tree.md, CR-### block in spec.md
/speckit-clarify                        answers the tree's open questions
/speckit-plan                           plan.md, which now sees the control requirements
/speckit-attacktree-model --from-plan   attack vectors and control touchpoints tied to real files
/speckit-attacktree-simulate            residual risk and control roadmap; set chosen controls to "planned"
/speckit-tasks                          tasks.md, with control tasks tagged [CR-###]
/speckit-attacktree-check               gap report from goals to tasks
/speckit-implement                      code and tests
/speckit-attacktree-converge            verdicts, verified controls, residual risk, remediation tasks
/speckit-converge                       core convergence completes the appended tasks
```

## Two modelling passes

After `/speckit-specify`, the tree captures **who wants what**: actors, goals, and the paths visible from user stories and requirements. Control touchpoints still name components. After `/speckit-plan`, the second pass (`--from-plan`) ties attacks to **where they land**, such as endpoints, tools, and stores, and turns touchpoints into file paths.

Both passes are incremental. Ids stay stable. The status, evidence, bypass rate, and notes of existing entities, decisions, and verification history are owned by humans and by converge, so the merge keeps them whatever the agent writes. Goals and nodes that disappear are retired, not deleted.

## Choosing controls

The model proposes controls with `status: proposed`. People decide what gets built. Read the [simulation](@/docs/simulation.md), agree on a roadmap, and set the chosen controls to `planned` (or `rejected`) in `attack-tree.yaml`. `simulate --scenario planned` then shows the risk the roadmap leaves. Converge moves controls to `implemented` and `verified` from evidence; nobody edits those statuses by hand.

## Accepting risk

Not every path gets a control. A `decisions[]` entry accepts or transfers the risk of a goal, or of every path through a node, with an owner, a rationale, and an expiry date. An unexpired decision stops a goal from blocking. An expired one protects nothing, and check A10 reports it. The agent never creates decisions on its own; it proposes them.

## Hooks

Spec Kit lists installed hooks in `.specify/extensions.yml`. All ship with `optional: true`: the core command asks whether to run the AttackTree command, and you decide. Set `optional: false` to make one automatic.

| Event | Runs | Why |
|---|---|---|
| `after_specify` | model | first pass |
| `after_clarify` | model | refresh after the spec changed |
| `after_plan` | model | pass over the plan |
| `after_tasks` | check | every requirement has a task |
| `before_implement` | simulate | current and planned risk; blocks on blocking goals under `enforcement: strict` |
| `after_implement` | converge | evidence-based verification |
| `before_converge` | converge | hands remediation tasks to core convergence |

Each AttackTree command also dispatches its own hook points, `before_attacktree_<command>` and `after_attacktree_<command>`, so other extensions can chain onto it.

## Companion preset

The `attacktree-sdd` preset appends one section to four core commands:

- `tasks` creates an implementation task and a test task per `CR-###`, tagged `[CR-###]`, ordered by the roadmap.
- `analyze` inventories `CR-###` next to `FR-###` and `SC-###`, reports requirements without tasks, and flags statements without a testable acceptance scenario.
- `converge` takes requirement verdicts from AttackTree's convergence report instead of judging from checkboxes.
- `checklist` offers a security-controls checklist built from acceptance scenarios and validation steps.

Without the preset, AttackTree's check and converge commands are still the authoritative passes; the core commands simply do not know about `CR-###`.

## Linking tasks

A task counts for a requirement only when it carries the bracket tag, as in `- [ ] T031 [US1] [CR-002] Filter retrieval by visibility`, or a comma list such as `[CR-001, CR-003]`. A prose mention like "CR-001 to CR-014" links nothing, so ranges cannot fake coverage.

## Files written

| Command | Writes |
|---|---|
| model | `attack-tree.yaml`, `attack-tree.md`, the `CR-###` block in `spec.md`, working files in `security/` |
| check | `security/attacktree-check-report.md` with `--persist` |
| simulate | `security/attacktree-simulation.{md,json}` with `--persist` |
| converge | `attack-tree.yaml` (verification, statuses, bypass rates), `attack-tree.md`, `security/attacktree-*`, an appended phase in `tasks.md` |

`plan.md` and OTM files are never written, and `tasks.md` is append-only. Inside `spec.md`, only the block between `<!-- attacktree:begin -->` and `<!-- attacktree:end -->` changes.

## Running the whole cycle

The optional `attacktree-sdd` workflow runs specify, model, plan, model from plan, simulate, tasks, check, implement, converge, and core converge in order. It pauses for review after the tree, after the simulation (so the team picks the controls), and after the gap check:

```bash
specify workflow run attacktree-sdd -i spec="An internal assistant that answers questions from our knowledge base"
```
