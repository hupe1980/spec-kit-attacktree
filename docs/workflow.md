# Workflow integration

AttackTree adds four commands to the Spec Kit lifecycle. Nothing changes until you invoke one or enable a hook.

```text
/speckit-specify                          spec.md
        ↓
/speckit-attacktree-model                 attack-tree.yaml + attack-tree.md + CR-### block in spec.md
        ↓
/speckit-plan                             plan.md (sees the control requirements)
        ↓
/speckit-attacktree-model --from-plan     concrete attack vectors, control touchpoints as file paths
        ↓
/speckit-attacktree-simulate              residual risk, choke points, single points of failure, control roadmap
        ↓   (set the chosen controls to planned)
/speckit-tasks                            tasks.md (control tasks tagged [CR-###])
        ↓
/speckit-attacktree-check                 gap report: goals → paths → controls → CR-### → tasks → verification
        ↓
/speckit-implement                        code + tests
        ↓
/speckit-attacktree-converge              evidence-based verification, residual risk with verified controls, remediation tasks
        ↓
/speckit-converge                         core convergence completes the appended tasks
```

## Why two model passes

After `/speckit-specify` the tree captures **who wants what**: actors, goals, and the paths visible from user stories and requirements; control touchpoints name components. After `/speckit-plan` the second pass attaches attack vectors to **where they land**: endpoints, tools, stores, and control touchpoints become file paths. Both passes are incremental; ids, statuses, decisions, bypass rates, and verification history survive.

## With an Open Threat Model file

Interop with other threat-modelling tools goes through the [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel) standard and is off by default. Set `model.otm` in the configuration to an OTM document (JSON or YAML, relative to the feature directory or the repository) and:

- `attacktree.sh seed` derives assets and one candidate goal per rated threat, with `links.threats` set; the model command starts from it.
- Check A13 verifies every `links.*` reference against the file; check A11 treats it as a source and reports drift when it changes.

Without it, the model command builds the tree from `spec.md` and `plan.md` alone. Managed blocks of other Spec Kit extensions in `spec.md` are ignored when hashing, so they never register as drift.

## Hooks

Installed hooks are listed in `.specify/extensions.yml`. All are `optional: true` by default: the core command prints a prompt and you decide. To make one mandatory, set `optional: false` for that entry.

| Event | Command | Purpose |
|---|---|---|
| `after_specify` | model | first pass |
| `after_clarify` | model | refresh after spec changes |
| `after_plan` | model | plan pass |
| `after_tasks` | check | every CR has a task |
| `before_implement` | simulate | residual risk with current and planned controls; blocks on `block_on` goals when `enforcement: strict` |
| `after_implement` | converge | evidence-based verification |
| `before_converge` | converge | hand remediation tasks to core convergence |

AttackTree commands also dispatch their own hook points: `before/after_attacktree_model`, `before/after_attacktree_check`, `before/after_attacktree_simulate`, `before/after_attacktree_converge`. Other extensions can register on them in their manifests.

## Companion preset `attacktree-sdd`

```bash
specify preset add --dev ./spec-kit-attacktree/preset/attacktree-sdd
```

Appends one section to the core `tasks`, `analyze`, `converge`, and `checklist` commands so that `CR-###` requirements are tagged, inventoried, ordered by the roadmap, and offered as a checklist type. Without it, AttackTree `check` and `converge` remain the authoritative passes for control coverage.

## Workflow `attacktree-sdd`

```bash
specify workflow add --dev ./spec-kit-attacktree/workflow/attacktree-sdd
specify workflow run attacktree-sdd -i spec="An internal assistant that answers questions from our knowledge base"
```

Runs the full cycle with review gates after the attack tree, after the simulation (so the team chooses the controls to plan before tasks are generated), and after the gap check.

## CI

The deterministic checks and the simulation need no agent:

```bash
.specify/extensions/attacktree/scripts/bash/attacktree.sh check --feature-dir specs/007-agent-assistant --format sarif --output attacktree.sarif
.specify/extensions/attacktree/scripts/bash/attacktree.sh simulate --feature-dir specs/007-agent-assistant --scenario current --no-monte-carlo
```

Upload the SARIF file with `github/codeql-action/upload-sarif` to see findings in the Security tab. Check exit codes: `0` nothing above MEDIUM, `1` HIGH (or MEDIUM with `--strict`), `2` CRITICAL. Simulate exit codes: `0` no goal at `risk.block_on` residual risk, `1` otherwise.

The repository also ships a composite GitHub Action (`action.yml`) that runs both, uploads SARIF under the `attacktree` category, and fails the job on HIGH/CRITICAL findings and, optionally, on blocking goals:

```yaml
- uses: hupe1980/spec-kit-attacktree@v0.1.0
  with:
    feature-dir: specs/007-agent-assistant
    strict: "false"                  # "true" also fails on MEDIUM
    scenario: current                # current | verified | planned | all
    fail-on-blocking-goals: "false"  # "true" fails when a goal stays at block_on residual risk
    upload-sarif: "true"
    fail-on-findings: "true"
```

Check A9 (requirement without verification) is phase-aware: LOW while no task for the requirement is done, MEDIUM while implementation is in progress, HIGH/MEDIUM once all tasks are checked but nothing verifies the requirement. A pre-implementation run therefore does not fail CI on verification alone.

## Task linking

A task counts for a requirement only when it carries the bracket tag `[CR-###]` (comma lists such as `[CR-001, CR-003]` are allowed) or is listed under `requirements[].tasks`. A prose mention like "CR-001 through CR-014" does not count, so ranges cannot produce false coverage.

## Re-running converge

`converge-apply` is idempotent on the not-converged path: a gap that already has an unchecked task in a `Control Convergence` phase is not duplicated, and no new phase is appended when there is nothing to add. Once that task is checked off but the requirement still fails verification, the next run appends a fresh task.

## Partial convergence runs

`converge-apply --only CR-003,CR-007` re-judges only the named requirements. Every other requirement keeps its most recent recorded verdict; no synthetic "missing" entries are written for them.

## Files written

| Command | Writes |
|---|---|
| model | `attack-tree.yaml`, `attack-tree.md`, `security/seed-attack-tree.yaml` (with an OTM file), `security/incoming-attack-tree.yaml`, the marked block in `spec.md` |
| check | `security/attacktree-check-report.md` (with `--persist`) |
| simulate | `security/attacktree-simulation.{md,json}` (with `--persist`) |
| converge | `attack-tree.yaml` (verification, bypass rates, status roll-up), `attack-tree.md`, `security/attacktree-scan.json`, `security/attacktree-verdicts.yaml`, `security/attacktree-convergence-report.{md,json}`, appended phase in `tasks.md` |

Nothing else is touched. `plan.md` and OTM files are never written; `tasks.md` is append-only. Every file under `security/` carries the `attacktree-` prefix so other tooling in the same directory is never overwritten.
