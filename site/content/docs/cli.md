+++
title = "Engine CLI"
description = "Reference for attacktree.sh, the deterministic AttackTree engine: global options, feature resolution, every subcommand with its flags, and exit codes."
weight = 31
[extra]
group = "Reference"
+++

The engine is `scripts/python/attacktree.py`. Call it through the wrappers `scripts/bash/attacktree.sh` or `scripts/powershell/attacktree.ps1`, which find a Python with PyYAML or fall back to `uv`. In an installed project the path is `.specify/extensions/attacktree/scripts/bash/attacktree.sh`.

```text
attacktree.sh [--repo PATH] [--feature-dir PATH] <subcommand> [options]
```

## Global options

| Option | Default |
|---|---|
| `--repo PATH` | The nearest parent directory containing `.specify/` or `.git`. |
| `--feature-dir PATH` | `SPECIFY_FEATURE`, then the directory under `specs/` named like the current git branch, then the newest `specs/*/spec.md`. |

Global options come **before** the subcommand.

## Subcommands

### `paths`

Prints the resolved repository, feature, and artifact paths, whether each artifact exists, and how the feature was found. `--json` for machine-readable output. Exit code 1 if no feature is found.

### `init`

Creates an empty `attack-tree.yaml` with source hashes and the configured baseline. `--project-id`, `--name`, and `--force` to overwrite an existing tree.

### `seed`

Derives assets and candidate goals from an Open Threat Model file. `--otm FILE` (default: `model.otm` from the configuration) and `--output FILE`.

### `validate FILE`

Validates a tree against the JSON Schema, the reference rules, and the tree structure. `--json` for machine-readable output. Exit code 1 on errors.

### `merge --incoming FILE`

Merges an agent-written tree into `attack-tree.yaml`: it keeps ids and human-owned fields, retires what disappeared, records source hashes, sorts deterministically, and validates. `--dry-run` prints the result without writing. `--allow-invalid` writes despite errors; avoid it.

### `render`

Writes `attack-tree.md` and the `CR-###` block in `spec.md`. `--no-markdown` and `--no-spec` skip either for one run.

### `check`

Runs checks A1 to A16. `--format md|json|sarif`, `--output FILE`, `--persist` (writes `security/attacktree-check-report.md`), `--strict`, `--enforcement warn|strict`. Exit code 0 when nothing is above MEDIUM, 1 for HIGH (or MEDIUM in strict mode), 2 for CRITICAL.

### `simulate`

Evaluates the tree. `--format md|json`, `--output FILE`, `--persist` (writes `security/attacktree-simulation.{md,json}`), `--scenario none|current|verified|planned|all`, `--apply IDS` and `--remove IDS` (comma-separated control ids, what-if only), `--iterations N`, `--seed N`, `--no-monte-carlo`. Refuses to run on an invalid tree. Exit code 1 while a goal is at `risk.block_on` residual risk without a decision.

### `converge-scan`

Collects evidence facts per requirement as JSON: tasks, test files, touchpoints, validation steps, residual risk with verified controls, and check findings. `--output FILE`.

### `converge-apply --verdicts FILE`

Records verdicts, rolls statuses up, writes the convergence report, and appends remediation tasks. `--only CR-001,CR-002` judges only those requirements; the others keep their last verdict. `--commit SHA` overrides the detected commit. `--no-render` skips re-rendering `attack-tree.md`. Exit code 0 when converged, 1 otherwise.

## Environment

| Variable | Effect |
|---|---|
| `SPECIFY_FEATURE` | Feature directory name under `specs/`. |
| `SPECKIT_ATTACKTREE_ENFORCEMENT` | Overrides `enforcement`. |
| `SPECKIT_ATTACKTREE_PROFILES` | Overrides `profiles` (comma-separated). |
| `SPECKIT_ATTACKTREE_SCENARIO` | Overrides `risk.scenario`. |
