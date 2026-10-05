+++
title = "Continuous integration"
description = "Run AttackTree's checks and simulation in CI without an agent, upload findings to GitHub code scanning as SARIF, and gate pull requests on residual risk."
weight = 21
[extra]
group = "Guides"
nav_title = "CI and code scanning"
+++

The engine needs no LLM, so every check and the simulation run in CI. This guide covers the bundled GitHub Action and the plain command line.

## GitHub Action

```yaml
# .github/workflows/attacktree.yml
name: AttackTree
on: [pull_request]
permissions:
  contents: read
  security-events: write   # for the SARIF upload
jobs:
  attacktree:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hupe1980/spec-kit-attacktree@v0.1.0
        with:
          feature-dir: specs/007-agent-assistant
```

The action runs the checks, uploads the findings to code scanning under the `attacktree` category, runs the simulation, and fails the job on HIGH or CRITICAL findings.

| Input | Default | Effect |
|---|---|---|
| `feature-dir` | auto-detect | Feature directory; otherwise `SPECIFY_FEATURE`, the branch name, or the newest spec. |
| `format` | `md` | Check report format in the log: `md` or `json`. |
| `strict` | `false` | Also fail on MEDIUM findings. |
| `scenario` | `current` | Control statuses the simulation counts: `none`, `current`, `verified`, `planned`, or `all`. |
| `fail-on-blocking-goals` | `false` | Fail while a goal is at `risk.block_on` residual risk without a decision. |
| `upload-sarif` | `true` | Upload findings to code scanning. |
| `fail-on-findings` | `true` | Fail on the check's exit code. |

Outputs: `exit-code` (check), `simulate-exit-code`, and `sarif` (the file path).

### Which gate to use

- **Every pull request:** the default. Structural errors and missing links fail the build; verification gaps before implementation stay LOW, so they don't.
- **Before merging to main:** add `fail-on-blocking-goals: "true"` with `scenario: planned`. The agreed roadmap must bring every goal below the blocking level.
- **After implementation:** `scenario: verified` counts only controls with evidence.

## Command line

The same engine runs anywhere Python and PyYAML are available:

```bash
EXT=.specify/extensions/attacktree/scripts/bash/attacktree.sh
$EXT --feature-dir specs/007-agent-assistant check --format sarif --output attacktree.sarif
$EXT --feature-dir specs/007-agent-assistant simulate --scenario current --no-monte-carlo
```

| Command | Exit 0 | Exit 1 | Exit 2 |
|---|---|---|---|
| `check` | nothing above MEDIUM | HIGH, or MEDIUM with `--strict` | CRITICAL |
| `simulate` | no blocking goal | a goal at `risk.block_on` | — |
| `converge-apply` | converged | not converged | — |

## Phase-aware verification findings

Check A9, a requirement without verification, follows implementation progress. It is LOW while no task for the requirement is done, MEDIUM while some are, and MEDIUM or HIGH once all are done but nothing verifies it. HIGH applies when the control guards a high or critical goal. A pull request that only changes the spec therefore does not fail for missing evidence.

## Code scanning

With `upload-sarif`, findings appear in the repository's **Security → Code scanning** tab and as annotations on the pull request, with rule IDs `A1` to `A16`, the file, and a recommendation.
