+++
title = "Simulation"
description = "What the AttackTree simulation reports: most likely and cheapest paths, choke points, Achilles heels, single points of failure, what-if and defence in depth, the roadmap, and Monte Carlo."
weight = 12
[extra]
group = "Concepts"
+++

`/speckit-attacktree-simulate`, or `attacktree.sh simulate` in CI, evaluates the tree for a [scenario](@/docs/risk-model.md#controls-scaling-the-subtree) and writes one report. This page explains each section and what to do with it.

## Goals

One row per goal: impact, the likelihood and level of its best path, residual risk, the strongest actor, the number of paths, how many of them have no control, the choke points, and the most likely path.

**Act on:** goals at a risk level listed in `risk.block_on` (default: critical). The simulation exits with code 1 while any of them lacks an unexpired [decision](@/docs/attack-tree-format.md#decisions).

## Paths

Up to ten paths per goal, ordered by likelihood. Each shows its leaves, likelihood, cost, the actors who can run it, and the controls on it. `(accepted)` marks paths through a node covered by a risk decision.

**Read for:** the story. "An employee asks directly and the assistant quotes the document" is the sentence to put in front of the team.

## Choke points and uncovered choke points

A **choke point** is a node that every feasible path to a goal crosses. A control there covers every path at once. An **uncovered** choke point has no active control, and it is usually the single best place to invest.

## Achilles heels

Leaves ranked by the share of paths that use them, weighted by those paths' likelihood. A leaf used by most paths is worth a specific control even when it is not a choke point.

## Single points of failure

Active controls whose removal alone raises a goal's risk level. They are what your defence rests on. Christian Schneider's rule of thumb is that every high-priority node should have at least two independent controls. A probabilistic control that is a single point of failure on a critical goal deserves both a second control and a measurement.

## What-if

Every control that is not active in the scenario, applied one at a time:

| Column | Meaning |
|---|---|
| Risk reduction | Impact-weighted drop of the goals' best-path likelihoods. |
| Depth reduction | Impact-weighted drop of the sum of all path likelihoods, including alternative paths. |
| Efficiency | Risk reduction divided by the control's cost weight: low 1, medium 3, high 9. |
| Class | Quick win, strategic, fill-in, deprioritize, defence in depth, or no effect. |

Quick wins reduce at least the median risk at low or medium cost, strategic controls do so at high cost; fill-ins and deprioritized controls are their below-median counterparts. **Defence in depth** marks a control that lowers no goal today, because the attacker's best path goes elsewhere, but cuts alternative paths. It is worth nothing until the best path is closed, and exactly what closes the next one.

## Roadmap

A greedy order: repeatedly add the control with the most risk reduction per cost, and show every goal's residual risk after each step. Use it to agree which controls to set to `planned`, then re-run with `--scenario planned` to confirm the result.

## Monte Carlo

Ratings are estimates, so the simulation also samples them. Each leaf's likelihood is drawn from a triangular distribution around its rating, bounded by its `likelihood_range` or by ± `simulation.likelihood_spread` points. Each probabilistic control's surviving fraction is jittered by ± 0.15. The report gives the mean, the median (P50), the 90th percentile (P90), the probability of at least a high likelihood, and the **drivers**: the leaves whose sampled values correlate most with the goal's outcome.

**Act on:** goals whose P90 lies a level above their mean, and their drivers. Those ratings decide the outcome and deserve a second opinion or a measurement. Runs are reproducible for a given `simulation.seed`.

## What-if from the command line

```bash
attacktree.sh simulate --scenario none                      # the undefended baseline
attacktree.sh simulate --scenario planned                   # after the agreed roadmap
attacktree.sh simulate --apply control.a,control.b          # try controls without changing the tree
attacktree.sh simulate --remove control.c                   # what if this control failed?
```

None of these changes `attack-tree.yaml`. The [CLI reference](@/docs/cli.md#simulate) lists every flag.
