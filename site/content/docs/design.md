+++
title = "Design and roadmap"
description = "Why AttackTree is built the way it is: positioning next to threat lists and attacktree.online, design decisions, what is out of scope, and the roadmap."
weight = 40
[extra]
group = "Project"
nav_title = "Design and roadmap"
+++

## Positioning

Per-element threat enumeration, such as STRIDE and its descendants, lists what can go wrong. Attack trees answer a different question: given a concrete adversary, how would they reach the outcome they want, which step is the bottleneck, and which control buys the most for the least. Christian Schneider's [Attack Tree](https://attacktree.online/) platform made that a practical workshop method. AttackTree brings the method into Spec-Driven Development as an artifact that lives next to the spec, changes with it, and can be simulated, checked, and verified without an LLM.

| Question | Spec Kit | AttackTree |
|---|---|---|
| What are we working on? | `spec.md`, `plan.md` | actors, assets, goals |
| What can go wrong? | — | goals reached through AND/OR paths |
| What are we going to do about it? | `tasks.md` | controls ranked by simulation, `CR-###`, tasks |
| Did we do a good job? | `/speckit-converge` | evidence per requirement, residual risk from verified controls |

## Design decisions

| Decision | Reason |
|---|---|
| **Tree as a flat list of nodes with parents** | Ids stay stable across regenerations, merges work per entity, and diffs stay readable. The rendered outline and diagrams restore the shape. |
| **Schneier's rules, literally** | OR takes the best child, AND multiplies likelihoods and adds costs, controls scale the subtree. One documented risk matrix, no hidden arithmetic. |
| **Attacker profiles are data** | Capabilities and `requires` tags live in profiles, so a team can redefine "insider" without touching code. |
| **Deterministic core, semantic edge** | The engine does feasibility, propagation, paths, choke points, what-if, Monte Carlo, checks, and evidence collection. The agent reads specs, proposes, and judges evidence it opened. |
| **Scenarios, not statuses** | Risk is always computed for a stated set of control statuses. Convergence believes only `verified`. |
| **Measure probabilistic controls** | Guardrails get a measured bypass rate from a micro attack simulation, and the tree uses the measurement from then on. |
| **Human-owned fields are sticky** | Statuses, evidence levels, bypass rates, decisions, and notes survive any regeneration by the agent. |
| **Unknowns stay unknown** | An open question is not a zero; goals that depend on one report `unknown` and are never marked mitigated. |
| **Native ids** | `CR-###` sits next to `FR-###` and `SC-###` in `spec.md`, so core commands can treat control requirements like any requirement. |
| **Open formats only** | JSON Schema for the tree, OTM for import, SARIF for findings. AttackTree writes no format it cannot validate. |

Deliberate limits:

- **Attack trees, not attack–defence trees.** Controls are attributes of nodes, not nodes, which keeps the YAML flat and the simulation simple. A control on an inner node still defends its whole subtree.
- **No coalitions.** An AND path counts only if one actor can perform every step.
- **Coarse costs.** Attack cost maps to four resource tiers, and control cost to three levels. The tree prioritises; it does not budget.
- **Bounded enumeration.** Paths are capped per node, and each actor's best paths are kept. Truncation is reported, never silent.

## attacktree.online files

attacktree.online saves trees as `.json` or `.json.gz`, but it publishes no schema for them. A tree exported by the app is a `Version: 1` document with a `NodeMap` (nodes with `AndOperator`, `Parent`, `Children`, `Impact`, `ThreatActor`, `Complexity`, and `Controls` as effect percentages), a `ControlMap`, an `AssetMap`, `Actors`, and report settings. Impact, complexity, actor, and status are numeric codes whose meaning is only visible in the app. The mapping from AttackTree would be direct, but without a specification the codes are guesses that a release of the tool could invalidate silently. An exporter therefore waits until the format is published.

## Roadmap

- **Next:** sequential AND gates with ordering; detectability on leaves feeding detective controls; coalition paths; a semantic `diff` of two trees for review; a cross-feature risk report; exporters for ADTool and, once specified, attacktree.online; adversarial test fixtures with injected instructions; pinned versions for the `uv` fallback; rejecting `extends` paths outside the repository.
- **Later:** a fault-tree view; OSCAL control mapping; the convergence report as an in-toto attestation.
- **Out of scope:** penetration testing, scanners, hosting, and dashboards. Scanner and simulation results are consumed as evidence; AttackTree does not produce them.

## Related work

| Tool | Relation |
|---|---|
| [Attack Tree](https://attacktree.online/) by Christian Schneider | The reference practice: visual editor, actor profiles, what-if, choke points, Monte Carlo, reports, API. AttackTree follows its vocabulary and brings the analyses that matter in a repository into the Spec Kit workflow. |
| ADTool | Attack–defence trees with quantitative attribute domains; prior art for the propagation rules. |
| IriusRisk, Threat Dragon, pytm, Threagile | Threat models as diagrams or code. Anything that produces OTM can seed an attack tree. |
