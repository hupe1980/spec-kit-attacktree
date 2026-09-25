# Methodology

AttackTree applies Bruce Schneier's attack trees to a Spec Kit feature and keeps the answers connected as the feature moves from specification to verified implementation. It borrows the working method of Christian Schneider's Attack Tree platform (attacktree.online): threat actors with capabilities, goals with business impact, AND/OR paths rated at the leaves, controls with effect and cost, what-if roadmaps, and probabilistic simulation, and it closes the loop with requirements, tasks, and evidence.

| Question | Where the answer lives | Who produces it |
|---|---|---|
| Who attacks us, and what can they do? | `actors[]` with `capabilities` | the model command, from spec roles and assumptions |
| What do they want, and what does it cost us? | `goals[]` with per-class `impact` | the model command |
| How do they get there? | `nodes[]`: AND/OR subgoals, rated attack vectors at the leaves | the model command (LLM), checked by the engine |
| What stops them, and how much? | `controls[]` with `effect`, `cost`, `status`, `validation` | the model command; simulation ranks them |
| What do we build and test? | `requirements[]` (`CR-###`) → tasks in `tasks.md` | the model command, then `/speckit-tasks` |
| Did it work? | `verification[]`, control status roll-up, residual risk with verified controls only | the converge command |

## Attack trees, as Schneier defined them

An attack tree has the attacker's goal as its root and ways of achieving that goal as its children. Children of an **OR** node are alternatives: any one of them achieves the parent. Children of an **AND** node are steps: all of them are needed. Leaves are concrete attacks. Values assigned to leaves propagate upward: for Boolean values, an OR node is possible if any child is possible and an AND node only if all are; for continuous values, an OR node takes the best child (the cheapest cost, the highest probability) and an AND node combines them (costs add, probabilities multiply).

AttackTree implements exactly that, with three additions from practice:

1. **Attacker profiles** decide which leaves count. Schneier: "The characteristics of your attacker determine which parts of the attack tree you have to worry about." A leaf is feasible for an actor whose `skill` covers the leaf's `complexity`, whose `resources` cover its `cost` tier, and who satisfies its `requires` tags (`authenticated`, `insider-access`, `privileged-access`, `special-equipment`, `long-duration`, `illegal`, `physical-presence`, `violence`). An AND path additionally needs one actor able to perform every step; collusion is out of scope. An actor's optional `occurrence` (1–100) then scales every path that actor can run, so the tree ranks attacks by who would actually attempt them, not only by who could.
2. **Controls scale the tree.** A control attached to a node multiplies the likelihood of everything below it by `1 − effect` (or by its measured `bypass_rate`); `effects` may set a different level per attached node. Attaching near the root is generic, attaching near a leaf is specific; the simulation tells you which placement cuts more paths.
3. **Scenarios** choose which control statuses count: `none` (the uncontrolled baseline), `current` (implemented and verified), `verified` (evidence only, used by converge), `planned` (what-if for the roadmap), `all` (structural, used by check A6).

## Values and levels

| Field | Scale | Meaning |
|---|---|---|
| `attack.complexity` | trivial, low, medium, high, extreme | skill required; also the default likelihood (90, 75, 50, 30, 10) when `likelihood` is not stated |
| `attack.likelihood` | 0–100 | probability that an attempt succeeds before controls |
| `attack.cost` | integer, currency-agnostic | maps to the `resources` tier an actor needs (≤ 1 000 minimal, ≤ 25 000 moderate, ≤ 250 000 substantial, above extensive) |
| `controls[].effect` | low 25 %, medium 50 %, high 80 %, eliminates 100 % | likelihood reduction below the attached node |
| `controls[].cost` | low 1, medium 3, high 9 | weight for cost-efficiency ranking |
| `goals[].impact` | per class: low, medium, high, critical | the highest class is the goal's impact level; weights 1, 2, 4, 8 rank what-if results |

Goal likelihood is the likelihood of the best feasible path. Its level (low < 15, medium < 40, high < 70, very-high ≥ 70) crossed with the impact level gives the residual risk:

|  | impact low | impact medium | impact high | impact critical |
|---|---|---|---|---|
| **very-high likelihood** | medium | high | critical | critical |
| **high** | low | medium | high | critical |
| **medium** | low | medium | medium | high |
| **low** | low | low | medium | high |

All scales live in `profiles/default.yaml` and can be replaced by a project profile.

## What the simulation answers

- **Most likely path and cheapest path**, overall and per actor.
- **Choke points**: nodes that every feasible path to a goal crosses. One control there covers every path; an uncovered choke point is the first thing to fix.
- **Achilles heels**: leaves ranked by the share of paths that use them, weighted by those paths' likelihood.
- **Single points of failure**: active controls whose removal raises a goal's risk level. Schneider's advice: "every high-priority node should have at least two independent controls."
- **What-if per inactive control**: risk reduction (impact-weighted drop of each goal's best path) and efficiency per cost, classified as quick win, strategic, fill-in, or deprioritize. Because an attacker takes the best path, a control that only cuts alternative paths lowers no goal today; the engine reports that as **depth reduction** (impact-weighted drop of the sum of all path likelihoods) and classes the control as **defence in depth**: worth nothing until the best path is closed, and exactly what closes the next one.
- **Roadmap**: greedy order of inactive controls by efficiency, with residual risk per goal after each step.
- **Monte Carlo**: every leaf likelihood is sampled from a triangular distribution around its rating (`likelihood_range` or ± `likelihood_spread`), and every `probabilistic` control's surviving fraction is jittered by ±0.15 around its value at each node it protects (a measured `bypass_rate` is jittered the same way; the sample size behind it is not modelled); the engine reports mean, P50, P90, the probability of at least a high likelihood, and the leaves whose samples correlate most with the outcome. Runs are reproducible for a given seed.

## Probabilistic controls and micro attack simulations

Guardrails, classifiers, and human approval do not block; they reduce. Mark them `probabilistic: true`, and expect converge to record a measured `bypass_rate` from a micro attack simulation: a targeted exercise that executes the control's `validation` steps at direct access, with enough probes to state a rate (thirty for a leaf-level control, hundreds for a control on a critical goal's choke point). Once recorded, the simulation uses the measured value instead of the effect level, so the tree reports what the control does rather than what it was assumed to do.

## Three ways a node can be unknown

| Marker | Meaning | Effect |
|---|---|---|
| `status: needs-clarification` on a node | the spec does not say whether the step exists | left out of the evaluation and listed as an assumption; a goal reachable only through such nodes is `unknown`; reported as check A14 for `/speckit-clarify` |
| `attacktree.exclusions[]` | a spec entity or threat deliberately left out | documents the omission; no check fires |
| `decisions[]` | a goal or node whose risk the team accepts or transfers | removes the goal, or every path through the node, from blocking checks until `expires`; an expired decision protects nothing |

## Evidence, not claims

The converge command collects facts per requirement: task state, test files that reference the CR id, touchpoint existence, the controls' validation steps. The agent judges only from evidence it opened and must supply a pointer for `verified`; the engine rejects `verified` without one. Control status rolls up from requirement verdicts, never the other way round; a control that claims `verified` without a passing verification entry is check A12.

**Definition of Converged**: no goal at or above `risk.block_on` residual risk with verified controls only, unless an unexpired decision covers it; every `CR-###` verified (or every control of it rejected); no expired decisions; no drift between the tree and `spec.md`, `plan.md`, or the configured OTM file.

## Untrusted content

Spec, plan, OTM file, code, tests, and fetched pages are inputs the agent reads, and any of them can contain instruction-like text. All four commands treat that text as data, quote it under an "Unverified" heading, and never follow it. Claims inside artifacts ("input is validated", `status: implemented`) change no likelihood; only controls with touchpoints, tasks, and evidence do.

## References

Schneier, "Attack Trees", Dr. Dobb's Journal, December 1999. Schneider, Attack Tree (attacktree.online) and "Threat modeling agentic AI: a scenario-driven approach" (2026), "Verifying agentic AI controls with attack tree micro simulations" (2026), "Micro attack simulations: scenario-driven validation" (2023). Kordy et al., ADTool (attack–defense trees). MITRE CAPEC. OWASP ASVS 4.0.3, OWASP Top 10 for LLM Applications 2026, OWASP Top 10 for Agentic Applications 2026, MAESTRO. MITRE ATLAS.
