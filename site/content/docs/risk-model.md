+++
title = "Risk model"
description = "How AttackTree computes likelihood, feasibility, control effects, actor occurrence, and residual risk, with a worked example and the full risk matrix."
weight = 11
[extra]
group = "Concepts"
+++

Every number in the simulation comes from a few documented rules. This page explains them with one path from the shipped example. The scales live in the `default` [profile](@/docs/profiles.md), so a team can change them without touching the engine.

## Leaves: likelihood per attempt

Each leaf states the probability that one attempt succeeds before any control, as an integer from 0 to 100. If `likelihood` is omitted, the leaf's `complexity` supplies a default:

| Complexity | Skill needed | Default likelihood |
|---|---|---|
| trivial | novice | 90 |
| low | novice | 75 |
| medium | intermediate | 50 |
| high | advanced | 30 |
| extreme | expert | 10 |

## Feasibility: who can run the leaf

A leaf counts for an actor only when all three conditions hold:

1. The actor's `skill` is at least the skill its complexity needs.
2. The actor's `resources` cover the tier of its `cost`: up to 1,000 is minimal, up to 25,000 moderate, up to 250,000 substantial, and anything above extensive.
3. The actor satisfies each `requires` tag. For example, `authenticated` needs `access: user` or more, and `illegal` needs `risk_appetite: medium` or more.

A capability an actor does not state never limits it. Check [A15](@/docs/checks.md) reports incompletely rated actors.

## Gates: OR and AND

- An **OR** node takes the best child path.
- An **AND** node multiplies the likelihoods of its children, adds their costs, and is feasible only if a single actor can perform every step. Coalitions of actors are out of scope.

Every combination of choices through the OR nodes is a **path**, a set of leaves that together achieve the goal. The engine enumerates paths per goal, up to `risk.max_paths` per node. It keeps each actor's most likely paths when it truncates and reports truncation as check A16.

## Controls: scaling the subtree

A control attached to a node multiplies the likelihood of everything below that node by what survives it:

| Effect | Reduction | Survives |
|---|---|---|
| low | 25 % | 0.75 |
| medium | 50 % | 0.50 |
| high | 80 % | 0.20 |
| eliminates | 100 % | 0 |

A control can state a different level per attached node with `effects`. Once a micro attack simulation has measured it, `bypass_rate` replaces the level: a 12 % bypass rate means 0.12 survives.

Which controls count depends on the **scenario**:

| Scenario | Active controls | Used for |
|---|---|---|
| `none` | no control | the undefended baseline |
| `current` | implemented and verified | today's risk; the default |
| `planned` | planned, implemented, and verified | the risk after the agreed roadmap |
| `verified` | verified only | convergence: evidence, not claims |
| `all` | every control not rejected | structure: is any path uncovered? |

## Actors: occurrence

Some actors can run an attack but rarely target the system. An actor's optional `occurrence`, from 1 to 100, scales every path that actor can run. A path's likelihood is its raw likelihood times the occurrence of the most active actor able to run it. Schneier lists "likelihood that an attacker will try" as a value of its own. Leave `occurrence` at 100 unless you have a reason.

## Goals: impact and residual risk

A goal rates its impact per class: business, customer, data, compliance, and safety. The highest rating is the goal's impact level. The goal's likelihood is the likelihood of its best feasible path, which maps to a level:

| Level | Likelihood |
|---|---|
| low | below 15 |
| medium | 15 to below 40 |
| high | 40 to below 70 |
| very-high | 70 and above |

Likelihood level and impact level give the **residual risk**:

| Likelihood ↓ / impact → | low | medium | high | critical |
|---|---|---|---|---|
| **very-high** | medium | high | critical | critical |
| **high** | low | medium | high | critical |
| **medium** | low | medium | medium | high |
| **low** | low | low | medium | high |

A goal no path can reach, with likelihood exactly 0, is **low** risk whatever its impact. A goal whose every path runs through an open question is **unknown**; see [Unknowns](#unknowns).

## Worked example

Goal `goal.read-restricted-documents` in the example is an AND of two subgoals, getting restricted content into the model's context and getting it out. Its impact is data: critical and compliance: high, so its level is **critical**.

1. The best way in is `node.rrd-ask-directly`: a curious employee asks a question only a restricted document answers. Complexity trivial, likelihood 70.
2. The best way out is `node.rrd-answer-quotes`: the assistant quotes the document. Likelihood 85.
3. The employee can do both, so the AND is feasible: 70 % × 85 % = **59.5**, which is **high**.
4. High likelihood × critical impact = **critical** residual risk.

Now add `control.visibility-filtered-retrieval` (effect `eliminates`) on the choke point `node.rrd-reach`. Every way in is multiplied by 0, the goal's likelihood becomes 0, and its risk becomes low. With a `medium` effect instead, the best path would be 70 × 0.5 × 85 % = 29.75, which is medium likelihood and **high** residual risk.

## Unknowns

A node with `status: needs-clarification` is a question the spec does not answer, such as "can administrators export the knowledge base?" It is not a rated step. The engine leaves it out of the evaluation, lists it as an assumption in the simulation, and reports it as check A14. A goal that can only be reached through open questions reports risk **unknown**: never low, never mitigated.

## What the numbers are not

The ratings are informed estimates, and the arithmetic makes them consistent and comparable, not precise. Read likelihoods as levels and rankings. The [Monte Carlo run](@/docs/simulation.md#monte-carlo) shows how sensitive each goal is to the ratings, so you know which ones deserve a second opinion or a measurement.
