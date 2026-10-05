+++
title = "What is AttackTree?"
description = "AttackTree is an open-source Spec Kit extension that builds attack trees from your spec, simulates which security controls cut the attack paths, and verifies each control with evidence."
weight = 1
[extra]
group = "Get started"
nav_title = "Introduction"
+++

AttackTree is an extension for [GitHub Spec Kit](https://github.com/github/spec-kit). It adds threat modelling with **attack trees** to Spec-Driven Development: from the specification of a feature, your coding agent builds a tree of what an attacker wants and every way to get there. A deterministic engine then simulates the tree and tells you which security controls matter. Those controls become requirements in the spec and, after implementation, are verified with evidence.

## The problem it solves

Security reviews of a spec usually produce a list: "prompt injection", "missing authorization", "credential theft". A list does not say which item an attacker would actually use, which one control would stop the most attacks, or whether the controls that were built work. So teams spend effort evenly, or on whatever sounds most dangerous.

An attack tree answers those questions. It describes attacks as paths from an attacker's starting point to a goal, so it can rank them by likelihood and cost for a given attacker. It also shows where paths converge on a single step. Bruce Schneier introduced the method in 1999; Christian Schneider's [Attack Tree](https://attacktree.online/) platform turned it into a practical workshop method with actors, controls, and simulation. AttackTree brings that practice into your repository and your agent's workflow.

## What you get

- **An attack tree per feature**, as `attack-tree.yaml` next to `spec.md`: threat actors with capabilities, attacker goals with business impact, AND/OR paths, rated attack vectors, and controls. It is versioned, diffable, and validated by a schema.
- **A simulation** of that tree: the most likely and cheapest path per attacker, residual risk per goal, choke points, single points of failure, a what-if ranking of every control not yet built, a roadmap ordered by risk reduction per cost, and a Monte Carlo run over the uncertainty in the ratings.
- **Control requirements** (`CR-001`, `CR-002`, …) with Given/When/Then acceptance criteria, published into `spec.md` so that planning and task generation treat them like functional requirements.
- **Sixteen deterministic checks** that keep the chain from goal to verified control complete, with Markdown, JSON, and SARIF output for code scanning.
- **Evidence-based convergence**: after implementation, each requirement is judged from tests, reviews, or micro attack simulations. Verified controls, measured bypass rates, and gaps flow back into the tree and into `tasks.md`.

## How it fits Spec Kit

AttackTree adds four commands. Each runs at a natural point of the Spec Kit lifecycle, and optional hooks can prompt for them automatically.

| After | Run | Result |
|---|---|---|
| `/speckit-specify` | `/speckit-attacktree-model` | the attack tree and the `CR-###` block in `spec.md` |
| `/speckit-plan` | `/speckit-attacktree-model --from-plan`, then `/speckit-attacktree-simulate` | concrete attack vectors and a control roadmap |
| `/speckit-tasks` | `/speckit-attacktree-check` | a gap report from goals to tasks |
| `/speckit-implement` | `/speckit-attacktree-converge` | verified controls, residual risk, remediation tasks |

The agent does what needs judgement: reading the spec, proposing attacks and controls, and judging evidence. The engine, a single Python script, does all the arithmetic and bookkeeping. It needs no LLM, so the same checks and simulation run in CI.

## Who it is for

- **Teams using Spec Kit** who want security designed in at the spec stage, not bolted on at review.
- **Security architects** who already run attack tree or threat modelling workshops and want the result to live in the repository, stay current as the spec changes, and connect to tasks and tests.
- **Builders of LLM and agentic features**, where prompt injection, tool misuse, and probabilistic guardrails make path-based reasoning essential. See [Agentic and LLM systems](@/docs/agentic-systems.md).

## Next steps

- [Install the extension](@/docs/installation.md).
- [Run the quickstart](@/docs/quickstart.md) on the shipped example in five minutes.
- Learn [how attack trees work](@/docs/attack-trees.md) if the method is new to you.
