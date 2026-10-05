+++
title = "Glossary"
description = "Definitions of the terms used by AttackTree: attack tree, goal, node, leaf, AND and OR gates, path, choke point, control, bypass rate, residual risk, scenario, and more."
weight = 36
[extra]
group = "Reference"
+++

**Achilles heel.** A leaf that many paths to a goal share, weighted by those paths' likelihood.

**Actor, threat actor.** Someone who attacks the system, described by skill, resources, access, risk appetite, and optionally occurrence.

**AND node.** A node whose children are steps that must all succeed. Likelihoods multiply and costs add.

**Attack tree.** A tree whose root is an attacker's goal, whose inner nodes are subgoals, and whose leaves are concrete attacks.

**Attack vector.** A leaf: a concrete action with a complexity, a likelihood, and optionally a cost and requirements.

**Bypass rate.** The measured share of attacks that get through a probabilistic control. Once recorded, it replaces the control's assumed effect.

**Choke point.** A node that every feasible path to a goal crosses. A control there covers every path.

**Complexity.** How hard a leaf is to execute, from trivial to extreme. It sets the skill an actor needs and the default likelihood.

**Control.** A security measure attached to one or more nodes. It reduces the likelihood of everything below them.

**Control requirement (`CR-###`).** A testable obligation derived from one or more controls, with Given/When/Then acceptance scenarios, published into `spec.md`.

**Converged.** No goal at blocking residual risk with verified controls only, every requirement verified, no expired decision, no drift. See [Verification](@/docs/evidence.md#definition-of-converged).

**Decision.** An owner's acceptance or transfer of a goal's risk, or of every path through a node, until an expiry date.

**Defence in depth.** In the what-if table, a control that lowers no goal's best path today but cuts alternative paths.

**Drift.** A change to `spec.md`, `plan.md`, or the OTM file since the tree was generated, detected by content hashes.

**Effect.** How much a control reduces the likelihood below its node: low (25 %), medium (50 %), high (80 %), or eliminates (100 %).

**Evidence level.** How a control's verification was established: assumed, design-reviewed, lab-validated, end-to-end-validated, or regression-tested.

**Feasible.** A leaf or path that at least one modelled actor can perform.

**Goal.** The root of a tree: an outcome an attacker wants, with an impact rating per class.

**Impact.** The damage if a goal is reached, rated per class (business, customer, data, compliance, safety) from low to critical.

**Micro attack simulation.** A small, targeted exercise that runs a control's validation steps against the real system to measure whether and how often it works.

**Monte Carlo.** Repeated evaluation of the tree with ratings sampled around their estimates, to show how sensitive each goal is to them.

**Needs clarification.** A node the spec does not settle. It is left out of the evaluation until the question is answered.

**Occurrence.** How likely an actor is to target the system at all, from 1 to 100. It scales every path the actor can run.

**OR node.** A node whose children are alternatives. The best one counts.

**Path.** A set of leaves that together achieve a goal: one choice at every OR node on the way.

**Probabilistic control.** A control that reduces rather than blocks, such as a classifier, guardrail, or human approval. Its effect needs measuring.

**Residual risk.** A goal's risk level after the controls of a scenario, from its likelihood level and impact level.

**Scenario.** The set of control statuses counted by a simulation: none, current, planned, verified, or all.

**Single point of failure.** An active control whose removal alone raises a goal's risk level.

**Touchpoint.** The file or component where a control is implemented.

**Zone.** In the agentic profile, the part of an AI agent a node targets: input, reasoning, tools, memory, or inter-agent.
