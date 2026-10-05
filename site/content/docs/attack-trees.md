+++
title = "Attack trees explained"
description = "What an attack tree is, where the method comes from, how AND and OR nodes and leaf values work, and why attack trees rank threats better than a list."
weight = 10
[extra]
group = "Concepts"
nav_title = "Attack trees"
seo_title = "Attack trees explained: AND/OR nodes and attacker profiles"
+++

An **attack tree** describes how an attacker can reach a goal. The goal is the root, the ways to reach it are its children, and the children are refined until each leaf is a concrete attack. Bruce Schneier popularised the method in his 1999 article [*Attack Trees*](https://www.schneier.com/academic/archives/1999/12/attack_trees.html). It borrows its logic from fault tree analysis, which engineers have used since the 1960s to reason about how systems fail.

## Nodes: goals, AND, OR, leaves

Schneier's first example is a safe. The attacker's goal is to open it:

```text
Open safe                                   OR
├── Pick lock
├── Learn combination                       OR
│   ├── Find written combination
│   └── Get combination from target         OR
│       ├── Threaten
│       ├── Blackmail
│       ├── Bribe
│       └── Eavesdrop                       AND
│           ├── Listen to conversation
│           └── Get target to state combination
├── Cut open safe
└── Install improperly
```

Two kinds of node connect children to their parent:

- **OR nodes** are alternatives. The parent succeeds if *any* child succeeds: the safe opens if the lock is picked, *or* the combination is learnt, *or* the safe is cut open.
- **AND nodes** are steps. The parent succeeds only if *every* child succeeds: eavesdropping needs the conversation *and* the target stating the combination.

**Leaves** are attack vectors, the concrete things an attacker does. Everything above a leaf is a subgoal.

## Values propagate upwards

Once leaves carry values, the tree computes the values of every subgoal and of the goal:

| Value on the leaves | OR node takes | AND node takes |
|---|---|---|
| possible / impossible | possible if any child is | possible only if all children are |
| cost | the cheapest child | the sum of the children |
| probability of success | the most likely child | the product of the children |

The result answers questions a list of threats cannot: what is the cheapest attack? What is the most likely one? Which attacks need no special equipment? In Schneier's safe, cutting the safe open costs little but needs a torch. Bribing someone who knows the combination costs more but needs no equipment. Which one matters depends on who attacks.

## Attackers decide which leaves count

"Different attackers have different levels of skill, access, risk aversion, money, and so on," Schneier wrote. A bored student will not bribe anyone; organised crime will. So the same tree has different answers for different attackers.

AttackTree makes this explicit. Every [threat actor](@/docs/attack-tree-format.md#actors) has four capabilities: `skill`, `resources`, `access`, and `risk_appetite`. Every leaf states what it takes: a `complexity` that sets the skill needed, a `cost` that sets the resources needed, and `requires` tags such as `insider-access` or `illegal`. A leaf only counts for actors who can do it, and an AND path only counts if one actor can do every step. The simulation then reports the answer per actor.

## Controls prune the tree

A control, or countermeasure, makes a node harder. Schneier's what-if is simple: raise the cost of bribery, recompute, and see what the cheapest attack becomes. AttackTree attaches controls to nodes with an effect, from 25 % to eliminating the step outright. Where you attach them matters:

- **Near the root**, a control is generic and protects everything below it.
- **Near a leaf**, a control is specific and protects one attack.
- **On a node every path crosses**, a *choke point*, one control protects every path to the goal.

The [simulation](@/docs/simulation.md) finds choke points, measures each unbuilt control's effect, and shows which controls your defence depends on alone.

## Why trees beat lists

A threat list says what can go wrong. A tree says how an attacker gets from where they start to what they want, and that difference changes what you build:

- **It ranks by the path, not the finding.** An attacker takes the easiest route. A severe but unreachable vulnerability ranks below a mundane one on the main path.
- **It shows leverage.** Paths converge. One control at a convergence point can do more than five on the leaves.
- **It exposes false comfort.** Schneier found that PGP's key length hardly mattered, because keyloggers and trojans were far cheaper routes to the same plaintext. "The areas people think of as vulnerable usually aren't."
- **It is reusable.** A subtree for "obtain a valid session" applies to every feature behind the same login.

Trees and lists complement each other. A STRIDE-style list is a good source of leaves; the tree puts them in order. AttackTree can [seed goals from an Open Threat Model file](@/docs/otm.md) produced by such tools.

## From method to practice

Schneier's paper leaves open how to rate leaves consistently and how to carry the analysis into delivery. Christian Schneider's Attack Tree platform ([attacktree.online](https://attacktree.online/)) closed that gap for workshops. Leaves get an actor and a complexity, and likelihood is derived from the two. Goals get impact per class, such as business, data, and compliance. Controls get an effect, a cost, a status, and validation steps. What-if and Monte Carlo simulations turn the tree into a prioritised roadmap. AttackTree follows the same vocabulary and adds the parts a repository needs: requirements in the spec, tasks, checks, and verification.

## Further reading

- Bruce Schneier, [*Attack Trees*](https://www.schneier.com/academic/archives/1999/12/attack_trees.html), Dr. Dobb's Journal, 1999.
- Christian Schneider, [*Threat modeling agentic AI: a scenario-driven approach*](https://christian-schneider.net/blog/threat-modeling-agentic-ai/), 2026.
- Christian Schneider, [*Verifying agentic AI controls with attack tree micro simulations*](https://christian-schneider.net/blog/verifying-agentic-ai-controls-attack-tree-micro-simulations/), 2026.
- Kordy, Kordy, Mauw, and Schweitzer, *ADTool: Security Analysis with Attack–Defense Trees*, 2013. It covers attack–defence trees, which model defences as nodes.

Next: [how AttackTree turns ratings into risk](@/docs/risk-model.md).
