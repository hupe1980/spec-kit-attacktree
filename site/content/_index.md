+++
title = "AttackTree for Spec Kit: attack trees for Spec-Driven Development"
description = "Open-source Spec Kit extension that turns specs into attack trees: model attacker goals and AND/OR paths, simulate which security controls cut them, and verify every control with evidence."
template = "index.html"

[extra]
eyebrow = "Spec Kit extension · open source"
headline = "Know how you will be attacked before you write the code."
lead = "AttackTree turns your spec into an attack tree: who attacks, what they want, and every path that gets them there. It simulates which security controls actually cut those paths, writes them into the spec as testable requirements, and verifies each one with evidence after implementation."

[[extra.faq]]
q = "What is an attack tree?"
a = "A diagram of how an attacker reaches a goal, introduced by Bruce Schneier in 1999. The goal is the root, the ways to reach it are the branches, and concrete attacks are the leaves. OR nodes are alternatives, AND nodes are steps that all have to succeed. Rate the leaves and the tree tells you which attack is the most likely, the cheapest, and which single defence blocks the most paths."

[[extra.faq]]
q = "How is this different from STRIDE or a threat list?"
a = "A threat list tells you what can go wrong per component. An attack tree tells you how an attacker gets from where they start to what they want, so it can rank threats by the path an attacker would really take and show where one control covers many paths. The two complement each other; AttackTree can seed its goals from any Open Threat Model file."

[[extra.faq]]
q = "Do I need an LLM to run the checks and the simulation?"
a = "No. The engine is a single Python script that needs only PyYAML. Checks, simulation, Monte Carlo, and SARIF output run without an agent, so they work in CI. The coding agent builds the tree from your spec and judges evidence; the engine does all the arithmetic."

[[extra.faq]]
q = "Which coding agents does it work with?"
a = "Every agent Spec Kit supports, including Claude Code, GitHub Copilot, Cursor, Gemini CLI, opencode, and Codex. Spec Kit renders the four commands for the agent you initialised the project with."

[[extra.faq]]
q = "Can I import the tree into attacktree.online?"
a = "Not yet. attacktree.online does not publish a schema for its file format, and AttackTree only writes formats it can validate. An exporter is on the roadmap for when the format is specified. The modelling vocabulary is the same: actors, goals with impact, AND/OR paths, controls with effect and cost."

[[extra.faq]]
q = "Is it free?"
a = "Yes. AttackTree is open source under the MIT license."
+++
