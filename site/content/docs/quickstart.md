+++
title = "Quickstart"
description = "Run AttackTree on the shipped example in five minutes, then build your first attack tree for your own feature with a coding agent."
weight = 3
[extra]
group = "Get started"
+++

This quickstart has two parts. First, run the engine on the example that ships with the repository to see what an attack tree produces, with no agent needed. Then build one for your own feature.

## Part 1: explore the example

The example is an internal assistant that answers employee questions from a knowledge base and can open support tickets. Its `attack-tree.yaml` is a realistic first pass: four actors, six goals, 23 attack vectors, and 14 proposed controls.

```bash
git clone https://github.com/hupe1980/spec-kit-attacktree.git
cd spec-kit-attacktree
alias attacktree='python3 scripts/python/attacktree.py --repo examples/agent-assistant --feature-dir specs/001-agent-assistant'
```

If `python3 -c "import yaml"` fails, use `uv run --with pyyaml python` instead of `python3` in the alias.

### Simulate the tree as it stands

```bash
attacktree simulate --no-monte-carlo
```

No control is built yet, so this is the undefended picture. Four of six goals are at critical risk. Look at `goal.read-restricted-documents`: its most likely path is an employee who asks a question that only a restricted document answers, with the assistant quoting that document. The path has a likelihood of 70 % × 85 % = 59.5 %. The report also lists `node.rrd-reach` as an **uncovered choke point**: every path to that goal crosses it, and no control sits there yet.

### Ask a what-if question

The what-if table ranks `control.visibility-filtered-retrieval` first. It is attached to that choke point. Check what building it would change:

```bash
attacktree simulate --no-monte-carlo --apply control.visibility-filtered-retrieval
```

The critical goal drops to likelihood 0: one control cut every path. Compare `--scenario all`, which counts every proposed control. Two goals stay high even then, which means the tree needs more controls on those goals. That is exactly the conversation a simulation should start.

### Run the checks

```bash
attacktree check
```

The report has two findings. One node needs clarification, because the spec does not say whether administrators can export the knowledge base. Fourteen requirements have no verification yet, which is expected before implementation. Try `--format sarif` to see the output code scanning consumes.

### Read the rendered tree

Open `examples/agent-assistant/specs/001-agent-assistant/attack-tree.md`. Each goal has an outline, a Mermaid diagram with its controls, and its paths. GitHub renders the diagrams inline.

## Part 2: your own feature

In a Spec Kit project with the extension [installed](@/docs/installation.md):

1. **Specify** the feature as usual with `/speckit-specify`.
2. **Model** it: run `/speckit-attacktree-model`. The agent reads `spec.md`, defines actors, goals, paths, and controls, and validates the tree through the engine. It then writes `attack-tree.yaml` and `attack-tree.md` and inserts the `CR-###` block into `spec.md`. Answer its open questions with `/speckit-clarify`.
3. **Plan** with `/speckit-plan`, then run `/speckit-attacktree-model --from-plan`. The second pass attaches attacks and controls to the files and components in the plan.
4. **Simulate** with `/speckit-attacktree-simulate`. Decide which controls to build and set them to `status: planned` in `attack-tree.yaml`.
5. **Generate tasks** with `/speckit-tasks`, then run `/speckit-attacktree-check` to confirm every control requirement has a task.
6. **Implement** with `/speckit-implement`, then run `/speckit-attacktree-converge`. The agent judges each requirement from the evidence and records the verdicts. Gaps become new tasks in `tasks.md`.

Repeat steps 5 and 6 until converge reports `CONVERGED`.

> [!TIP]
> Want every step prompted automatically? Enable the hooks, or install the [`attacktree-sdd` workflow](@/docs/installation.md#optional-companions), which runs the whole cycle with review gates.

## Where to go next

- [Attack trees](@/docs/attack-trees.md) explains the method behind the numbers.
- [Simulation](@/docs/simulation.md) explains every section of the simulation report.
- [CI](@/docs/ci.md) shows how to gate pull requests on residual risk.
