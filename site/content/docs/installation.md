+++
title = "Installation"
description = "Install the AttackTree extension into a Spec Kit project from a release archive, a catalog, or a local checkout, plus the optional preset and workflow."
weight = 2
[extra]
group = "Get started"
+++

## Requirements

- [Spec Kit](https://github.com/github/spec-kit) 1.0 or later, with a project initialised by `specify init`.
- Python 3.11 or later with [PyYAML](https://pypi.org/project/PyYAML/). If PyYAML is missing, the wrapper scripts fall back to [uv](https://docs.astral.sh/uv/), which fetches PyYAML and jsonschema on the fly.
- Any coding agent that Spec Kit supports: Claude Code, GitHub Copilot, Cursor, Gemini CLI, opencode, Codex, and others.

## Install the extension

Pick one of three sources. All three install the same files into `.specify/extensions/attacktree/` and register the four commands with your agent.

**From a release archive.** The CLI asks you to confirm the URL because it is not in a catalog you trust yet.

```bash
specify extension add attacktree --from https://github.com/hupe1980/spec-kit-attacktree/archive/refs/tags/v0.1.0.zip
```

**From this project's catalog.** Register the catalog once, then install and update by name.

```bash
specify extension catalog add https://raw.githubusercontent.com/hupe1980/spec-kit-attacktree/main/catalog.json \
  --name attacktree --install-allowed
specify extension add attacktree
```

**From a local checkout**, for development:

```bash
git clone https://github.com/hupe1980/spec-kit-attacktree.git
specify extension add --dev ./spec-kit-attacktree
```

## Verify

```bash
specify extension list
```

The list shows `AttackTree — Attack Tree Modeling & Control Simulation` with 4 commands and 7 hooks. If your agent was already running, restart it so it picks up the new commands. Depending on the agent, they appear as `/speckit-attacktree-model` (Claude Code, Copilot, Cursor, and most others) or `/speckit.attacktree.model` (opencode, Gemini, Qwen).

The install also scaffolds `.specify/extensions/attacktree/attacktree-config.yml`. The defaults work; see [Configuration](@/docs/configuration.md) before you change them.

## Optional companions

The repository ships two optional add-ons. They are not part of the extension archive, so install them from a checkout.

| Add-on | What it does | Install |
|---|---|---|
| Preset `attacktree-sdd` | Appends a short section to the core `tasks`, `analyze`, `converge`, and `checklist` commands so they tag, inventory, and check `CR-###` requirements natively | `specify preset add --dev ./spec-kit-attacktree/preset/attacktree-sdd` |
| Workflow `attacktree-sdd` | Runs the whole cycle from specify to converge with review gates after the tree, the simulation, and the gap check | `specify workflow add --dev ./spec-kit-attacktree/workflow/attacktree-sdd` |

## Hooks

All seven hooks are optional: after `/speckit-specify`, `/speckit-plan`, `/speckit-tasks`, and the other core commands, the agent asks whether to run the matching AttackTree command. Nothing runs without your confirmation. To make a hook automatic, set `optional: false` for it in `.specify/extensions.yml`. The [workflow guide](@/docs/workflow.md#hooks) lists every hook.

## Update and remove

```bash
specify extension update attacktree
specify extension remove attacktree        # add --keep-config to keep your configuration
```

Removing the extension leaves your feature artifacts (`attack-tree.yaml`, the `CR-###` block in `spec.md`) untouched.
