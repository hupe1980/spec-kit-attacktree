+++
title = "Open Threat Model interop"
description = "Seed AttackTree goals and assets from an Open Threat Model (OTM) file exported by other threat modelling tools, link goals back to threats, and track drift."
weight = 22
[extra]
group = "Guides"
nav_title = "OTM interop"
+++

The [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel) (OTM) is a tool-neutral format for threat models. IriusRisk created it, and its open-source [StartLeft](https://github.com/iriusrisk/startleft) converter produces OTM from Terraform, CloudFormation, and diagram formats. If your team already keeps a threat model in OTM, AttackTree can start from it instead of from a blank page. OTM interop is off by default.

## Enable it

Point `model.otm` at the file, relative to the feature directory or the repository:

```yaml
# .specify/extensions/attacktree/attacktree-config.yml
model:
  otm: threat-model.otm.yaml
```

## What it does

**Seeding.** The model command calls `attacktree.sh seed`, which reads the OTM file and proposes:

- one asset per OTM asset, with ids normalised to `asset.<slug>`;
- one candidate goal per rated, non-retired threat, with impact derived from the threat's impact score and `links.threats` pointing back to it.

The agent then merges candidates that describe the same attacker outcome, drops threats that are weaknesses rather than goals (recording them under `attacktree.exclusions` with a reason), defines the actors (OTM has no actor entity), and builds the paths.

**Links.** Goals and nodes may carry `links: { threats: […], mitigations: […] }` with ids exactly as the OTM file spells them. Check A13 reports links to entities that no longer exist.

**Drift.** The OTM file is hashed with `spec.md` and `plan.md`. When it changes, check A11 asks you to refresh the tree.

## Seed by hand

```bash
attacktree.sh seed --otm path/to/model.otm.json --output seed.yaml
```

`seed` never writes `attack-tree.yaml`; it prints or saves a starting point for the model command.
