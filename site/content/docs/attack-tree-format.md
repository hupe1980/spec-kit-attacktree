+++
title = "attack-tree.yaml format"
description = "Complete reference for attack-tree.yaml: actors, assets, goals, AND/OR nodes, attack vectors, controls, CR requirements, verification, decisions, reference rules, baselines, and drift hashes."
weight = 32
[extra]
group = "Reference"
nav_title = "File format"
+++

`attack-tree.yaml` lives next to `spec.md` in each feature directory and is the single source of truth: `attack-tree.md` and the `CR-###` block in `spec.md` are rendered from it. The [JSON Schema](https://github.com/hupe1980/spec-kit-attacktree/blob/main/schemas/attack-tree.schema.json) describes its shape; the engine validates against the schema, the reference rules below, and the tree structure on every write. An annotated [skeleton](https://github.com/hupe1980/spec-kit-attacktree/blob/main/templates/attack-tree.yaml) and a [complete example](https://github.com/hupe1980/spec-kit-attacktree/blob/main/examples/agent-assistant/specs/001-agent-assistant/attack-tree.yaml) are in the repository.

## Top level

| Key | Purpose |
|---|---|
| `attacktree` | `version`, `generated`, `profiles`, `extends`, `sources`, `exclusions` |
| `project` | `id`, `name`, optional `description`, `owner` |
| `actors` | who attacks, with `capabilities` |
| `assets` | what the goals hit (optional, OTM-compatible ids) |
| `goals` | roots: attacker outcomes with `impact` |
| `nodes` | the tree, as a flat list with `parent`; leaves carry `attack` |
| `controls` | safeguards attached to nodes or goals |
| `requirements` | `CR-###` control requirements |
| `verification` | append-only evidence history |
| `decisions` | accepted or transferred risks |

## Identifiers

| Entity | Pattern | Example |
|---|---|---|
| actor | `actor.<slug>` | `actor.content-author` |
| asset | `asset.<slug>` | `asset.document` |
| goal | `goal.<slug>` | `goal.read-restricted-documents` |
| node | `node.<slug>` | `node.rrd-inject-document` |
| control | `control.<slug>` | `control.ticket-confirmation` |
| requirement | `CR-###` | `CR-003` |
| verification | `verification.<slug>` | `verification.cr-003.2026-09-25` |
| decision | `decision.<slug>` | `decision.deny-service` |

Ids are immutable. A goal or node the model command no longer produces keeps its entry with `status: retired` and a `retired_reason`; retiring a goal or an interior node by hand retires its whole subtree. Asset ids follow the OTM convention (`asset.<slug>`) so `seed` and `links` line up with an OTM file.

## Actors

```yaml
- id: actor.outsider
  name: Outside attacker group
  archetype: outside-attacker-group        # optional, from the profile's actor_archetypes
  capabilities:
    skill: advanced                          # novice | intermediate | advanced | expert
    resources: substantial                   # minimal | moderate | substantial | extensive
    access: external                         # external | user | insider | privileged
    risk_appetite: high                      # low | medium | high
  occurrence: 60                             # optional, 1–100: how likely this actor targets the system (default 100)
  motivation: Sell internal documents
  source: "spec.md#Assumptions"
```

Leave out `occurrence` unless you have a reason; it defaults to 100. A capability an actor does not state never limits it, so an unrated or partially rated actor can run more than it should (check A15 names the missing keys). `occurrence` scales every path that actor can run: a path's reported likelihood is its raw likelihood times the occurrence of the most active actor able to run it, so a trivial attack that only a rare actor attempts ranks below a harder one that a common actor attempts. Schneier lists "likelihood that an attacker will try a given attack" as its own node value; attacktree.online calls it the actor's occurrence.

## Goals

```yaml
- id: goal.read-restricted-documents
  name: Attacker reads documents outside their visibility
  gate: and                                  # or (default) | and
  impact: { data: critical, compliance: high }   # profile impact classes; the highest wins
  assets: [asset.document]
  links: { threats: [threat.visibility-bypass-via-retrieval] }   # into the configured OTM file (check A13)
  source: "spec.md#Key-Entities"
  status: open                               # open | mitigated | accepted | transferred | retired
```

`impact` may also be a single level (`impact: high`). `status` is human- and engine-owned: the model command never changes it on an existing goal; converge sets `mitigated` when the goal has feasible paths, every one carries a verified control, the residual risk is below `risk.block_on`, and the goal is not `unknown`; `accepted` and `transferred` follow an unexpired decision and fall back to `open` when it expires.

## Nodes

```yaml
- id: node.rrd-reach                         # intermediate node
  name: Get restricted content into the model context
  parent: goal.read-restricted-documents     # a goal or node id
  gate: or
  zone: input                                # optional (agentic profile): input | reasoning | tools | memory | inter-agent
- id: node.rrd-inject-document               # leaf: an attack vector
  name: Plant instructions in a published document
  parent: node.rrd-reach
  attack:
    actors: [actor.content-author, actor.outsider]
    complexity: low                          # trivial | low | medium | high | extreme
    cost: 100                                # optional
    likelihood: 65                           # 0–100; default from complexity
    likelihood_range: [50, 80]               # optional; Monte Carlo bounds
    requires: [authenticated]                # tags defined by the profile
    detectability: low                       # optional
    references: { capec: [CAPEC-137], owasp-llm-2026: [LLM01] }
  source: "spec.md#FR-003"
  status: open                               # open | needs-clarification | retired
```

A node with children is a subgoal and must not carry `attack`; a node without children is a leaf and should (check A4). A node with `status: needs-clarification` is a question: give it a name starting with `[NEEDS CLARIFICATION: …]`, place it under an OR node next to a rated sibling, and the engine evaluates the tree without it (an interior node in that state hides its whole subtree), lists it as an assumption in the simulation, and reports it as check A14. A goal whose every path runs through open questions is reported as `unknown`, not as low risk, and converge never marks it mitigated.

## Controls

```yaml
- id: control.untrusted-context-delimiting
  name: Retrieved documents are delimited as untrusted data with their source
  kind: preventive                           # preventive | detective | compensating
  nodes: [node.rrd-inject-document, node.ft-inject]   # goal or node ids; nearer the root = more generic
  effect: medium                             # low 25 % | medium 50 % | high 80 % | eliminates 100 %
  effects: { node.ft-inject: high }           # optional per-node override of effect (keys must be attached nodes)
  bypass_rate: 12                            # optional, 0–100; measured, overrides effect; set by converge
  probabilistic: true                        # guardrails, classifiers, human review: sampled in Monte Carlo
  cost: medium                               # low | medium | high
  status: proposed                           # proposed | planned | implemented | verified | rejected
  evidence: assumed                          # assumed | design-reviewed | lab-validated | end-to-end-validated | regression-tested
  touchpoints: [src/agent/prompt_builder.py]
  requirements: [CR-002]
  validation:
    - Publish a document containing an instruction; ask an unrelated question; expect no tool call
  references: { owasp-llm-2026: [LLM01] }
```

`status` is human-owned for `proposed`, `planned`, and `rejected`; converge sets `implemented` (from evidence of code at the touchpoint) and `verified`, and demotes a `verified` claim without evidence to `implemented`. The model command never changes the status of an existing control, whatever its incoming file says. `evidence` follows the verification method: tests, scans, and simulations give `lab-validated`, reviews `design-reviewed`, manual drills `end-to-end-validated`; `regression-tested` is set by hand once the check runs in CI.

## Requirements

```yaml
- id: CR-002
  statement: Retrieved documents MUST be delimited as untrusted data and MUST NOT alter tool-call policy.
  priority: P1
  controls: [control.untrusted-context-delimiting]
  acceptance:
    - given: a document containing an injected instruction
      when: the user asks an unrelated question
      then: no tool call is issued and the attempt is logged
  tasks: [T011, T012]                        # optional, for tasks that cannot carry a tag; tasks tagged [CR-002] in tasks.md are matched at run time
```

## Verification

Appended by converge and never rewritten.

```yaml
- id: verification.cr-002.2026-09-25
  requirement: CR-002
  method: simulation                         # test | review | scan | simulation | manual | evidence
  evidence: security/micro-sim-injection.md
  result: pass                               # pass | fail | partial | inconclusive
  verdict: verified                          # verified | implemented-unverified | partial | missing
  bypass_rate: 12                            # optional; copied to the control
  justification: 300 probes, 36 reached the planner, none triggered a tool call.
  verified_at: "2026-09-25T14:03:00Z"
  commit: a1b2c3d
```

## Decisions

```yaml
- id: decision.deny-service
  target: goal.deny-service                  # a goal or node id
  status: accepted                           # accepted | transferred
  owner: "@hupe"
  rationale: Internal users only until rate limiting ships
  expires: 2027-03-01
```

## Reference rules (check A2)

- `nodes[].parent` → a goal or node; parent chains must end at a goal without cycles
- a node with children must not have `attack`
- `nodes[].attack.actors` → `actors[]`; `attack.requires` tags → the profile's `scales.requires`
- `goals[].assets` → `assets[]`
- `controls[].nodes` → goals or nodes; `controls[].effects` keys → attached nodes; `controls[].requirements` → `requirements[]`
- `requirements[].controls` → `controls[]`
- `verification[].requirement` → `requirements[]`; `decisions[].target` → goals or nodes (a decision on a node accepts every path through it: those paths count in the goal's likelihood but not in blocking or check A6)

Links into an OTM file (`links.threats`, `links.mitigations`) carry the ids exactly as the OTM file spells them and are checked only when `model.otm` is configured and the file exists (check A13).

## Exclusions

```yaml
attacktree:
  exclusions:
    - entity: threat.conversation-log-exposure
      reason: A data-handling weakness, not an attacker goal with a path
```

## Baseline inheritance

`attacktree.extends` may point at a project-level tree (by convention `.specify/memory/attack-tree.yaml`) that holds shared actors, assets, controls, and decisions. Entities from the baseline are visible for reference resolution, simulation, and rendering; the feature tree wins on id clashes. The baseline is never written by feature commands.

## Drift hashes

`attacktree.sources[]` records a SHA-256 per source file (`spec.md`, `plan.md`, and the configured OTM file). The hash is computed on universal-newline text with trailing newlines trimmed, so a CRLF checkout produces the same digest as an LF one. For Markdown sources every extension-managed block (`<!-- attacktree:begin -->` … `<!-- attacktree:end -->`, and any other extension's `<!-- <id>:begin -->` … `<!-- <id>:end -->`) is removed first, so rendering never counts as drift; any edit outside the markers does.

## Determinism

The engine writes entities sorted by id with a fixed key order, so regenerating an unchanged tree yields a byte-identical file, and the rendered `attack-tree.md` is identical for an identical tree and configuration. Monte Carlo results are reproducible for a given seed.
