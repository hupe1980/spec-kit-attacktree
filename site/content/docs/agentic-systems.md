+++
title = "Agentic and LLM systems"
description = "Model attack trees for LLM applications and AI agents: the five attack-surface zones, prompt injection and tool-misuse paths, probabilistic guardrails, and bypass-rate measurement."
weight = 23
[extra]
group = "Guides"
+++

LLM applications and agents are where path-based reasoning pays off most. A prompt injection is rarely the goal. It is the first step of a path that continues through planning, tool use, and egress, and the defences along that path are often probabilistic. Enable the `agentic` profile next to `default`:

```yaml
# .specify/extensions/attacktree/attacktree-config.yml
profiles: [default, agentic]
```

## Five zones

The profile tags nodes with the zone of the agent they target, following Christian Schneider's scenario-driven approach:

| Zone | Where the step happens | Typical attacks |
|---|---|---|
| `input` | every channel into the context: prompts, retrieval, email, tool output, tool descriptions | direct and indirect prompt injection, tool description poisoning |
| `reasoning` | planning and goal interpretation | goal hijack, sensitive context leakage |
| `tools` | tool execution with the agent's privileges | tool misuse, delegated credential abuse, egress |
| `memory` | context, working memory, long-term storage | memory poisoning that persists across sessions |
| `inter-agent` | messages between agents | spoofed or tampered messages, cascading compromise |

Walking a goal zone by zone is a reliable way to find the paths. A typical exfiltration path needs a step in **input** (instructions reach the agent), **reasoning** (the plan shifts), **tools** (a data-reading tool runs), and **tools** again (data leaves). That is an AND of four steps, and every one of them is a place for a control.

## Vectors and references

The profile proposes 15 attack vectors with references to the OWASP Top 10 for LLM Applications 2026 (`owasp-llm-2026`), the OWASP Top 10 for Agentic Applications 2026 (`owasp-asi-2026`), MITRE ATLAS (`mitre-atlas`), and MAESTRO layers. Proposals are a checklist, not a template: the model records a vector only when the spec makes it possible.

## Probabilistic controls

Guardrails, injection classifiers, goal-lock checks, output filters, and human approval reduce attacks without blocking them. Mark them `probabilistic: true`:

```yaml
- id: control.injection-classifier
  name: Injection classifier on retrieved content
  kind: preventive
  nodes: [node.inject-via-document]
  effect: medium            # assumed until measured
  probabilistic: true
  validation:
    - Send 300 injection probes through the retrieval path; count how many reach the planner
```

The effect is an assumption until a [micro attack simulation](@/docs/evidence.md#probabilistic-controls-and-bypass-rates) measures it. Converge then records the measured `bypass_rate`, and the tree uses it. In Monte Carlo runs, probabilistic controls are sampled as well, so goals that depend on them show a wider spread.

Two rules from practice:

- **Layer different failure modes.** Two classifiers that both fail on the same payload family are one control, not two. Pair a probabilistic control with a deterministic one, such as a tool allowlist, an egress allowlist, or scoped credentials, on the same path.
- **Give humans the context.** Human approval that shows "Send email? Yes/No" without the reasoning chain approves the attack. Write a validation step that checks what the approver sees.

## The same example, zone by zone

The shipped [example](https://github.com/hupe1980/spec-kit-attacktree/tree/main/examples/agent-assistant) is an agentic assistant with a retrieval path and a ticket tool. Its goal `goal.abuse-ticket-credential` combines an injection (`input`) with a call beyond scope (`tools`). Its most likely path, however, is an operator reading the credential from configuration. Path-based ranking surfaces exactly this kind of finding: the AI-specific path is real, but not the cheapest.
