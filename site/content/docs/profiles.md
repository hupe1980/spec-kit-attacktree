+++
title = "Profiles"
description = "AttackTree profiles supply the scales the engine computes with and libraries of actor archetypes, attack vectors, and controls: the default and agentic profiles, and how to write your own."
weight = 35
[extra]
group = "Reference"
+++

A profile is a YAML file in `profiles/`. It supplies two things:

- **Scales** the engine computes with: capability levels, complexity, cost tiers, `requires` tags, control effect and cost levels, impact classes, likelihood levels, and the risk matrix.
- **Libraries** the model command draws on: actor archetypes, attack vector proposals, control proposals, and, for agentic systems, zones. Proposals are a checklist for the agent, never inserted automatically.

Activate profiles with `profiles` in the [configuration](@/docs/configuration.md#profiles). A tree records the profiles it was built with in `attacktree.profiles`, and that list wins over the configuration. The `default` profile's scales always apply; other profiles add libraries on top.

## `default`

| Part | Contents |
|---|---|
| Scales | the values documented in [Risk model](@/docs/risk-model.md) |
| `requires` tags | `authenticated`, `insider-access`, `privileged-access`, `special-equipment`, `long-duration`, `illegal`, `physical-presence`, `violence` |
| Actor archetypes | 8, following Christian Schneider's scenario-driven set: script kiddie, hacktivist, outside and inside attacker groups, social engineer, compromised employee, malicious administrator, state-sponsored group |
| Vector proposals | 20 common attacks, from credential stuffing and SQL injection to dependency compromise and bribery, with MITRE CAPEC, CWE, and ATT&CK references |
| Control proposals | 16 safeguards with default kind and effect and OWASP ASVS 4.0.3 references (one, immutable backups, cites NIST CSF) |

The ASVS references use the key `asvs-4.0` because ASVS 5.0 renumbered every chapter. Edition-pinned keys keep references meaningful when standards move.

## `agentic`

| Part | Contents |
|---|---|
| Zones | `input`, `reasoning`, `tools`, `memory`, `inter-agent` |
| Actor archetypes | 4: author of content the agent reads, publisher of a malicious tool or MCP server, model-assisted adversary, compromised peer agent |
| Vector proposals | 15, with OWASP Top 10 for LLM Applications 2026, OWASP Top 10 for Agentic Applications 2026, MITRE ATLAS, and MAESTRO references |
| Control proposals | 16: 11 deterministic (tool pinning, allowlists, credential isolation, sandboxing, recursion caps, …) and 5 probabilistic (injection classifier, goal-lock check, human-in-the-loop, output guardrail, behaviour monitoring) |

See [Agentic and LLM systems](@/docs/agentic-systems.md) for how to use it.

## Write your own

Add `profiles/<id>.yaml` to the extension, in an installed project `.specify/extensions/attacktree/profiles/`. Give it a unique `profile.id` and add the id to `profiles`. Keep the file under version control elsewhere too: `specify extension update` replaces the extension directory. To change the arithmetic, declare only the `scales` keys you change; everything else comes from `default`:

```yaml
profile:
  id: fintech
  name: Payment platform
  version: "0.1"

scales:
  requires:
    authenticated: { access: user }
    payment-instrument: { resources: moderate }   # a new tag for leaves
  likelihood_levels: { low: 0, medium: 10, high: 30, very-high: 60 }   # stricter bands

actor_archetypes:
  - { id: fraud-ring, name: Organised fraud ring, skill: advanced, resources: substantial, access: external, risk_appetite: high }
```

Keep it consistent: every complexity maps to a defined skill, every `requires` tag names defined capability levels, and every risk-matrix row covers every impact level. `attacktree.sh validate` rejects trees that use a `requires` tag no active profile defines.
