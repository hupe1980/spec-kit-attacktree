# AttackTree for Spec Kit

[![CI](https://github.com/hupe1980/spec-kit-attacktree/actions/workflows/ci.yml/badge.svg)](https://github.com/hupe1980/spec-kit-attacktree/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-hupe1980.github.io-047857)](https://hupe1980.github.io/spec-kit-attacktree/)
[![Spec Kit](https://img.shields.io/badge/Spec%20Kit-%E2%89%A5%201.0-0f172a)](https://github.com/github/spec-kit)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Know how you will be attacked before you write the code.** AttackTree is a [Spec Kit](https://github.com/github/spec-kit) extension that turns a feature spec into an attack tree: who attacks, what they want, and every path that gets them there. It simulates which security controls actually cut those paths. It writes the controls into the spec as testable requirements and verifies each one with evidence after implementation.

📖 **Documentation: [hupe1980.github.io/spec-kit-attacktree](https://hupe1980.github.io/spec-kit-attacktree/)**

```text
Actor ─▶ Goal ─▶ AND/OR path ─▶ Attack vector
                      │
                      └─▶ Control ─▶ CR-### requirement ─▶ Task ─▶ Evidence ─▶ Residual risk
```

## Why attack trees

A threat list says what can go wrong. An [attack tree](https://hupe1980.github.io/spec-kit-attacktree/docs/attack-trees/) says how an attacker gets from where they start to what they want, following [Bruce Schneier's method](https://www.schneier.com/academic/archives/1999/12/attack_trees.html) and [Christian Schneider's scenario-driven practice](https://attacktree.online/). That lets it:

- **rank threats by the path an attacker would really take**, per attacker profile;
- **find choke points**, where one control cuts every path to a goal;
- **expose single points of failure**, the controls your defence depends on alone;
- **prove controls work**, recomputing risk from verified controls only, including measured bypass rates for guardrails.

## Install

```bash
specify extension add attacktree --from https://github.com/hupe1980/spec-kit-attacktree/archive/refs/tags/v0.1.0.zip
```

Requires Spec Kit 1.0 or later and Python 3.11 or later with PyYAML, or [uv](https://docs.astral.sh/uv/). It works with every agent Spec Kit supports. Other install sources, the companion preset, and the workflow are covered in [Installation](https://hupe1980.github.io/spec-kit-attacktree/docs/installation/).

## Use

| Run after | Command | Result |
|---|---|---|
| `/speckit-specify` | `/speckit-attacktree-model` | `attack-tree.yaml`, `attack-tree.md`, and `CR-###` requirements in `spec.md` |
| `/speckit-plan` | `/speckit-attacktree-model --from-plan`, then `/speckit-attacktree-simulate` | attacks tied to real files; residual risk, choke points, a control roadmap |
| `/speckit-tasks` | `/speckit-attacktree-check` | 16 deterministic checks plus semantic review; Markdown, JSON, or SARIF |
| `/speckit-implement` | `/speckit-attacktree-converge` | verdicts from evidence, verified controls, remediation tasks |

Agents on Spec Kit's dotted style spell the commands `/speckit.attacktree.model`. All seven lifecycle hooks are optional.

Try it on the shipped [example](examples/agent-assistant/) without an agent:

```bash
python3 scripts/python/attacktree.py --repo examples/agent-assistant --feature-dir specs/001-agent-assistant simulate
```

The [quickstart](https://hupe1980.github.io/spec-kit-attacktree/docs/quickstart/) walks through the output.

## CI

The engine needs no LLM, so checks and simulation run in CI. The bundled action uploads findings to code scanning as SARIF and can fail while a goal stays at blocking risk:

```yaml
- uses: hupe1980/spec-kit-attacktree@v0.1.0
  with:
    feature-dir: specs/007-agent-assistant
    fail-on-blocking-goals: "true"
```

See [CI and code scanning](https://hupe1980.github.io/spec-kit-attacktree/docs/ci/).

## Configure

The install writes `.specify/extensions/attacktree/attacktree-config.yml` with safe defaults. The most common changes:

```yaml
profiles: [default, agentic]   # add the agentic profile for LLM and agent features
enforcement: strict            # CRITICAL findings and blocking goals stop /speckit-implement
risk:
  block_on: [critical, high]   # residual risk levels that block
```

Every key is documented in [Configuration](https://hupe1980.github.io/spec-kit-attacktree/docs/configuration/).

## Documentation

| | |
|---|---|
| Get started | [Introduction](https://hupe1980.github.io/spec-kit-attacktree/docs/introduction/) · [Installation](https://hupe1980.github.io/spec-kit-attacktree/docs/installation/) · [Quickstart](https://hupe1980.github.io/spec-kit-attacktree/docs/quickstart/) |
| Concepts | [Attack trees](https://hupe1980.github.io/spec-kit-attacktree/docs/attack-trees/) · [Risk model](https://hupe1980.github.io/spec-kit-attacktree/docs/risk-model/) · [Simulation](https://hupe1980.github.io/spec-kit-attacktree/docs/simulation/) · [Verification](https://hupe1980.github.io/spec-kit-attacktree/docs/evidence/) |
| Guides | [Workflow](https://hupe1980.github.io/spec-kit-attacktree/docs/workflow/) · [CI](https://hupe1980.github.io/spec-kit-attacktree/docs/ci/) · [OTM interop](https://hupe1980.github.io/spec-kit-attacktree/docs/otm/) · [Agentic systems](https://hupe1980.github.io/spec-kit-attacktree/docs/agentic-systems/) · [Troubleshooting](https://hupe1980.github.io/spec-kit-attacktree/docs/troubleshooting/) |
| Reference | [Commands](https://hupe1980.github.io/spec-kit-attacktree/docs/commands/) · [Engine CLI](https://hupe1980.github.io/spec-kit-attacktree/docs/cli/) · [File format](https://hupe1980.github.io/spec-kit-attacktree/docs/attack-tree-format/) · [Checks](https://hupe1980.github.io/spec-kit-attacktree/docs/checks/) · [Profiles](https://hupe1980.github.io/spec-kit-attacktree/docs/profiles/) · [Glossary](https://hupe1980.github.io/spec-kit-attacktree/docs/glossary/) |
| Project | [Design and roadmap](https://hupe1980.github.io/spec-kit-attacktree/docs/design/) · [Security](https://hupe1980.github.io/spec-kit-attacktree/docs/security/) · [Releasing](https://hupe1980.github.io/spec-kit-attacktree/docs/releasing/) |

## Contributing

Issues and pull requests are welcome. Before opening a pull request:

```bash
uv run --python 3.11 --with pytest --with pyyaml --with jsonschema pytest -q   # the engine and manifests
zola --root site check                                                         # the site, if you changed it
```

Keep `CHANGELOG.md` current, and bump `extension.version` and `catalog.json` together on every release; the tests check that they agree. The site lives in `site/` and is built with [Zola](https://www.getzola.org/); preview it with `zola --root site serve`.

## License

[MIT](LICENSE)
