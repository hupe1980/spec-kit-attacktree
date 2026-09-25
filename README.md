# 🌳 AttackTree — Attack Tree Modeling & Control Simulation for Spec Kit

**AttackTree is a [Spec Kit](https://github.com/github/spec-kit) extension that makes attack trees a first-class part of Spec-Driven Development.**

It builds a machine-readable attack tree from your Spec Kit artifacts: who attacks (threat actors with capabilities), what they want (goals with business impact), how they get there (AND/OR paths ending in rated attack vectors), and what stops them (controls with effect, cost, and status). It then simulates the tree the way [Schneier](https://www.schneier.com/academic/archives/1999/12/attack_trees.html) described and [Christian Schneider's Attack Tree](https://christian-schneider.net/development/attacktree-free-saas/) practises: most likely and cheapest path per attacker, choke points, single points of failure, a what-if roadmap of controls ranked by risk reduction per cost, and a seeded Monte Carlo over the uncertainty in the ratings. Controls become testable `CR-###` requirements in `spec.md`, tasks in `tasks.md`, and, after implementation, evidence-backed verification that recomputes residual risk with verified controls only.

```text
Actor ─▶ Goal ─▶ AND/OR path ─▶ Attack vector (leaf)
                     │
                     └─▶ Control ─▶ Control Requirement (CR-###)
                                          ├──▶ Task (T###)        tasks.md
                                          ├──▶ Verification       test | simulation | review | scan | evidence
                                          └──▶ Residual risk      recomputed with verified controls only
```

## 🔁 Workflow

```text
/speckit-specify                          spec.md
        ↓
/speckit-attacktree-model                 attack-tree.yaml + attack-tree.md + CR-### block in spec.md
        ↓
/speckit-plan                             plan.md (sees the control requirements)
        ↓
/speckit-attacktree-model --from-plan     concrete attack vectors, control touchpoints as file paths
        ↓
/speckit-attacktree-simulate              residual risk, choke points, single points of failure, control roadmap
        ↓
/speckit-tasks                            tasks.md (control tasks tagged [CR-###])
        ↓
/speckit-attacktree-check                 gap report: goals → paths → controls → CR-### → tasks → verification
        ↓
/speckit-implement                        code + tests
        ↓
/speckit-attacktree-converge              evidence-based verification, measured bypass rates, remediation tasks
        ↓
/speckit-converge                         core convergence completes the appended tasks
```

✏️ Command names are shown in the hyphenated skills form used by Claude Code, Copilot, Cursor and most other agents. Agents on the dotted default — opencode, gemini, qwen and friends — spell the same commands `/speckit.attacktree.model`. The command bodies never hard-code either form; they use `__SPECKIT_COMMAND_*__` tokens that Spec Kit renders per agent.

🔌 Every AttackTree hook is optional by default. Nothing in the core workflow changes unless you opt in.

🔄 Optional interop through the [Open Threat Model](https://github.com/iriusrisk/OpenThreatModel) standard: point `model.otm` at an OTM file and the model command seeds assets and candidate goals from it and links goals back to its threats.

## 📦 Installation

```bash
# From a release archive (the CLI asks you to confirm the untrusted URL)
specify extension add attacktree --from https://github.com/hupe1980/spec-kit-attacktree/archive/refs/tags/v0.1.0.zip

# Or register this repository's catalog once, then install by name
specify extension catalog add https://raw.githubusercontent.com/hupe1980/spec-kit-attacktree/main/catalog.json --name attacktree --install-allowed
specify extension add attacktree

# From a local checkout (development)
specify extension add --dev ./spec-kit-attacktree

# Optional companions
specify preset add --dev ./spec-kit-attacktree/preset/attacktree-sdd        # CR-### awareness in tasks/analyze/converge/checklist
specify workflow add --dev ./spec-kit-attacktree/workflow/attacktree-sdd     # one-shot attack-tree-driven SDD cycle with review gates
```

Requirements: Spec Kit ≥ 1.0.0, Python 3 with PyYAML (or [uv](https://docs.astral.sh/uv/), which the wrappers use to fetch PyYAML and jsonschema on the fly).

## 🧭 Commands

| Command | What it does | Writes |
|---|---|---|
| 🧠 `/speckit-attacktree-model` | Builds or incrementally updates `attack-tree.yaml` from `spec.md` (actors, goals, paths, controls, `CR-###`), from a configured OTM file (seeded assets and goals), and, with `--from-plan`, from `plan.md` (concrete vectors, touchpoints). | `attack-tree.yaml`, `attack-tree.md`, the marked block in `spec.md` |
| 🔍 `/speckit-attacktree-check` | Deterministic checks A1–A16 from the engine plus ten semantic passes; report in the `/speckit-analyze` shape; `--format sarif` for GitHub code scanning. | optional `security/attacktree-check-report.md` |
| 🎲 `/speckit-attacktree-simulate` | Paths per actor, residual risk per goal, choke points, Achilles heels, single points of failure, what-if per inactive control, greedy roadmap, Monte Carlo; `--apply` / `--remove` / `--scenario` for what-if questions. | optional `security/attacktree-simulation.{md,json}` |
| ✅ `/speckit-attacktree-converge` | Collects evidence per `CR-###`, has the agent judge only from that evidence (tests, micro attack simulations with bypass rates, reviews), records append-only verification, rolls control and goal status up, recomputes residual risk with verified controls, appends remediation tasks. | `attack-tree.yaml`, `security/attacktree-convergence-report.{md,json}`, appended phase in `tasks.md` |

### ⚙️ Deterministic checks

| ID | Check | Severity |
|---|---|---|
| A1 | Schema validation | 🔴 CRITICAL |
| A2 | Dangling reference, parent cycle, attack block on a non-leaf | 🔴 CRITICAL |
| A3 | Goal with no attack path modelled | 🟡 MEDIUM |
| A4 | Attack vector without actors or complexity | 🟠 HIGH |
| A5 | AND/OR node with a single child | 🟢 LOW |
| A6 | Feasible path with no control and no decision | 🟠 HIGH / 🔴 CRITICAL |
| A7 | Control without `CR-###` | 🟠 HIGH |
| A8 | `CR-###` without a task | 🟠 HIGH |
| A9 | `CR-###` without verification | 🟢 LOW → 🟠 HIGH (phase-aware) |
| A10 | Decision missing owner, rationale, expiry, or expired | 🟠 HIGH |
| A11 | `spec.md`, `plan.md`, or the configured OTM file changed since the tree was generated | 🟡 MEDIUM |
| A12 | Control marked verified without a passing verification entry | 🟠 HIGH |
| A13 | Link to an unknown threat or mitigation in the configured OTM file | 🟡 MEDIUM |
| A14 | Node needs clarification | 🟡 MEDIUM |
| A15 | Actor without (complete) capabilities | 🟡 MEDIUM |
| A16 | Path enumeration truncated at `risk.max_paths` | 🟢 LOW |

The engine runs without an agent, so the same checks and the simulation work in CI:

```bash
.specify/extensions/attacktree/scripts/bash/attacktree.sh check --feature-dir specs/007-agent-assistant --format sarif --output attacktree.sarif
.specify/extensions/attacktree/scripts/bash/attacktree.sh simulate --feature-dir specs/007-agent-assistant --no-monte-carlo
```

Check exit codes: `0` nothing above MEDIUM, `1` HIGH (or MEDIUM in strict mode), `2` CRITICAL. Simulate exit codes: `0` no goal at `risk.block_on` residual risk, `1` otherwise.

🤖 Or use the bundled GitHub Action, which runs both and uploads SARIF to code scanning:

```yaml
# .github/workflows/attacktree.yml
name: AttackTree
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hupe1980/spec-kit-attacktree@v0.1.0
        with:
          feature-dir: specs/007-agent-assistant   # optional; auto-detected from SPECIFY_FEATURE or the branch
          fail-on-blocking-goals: "false"           # "true" fails when a goal stays at block_on residual risk
```

## 🎲 What the simulation tells you

For the shipped example (an internal assistant over a knowledge base with a ticket tool) the engine reports, with every control still `proposed`:

```text
| Goal                            | Impact   | Likelihood       | Risk     | Strongest actor | Paths | Uncontrolled | Choke points                    | Most likely path                              |
| goal.read-restricted-documents  | critical | 59.5 (high)      | critical | actor.employee  | 5     | 5            | node.rrd-egress, node.rrd-reach | node.rrd-answer-quotes + node.rrd-ask-directly |
| goal.abuse-ticket-credential    | high     | 80.0 (very-high) | critical | actor.operator  | 3     | 3            | —                               | node.atc-read-config                          |
| goal.poison-answers             | high     | 80.0 (very-high) | critical | actor.operator  | 3     | 3            | —                               | node.pa-store-tamper                          |
…
Uncovered choke points: goal.read-restricted-documents → node.rrd-reach, node.rrd-egress
What-if: 1. control.visibility-filtered-retrieval (quick win, cuts every path to the critical goal)
         2. control.reporter-from-session (quick win)  3. control.rate-and-size-limits (quick win)
         8. control.ticket-confirmation (defence in depth: lowers no goal today, cuts 7 alternative paths)
```

Then, with `--scenario planned` or `--apply control.x`, what changes. The rules are Schneier's: a leaf is feasible for an actor whose skill covers its complexity, whose resources cover its cost, and whose access and risk appetite satisfy its `requires` tags; OR nodes take the most likely (and cheapest) child; AND nodes multiply likelihoods and add costs; each control on a node multiplies the likelihood below it by `1 − effect`, or by its measured bypass rate. Details in [docs/methodology.md](docs/methodology.md).

## 🧪 Example

[examples/agent-assistant](examples/agent-assistant/) holds a complete first pass for an internal RAG assistant built from `spec.md` alone: four actors, six goals, 23 attack vectors under AND/OR paths plus one open question, 14 controls (two probabilistic), 14 `CR-###`, the rendered `attack-tree.md` with a Mermaid diagram per goal, and the persisted check and simulation reports. See [examples/README.md](examples/README.md).

## 🗂️ The tree

`attack-tree.yaml` is validated by `schemas/attack-tree.schema.json` and by the engine's reference and structure rules. See `templates/attack-tree.yaml` for the annotated skeleton and [docs/attack-tree-format.md](docs/attack-tree-format.md) for the reference.

Profiles supply the scales and proposal libraries:

| Profile | Supplies |
|---|---|
| `default` | capability, complexity, effect, cost, and impact scales, the risk matrix, Schneider's actor archetypes, CAPEC-mapped attack vector proposals, ASVS 4.0.3-mapped control proposals |
| `agentic` | five attack-surface zones, agentic actor archetypes, vectors mapped to OWASP Top 10 for Agentic Applications 2026, OWASP Top 10 for LLM Applications 2026, MITRE ATLAS and MAESTRO, controls split into deterministic and probabilistic |

## 🎛️ Configuration

`.specify/extensions/attacktree/attacktree-config.yml` (see `config-template.yml`):

```yaml
profiles: [default, agentic]
enforcement: warn            # strict → CRITICAL findings and blocking goals stop /speckit-implement
risk: { block_on: [critical], scenario: current, max_paths: 200 }   # scenario: none | current | verified | planned | all
simulation: { iterations: 2000, seed: 42, likelihood_spread: 15 }
risk_acceptance: { require_owner: true, max_duration_days: 180 }
model: { baseline: .specify/memory/attack-tree.yaml, otm: "", write_requirements_to_spec: true, render_markdown: true, diagram: mermaid }
verification: { test_command: "", scanners: [], evidence_markers: ["CR-"], test_dirs: [tests, test, spec, __tests__] }
```

Every key, its default, what reads it, and the merge order: [docs/configuration.md](docs/configuration.md).

## 🧱 Design principles

♻️ Reusable · 🤝 agent-agnostic · 🔗 traceable · 🎯 deterministic where possible · 🪶 non-intrusive · 📈 incremental · 🧾 evidence over claims · 📐 Schneier's rules, literally · 🎲 uncertainty made explicit · 🔄 interoperable (OTM, SARIF) · 🔒 secure by construction (artifact content is untrusted data).

📚 Positioning, design bets, roadmap, and the landscape: [docs/design.md](docs/design.md). Methodology: [docs/methodology.md](docs/methodology.md). Tree reference: [docs/attack-tree-format.md](docs/attack-tree-format.md). Lifecycle and CI: [docs/workflow.md](docs/workflow.md). Configuration: [docs/configuration.md](docs/configuration.md). AttackTree's own threat model: [docs/threat-model.md](docs/threat-model.md).

## 🩺 Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `attacktree: no Python runtime with PyYAML found` | Install PyYAML (`pip install pyyaml`) or [uv](https://docs.astral.sh/uv/); the wrappers try `python3`, `python`, then `uv run --with pyyaml --with jsonschema`. |
| `attacktree: no feature directory found` | Pass `--feature-dir specs/<feature>` before the subcommand, or set `SPECIFY_FEATURE`. Resolution order: flag, `SPECIFY_FEATURE`, git branch name, newest `specs/*/spec.md`. |
| `YAML parse error … quote any scalar` | A `[NEEDS CLARIFICATION: …]` name or a value containing `: ` is unquoted in the incoming tree. Quote it and re-run `merge`. |
| `merge rejected, N validation error(s)` | The incoming tree references an id that does not exist, has a parent cycle, or puts an `attack` block on a node with children. The errors name the entity; fix the file, do not bypass. |
| `cannot simulate, N validation error(s)` | Same fix; the simulation refuses to run on a broken tree. |
| A goal has no feasible path although leaves exist | The modelled actors cannot execute the steps (skill, resources, `requires` tags), or an AND node has a `needs-clarification` or infeasible child. The rendered outline shows each leaf's actors and requirements. |
| `truncated` in the simulation | The tree exceeds `risk.max_paths`; raise it or split the goal. |
| Commands do not appear in the agent | Run `specify extension list`; if installed, restart the agent so it reloads `.claude/commands` or `.claude/skills`. |
| A11 drift right after editing `spec.md` | Expected: re-run the model command so the hashes match. Rendering the CR block (or another extension's managed block) does not count as drift. |
| Convergence keeps reporting `never hashed` | The tree predates source hashing; run the model command once to record hashes. |

## 🤝 Contributing

Issues and pull requests are welcome at [github.com/hupe1980/spec-kit-attacktree](https://github.com/hupe1980/spec-kit-attacktree). Run the test suite before opening a PR, keep `CHANGELOG.md` current, and bump `extension.version` and `catalog.json` together on every content change (the tests enforce that they agree). New profiles go in `profiles/` and need scales (or inherit them), archetypes, and proposals that the profile consistency test accepts. Release and catalog submission steps are in [docs/publishing.md](docs/publishing.md).

## 🛠️ Development

```bash
uv run --with pytest --with pyyaml --with jsonschema pytest -q
python3 scripts/python/attacktree.py --help
python3 scripts/python/attacktree.py --repo examples/agent-assistant --feature-dir specs/001-agent-assistant simulate
```

## 📄 License

MIT
