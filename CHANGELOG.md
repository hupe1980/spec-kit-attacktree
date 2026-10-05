# Changelog

All notable changes to the AttackTree extension are documented here. The format follows Keep a Changelog; versions follow SemVer.

## [Unreleased]

### Added

**Commands**

- `speckit.attacktree.model`: create or incrementally update `attack-tree.yaml` from `spec.md`, `plan.md`, and an optional Open Threat Model file (seeded assets and candidate goals with `links.threats`); publish `CR-###` control requirements into `spec.md` between managed markers. Existing ids, statuses, evidence levels, bypass rates, decisions, and verification history survive; goals and nodes that disappear are retired, not deleted.
- `speckit.attacktree.check`: deterministic checks A1–A16 (schema, references and tree structure, empty goals, unrated leaves, degenerate gates, uncontrolled paths, controls without requirements, requirements without tasks or verification, decisions, drift, unverified status claims, OTM links, clarification nodes, unrated actors, truncated enumeration) with `md`, `json`, and `sarif` output, plus ten semantic passes.
- `speckit.attacktree.simulate`: attack paths per actor with Schneier's propagation rules and attacker-profile feasibility; residual risk per goal; choke points, Achilles heels, single points of failure; what-if per inactive control with quick-win / strategic classification; greedy roadmap; seeded Monte Carlo over leaf likelihoods and probabilistic controls; `--scenario`, `--apply`, `--remove` for what-if questions; exit code reflects goals at `risk.block_on`.
- `speckit.attacktree.converge`: evidence-based verification of every `CR-###` (tests, micro attack simulations with measured bypass rates, reviews, scans), append-only verification history, control status and evidence-level roll-up, goal status roll-up, residual risk with verified controls only, convergence report, and appended `Control Convergence` tasks. `verified` requires an inspectable evidence pointer; re-running does not duplicate tasks.

**Engine**

- `scripts/python/attacktree.py` with bash and PowerShell wrappers; subcommands `paths`, `init`, `seed`, `validate`, `merge`, `render`, `check`, `simulate`, `converge-scan`, `converge-apply`. PyYAML is the only requirement; `jsonschema` enables full schema validation.
- JSON Schema `schemas/attack-tree.schema.json`: actors with capabilities, assets, goals with per-class impact, flat AND/OR node list with rated attack vectors at the leaves, controls with effect, bypass rate, probabilistic flag, cost, status, evidence level, touchpoints, validation steps, `CR-###` requirements, verification, decisions.
- Rendered `attack-tree.md` with an outline and a Mermaid flowchart per goal, paths, residual risk in the configured scenario, the what-if roadmap, and the requirement sections.
- Runs without an agent: exit codes reflect severity and blocking goals, output is CI-ready, hashes and reported paths are stable across Linux, macOS, and Windows, and Monte Carlo runs are reproducible for a seed.

**Model semantics**

- Attacker profiles: a leaf is feasible for an actor whose skill covers its complexity, whose resources cover its cost tier, and who satisfies its `requires` tags; an AND path needs one actor able to perform every step.
- Controls scale the likelihood of the subtree they are attached to by `1 − effect`, or by a measured `bypass_rate` once converge records one; scenarios (`current`, `verified`, `planned`, `all`) choose which statuses count.
- `needs-clarification` nodes are left out of the evaluation and listed as assumptions; a goal reachable only through open questions reports risk `unknown` and is never marked mitigated (check A14). `attacktree.exclusions` records deliberate omissions. Decisions (`accepted`, `transferred`) require owner, rationale, and expiry; while unexpired they stop a goal, or every path through a node, from blocking.
- Actor `occurrence` (1–100) weights every path an actor can run; per-node control `effects` override a control's effect at one node; a goal with likelihood 0 is low risk whatever its impact.
- Scenarios `none`, `current`, `planned`, `verified`, and `all` choose which control statuses count; the what-if table reports depth reduction and classes controls that only cut alternative paths as defence in depth.
- Human-owned fields (statuses, evidence levels, bypass rates, occurrence, notes, decisions, verification) survive every regeneration; retiring a goal or inner node retires its subtree.
- Drift detection hashes `spec.md`, `plan.md`, and the configured OTM file with every extension-managed block removed, so no extension's render is mistaken for a change.
- Tasks link to requirements through `[CR-###]` bracket tags only, so prose ranges cannot inflate coverage.

**Profiles**

- `default`: capability, complexity, control effect and cost, impact scales, the risk matrix, Schneider's actor archetypes, 20 CAPEC-mapped attack vector proposals, 16 ASVS 4.0.3-mapped control proposals.
- `agentic`: five attack-surface zones, agentic archetypes, 15 vectors mapped to OWASP Top 10 for Agentic Applications 2026, OWASP Top 10 for LLM Applications 2026, MITRE ATLAS and MAESTRO, 16 controls split into deterministic and probabilistic.

**Integration**

- Seven optional lifecycle hooks (`after_specify` through `before_converge`) and own hook points (`before/after_attacktree_*`) for other extensions to chain on.
- Companion preset `attacktree-sdd` (append overrides for `tasks`, `analyze`, `converge`, `checklist`) and workflow `attacktree-sdd` with a roadmap review gate.
- Composite GitHub Action (`action.yml`) that runs the check and the simulation and uploads SARIF to code scanning.
- `catalog.json` at the repository root: an installable self-hosted catalog with a tag-pinned download URL.

**Documentation and tests**

- Documentation site in `site/`, built with Zola and deployed to GitHub Pages: landing page, quickstart, concepts, guides, full reference, design, security, and releasing, with search, light and dark themes, structured data, and a sitemap. CI builds it and checks every link.
- `examples/agent-assistant`: a complete first pass for an internal RAG assistant built from its spec alone, with rendered view, check report, and simulation, kept valid by tests.
- Test suite covering the manifest, schema, profiles, checks, simulation (propagation rules, feasibility, scenarios, what-if, single points of failure, Monte Carlo reproducibility, truncation), merge, render, seed, convergence, and the shipped example; CI on Linux and Windows across Python 3.11 and 3.13.
