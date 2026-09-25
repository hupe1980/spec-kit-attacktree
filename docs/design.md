# Design: positioning, bets, roadmap

## Positioning

Per-element threat enumeration (STRIDE and its descendants) lists what can go wrong. Attack trees answer a different question: given a concrete adversary, how would they actually get to the outcome they want, which step is the bottleneck, and which control buys the most for the least. Schneier's 1999 paper framed it: "the areas people think of as vulnerable usually aren't." Schneider's Attack Tree platform turned the method into a practice: actors with capabilities, goals with impact, paths rated at the leaves, controls with effect and cost, what-if roadmaps, Monte Carlo, single points of failure, and micro attack simulations to measure what a control really does.

AttackTree brings that practice into Spec-Driven Development as a machine-readable artifact that survives the lifecycle and can be simulated, checked, and converged without an LLM.

| Question | Spec Kit | AttackTree |
|---|---|---|
| What are we working on? | `spec.md`, `plan.md` | actors, assets, goals |
| What can go wrong? | — | goals reached through AND/OR paths |
| What are we going to do about it? | `tasks.md` | controls ranked by simulation → CR-### → tasks |
| Did we do a good job? | `/speckit-converge` | evidence per CR, residual risk with verified controls only |

## Design bets

| Bet | Meaning |
|---|---|
| **Tree as code, flat list with parents** | `attack-tree.yaml` stores nodes as a flat list with `parent`, so ids stay stable across regenerations and merges are per entity. The rendered outline and Mermaid diagram give the tree shape back. |
| **Schneier's rules, literally** | OR takes the best child, AND multiplies likelihoods and adds costs, values propagate up, controls scale down. No custom risk arithmetic beyond one documented matrix. |
| **Attacker profiles are data** | Capabilities and the `requires` tags that gate a leaf live in the profile, so a team can redefine what "insider" or "special equipment" means without touching the engine. |
| **Deterministic core, semantic edge** | Feasibility, propagation, path enumeration, choke points, single points of failure, what-if, Monte Carlo, checks, and evidence collection run in a script. The LLM builds the tree, proposes controls, and judges evidence it opened. |
| **Scenarios, not statuses** | Residual risk is always computed for a stated set of control statuses (`current`, `verified`, `planned`, `all`); converge only believes `verified`. |
| **Probabilistic controls are measured** | Guardrails, classifiers, and human approval carry `probabilistic: true`; converge records a `bypass_rate` from a micro attack simulation, and from then on the tree uses the measurement. |
| **Native IDs** | `CR-###` sits next to `FR-###` and `SC-###` in `spec.md`; the companion preset appends one paragraph to core commands so `tasks`, `analyze`, `converge`, and `checklist` treat them natively. |
| **Evidence, not checkboxes** | `verified` requires an inspectable pointer; control status rolls up from requirement verdicts; a claimed `verified` without evidence is a finding. |
| **Interoperable** | Seeds from Open Threat Model files, links back to their threats, shares the OTM asset id convention, ignores other extensions' managed blocks when hashing, writes SARIF. |
| **Runs without an agent** | Checks and simulation are plain scripts with `md`, `json`, and `sarif` output, usable in CI and code scanning. |
| **Secure by construction** | Artifact content is untrusted data; commands never reproduce secrets or full instruction blocks; the extension ships its own threat model. |

## Decisions taken

- Attack trees, not attack–defense trees: controls are attributes of nodes rather than nodes of their own, which keeps the YAML flat and the simulation simple. A control on an intermediate node still expresses "defend the subtree".
- Collusion is out of scope: an AND path is feasible for an actor who can perform every step alone. Modelling coalitions would need per-leaf actor assignment and is deferred.
- Costs are currency-agnostic integers mapped to resource tiers; the tree does not try to price controls beyond three levels.
- Monte Carlo samples leaves and probabilistic controls only; deterministic controls keep their effect. Results are reproducible for a seed.
- The `seed` subcommand reads any OTM document; interop is opt-in through `model.otm` and never assumed.
- Security artifacts carry the `attacktree-` prefix so other tooling can share `FEATURE_DIR/security/`.

## Roadmap

**v0.2**: sequential AND (`sand`) gates with ordering constraints; per-leaf detectability feeding a detective-control model (detection before completion); coalition paths (assign actors per leaf); `diff` (semantic diff of two trees for PR review); `report` (cross-feature roll-up of goals, residual risk, and roadmap); exporters (ADTool XML, Mermaid-only, and attacktree.online JSON once its format is specified, see below); adversarial fixtures with injected instructions inside spec and code; version pins for the `uv run` fallback; rejection of `extends` paths outside the repository.

**v0.3 ideas**: fault-tree mode (Schneider's editions list it as an alternative view); OSCAL control mapping; convergence report as an in-toto attestation predicate.

**Out of scope**: penetration testing, scanning engines, hosting, dashboards. Micro attack simulation records are consumed as evidence; AttackTree does not run them.

## attacktree.online file format (observed, not specified)

The free edition saves and opens trees as `.json` or `.json.gz`. No schema is published. Loading a bundled template and calling the app's own export endpoint (September 2026) yields a `Version: 1` document with these top-level keys: `UUID`, `Timestamp`, `TreeType`, `Root`, `NodeMap`, `NodeHighestID`, `ControlMap`, `ControlHighestID`, `PackageMap`, `AssetMap`, `Actors`, `Report`, `QuestionMap`, `WizardMap`, `Changelog`. Nodes carry `ID` (`A<n>`), `Title`, `Description`, `AndOperator`, `Parent`, `Children`, `Impact`, `ImpactSubclasses`, `AffectedAssets`, `ThreatActor`, `ActorSubtype`, `Complexity`, `Uncertainty`, `STRIDE`, `TTP`, `Controls` (`{"C<n>": effectPercent}`), `OutOfScope`. Controls carry `Status`, `Effort`, `Nature`, `Kind`, `Ticket`, `Friction`, `Protection`, `Validation`, `Result`, `Requirements`. Impact, complexity, actor, status, nature, kind, and STRIDE are numeric enums whose meanings are only visible in the UI (impact and complexity appear to run 0–4 for Very Low … Very High and trivial … extreme; the seven default actors are numbered in the order Script Kiddie … Evil Admin).

An exporter would be a straightforward mapping (goals and nodes → `NodeMap` with `AndOperator`; `attack.actors[0]` and `complexity` → `ThreatActor` and `Complexity`; controls → `ControlMap` with per-node effect percentages; `status` → the tool's timeline statuses; assets → `AssetMap`), and it could be verified by posting the result to the app's import form. It is deliberately not implemented: without a published schema the enum values and required fields are guesses that a release of the tool could invalidate silently. It stays on the roadmap until Schneider publishes the format or a stable API for it.

## Landscape (September 2026)

| Tool | What it does | Relation |
|---|---|---|
| Attack Tree by Christian Schneider (attacktree.online, custom SaaS, self-hosted) | Visual editor, actor and risk profile customisation, risk-to-asset mapping, what-if analysis, single points of success and failure, choke-point and heat-map analysis, Monte Carlo, k-means quick wins vs strategic controls, dashboards, PDF/Excel/JSON/SVG export, REST API, Threagile/OTM/OWASP import | The reference practice. AttackTree reproduces the modelling vocabulary and the analyses that matter in a repository (paths, choke points, single points of failure, what-if, Monte Carlo, roadmap) without the UI; a JSON exporter for round-tripping is on the roadmap. |
| ADTool (University of Luxembourg) | Attack–defense trees with quantitative attribute domains | Prior art for the propagation rules; AttackTree keeps defenses as node attributes. |
| OWASP pytm, Threagile, Threat Dragon, IriusRisk | Threat models as code / diagrams | Any of them that exports OTM feeds `seed` today. |

## References

Schneier, "Attack Trees" (1999); Schneider, Attack Tree editions overview and blog series (2023–2026); Kordy, Kordy, Mauw, Schweitzer, "ADTool: Security Analysis with Attack–Defense Trees" (2013); Spec Kit `extensions/EXTENSION-{API-REFERENCE,DEVELOPMENT-GUIDE,PUBLISHING-GUIDE}.md`; OWASP ASVS 4.0.3; OWASP Top 10 for LLM Applications 2026; OWASP Top 10 for Agentic Applications 2026; MAESTRO; MITRE CAPEC and ATLAS; SARIF 2.1.0.
