# Examples

## `agent-assistant`

An internal assistant that answers questions from a knowledge base and can open support tickets. The feature directory `specs/001-agent-assistant/` shows what AttackTree produces from `spec.md` alone **before any plan exists** and before any control is built:

| File | Produced by | What to look at |
|---|---|---|
| `spec.md` | `/speckit-specify`, then the model command's render | The managed `### Control Requirements` block (CR-001 … CR-014) between the `attacktree` markers, inserted before Success Criteria; nothing else was touched |
| `attack-tree.yaml` | `/speckit-attacktree-model` (first pass, profiles `default`, `agentic`) | 4 actors with capabilities, 4 assets, 6 goals with per-class impact, 23 attack vectors under AND/OR nodes plus 1 `needs-clarification` node, 14 controls (2 probabilistic) with validation steps, 14 requirements with Given/When/Then acceptance |
| `attack-tree.md` | `attacktree.sh render` | The human view: per goal the outline, a Mermaid diagram with controls attached, paths with feasible actors, choke points and Achilles heels; then the controls table and the what-if roadmap |
| `security/attacktree-check-report.md` | `attacktree.sh check --persist` | One A14 finding (the open question) and one aggregated A9 line; nothing HIGH or CRITICAL |
| `security/attacktree-simulation.md` | `attacktree.sh simulate --persist` | With every control still `proposed`: four goals at critical residual risk, one uncovered choke point, the what-if table ranking the 14 controls, the greedy roadmap, and the Monte Carlo summary |

Two things the tree makes visible that a flat list of threats would not: `goal.read-restricted-documents` is an AND of "get restricted content into the context" and "get it out", so `node.rrd-reach` is a choke point where one control (visibility-filtered retrieval) cuts every path; and the operator's direct access to the store and the credential (`node.pa-store-tamper`, `node.atc-read-config`) is the most likely path to two goals, which a per-element enumeration lists but does not rank.

The tree was written as a realistic first pass, not a curated ideal: the check command's semantic passes still find things to improve (a second control on the critical goal's most likely path, ratings that deserve a measurement), and that is the point of the workflow.

### Reproduce

```bash
specify init demo --integration claude && cd demo
specify extension add --dev /path/to/spec-kit-attacktree
mkdir -p specs/001-agent-assistant
cp /path/to/spec-kit-attacktree/examples/agent-assistant/specs/001-agent-assistant/spec.md specs/001-agent-assistant/
export SPECIFY_FEATURE=001-agent-assistant
# in your agent:
/speckit-attacktree-model
/speckit-attacktree-simulate
/speckit-attacktree-check
```

Or run only the deterministic engine on the shipped files:

```bash
python3 scripts/python/attacktree.py --repo examples/agent-assistant --feature-dir specs/001-agent-assistant check
python3 scripts/python/attacktree.py --repo examples/agent-assistant --feature-dir specs/001-agent-assistant simulate
python3 scripts/python/attacktree.py --repo examples/agent-assistant --feature-dir specs/001-agent-assistant simulate --scenario all
python3 scripts/python/attacktree.py --repo examples/agent-assistant --feature-dir specs/001-agent-assistant simulate --apply control.visibility-filtered-retrieval,control.ticket-tool-least-privilege
```

### Next steps in the lifecycle (not included here)

`/speckit-clarify` to answer the open question, `/speckit-plan`, then `/speckit-attacktree-model --from-plan` to replace the component-id touchpoints with file paths, `/speckit-attacktree-simulate` to agree the roadmap and set the chosen controls to `planned`, `/speckit-tasks`, and after implementation `/speckit-attacktree-converge`. The test fixture under `tests/fixtures/agent-assistant/` shows a smaller tree further along that path, with implemented controls, tasks, touchpoint files, and a convergence run.
