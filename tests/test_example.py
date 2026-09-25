"""The shipped example must stay valid and clean as the engine evolves."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / "examples" / "agent-assistant"
FEATURE = REPO / "specs" / "001-agent-assistant"


def test_example_tree_is_valid(engine):
    model = engine.load_model(FEATURE / "attack-tree.yaml")
    assert engine.schema_validate(model) == []
    assert engine.reference_errors(model, engine.scales_of(engine.load_profiles(model["attacktree"]["profiles"]))) == []
    assert len(model["goals"]) >= 5 and len(model["controls"]) >= 10 and len(model["requirements"]) >= 10


def test_example_check_has_nothing_above_medium_and_no_drift(engine):
    paths = engine.Paths(REPO, FEATURE)
    findings, metrics = engine.run_checks(paths, engine.load_config(REPO))
    assert engine.worst_severity(findings) in ("none", "low", "medium")
    assert not any(f.check == "A11" for f in findings), "example sources must be hashed and current"
    assert not any(f.check in ("A6", "A13") for f in findings)
    assert metrics["needs_clarification"] >= 1


def test_example_spec_carries_the_managed_block_and_render_matches(engine):
    spec = (FEATURE / "spec.md").read_text(encoding="utf-8")
    assert engine.BEGIN_MARK in spec and engine.END_MARK in spec
    assert "threatspec" not in spec.lower(), "the example stands alone"
    assert spec.index(engine.BEGIN_MARK) < spec.index("## Success Criteria")
    model = engine.load_model(FEATURE / "attack-tree.yaml")
    assert engine.cr_block(model) in spec


def test_example_simulation_is_complete(engine):
    paths = engine.Paths(REPO, FEATURE)
    cfg = engine.load_config(REPO)
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(model["attacktree"]["profiles"]))
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    assert sim["truncated"] == []
    assert all(g["feasible"] for g in sim["goals"])
    assert sim["blocking_goals"], "with every control proposed, critical goals must block"
    everything = engine.simulate(model, cfg, scales, scenario="all", with_monte_carlo=False)
    assert all(g["uncontrolled_paths"] == 0 for g in everything["goals"]), "every path has a proposed control"
    assert everything["blocking_goals"] == []
    assert len(sim["what_if"]) == len(model["controls"]) and sim["roadmap"]


def test_example_is_self_contained(engine):
    model = engine.load_model(FEATURE / "attack-tree.yaml")
    assert not any((g.get("links") or {}) for g in model["goals"])
    assert [src["path"] for src in model["attacktree"]["sources"]] == ["spec.md"]
    assert not (FEATURE / "threat-model.yaml").exists()
