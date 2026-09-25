import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "schemas" / "attack-tree.schema.json"
GOOD = ROOT / "tests" / "fixtures" / "agent-assistant" / "specs" / "007-agent-assistant" / "attack-tree.yaml"
BROKEN = ROOT / "tests" / "fixtures" / "broken" / "attack-tree.yaml"


def test_schema_is_valid_json_schema():
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert schema["$schema"].endswith("2020-12/schema")
    assert set(schema["required"]) == {"attacktree", "project"}


def test_good_fixture_passes_engine_validation(engine):
    model = engine.load_yaml(GOOD)
    assert engine.schema_validate(model) == []
    assert engine.reference_errors(model, engine.scales_of(engine.load_profiles(["default"]))) == []


def test_broken_fixture_reports_dangling_references_and_cycles(engine):
    model = engine.load_yaml(BROKEN)
    errs = engine.reference_errors(model)
    assert any("actor.missing" in e for e in errs)
    assert any("node.missing" in e for e in errs)
    assert any("cycle" in e for e in errs)


def test_builtin_validation_catches_required_fields(engine):
    errs = engine.builtin_validate({"attacktree": {"version": "0.1"}, "project": {"id": "x", "name": "x"},
                                    "goals": [{"id": "goal.x", "name": "x"}],
                                    "nodes": [{"id": "node.x", "name": "x", "attack": {"likelihood": 200}}],
                                    "controls": [{"id": "control.x", "name": "x"}]})
    assert any("impact" in e for e in errs)
    assert any("parent" in e for e in errs)
    assert any("likelihood" in e for e in errs)
    assert any("nodes is required" in e for e in errs)


def test_jsonschema_validation_if_available(engine):
    pytest.importorskip("jsonschema")
    model = engine.load_yaml(GOOD)
    assert engine.schema_validate(model) == []
    bad = engine.load_yaml(GOOD)
    bad["controls"][0]["status"] = "bogus"
    assert any("bogus" in e for e in engine.schema_validate(bad))
    bad = engine.load_yaml(GOOD)
    bad["goals"][0]["impact"] = {"data": "enormous"}
    assert engine.schema_validate(bad)


def test_unknown_requires_tag_is_a_reference_error(engine):
    model = engine.load_yaml(GOOD)
    leaf = next(n for n in model["nodes"] if n["id"] == "node.phish-employee")
    leaf["attack"]["requires"] = ["telepathy"]
    errs = engine.reference_errors(model, engine.scales_of(engine.load_profiles(["default"])))
    assert any("telepathy" in e for e in errs)


def test_leaf_with_children_is_rejected(engine):
    model = engine.load_yaml(GOOD)
    parent = next(n for n in model["nodes"] if n["id"] == "node.session-theft")
    parent["attack"] = {"actors": ["actor.outsider"], "complexity": "low"}
    errs = engine.reference_errors(model)
    assert any("has children and an attack block" in e for e in errs)


def test_template_skeleton_is_parseable_and_shaped():
    tpl = yaml.safe_load((ROOT / "templates" / "attack-tree.yaml").read_text(encoding="utf-8"))
    for key in ("attacktree", "project", "actors", "goals", "nodes", "controls", "requirements", "verification", "decisions"):
        assert key in tpl


def test_profiles_are_consistent():
    default = yaml.safe_load((ROOT / "profiles" / "default.yaml").read_text(encoding="utf-8"))
    scales = default["scales"]
    assert default["profile"]["id"] == "default"
    for level, spec in scales["complexity"].items():
        assert spec["skill"] in scales["skill"], level
        assert 0 <= spec["likelihood"] <= 100
    for tag, need in scales["requires"].items():
        for cap, minimum in need.items():
            assert minimum in scales[cap], f"{tag}: {cap}={minimum}"
    for lk_level, row in scales["risk_matrix"].items():
        assert lk_level in scales["likelihood_levels"]
        assert set(row) == set(scales["impact_levels"])
    for name in ("default", "agentic"):
        prof = yaml.safe_load((ROOT / "profiles" / f"{name}.yaml").read_text(encoding="utf-8"))
        assert prof["profile"]["id"] == name
        for v in prof.get("vector_proposals", []):
            assert v["complexity"] in scales["complexity"], f"{name}: {v['id']}"
            for tag in v.get("requires", []):
                assert tag in scales["requires"], f"{name}: {v['id']} requires undeclared tag {tag}"
        for c in prof.get("control_proposals", []):
            assert c["kind"] in ("preventive", "detective", "compensating"), f"{name}: {c['id']}"
            assert c["effect"] in scales["control_effect"], f"{name}: {c['id']}"
        for a in prof.get("actor_archetypes", []):
            for cap in ("skill", "resources", "access", "risk_appetite"):
                assert a[cap] in scales[cap], f"{name}: archetype {a['id']} {cap}={a[cap]}"
