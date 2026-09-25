from pathlib import Path

import pytest
import yaml


def write_verdicts(feature: Path, verdicts):
    vf = feature / "security" / "attacktree-verdicts.yaml"
    vf.parent.mkdir(exist_ok=True)
    vf.write_text(yaml.safe_dump({"verdicts": verdicts}), encoding="utf-8")
    return vf


def test_converge_scan_finds_tasks_evidence_and_residual(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    data = engine.converge_scan(paths, engine.load_config(agent_repo))
    assert data["config"]["verification"]["test_command"] == ""
    assert data["config"]["config_file"].endswith("attacktree-config.yml")
    by_id = {r["id"]: r for r in data["requirements"]}
    assert by_id["CR-001"]["all_tasks_done"] is True and by_id["CR-001"]["probabilistic"] is True
    assert "tests/agent/test_prompt_injection.py" in by_id["CR-001"]["evidence"]["test_files"]
    assert by_id["CR-001"]["evidence"]["touchpoints"][0]["exists"] is True
    assert by_id["CR-001"]["validation_steps"]
    assert by_id["CR-002"]["all_tasks_done"] is False and by_id["CR-002"]["evidence"]["test_files"] == []
    assert by_id["CR-004"]["evidence"]["touchpoints"][0]["exists"] is False
    # with no verified control, residual risk uses raw likelihoods
    assert data["residual_with_verified_controls"]["goal.exfiltrate-documents"] == {"likelihood": 48.0, "risk": "critical"}
    assert data["blocking_goals"] == ["goal.exfiltrate-documents"]


def test_evidence_scan_skips_caches_and_accepts_id_spellings(engine, agent_repo):
    cache = agent_repo / "tests" / "agent" / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "x.cpython-313.pyc").write_text("CR-001", encoding="utf-8")
    (agent_repo / "tests" / "agent" / "test_underscore.py").write_text("def test_cr_001_blocks(): pass\n", encoding="utf-8")
    (agent_repo / "tests" / "agent" / "test_other.py").write_text("# covers CR-0010 only\n", encoding="utf-8")
    ev = engine.find_evidence(agent_repo, "CR-001", engine.load_config(agent_repo), [])
    assert ev["test_files"] == ["tests/agent/test_prompt_injection.py", "tests/agent/test_underscore.py"]
    assert all("\\" not in p for p in ev["test_files"])


def test_converge_apply_records_rolls_up_and_appends_tasks(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    vf = write_verdicts(agent_feature, [
        {"requirement": "CR-001", "verdict": "verified", "method": "simulation", "evidence": "security/micro-sim-injection.md",
         "result": "pass", "bypass_rate": 12, "justification": "300 probes, 36 reached the planner, no tool call."},
        {"requirement": "CR-003", "verdict": "verified", "method": "test",
         "evidence": "tests/agent/test_ticket.py::test_no_ticket_without_confirmation", "result": "pass"},
        {"requirement": "CR-002", "verdict": "missing", "method": "review", "evidence": "none", "result": "fail",
         "justification": "No visibility filter in retriever.py."},
    ])
    tasks_before = paths.tasks.read_text(encoding="utf-8")
    summary = engine.converge_apply(paths, cfg, vf, commit="abc1234")
    assert summary["status"] == "NOT CONVERGED"
    assert summary["requirements"]["verified"] == ["CR-001", "CR-003"]
    assert summary["requirements"]["missing"] == ["CR-002", "CR-004", "CR-005"]  # no verdict → missing
    assert summary["controls"]["verified"] == ["control.ticket-confirmation", "control.untrusted-context-delimiting"]
    model = engine.load_model(paths.model)
    ctrls = {c["id"]: c for c in model["controls"]}
    assert ctrls["control.untrusted-context-delimiting"]["bypass_rate"] == 12
    assert ctrls["control.untrusted-context-delimiting"]["evidence"] == "lab-validated"
    assert ctrls["control.visibility-filtered-retrieval"]["status"] == "planned"
    assert len(model["verification"]) == 3 and all(v["commit"] == "abc1234" for v in model["verification"])
    assert next(v for v in model["verification"] if v["requirement"] == "CR-001")["bypass_rate"] == 12
    # residual with verified controls: 60 × 0.12 (measured bypass) × 0.8 = 5.76
    assert summary["goals"]["residual"]["goal.exfiltrate-documents"]["likelihood"] == 5.8
    statuses = {g["id"]: g["status"] for g in model["goals"]}
    assert statuses["goal.disrupt-service"] == "accepted" and statuses["goal.forge-ticket"] == "open"
    tasks_after = paths.tasks.read_text(encoding="utf-8")
    assert tasks_after.startswith(tasks_before)
    assert "## Phase 4: Control Convergence" in tasks_after
    assert "[CR-002]" in tasks_after and "[CR-004]" in tasks_after and "[CR-005]" in tasks_after
    assert "T023" in tasks_after  # continues numbering after T022
    assert (agent_feature / "security" / "attacktree-convergence-report.json").exists()
    md = (agent_feature / "security" / "attacktree-convergence-report.md").read_text(encoding="utf-8")
    assert "Residual risk" in md and "| `goal.exfiltrate-documents` |" in md


def test_converge_apply_converges_when_everything_verified(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    vf = write_verdicts(agent_feature, [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/x.py::{rid}", "result": "pass"}
        for rid in ("CR-001", "CR-002", "CR-003", "CR-004", "CR-005")])
    tasks_before = paths.tasks.read_text(encoding="utf-8")
    summary = engine.converge_apply(paths, cfg, vf, commit="abc1234")
    assert summary["status"] == "CONVERGED"
    assert paths.tasks.read_text(encoding="utf-8") == tasks_before
    model = engine.load_model(paths.model)
    assert all(c["status"] == "verified" for c in model["controls"])
    statuses = {g["id"]: g["status"] for g in model["goals"]}
    assert statuses["goal.exfiltrate-documents"] == "mitigated" and statuses["goal.forge-ticket"] == "mitigated"
    assert statuses["goal.disrupt-service"] == "accepted"


def test_verified_without_evidence_is_rejected(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    vf = write_verdicts(agent_feature, [{"requirement": "CR-001", "verdict": "verified"}])
    with pytest.raises(SystemExit):
        engine.converge_apply(paths, engine.load_config(agent_repo), vf, commit="x")
    vf = write_verdicts(agent_feature, [{"requirement": "CR-099", "verdict": "missing", "evidence": "none"}])
    with pytest.raises(SystemExit):
        engine.converge_apply(paths, engine.load_config(agent_repo), vf, commit="x")


def test_only_scope_carries_previous_verdicts_forward(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    vf = write_verdicts(agent_feature, [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/a.py::{rid}", "result": "pass"}
        for rid in ("CR-001", "CR-003", "CR-004", "CR-005")] + [
        {"requirement": "CR-002", "verdict": "missing", "method": "review", "evidence": "none", "result": "fail"}])
    engine.converge_apply(paths, cfg, vf, commit="c1")
    vf = write_verdicts(agent_feature, [{"requirement": "CR-002", "verdict": "verified", "method": "test", "evidence": "tests/c.py::t", "result": "pass"}])
    summary = engine.converge_apply(paths, cfg, vf, commit="c2", only=["CR-002"])
    assert summary["status"] == "CONVERGED"
    assert len(engine.load_model(paths.model)["verification"]) == 6
    vf = write_verdicts(agent_feature, [{"requirement": "CR-001", "verdict": "missing", "evidence": "none"}])
    with pytest.raises(SystemExit):
        engine.converge_apply(paths, cfg, vf, commit="c3", only=["CR-002"])


def test_converge_apply_is_idempotent_when_not_converged(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    vf = write_verdicts(agent_feature, [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/a.py::{rid}", "result": "pass"}
        for rid in ("CR-001", "CR-003", "CR-004", "CR-005")] + [
        {"requirement": "CR-002", "verdict": "missing", "method": "review", "evidence": "none", "result": "fail"}])
    first = engine.converge_apply(paths, cfg, vf, commit="c1")
    after_first = paths.tasks.read_text(encoding="utf-8")
    assert first["appended_tasks"] == ["T023"] and "[CR-002]" in after_first
    second = engine.converge_apply(paths, cfg, vf, commit="c2")
    assert second["appended_tasks"] == [] and second["already_open_tasks_for"] == ["CR-002"]
    assert paths.tasks.read_text(encoding="utf-8") == after_first
    assert after_first.count("## Phase 4: Control Convergence") == 1
    paths.tasks.write_text(after_first.replace("- [ ] T023 [CR-002]", "- [x] T023 [CR-002]"), encoding="utf-8")
    third = engine.converge_apply(paths, cfg, vf, commit="c3")
    assert third["appended_tasks"] == ["T024"]


def test_blocking_goal_appends_a_goal_task_and_blocks_convergence(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    model = engine.load_model(paths.model)
    next(g for g in model["goals"] if g["id"] == "goal.forge-ticket")["impact"] = {"customer": "critical"}
    for n in model["nodes"]:
        if n["id"] == "node.phish-employee":
            n["attack"]["likelihood"] = 90
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    vf = write_verdicts(agent_feature, [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/a.py::{rid}", "result": "pass"}
        for rid in ("CR-001", "CR-002", "CR-003", "CR-004", "CR-005")])
    summary = engine.converge_apply(paths, cfg, vf, commit="c1")
    # short-lived sessions (medium → ×0.5) leaves phishing at 45 → very-high? no: 45 is 'high' × critical = critical
    assert summary["status"] == "NOT CONVERGED" and summary["goals"]["open_blocking"] == ["goal.forge-ticket"]
    assert "[attacktree] Reduce residual risk of goal `goal.forge-ticket`" in paths.tasks.read_text(encoding="utf-8")


def test_unhashed_sources_block_convergence(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    model = engine.load_model(paths.model)
    model["attacktree"]["sources"] = []
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    vf = write_verdicts(agent_feature, [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/x.py::{rid}", "result": "pass"}
        for rid in ("CR-001", "CR-002", "CR-003", "CR-004", "CR-005")])
    summary = engine.converge_apply(paths, cfg, vf, commit="x")
    assert summary["status"] == "NOT CONVERGED" and any("never hashed" in d for d in summary["drift"])


def test_a12_fires_when_verified_status_is_claimed_without_evidence(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    next(c for c in model["controls"] if c["id"] == "control.rate-limit")["status"] = "verified"
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _ = engine.run_checks(paths, engine.load_config(agent_repo))
    assert any(f.check == "A12" and "control.rate-limit" in f.location for f in findings)
    # converge demotes the claim
    vf = write_verdicts(agent_feature, [{"requirement": "CR-005", "verdict": "implemented-unverified", "method": "review", "evidence": "src/api/routes.py:10"}])
    engine.converge_apply(paths, engine.load_config(agent_repo), vf, commit="x")
    model = engine.load_model(paths.model)
    ctrl = next(c for c in model["controls"] if c["id"] == "control.rate-limit")
    assert ctrl["status"] == "implemented" and ctrl["evidence"] == "design-reviewed"
