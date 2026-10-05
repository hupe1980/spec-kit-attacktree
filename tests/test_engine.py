import json
from pathlib import Path

import pytest
import yaml


def run_check(engine, repo: Path, feature: Path):
    paths = engine.Paths(repo, feature)
    cfg = engine.load_config(repo)
    findings, metrics = engine.run_checks(paths, cfg)
    return findings, metrics, paths


def checks(findings):
    return {f.check for f in findings}


def sim_for(engine, repo: Path, feature: Path, **kw):
    paths = engine.Paths(repo, feature)
    cfg = engine.load_config(repo)
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(model["attacktree"]["profiles"]))
    return engine.simulate(model, cfg, scales, with_monte_carlo=False, **kw)


# --------------------------------------------------------------------------- checks

def test_good_fixture_only_reports_expected_gaps(engine, agent_repo, agent_feature):
    findings, metrics, _ = run_check(engine, agent_repo, agent_feature)
    ids = checks(findings)
    assert not ids & {"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A10", "A11", "A12", "A13", "A15"}
    assert "A14" in ids  # the needs-clarification node
    assert sum(1 for f in findings if f.check == "A9") == 5
    assert metrics["goals"] == 3 and metrics["attack_vectors"] == 8 and metrics["requirements_with_tasks"] == 5
    assert metrics["goals_by_risk"] == {"high": 3}
    assert engine.worst_severity(findings) == "high"  # CR-001/CR-003 done but unverified


def test_broken_fixture_reports_structural_findings(engine, tmp_path):
    repo = tmp_path / "repo"
    feature = repo / "specs" / "001-broken"
    feature.mkdir(parents=True)
    (repo / ".specify").mkdir()
    src = Path(__file__).parent / "fixtures" / "broken" / "attack-tree.yaml"
    (feature / "attack-tree.yaml").write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    findings, _, paths = run_check(engine, repo, feature)
    ids = checks(findings)
    assert {"A2", "A3", "A4", "A5", "A7", "A10", "A12", "A14", "A15"} <= ids
    assert "A6" not in ids, "structural errors skip the path simulation"
    assert engine.worst_severity(findings) == "critical"
    assert engine.exit_code_for(findings, strict=False) == 2
    sarif = json.loads(engine.report_sarif(findings, paths))
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert all("\\" not in r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"])


def test_uncontrolled_path_is_a6_and_critical_on_critical_goals(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    model["controls"] = [c for c in model["controls"] if c["id"] != "control.short-lived-sessions"]
    model["requirements"] = [r for r in model["requirements"] if r["id"] != "CR-004"]
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    a6 = [f for f in findings if f.check == "A6"]
    assert len(a6) == 1 and "goal.forge-ticket" in a6[0].location and a6[0].severity == "high"
    # remove every control from the critical goal → CRITICAL
    model["controls"] = [c for c in model["controls"] if c["id"] not in ("control.untrusted-context-delimiting", "control.visibility-filtered-retrieval")]
    model["requirements"] = [r for r in model["requirements"] if r["id"] not in ("CR-001", "CR-002")]
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert any(f.check == "A6" and f.severity == "critical" and "goal.exfiltrate-documents" in f.location for f in findings)


def test_decision_silences_a6(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    model["controls"] = [c for c in model["controls"] if c["id"] != "control.short-lived-sessions"]
    model["requirements"] = [r for r in model["requirements"] if r["id"] != "CR-004"]
    model["decisions"].append({"id": "decision.forge", "target": "goal.forge-ticket", "status": "transferred", "owner": "@x",
                               "rationale": "cyber insurance", "expires": "2027-01-01"})
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert not any(f.check == "A6" for f in findings)


def test_drift_detected_after_spec_change_but_not_after_render(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert "A11" not in checks(findings)
    model = engine.load_model(paths.model)
    engine.upsert_cr_block(paths.spec, engine.cr_block(model))
    # any other extension's managed block is ignored as well
    paths.spec.write_text(paths.spec.read_text(encoding="utf-8").replace("## Success Criteria", "<!-- other-ext:begin -->\n### Managed by another extension\n- **X-001**: x\n<!-- other-ext:end -->\n\n## Success Criteria"), encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert "A11" not in checks(findings)
    paths.spec.write_text(paths.spec.read_text(encoding="utf-8") + "\n- **FR-009**: New requirement.\n", encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert any(f.check == "A11" and f.severity == "medium" and f.location == "spec.md" for f in findings)
    paths.plan.write_text(paths.plan.read_text(encoding="utf-8") + "\n- new component\n", encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert any(f.check == "A11" and f.location == "plan.md" for f in findings)


def test_a9_severity_follows_implementation_state(engine, agent_repo, agent_feature):
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    a9 = {f.location.split("#")[1]: f for f in findings if f.check == "A9"}
    assert a9["CR-001"].severity == "high"     # tasks done, guards a critical goal
    assert a9["CR-003"].severity == "high"     # tasks done, guards a critical goal
    assert a9["CR-002"].severity == "low" and "not started" in a9["CR-002"].summary


def test_missing_task_is_a8_and_prose_mentions_do_not_count(engine, agent_repo, agent_feature):
    tasks = agent_feature / "tasks.md"
    tasks.write_text(tasks.read_text(encoding="utf-8").replace("[CR-002]", "for CR-002"), encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert any(f.check == "A8" and "CR-002" in f.summary for f in findings)
    parsed = {t["id"]: t for t in engine.parse_tasks(tasks)}
    assert parsed["T013"]["crs"] == [] and parsed["T013"]["mentions"] == ["CR-002"]


def configure_otm(engine, repo: Path, feature: Path) -> Path:
    """Copy the generic OTM fixture next to the feature and point model.otm at it."""
    import shutil
    dst = feature / "model.otm.yaml"
    shutil.copy(Path(__file__).parent / "fixtures" / "otm" / "model.otm.yaml", dst)
    ext = repo / ".specify" / "extensions" / "attacktree"
    ext.mkdir(parents=True, exist_ok=True)
    (ext / "attacktree-config.yml").write_text("model:\n  otm: model.otm.yaml\n", encoding="utf-8")
    return dst


def test_otm_is_optional_and_off_by_default(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    assert paths.otm is None and paths.as_dict()["OTM"] is None
    assert [s["path"] for s in engine.sources_for(paths)] == ["spec.md", "plan.md"]
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert not any(f.check == "A13" for f in findings)


def test_link_to_unknown_threat_is_a13_when_an_otm_file_is_configured(engine, agent_repo, agent_feature):
    configure_otm(engine, agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    paths = engine.Paths(agent_repo, agent_feature, cfg["model"]["otm"])
    assert paths.otm and paths.otm.exists()
    model = engine.load_model(paths.model)
    next(g for g in model["goals"] if g["id"] == "goal.forge-ticket")["links"] = {"threats": ["threat.does-not-exist"]}
    next(g for g in model["goals"] if g["id"] == "goal.exfiltrate-documents")["links"] = {"threats": ["threat.rag-poisoning"], "mitigations": ["mitigation.context-isolation"]}
    model["attacktree"]["sources"] = engine.sources_for(paths)
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _ = engine.run_checks(paths, cfg)
    a13 = [f for f in findings if f.check == "A13"]
    assert len(a13) == 1 and "threat.does-not-exist" in a13[0].summary and "model.otm.yaml" in a13[0].summary
    assert not any(f.check == "A11" for f in findings)
    paths.otm.write_text(paths.otm.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    findings, _ = engine.run_checks(paths, cfg)
    assert any(f.check == "A11" and f.location == "model.otm.yaml" for f in findings)


def test_a9_low_findings_are_aggregated(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    paths.tasks.unlink()
    model = engine.load_model(paths.model)
    for i in range(6, 10):
        model["requirements"].append({"id": f"CR-00{i}", "statement": "x MUST y", "controls": ["control.rate-limit"]})
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    a9 = [f for f in findings if f.check == "A9"]
    assert len(a9) == 1 and "9 requirements" in a9[0].summary


def test_strict_flag_is_reflected_in_report_and_exit_code(engine, agent_repo, agent_feature, capsys):
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "check", "--format", "json", "--strict"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["enforcement"] == "strict"
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "check", "--format", "md", "--persist"])
    assert "Enforcement: `warn`" in capsys.readouterr().out
    assert (agent_feature / "security" / "attacktree-check-report.md").exists()


def test_report_md_has_table_and_next_actions(engine, agent_repo, agent_feature):
    findings, metrics, paths = run_check(engine, agent_repo, agent_feature)
    md = engine.report_md(findings, metrics, paths, "warn")
    assert "| ID | Check | Severity |" in md and "**Next actions**" in md and "goals by residual risk" in md


def test_source_hash_is_line_ending_independent(engine, agent_repo, agent_feature):
    lf = {n: engine.source_hash(agent_feature / n) for n in ("spec.md", "plan.md")}
    for n in lf:
        raw = (agent_feature / n).read_bytes()
        (agent_feature / n).write_bytes(raw.replace(b"\n", b"\r\n"))
    crlf = {n: engine.source_hash(agent_feature / n) for n in lf}
    assert crlf == lf
    findings, _, _ = run_check(engine, agent_repo, agent_feature)
    assert "A11" not in checks(findings)


def test_yaml_parse_error_is_reported_cleanly(engine, tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("nodes:\n  - name: [NEEDS CLARIFICATION: unquoted marker\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        engine.load_yaml(bad)
    assert "YAML parse error" in str(exc.value) and "quote" in str(exc.value)


# --------------------------------------------------------------------------- simulation

def test_schneier_propagation_rules(engine, agent_repo, agent_feature):
    sim = sim_for(engine, agent_repo, agent_feature)
    goals = {g["id"]: g for g in sim["goals"]}
    # OR takes the best child, controls scale the subtree: 70 × 0.5 (hijack) → 35; AND multiplies: 60×0.5=30 × 80 → 24
    ex = goals["goal.exfiltrate-documents"]
    assert ex["likelihood"] == 24.0 and ex["likelihood_level"] == "medium" and ex["risk"] == "high"
    assert ex["most_likely_path"] == ["node.answer-leak", "node.inject-via-question"]
    assert ex["path_count"] == 3  # {doc, answer-leak} has no common actor and is dropped
    assert ex["strongest_actor"] == "actor.employee"
    assert ex["choke_points"] == ["node.egress", "node.hijack-agent"]
    # OR goal: cheapest vs most likely differ
    ft = goals["goal.forge-ticket"]
    assert ft["likelihood"] == 55.0 and ft["most_likely_path"] == ["node.phish-employee"]
    assert ft["cheapest_path"] == ["node.replay-token"] and ft["cheapest_cost"] == 0
    assert ft["uncontrolled_paths"] == 2
    # ticket confirmation (high → ×0.2) on the leaf: 45 → 9
    assert next(p for p in ft["paths"] if p["leaves"] == ["node.unconfirmed-ticket"])["likelihood"] == 9.0
    ds = goals["goal.disrupt-service"]
    assert ds["likelihood"] == 85.0 and ds["risk"] == "high"
    assert sim["blocking_goals"] == [] and sim["decided_goals"] == ["goal.disrupt-service"]


def test_actor_capabilities_filter_leaves(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    leaf = next(n for n in model["nodes"] if n["id"] == "node.inject-via-question")  # requires authenticated
    outsider = next(a for a in model["actors"] if a["id"] == "actor.outsider")
    employee = next(a for a in model["actors"] if a["id"] == "actor.employee")
    assert not engine.leaf_feasible(leaf, outsider, scales) and engine.leaf_feasible(leaf, employee, scales)
    phish = next(n for n in model["nodes"] if n["id"] == "node.phish-employee")  # requires illegal, costs 500
    assert engine.leaf_feasible(phish, outsider, scales)
    outsider["capabilities"]["risk_appetite"] = "low"
    assert not engine.leaf_feasible(phish, outsider, scales)
    outsider["capabilities"]["risk_appetite"] = "high"
    phish["attack"]["cost"] = 1_000_000  # extensive tier > substantial
    assert not engine.leaf_feasible(phish, outsider, scales)
    hard = {"attack": {"complexity": "extreme"}}
    assert not engine.leaf_feasible(hard, employee, scales)
    assert engine.leaf_feasible(hard, {"id": "actor.x"}, scales)  # unrated actor: no constraint


def test_scenarios_apply_and_remove(engine, agent_repo, agent_feature):
    current = {g["id"]: g["likelihood"] for g in sim_for(engine, agent_repo, agent_feature)["goals"]}
    planned = {g["id"]: g["likelihood"] for g in sim_for(engine, agent_repo, agent_feature, scenario="planned")["goals"]}
    assert planned["goal.exfiltrate-documents"] == 3.5 < current["goal.exfiltrate-documents"]  # visibility filter eliminates answer-leak
    applied = sim_for(engine, agent_repo, agent_feature, apply=["control.rate-limit"])
    assert {g["id"]: g["likelihood"] for g in applied["goals"]}["goal.disrupt-service"] == 17.0
    removed = sim_for(engine, agent_repo, agent_feature, remove=["control.untrusted-context-delimiting"])
    assert {g["id"]: g["likelihood"] for g in removed["goals"]}["goal.exfiltrate-documents"] == 48.0
    verified = sim_for(engine, agent_repo, agent_feature, scenario="verified")
    assert verified["active_controls"] == []
    with pytest.raises(SystemExit):
        sim_for(engine, agent_repo, agent_feature, apply=["control.nope"])


def test_what_if_roadmap_and_single_points_of_failure(engine, agent_repo, agent_feature):
    sim = sim_for(engine, agent_repo, agent_feature)
    what_if = {w["control"]: w for w in sim["what_if"]}
    assert set(what_if) == {"control.rate-limit", "control.short-lived-sessions", "control.visibility-filtered-retrieval"}
    assert what_if["control.rate-limit"]["class"] == "quick win" and what_if["control.rate-limit"]["goals"] == ["goal.disrupt-service"]
    assert sim["what_if"][0]["control"] == "control.rate-limit"  # best efficiency first
    assert [r["control"] for r in sim["roadmap"]] == ["control.rate-limit", "control.short-lived-sessions", "control.visibility-filtered-retrieval"]
    assert sim["roadmap"][-1]["residual"]["goal.exfiltrate-documents"]["likelihood"] == 3.5
    spof = {s["control"]: s for s in sim["single_points_of_failure"]}
    assert spof["control.untrusted-context-delimiting"]["goals"] == ["goal.exfiltrate-documents"]
    assert {(u["goal"], u["node"]) for u in sim["uncovered_choke_points"]} == {("goal.disrupt-service", "node.question-flood"), ("goal.exfiltrate-documents", "node.egress")}


def test_bypass_rate_overrides_effect(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    ctrl = next(c for c in model["controls"] if c["id"] == "control.untrusted-context-delimiting")
    scales = engine.scales_of(engine.load_profiles(["default"]))
    assert engine.control_factor(ctrl, scales) == 0.5
    ctrl["bypass_rate"] = 10
    assert engine.control_factor(ctrl, scales) == 0.1
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    sim = sim_for(engine, agent_repo, agent_feature)
    assert {g["id"]: g["likelihood"] for g in sim["goals"]}["goal.exfiltrate-documents"] == 4.8  # 60 × 0.1 × 0.8


def test_monte_carlo_is_reproducible_and_consistent(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    cfg["simulation"] = {"iterations": 300, "seed": 7, "likelihood_spread": 10}
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(model["attacktree"]["profiles"]))
    a = engine.simulate(model, cfg, scales)["monte_carlo"]
    b = engine.simulate(model, cfg, scales)["monte_carlo"]
    assert a == b and a["iterations"] == 300 and a["probabilistic_controls"] == ["control.untrusted-context-delimiting"]
    ex = a["goals"]["goal.exfiltrate-documents"]
    assert 18 <= ex["mean"] <= 30 and ex["p50"] <= ex["p90"]
    assert a["goals"]["goal.disrupt-service"]["drivers"][0]["node"] == "node.question-flood"
    cfg["simulation"]["iterations"] = 0
    assert engine.simulate(model, cfg, scales)["monte_carlo"]["iterations"] == 0


def test_needs_clarification_and_infeasible_leaves_are_excluded(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    cfg = engine.load_config(agent_repo)
    # the clarification node under the OR egress node never appears in a path
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    assert all("node.admin-export" not in p["leaves"] for g in sim["goals"] for p in g["paths"])
    # an AND goal with an infeasible mandatory step has no path at all
    for n in model["nodes"]:
        if n["id"] in ("node.inject-via-document", "node.inject-via-question"):
            n["attack"]["complexity"] = "extreme"
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    ex = next(g for g in sim["goals"] if g["id"] == "goal.exfiltrate-documents")
    assert ex["feasible"] is False and ex["path_count"] == 0 and ex["risk"] == "low"


def test_simulate_cli_exit_code_reflects_blocking_goals(engine, agent_repo, agent_feature, capsys):
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "simulate", "--no-monte-carlo", "--persist"])
    out = capsys.readouterr().out
    assert rc == 0 and "### Goals" in out and (agent_feature / "security" / "attacktree-simulation.json").exists()
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    next(g for g in model["goals"] if g["id"] == "goal.forge-ticket")["impact"] = {"customer": "critical"}
    for n in model["nodes"]:
        if n["id"] == "node.phish-employee":
            n["attack"]["likelihood"] = 90
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "simulate", "--no-monte-carlo"])
    assert rc == 1 and "**Blocking**" in capsys.readouterr().out


def test_path_enumeration_is_capped(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    for i in range(12):
        model["nodes"].append({"id": f"node.alt-{i}", "name": f"alt {i}", "parent": "node.session-theft",
                               "attack": {"actors": ["actor.outsider"], "complexity": "low", "likelihood": 20 + i}})
    cfg = engine.load_config(agent_repo)
    cfg["risk"]["max_paths"] = 5
    scales = engine.scales_of(engine.load_profiles(["default"]))
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    ft = next(g for g in sim["goals"] if g["id"] == "goal.forge-ticket")
    assert ft["path_count"] == 5 and ft["truncated"] and "node.session-theft" in sim["truncated"]
    assert ft["likelihood"] == 55.0  # the best path survives truncation


# --------------------------------------------------------------------------- merge, render, seed

def test_merge_preserves_human_fields_and_retires(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    existing = engine.load_model(paths.model)
    incoming = json.loads(json.dumps(existing))
    incoming["nodes"] = [n for n in incoming["nodes"] if n["id"] != "node.replay-token"]
    incoming["nodes"].append({"id": "node.new", "name": "New vector", "parent": "node.session-theft",
                              "attack": {"actors": ["actor.outsider"], "complexity": "high"}})
    for c in incoming["controls"]:
        c.pop("status", None); c.pop("evidence", None)
    incoming["controls"][0]["bypass_rate"] = None
    incoming["goals"][0].pop("status", None)
    incoming["decisions"] = []
    merged, stats = engine.merge_models(existing, incoming, paths)
    nodes = {n["id"]: n for n in merged["nodes"]}
    assert nodes["node.replay-token"]["status"] == "retired" and nodes["node.new"]["status"] == "open"
    ctrls = {c["id"]: c for c in merged["controls"]}
    assert ctrls["control.untrusted-context-delimiting"]["status"] == "implemented"
    assert ctrls["control.rate-limit"]["status"] == "proposed" and ctrls["control.rate-limit"]["evidence"] == "assumed"
    assert merged["decisions"] == existing["decisions"]
    assert stats["added"] == 1 and stats["retired"] == 1
    assert merged["attacktree"]["sources"], "sources must be hashed on merge"
    assert engine.schema_validate(merged) == []
    # a clarification marker in the name sets the status
    incoming["nodes"].append({"id": "node.q", "name": "[NEEDS CLARIFICATION: x?]", "parent": "node.egress"})
    merged, _ = engine.merge_models(existing, incoming, paths)
    assert next(n for n in merged["nodes"] if n["id"] == "node.q")["status"] == "needs-clarification"


def test_merge_cli_rejects_invalid_incoming(engine, agent_repo, agent_feature, tmp_path, capsys):
    paths = engine.Paths(agent_repo, agent_feature)
    incoming = engine.load_model(paths.model)
    incoming["controls"][0]["nodes"] = ["node.missing"]
    inc = tmp_path / "incoming.yaml"
    inc.write_text(engine.dump_yaml(incoming), encoding="utf-8")
    before = paths.model.read_text(encoding="utf-8")
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "merge", "--incoming", str(inc)])
    assert rc == 1 and "merge rejected" in capsys.readouterr().err
    assert paths.model.read_text(encoding="utf-8") == before


def test_dump_is_deterministic(engine, agent_feature):
    model = engine.load_yaml(agent_feature / "attack-tree.yaml")
    a = engine.dump_yaml(model)
    shuffled = dict(reversed(list(model.items())))
    shuffled["nodes"] = list(reversed(shuffled["nodes"]))
    assert engine.dump_yaml(shuffled) == a


def test_render_writes_markdown_and_cr_block(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    model = engine.load_model(paths.model)
    md = engine.render_markdown(model, model, paths, cfg)
    assert "```mermaid" in md and "flowchart TD" in md and "**AND** Attacker obtains" in md and "(\"OR · " in md
    assert "### `goal.exfiltrate-documents`" in md and "**Residual risk (current)**: **high**" in md
    assert "### CR-001" in md and "## Roadmap (what-if)" in md and "Single points of failure" in md
    assert "❓" in md  # the clarification node is flagged in the outline
    action = engine.upsert_cr_block(paths.spec, engine.cr_block(model))
    spec = paths.spec.read_text(encoding="utf-8")
    assert action == "inserted"
    assert spec.index(engine.BEGIN_MARK) < spec.index("## Success Criteria")
    assert "**CR-002**" in spec and "Cuts: `goal.exfiltrate-documents` via `control.visibility-filtered-retrieval`" in spec
    action = engine.upsert_cr_block(paths.spec, engine.cr_block(model))
    assert action == "updated" and spec == paths.spec.read_text(encoding="utf-8")
    md2 = engine.render_markdown(model, model, paths, cfg)
    assert md == md2, "rendering is deterministic"


def test_render_cli_respects_config_switches(engine, agent_repo, agent_feature):
    ext = agent_repo / ".specify" / "extensions" / "attacktree"
    ext.mkdir(parents=True)
    (ext / "attacktree-config.yml").write_text("model:\n  write_requirements_to_spec: false\n  diagram: none\n", encoding="utf-8")
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "render"])
    assert rc == 0
    assert engine.BEGIN_MARK not in (agent_feature / "spec.md").read_text(encoding="utf-8")
    assert "```mermaid" not in (agent_feature / "attack-tree.md").read_text(encoding="utf-8")


def test_config_layers_and_env(engine, agent_repo, monkeypatch):
    ext = agent_repo / ".specify" / "extensions" / "attacktree"
    ext.mkdir(parents=True)
    (ext / "attacktree-config.yml").write_text("enforcement: strict\nrisk:\n  max_paths: 50\n", encoding="utf-8")
    (ext / "attacktree-config.local.yml").write_text("risk:\n  scenario: planned\n", encoding="utf-8")
    cfg = engine.load_config(agent_repo)
    assert cfg["enforcement"] == "strict" and cfg["risk"]["max_paths"] == 50 and cfg["risk"]["scenario"] == "planned"
    assert cfg["risk"]["block_on"] == ["critical"]  # untouched default survives the deep merge
    monkeypatch.setenv("SPECKIT_ATTACKTREE_SCENARIO", "verified")
    monkeypatch.setenv("SPECKIT_ATTACKTREE_PROFILES", "default, agentic")
    cfg = engine.load_config(agent_repo)
    assert cfg["risk"]["scenario"] == "verified" and cfg["profiles"] == ["default", "agentic"]


def test_seed_from_otm_file(engine, agent_repo, agent_feature, capsys):
    otm_path = configure_otm(engine, agent_repo, agent_feature)
    otm = engine.load_yaml(otm_path)
    model = engine.seed_from_otm(otm, "007-agent-assistant", "Agent Assistant", ["default"])
    assert model["actors"] == []  # OTM has no actor entity; the model command defines them
    assert {a["id"] for a in model["assets"]} == {"asset.document", "asset.ticket-api-tool"}
    assert next(a for a in model["assets"] if a["id"] == "asset.ticket-api-tool")["type"] == "technical"
    goals = {g["id"]: g for g in model["goals"]}
    assert set(goals) == {"goal.rag-poisoning", "goal.inference-exhaustion"}  # retired threats are skipped
    assert goals["goal.rag-poisoning"]["links"]["threats"] == ["threat.rag-poisoning"]
    assert goals["goal.rag-poisoning"]["impact"] == {"business": "critical"} and goals["goal.rag-poisoning"]["assets"] == ["asset.document"]
    assert engine.schema_validate(model) == [] and engine.reference_errors(model) == []
    # the CLI reads model.otm from the config when --otm is not given
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "seed"])
    assert rc == 0 and "goal.rag-poisoning" in capsys.readouterr().out
    (agent_repo / ".specify" / "extensions" / "attacktree" / "attacktree-config.yml").unlink()
    with pytest.raises(SystemExit):
        engine.main(["--repo", str(agent_repo), "--feature-dir", str(agent_feature), "seed"])


def test_init_creates_skeleton_with_hashes(engine, agent_repo, capsys):
    feature = agent_repo / "specs" / "008-new"
    feature.mkdir()
    (feature / "spec.md").write_text("# Spec\n\n## Success Criteria\n", encoding="utf-8")
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(feature), "init"])
    assert rc == 0
    model = engine.load_model(feature / "attack-tree.yaml")
    assert model["attacktree"]["sources"][0]["path"] == "spec.md" and model["goals"] == []
    rc = engine.main(["--repo", str(agent_repo), "--feature-dir", str(feature), "init"])
    assert rc == 0 and "exists" in capsys.readouterr().out


# --------------------------------------------------------------------------- occurrence, per-node effects, scenarios, retirement

def test_actor_occurrence_weights_paths(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    cfg = engine.load_config(agent_repo)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    next(a for a in model["actors"] if a["id"] == "actor.employee")["occurrence"] = 25
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    goals = {g["id"]: g for g in sim["goals"]}
    # the employee-only path drops to 24 × 0.25 = 6; the outsider path (3.5) is unweighted → best is now 6
    ex = goals["goal.exfiltrate-documents"]
    assert ex["likelihood"] == 6.0 and ex["strongest_actor"] == "actor.employee"
    assert ex["paths"][0]["raw_likelihood"] == 24.0 and ex["paths"][0]["likelihood"] == 6.0
    assert goals["goal.disrupt-service"]["likelihood"] == 21.2  # 85 × 0.25
    assert goals["goal.forge-ticket"]["likelihood"] == 55.0     # outsider paths untouched
    next(a for a in model["actors"] if a["id"] == "actor.employee")["occurrence"] = 100
    assert {g["id"]: g["likelihood"] for g in engine.simulate(model, cfg, scales, with_monte_carlo=False)["goals"]}["goal.exfiltrate-documents"] == 24.0


def test_per_node_control_effects(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    cfg = engine.load_config(agent_repo)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    ctrl = next(c for c in model["controls"] if c["id"] == "control.ticket-confirmation")
    ctrl["effects"] = {"node.unconfirmed-ticket": "eliminates"}          # high elsewhere
    assert engine.control_factor(ctrl, scales) == pytest.approx(0.2)
    assert engine.control_factor(ctrl, scales, "node.unconfirmed-ticket") == 0.0
    assert engine.control_factor(ctrl, scales, "node.ticket-tool-exfil") == pytest.approx(0.2)
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    ft = next(g for g in sim["goals"] if g["id"] == "goal.forge-ticket")
    assert all(p["leaves"] != ["node.unconfirmed-ticket"] for p in ft["paths"]) or \
        next(p for p in ft["paths"] if p["leaves"] == ["node.unconfirmed-ticket"])["likelihood"] == 0.0
    ctrl["effects"] = {"node.not-attached": "low"}
    assert any("not attached" in e for e in engine.reference_errors(model, scales))


def test_scenario_none_is_the_uncontrolled_baseline(engine, agent_repo, agent_feature):
    sim = sim_for(engine, agent_repo, agent_feature, scenario="none")
    assert sim["active_controls"] == []
    assert {g["id"]: g["likelihood"] for g in sim["goals"]}["goal.exfiltrate-documents"] == 48.0
    assert len(sim["what_if"]) == 5


def test_truncation_flag_is_per_goal(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    for i in range(12):
        model["nodes"].append({"id": f"node.alt-{i}", "name": f"alt {i}", "parent": "node.session-theft",
                               "attack": {"actors": ["actor.outsider"], "complexity": "low", "likelihood": 20 + i}})
    cfg = engine.load_config(agent_repo)
    cfg["risk"]["max_paths"] = 5
    sim = engine.simulate(model, cfg, engine.scales_of(engine.load_profiles(["default"])), with_monte_carlo=False)
    flags = {g["id"]: g["truncated"] for g in sim["goals"]}
    assert flags["goal.forge-ticket"] and not flags["goal.exfiltrate-documents"] and not flags["goal.disrupt-service"]


def test_merge_retires_descendants_of_a_retired_node(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    existing = engine.load_model(paths.model)
    incoming = json.loads(json.dumps(existing))
    incoming["nodes"] = [n for n in incoming["nodes"] if n["id"] != "node.session-theft"]  # children still listed
    merged, stats = engine.merge_models(existing, incoming, paths)
    nodes = {n["id"]: n for n in merged["nodes"]}
    assert nodes["node.session-theft"]["status"] == "retired"
    assert nodes["node.phish-employee"]["status"] == "retired" and "Parent" in nodes["node.phish-employee"]["retired_reason"]
    assert nodes["node.replay-token"]["status"] == "retired"
    assert stats["retired"] == 3
    assert engine.reference_errors(merged) == []
    sim = engine.simulate(merged, engine.load_config(agent_repo), engine.scales_of(engine.load_profiles(["default"])), with_monte_carlo=False)
    ft = next(g for g in sim["goals"] if g["id"] == "goal.forge-ticket")
    assert ft["path_count"] == 1  # only the unconfirmed-ticket path survives


def test_sarif_handles_feature_outside_repo(engine, agent_repo, agent_feature, tmp_path):
    outside = tmp_path / "elsewhere" / "specs" / "001-x"
    outside.mkdir(parents=True)
    (outside / "attack-tree.yaml").write_text((agent_feature / "attack-tree.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    paths = engine.Paths(agent_repo, outside)
    findings, _ = engine.run_checks(paths, engine.load_config(agent_repo))
    sarif = json.loads(engine.report_sarif(findings, paths))
    assert sarif["runs"][0]["results"]


# --------------------------------------------------------------------------- review follow-ups

def test_merge_keeps_human_fields_even_when_incoming_restates_them(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    existing = engine.load_model(paths.model)
    ctrl = next(c for c in existing["controls"] if c["id"] == "control.untrusted-context-delimiting")
    ctrl.update({"status": "verified", "evidence": "lab-validated", "bypass_rate": 12, "notes": "measured in sim 3"})
    planned = next(c for c in existing["controls"] if c["id"] == "control.visibility-filtered-retrieval")
    assert planned["status"] == "planned"
    incoming = json.loads(json.dumps(existing))
    for c in incoming["controls"]:  # an over-eager model run restates every control as new
        c.update({"status": "proposed", "evidence": "assumed", "bypass_rate": None}); c.pop("notes", None)
    for g in incoming["goals"]:
        g["status"] = "open"
    merged, _ = engine.merge_models(existing, incoming, paths)
    ctrls = {c["id"]: c for c in merged["controls"]}
    assert ctrls["control.untrusted-context-delimiting"]["status"] == "verified"
    assert ctrls["control.untrusted-context-delimiting"]["evidence"] == "lab-validated"
    assert ctrls["control.untrusted-context-delimiting"]["bypass_rate"] == 12
    assert ctrls["control.untrusted-context-delimiting"]["notes"] == "measured in sim 3"
    assert ctrls["control.visibility-filtered-retrieval"]["status"] == "planned"
    assert {g["id"]: g["status"] for g in merged["goals"]}["goal.disrupt-service"] == "open"  # no decision status was set on the goal itself
    assert engine.schema_validate(merged) == []


def test_merge_revives_a_retired_node_that_reappears_and_keeps_extends(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    existing = engine.load_model(paths.model)
    existing["attacktree"]["extends"] = "../../.specify/memory/attack-tree.yaml"
    node = next(n for n in existing["nodes"] if n["id"] == "node.replay-token")
    node["status"] = "retired"; node["retired_reason"] = "gone"
    incoming = json.loads(json.dumps(existing))
    incoming["attacktree"]["extends"] = None
    next(n for n in incoming["nodes"] if n["id"] == "node.replay-token").pop("status")
    merged, _ = engine.merge_models(existing, incoming, paths)
    revived = next(n for n in merged["nodes"] if n["id"] == "node.replay-token")
    assert revived["status"] == "open" and "retired_reason" not in revived
    assert merged["attacktree"]["extends"] == "../../.specify/memory/attack-tree.yaml"


def test_goal_reachable_only_through_open_questions_is_unknown(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    cfg = engine.load_config(agent_repo)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    # a question under the AND goal is left out, the goal is still rated
    next(n for n in model["nodes"] if n["id"] == "node.admin-export")["parent"] = "goal.exfiltrate-documents"
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    ex = next(g for g in sim["goals"] if g["id"] == "goal.exfiltrate-documents")
    assert ex["likelihood"] == 24.0 and ex["unknown"] is False and ex["assumed"] == ["node.admin-export"]
    assert "Evaluated without these open questions" in engine.simulation_md(sim, "f")
    # a goal whose only child is a question is unknown, never low
    model["nodes"].append({"id": "node.q-only", "name": "[NEEDS CLARIFICATION: is there an export?]", "parent": "goal.disrupt-service", "status": "needs-clarification"})
    for n in model["nodes"]:
        if n["id"] == "node.question-flood":
            n["parent"] = "node.q-only-parent"
    model["nodes"].append({"id": "node.q-only-parent", "name": "unreachable", "parent": "goal.forge-ticket"})  # move the flood leaf away
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    ds = next(g for g in sim["goals"] if g["id"] == "goal.disrupt-service")
    assert ds["unknown"] is True and ds["risk"] == "unknown" and ds["likelihood_level"] == "unknown" and ds["path_count"] == 0
    assert sim["unknown_goals"] == ["goal.disrupt-service"] and "goal.disrupt-service" not in sim["blocking_goals"]
    md = engine.render_markdown(model, model, paths, cfg)
    assert "runs through an open question" in md


def test_unknown_goal_is_never_mitigated_by_converge(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    model["decisions"] = []
    for n in model["nodes"]:
        if n["id"] == "node.question-flood":
            n["status"] = "needs-clarification"; n["name"] = "[NEEDS CLARIFICATION: flood?]"
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    vf = agent_feature / "security" / "attacktree-verdicts.yaml"; vf.parent.mkdir(exist_ok=True)
    vf.write_text(yaml.safe_dump({"verdicts": [
        {"requirement": rid, "verdict": "verified", "method": "test", "evidence": f"tests/x.py::{rid}", "result": "pass"}
        for rid in ("CR-001", "CR-002", "CR-003", "CR-004", "CR-005")]}), encoding="utf-8")
    engine.converge_apply(paths, engine.load_config(agent_repo), vf, commit="x")
    statuses = {g["id"]: g["status"] for g in engine.load_model(paths.model)["goals"]}
    assert statuses["goal.disrupt-service"] == "open" and statuses["goal.forge-ticket"] == "mitigated"


def test_agentic_profile_alone_still_has_default_scales(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    model["attacktree"]["profiles"] = ["agentic"]
    scales = engine.scales_of(engine.load_profiles(["agentic"]))
    assert "authenticated" in scales["requires"] and scales["complexity"]["extreme"]["skill"] == "expert"
    assert engine.reference_errors(model, scales) == []


def test_converge_promotes_planned_controls_from_evidence_and_scopes_bypass_rates(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    cfg = engine.load_config(agent_repo)
    # CR-003's control is deterministic; CR-001's is probabilistic
    vf = agent_feature / "security" / "attacktree-verdicts.yaml"; vf.parent.mkdir(exist_ok=True)
    vf.write_text(yaml.safe_dump({"verdicts": [
        {"requirement": "CR-002", "verdict": "implemented-unverified", "method": "review", "evidence": "src/retrieval/retriever.py:10"},
        {"requirement": "CR-003", "verdict": "verified", "method": "simulation", "evidence": "security/sim.md", "result": "pass", "bypass_rate": 5},
        {"requirement": "CR-001", "verdict": "verified", "method": "simulation", "evidence": "security/sim.md", "result": "pass", "bypass_rate": 12},
    ]}), encoding="utf-8")
    engine.converge_apply(paths, cfg, vf, commit="x")
    ctrls = {c["id"]: c for c in engine.load_model(paths.model)["controls"]}
    assert ctrls["control.visibility-filtered-retrieval"]["status"] == "implemented"   # was planned, code found
    assert ctrls["control.visibility-filtered-retrieval"]["evidence"] == "design-reviewed"
    assert ctrls["control.ticket-confirmation"]["status"] == "verified" and ctrls["control.ticket-confirmation"].get("bypass_rate") is None
    assert ctrls["control.untrusted-context-delimiting"]["bypass_rate"] == 12
    assert ctrls["control.rate-limit"]["status"] == "proposed"  # no verdict → untouched


# --------------------------------------------------------------------------- adversarial review follow-ups

def base_model(engine):
    return {"attacktree": {"version": "0.1", "profiles": ["default"]}, "project": {"id": "p", "name": "p"},
            "actors": [{"id": "actor.x", "name": "x", "capabilities": {"skill": "expert", "resources": "extensive", "access": "privileged", "risk_appetite": "high"}},
                       {"id": "actor.y", "name": "y", "capabilities": {"skill": "expert", "resources": "extensive", "access": "privileged", "risk_appetite": "high"}}],
            "goals": [], "nodes": [], "controls": [], "requirements": [], "verification": [], "decisions": []}


def leaf(nid, parent, actors, lk, **extra):
    return {"id": nid, "name": nid, "parent": parent, "attack": {"actors": actors, "complexity": "low", "likelihood": lk, **extra}}


def test_path_cap_keeps_every_actors_best_paths_for_parent_and(engine):
    m = base_model(engine)
    m["goals"] = [{"id": "goal.g", "name": "g", "gate": "and", "impact": "critical"}]
    m["nodes"] = [{"id": "node.a", "name": "a", "parent": "goal.g", "gate": "or"}, {"id": "node.b", "name": "b", "parent": "goal.g", "gate": "or"}]
    m["nodes"] += [leaf(f"node.a{i}", "node.a", ["actor.x"], 90) for i in range(5)]
    m["nodes"] += [leaf("node.a9", "node.a", ["actor.y"], 80), leaf("node.b1", "node.b", ["actor.y"], 95)]
    scales = engine.scales_of(engine.load_profiles(["default"]))
    cfg = {"risk": {"block_on": ["critical"], "max_paths": 3}, "simulation": {"iterations": 0}}
    g = engine.simulate(m, cfg, scales, with_monte_carlo=False)["goals"][0]
    assert g["feasible"] and g["likelihood"] == 76.0 and g["risk"] == "critical" and g["truncated"]


def test_truncation_is_reported_as_a16(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    for i in range(12):
        model["nodes"].append(leaf(f"node.alt-{i}", "node.session-theft", ["actor.outsider"], 20 + i))
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    ext = agent_repo / ".specify" / "extensions" / "attacktree"; ext.mkdir(parents=True)
    (ext / "attacktree-config.yml").write_text("risk:\n  max_paths: 5\n", encoding="utf-8")
    findings, _ = engine.run_checks(paths, engine.load_config(agent_repo))
    assert any(f.check == "A16" and "goal.forge-ticket" in f.location for f in findings)


def test_expired_decisions_protect_nothing(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    model["decisions"][0]["expires"] = "2020-01-01"
    next(g for g in model["goals"] if g["id"] == "goal.disrupt-service")["impact"] = {"business": "critical"}
    model["controls"] = [c for c in model["controls"] if c["id"] != "control.rate-limit"]
    model["requirements"] = [r for r in model["requirements"] if r["id"] != "CR-005"]
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    cfg = engine.load_config(agent_repo)
    findings, _ = engine.run_checks(paths, cfg)
    assert any(f.check == "A6" and "goal.disrupt-service" in f.location for f in findings)
    assert any(f.check == "A10" and "expired" in f.summary for f in findings)
    sim = engine.simulate(model, cfg, engine.scales_of(engine.load_profiles(["default"])), with_monte_carlo=False)
    assert "goal.disrupt-service" in sim["blocking_goals"]
    vf = agent_feature / "security" / "attacktree-verdicts.yaml"; vf.parent.mkdir(exist_ok=True)
    vf.write_text(yaml.safe_dump({"verdicts": []}), encoding="utf-8")
    engine.converge_apply(paths, cfg, vf, commit="x")
    assert {g["id"]: g["status"] for g in engine.load_model(paths.model)["goals"]}["goal.disrupt-service"] == "open"
    md = engine.render_markdown(engine.load_model(paths.model), engine.load_model(paths.model), paths, cfg)
    assert "(expired)" in md


def test_node_level_decision_accepts_only_those_paths(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    next(g for g in model["goals"] if g["id"] == "goal.forge-ticket")["impact"] = {"customer": "critical"}
    for n in model["nodes"]:
        if n["id"] == "node.phish-employee":
            n["attack"]["likelihood"] = 90
    model["decisions"].append({"id": "decision.phish", "target": "node.session-theft", "status": "accepted", "owner": "@x",
                               "rationale": "SSO team owns phishing", "expires": "2099-01-01"})
    scales = engine.scales_of(engine.load_profiles(["default"]))
    sim = engine.simulate(model, engine.load_config(agent_repo), scales, with_monte_carlo=False)
    ft = next(g for g in sim["goals"] if g["id"] == "goal.forge-ticket")
    assert ft["likelihood"] == 90.0 and ft["risk"] == "critical"            # reality is unchanged
    assert ft["accepted_paths"] == 2 and ft["residual_risk"] != "critical"  # but the accepted paths do not block
    assert "goal.forge-ticket" not in sim["blocking_goals"]
    assert "(accepted)" in engine.simulation_md(sim, "f")


def test_monte_carlo_respects_per_node_effects(engine):
    m = base_model(engine)
    m["goals"] = [{"id": "goal.g", "name": "g", "impact": "high"}]
    m["nodes"] = [leaf("node.l", "goal.g", ["actor.x"], 80)]
    m["controls"] = [{"id": "control.c", "name": "c", "nodes": ["node.l"], "effect": "low", "effects": {"node.l": "eliminates"},
                      "probabilistic": True, "status": "implemented"}]
    scales = engine.scales_of(engine.load_profiles(["default"]))
    cfg = {"risk": {"block_on": ["critical"], "max_paths": 50}, "simulation": {"iterations": 200, "seed": 3, "likelihood_spread": 0}}
    sim = engine.simulate(m, cfg, scales)
    assert sim["goals"][0]["likelihood"] == 0.0
    assert sim["monte_carlo"]["goals"]["goal.g"]["mean"] == 0.0
    m["controls"][0]["effects"] = {"node.l": "high"}
    mc = engine.simulate(m, cfg, scales)["monte_carlo"]["goals"]["goal.g"]
    assert 5 <= mc["mean"] <= 30  # around 80 × 0.2 = 16, jittered


def test_partial_capabilities_do_not_make_everything_infeasible(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    actor = next(a for a in model["actors"] if a["id"] == "actor.employee")
    actor["capabilities"] = {"access": "user"}
    lf = next(n for n in model["nodes"] if n["id"] == "node.question-flood")
    assert engine.leaf_feasible(lf, actor, scales)
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    findings, _ = engine.run_checks(paths, engine.load_config(agent_repo))
    a15 = next(f for f in findings if f.check == "A15" and "actor.employee" in f.location)
    assert "skill" in a15.summary and "resources" in a15.summary


def test_interior_clarification_node_hides_its_subtree(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    next(n for n in model["nodes"] if n["id"] == "node.session-theft")["status"] = "needs-clarification"
    sim = engine.simulate(model, engine.load_config(agent_repo), engine.scales_of(engine.load_profiles(["default"])), with_monte_carlo=False)
    ft = next(g for g in sim["goals"] if g["id"] == "goal.forge-ticket")
    assert ft["path_count"] == 1 and ft["assumed"] == ["node.session-theft"] and ft["likelihood"] == 9.0


def test_retiring_a_goal_or_interior_node_by_hand_retires_its_subtree(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    next(g for g in model["goals"] if g["id"] == "goal.forge-ticket")["status"] = "retired"
    next(n for n in model["nodes"] if n["id"] == "node.egress")["status"] = "retired"
    assert engine.reference_errors(model, scales) == []
    tree = engine.Tree(model)
    assert "goal.forge-ticket" not in tree.goals and "node.phish-employee" not in tree.nodes and "node.answer-leak" not in tree.nodes
    sim = engine.simulate(model, engine.load_config(agent_repo), scales, with_monte_carlo=False)
    assert {g["id"] for g in sim["goals"]} == {"goal.exfiltrate-documents", "goal.disrupt-service"}
    ex = next(g for g in sim["goals"] if g["id"] == "goal.exfiltrate-documents")
    assert ex["feasible"] and ex["likelihood"] == 35.0 and all(set(p["leaves"]) <= {"node.inject-via-document", "node.inject-via-question"} for p in ex["paths"])


def test_converge_follows_reverse_requirement_links(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    next(r for r in model["requirements"] if r["id"] == "CR-005")["controls"] = ["control.short-lived-sessions"]
    next(c for c in model["controls"] if c["id"] == "control.rate-limit")["requirements"] = ["CR-005"]
    paths.model.write_text(engine.dump_yaml(model), encoding="utf-8")
    vf = agent_feature / "security" / "attacktree-verdicts.yaml"; vf.parent.mkdir(exist_ok=True)
    vf.write_text(yaml.safe_dump({"verdicts": [{"requirement": "CR-005", "verdict": "verified", "method": "test", "evidence": "tests/x.py::t", "result": "pass"}]}), encoding="utf-8")
    engine.converge_apply(paths, engine.load_config(agent_repo), vf, commit="x")
    ctrls = {c["id"]: c for c in engine.load_model(paths.model)["controls"]}
    assert ctrls["control.rate-limit"]["status"] == "verified"               # linked only through its own requirements list
    assert ctrls["control.short-lived-sessions"]["status"] == "implemented"  # CR-005 verified, CR-004 still open


def test_seed_normalises_foreign_ids(engine):
    otm = {"project": {"id": "x", "name": "X"}, "assets": [{"id": "Customer DB", "name": "Customer DB"}],
           "threats": [{"id": "T-001", "name": "Dump the DB", "risk": {"impact": 90}, "attributes": {"assets": ["Customer DB"]}}]}
    model = engine.seed_from_otm(otm, "x", "X", ["default"])
    assert model["assets"][0]["id"] == "asset.customer-db"
    assert model["goals"][0]["id"] == "goal.t-001" and model["goals"][0]["assets"] == ["asset.customer-db"]
    assert engine.schema_validate(model) == [] and engine.reference_errors(model) == []


def test_apply_rejected_control_is_refused_and_level_matches_display(engine, agent_repo, agent_feature):
    paths = engine.Paths(agent_repo, agent_feature)
    model = engine.load_model(paths.model)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    cfg = engine.load_config(agent_repo)
    next(c for c in model["controls"] if c["id"] == "control.rate-limit")["status"] = "rejected"
    with pytest.raises(SystemExit):
        engine.simulate(model, cfg, scales, apply=["control.rate-limit"], with_monte_carlo=False)
    next(a for a in model["actors"] if a["id"] == "actor.employee")["occurrence"] = 74
    for n in model["nodes"]:
        if n["id"] == "node.question-flood":
            n["attack"]["likelihood"] = 54
    ds = next(g for g in engine.simulate(model, cfg, scales, with_monte_carlo=False)["goals"] if g["id"] == "goal.disrupt-service")
    assert ds["likelihood"] == 40.0 and ds["likelihood_level"] == "high"  # level computed from the displayed value


def test_init_stores_posix_baseline_path(engine, agent_repo, capsys):
    (agent_repo / ".specify" / "memory").mkdir(parents=True)
    (agent_repo / ".specify" / "memory" / "attack-tree.yaml").write_text("attacktree: {version: '0.1'}\nproject: {id: base, name: base}\n", encoding="utf-8")
    feature = agent_repo / "specs" / "009-new"; feature.mkdir()
    (feature / "spec.md").write_text("# Spec\n", encoding="utf-8")
    assert engine.main(["--repo", str(agent_repo), "--feature-dir", str(feature), "init"]) == 0
    model = engine.load_model(feature / "attack-tree.yaml")
    assert model["attacktree"]["extends"] == "../../.specify/memory/attack-tree.yaml"
    assert engine.load_baseline(model, feature / "attack-tree.yaml")["project"]["id"] == "base"


def test_zero_likelihood_is_low_risk_even_for_critical_goals(engine, agent_repo, agent_feature):
    sim = sim_for(engine, agent_repo, agent_feature, apply=["control.visibility-filtered-retrieval"], scenario="none")
    ex = next(g for g in sim["goals"] if g["id"] == "goal.exfiltrate-documents")
    assert ex["impact"] == "critical" and ex["likelihood"] > 0 and ex["risk"] in ("medium", "high")
    m = engine.load_model(engine.Paths(agent_repo, agent_feature).model)
    for n in m["nodes"]:
        if n.get("attack"):
            n["attack"]["likelihood"] = 0
    scales = engine.scales_of(engine.load_profiles(["default"]))
    sim = engine.simulate(m, engine.load_config(agent_repo), scales, with_monte_carlo=False)
    assert all(g["likelihood"] == 0.0 and g["risk"] == "low" for g in sim["goals"])
