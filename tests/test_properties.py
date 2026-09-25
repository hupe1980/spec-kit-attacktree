"""Randomised invariants of the propagation rules (seeded, so failures reproduce)."""
import random

import pytest

SCALE = {"skill": ["novice", "intermediate", "advanced", "expert"], "resources": ["minimal", "moderate", "substantial", "extensive"],
         "access": ["external", "user", "insider", "privileged"], "risk_appetite": ["low", "medium", "high"]}
COMPLEXITY = ["trivial", "low", "medium", "high", "extreme"]


def random_tree(rng: random.Random, goals=3, depth=3, fanout=3):
    actors = [{"id": f"actor.a{i}", "name": f"A{i}",
               "capabilities": {k: rng.choice(v) for k, v in SCALE.items()},
               **({"occurrence": rng.randint(10, 100)} if rng.random() < 0.5 else {})} for i in range(3)]
    nodes, controls, counter = [], [], [0]

    def build(parent, d):
        n = fanout if d == 0 else rng.randint(1, fanout)
        for _ in range(n):
            counter[0] += 1
            nid = f"node.n{counter[0]}"
            if d >= depth - 1 or rng.random() < 0.35:
                nodes.append({"id": nid, "name": nid, "parent": parent, "attack": {
                    "actors": rng.sample([a["id"] for a in actors], rng.randint(1, 3)),
                    "complexity": rng.choice(COMPLEXITY), "likelihood": rng.randint(1, 100),
                    "cost": rng.choice([0, 100, 5000, 50000]),
                    "requires": rng.sample(["authenticated", "illegal", "special-equipment"], rng.randint(0, 2))}})
            else:
                nodes.append({"id": nid, "name": nid, "parent": parent, "gate": rng.choice(["or", "and"])})
                build(nid, d + 1)

    gs = []
    for g in range(goals):
        gid = f"goal.g{g}"
        gs.append({"id": gid, "name": gid, "gate": rng.choice(["or", "and"]), "impact": rng.choice(["low", "medium", "high", "critical"])})
        build(gid, 0)
    targets = [n["id"] for n in nodes] + [g["id"] for g in gs]
    for i in range(rng.randint(2, 8)):
        controls.append({"id": f"control.c{i}", "name": f"C{i}", "nodes": rng.sample(targets, rng.randint(1, 3)),
                         "effect": rng.choice(["low", "medium", "high", "eliminates"]), "cost": rng.choice(["low", "medium", "high"]),
                         "status": rng.choice(["proposed", "planned", "implemented", "verified"]), "requirements": []})
    return {"attacktree": {"version": "0.1", "profiles": ["default"]}, "project": {"id": "p", "name": "p"},
            "actors": actors, "goals": gs, "nodes": nodes, "controls": controls, "requirements": [], "verification": [], "decisions": []}


@pytest.mark.parametrize("seed", range(40))
def test_propagation_invariants(engine, seed):
    rng = random.Random(seed)
    model = random_tree(rng)
    assert engine.schema_validate(model) == [] and engine.reference_errors(model) == []
    scales = engine.scales_of(engine.load_profiles(["default"]))
    cfg = {"risk": {"block_on": ["critical"], "scenario": "current", "max_paths": 500}, "simulation": {"iterations": 0}}
    none = {g["id"]: g for g in engine.simulate(model, cfg, scales, scenario="none", with_monte_carlo=False)["goals"]}
    cur = {g["id"]: g for g in engine.simulate(model, cfg, scales, scenario="current", with_monte_carlo=False)["goals"]}
    every = {g["id"]: g for g in engine.simulate(model, cfg, scales, scenario="all", with_monte_carlo=False)["goals"]}
    for gid in none:
        # controls never raise likelihood, and more active controls never raise it either
        assert none[gid]["likelihood"] >= cur[gid]["likelihood"] >= every[gid]["likelihood"]
        for snap in (none[gid], cur[gid], every[gid]):
            assert 0.0 <= snap["likelihood"] <= 100.0
            if snap["paths"]:
                # goal likelihood is the best path; paths are sorted; weighted never exceeds raw
                assert snap["likelihood"] == max(p["likelihood"] for p in snap["paths"])
                lks = [p["likelihood"] for p in snap["paths"]]
                assert lks == sorted(lks, reverse=True)  # rounded values are non-increasing; ties keep the engine's cost/leaf order
                assert all(p["likelihood"] <= p["raw_likelihood"] + 1e-9 for p in snap["paths"])
                assert all(p["actors"] for p in snap["paths"])
                # every path is a genuine cut set: feasible for a common actor, leaves under the goal
                tree = engine.Tree(model)
                assert all(tree.goal_of[l] == gid for p in snap["paths"] for l in p["leaves"])
                # choke points lie on every path
                assert all(all(c in p["nodes"] for p in snap["paths"]) for c in snap["choke_points"])
            else:
                assert snap["likelihood"] == 0.0 and not snap["feasible"]
    # what-if: applying a control never increases risk, roadmap steps are monotone
    sim = engine.simulate(model, cfg, scales, with_monte_carlo=False)
    for w in sim["what_if"]:
        assert w["risk_reduction"] >= -1e-9 and w["depth_reduction"] >= -1e-9
    prev = None
    for step in sim["roadmap"]:
        total = sum(v["likelihood"] for v in step["residual"].values())
        assert prev is None or total <= prev + 1e-9
        prev = total
    # determinism
    assert engine.simulate(model, cfg, scales, with_monte_carlo=False) == sim


def test_and_of_or_matches_hand_computation(engine):
    scales = engine.scales_of(engine.load_profiles(["default"]))
    model = {"attacktree": {"version": "0.1"}, "project": {"id": "p", "name": "p"},
             "actors": [{"id": "actor.x", "name": "x", "capabilities": {"skill": "expert", "resources": "extensive", "access": "privileged", "risk_appetite": "high"}}],
             "goals": [{"id": "goal.g", "name": "g", "gate": "and", "impact": "high"}],
             "nodes": [{"id": "node.a", "name": "a", "parent": "goal.g", "gate": "or"},
                       {"id": "node.a1", "name": "a1", "parent": "node.a", "attack": {"actors": ["actor.x"], "complexity": "low", "likelihood": 80}},
                       {"id": "node.a2", "name": "a2", "parent": "node.a", "attack": {"actors": ["actor.x"], "complexity": "low", "likelihood": 30, "cost": 10}},
                       {"id": "node.b", "name": "b", "parent": "goal.g", "attack": {"actors": ["actor.x"], "complexity": "low", "likelihood": 50, "cost": 100}}],
             "controls": [{"id": "control.c", "name": "c", "nodes": ["node.a"], "effect": "high", "status": "implemented"},
                          {"id": "control.g", "name": "g", "nodes": ["goal.g"], "effect": "low", "status": "implemented"}],
             "requirements": [], "verification": [], "decisions": []}
    cfg = {"risk": {"block_on": ["critical"], "max_paths": 50}, "simulation": {"iterations": 0}}
    g = engine.simulate(model, cfg, scales, with_monte_carlo=False)["goals"][0]
    # a: max(80, 30) × 0.2 = 16; goal: 16 × 50/100 = 8 × 0.75 (goal-level control) = 6
    assert g["likelihood"] == 6.0
    assert g["paths"][0]["leaves"] == ["node.a1", "node.b"] and g["paths"][0]["cost"] == 100
    assert g["cheapest_path"] == ["node.a1", "node.b"]  # a2 is cheaper alone but the AND adds b's cost either way: 110 vs 100
    assert g["choke_points"] == ["node.a", "node.b"]


def test_large_tree_stays_fast(engine):
    rng = random.Random(7)
    model = random_tree(rng, goals=8, depth=4, fanout=4)
    scales = engine.scales_of(engine.load_profiles(["default"]))
    cfg = {"risk": {"block_on": ["critical"], "max_paths": 200}, "simulation": {"iterations": 300, "seed": 1, "likelihood_spread": 15}}
    import time
    t = time.perf_counter()
    sim = engine.simulate(model, cfg, scales)
    elapsed = time.perf_counter() - t
    leaves = sum(1 for n in model["nodes"] if "attack" in n)
    assert leaves >= 60 and sim["goals"]
    assert elapsed < 20, f"{leaves} leaves took {elapsed:.1f}s"
