#!/usr/bin/env python3
"""AttackTree engine — deterministic core for the Spec Kit AttackTree extension.

Subcommands
  paths           Resolve repo root, feature directory and artifact paths
  init            Create an empty attack-tree.yaml for a feature
  seed            Derive assets and candidate goals from an Open Threat Model (OTM) file
  validate        Validate a tree against the schema, reference rules and tree structure
  merge           Merge an LLM-produced tree into the existing one (stable ids, human fields kept)
  render          Render attack-tree.md and the CR block inside spec.md
  check           Run gap checks A1–A15 (md | json | sarif), exit code reflects severity
  simulate        Attack paths per actor, residual risk, choke points, what-if roadmap, Monte Carlo
  converge-scan   Collect per-requirement evidence facts for the converge command
  converge-apply  Record verdicts, roll up control status, write the convergence report, append tasks

Semantics follow Schneier's attack trees: OR nodes take the best (most likely, cheapest) child,
AND nodes need every child (likelihoods multiply, costs add). Leaves are attack vectors rated with
complexity, cost and likelihood and feasible only for actors whose capabilities suffice. Controls
attached to a node scale the likelihood of everything below it. Only the standard library plus
PyYAML are required; `jsonschema` is used when available.
"""
from __future__ import annotations

import argparse
import copy
import datetime as _dt
import hashlib
import json
import math
import os
import random
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("attacktree: PyYAML is required (pip install pyyaml, or run via uv: uv run --with pyyaml ...)\n")
    sys.exit(2)

EXT_ROOT = Path(__file__).resolve().parent.parent.parent
SCHEMA_PATH = EXT_ROOT / "schemas" / "attack-tree.schema.json"
PROFILES_DIR = EXT_ROOT / "profiles"

MODEL_FILE = "attack-tree.yaml"
RENDER_FILE = "attack-tree.md"
SECURITY_DIR = "security"
BEGIN_MARK = "<!-- attacktree:begin -->"
END_MARK = "<!-- attacktree:end -->"
MANAGED_BLOCK_RE = re.compile(r"<!-- [a-z0-9-]+:begin -->.*?<!-- [a-z0-9-]+:end -->\n*", re.S)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
STATUS_SETS = {
    "none": set(),
    "current": {"implemented", "verified"},
    "verified": {"verified"},
    "planned": {"planned", "implemented", "verified"},
    "all": {"proposed", "planned", "implemented", "verified"},
}
EVIDENCE_FOR_METHOD = {"test": "lab-validated", "scan": "lab-validated", "simulation": "lab-validated",
                       "review": "design-reviewed", "manual": "end-to-end-validated", "evidence": "lab-validated"}

TASK_RE = re.compile(r"^\s*-\s*\[( |x|X)\]\s*(T\d{3,})\b(.*)$")
CR_RE = re.compile(r"\bCR-\d{3,}\b")
CR_TAG_RE = re.compile(r"\[((?:CR-\d{3,})(?:\s*,\s*CR-\d{3,})*)\]")

KEY_ORDER = {
    "root": ["attacktree", "project", "actors", "assets", "goals", "nodes", "controls", "requirements",
             "verification", "decisions"],
    "generic": ["id", "name", "type", "description", "statement", "priority", "parent", "gate", "impact", "zone",
                "archetype", "capabilities", "motivation", "classification", "attack", "actors", "complexity", "cost",
                "likelihood", "likelihood_range", "requires", "detectability", "references", "kind", "nodes", "effect",
                "bypass_rate", "probabilistic", "assets", "controls", "acceptance", "tasks", "links", "touchpoints",
                "validation", "requirement", "method", "evidence", "result", "verdict", "justification", "verified_at",
                "verified_by", "commit", "target", "status", "owner", "rationale", "expires", "decided_at",
                "retired_reason", "source", "notes"],
}


# --------------------------------------------------------------------------- utilities

def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def normalize_dates(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: normalize_dates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_dates(i) for i in obj]
    if isinstance(obj, _dt.datetime):
        return obj.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if isinstance(obj, _dt.date):
        return obj.isoformat()
    return obj


def load_yaml(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return normalize_dates(yaml.safe_load(fh) or {})
    except yaml.YAMLError as exc:
        raise SystemExit(
            f"attacktree: YAML parse error in {path}: {exc}\n"
            "Hint: quote any scalar that contains ': ', '#', or starts with '[' — e.g. "
            "name: \"[NEEDS CLARIFICATION: is the admin API reachable from the internet?]\"") from None


def order_keys(obj: Any, order: List[str]) -> Any:
    if isinstance(obj, dict):
        known = [k for k in order if k in obj]
        rest = sorted(k for k in obj if k not in order)
        return {k: order_keys(obj[k], KEY_ORDER["generic"]) for k in known + rest}
    if isinstance(obj, list):
        return [order_keys(i, KEY_ORDER["generic"]) for i in obj]
    return obj


def sort_entities(model: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("actors", "assets", "goals", "nodes", "controls", "requirements", "verification", "decisions"):
        items = model.get(key)
        if isinstance(items, list):
            model[key] = sorted(items, key=lambda i: str(i.get("id", "")))
    ts = model.get("attacktree") or {}
    if isinstance(ts.get("sources"), list):
        ts["sources"] = sorted(ts["sources"], key=lambda i: str(i.get("path", "")))
    return model


def dump_yaml(model: Dict[str, Any]) -> str:
    ordered = order_keys(sort_entities(copy.deepcopy(model)), KEY_ORDER["root"])
    return yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, width=110, default_flow_style=False)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def git(args: List[str], cwd: Path) -> Optional[str]:
    try:
        out = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True, check=False)
        return out.stdout.strip() if out.returncode == 0 else None
    except OSError:
        return None


def md_escape(text: Any) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return s or "item"


# --------------------------------------------------------------------------- paths & config

def find_repo_root(start: Path) -> Path:
    cur = start.resolve()
    for candidate in [cur, *cur.parents]:
        if (candidate / ".specify").is_dir() or (candidate / ".git").exists():
            return candidate
    return cur


FEATURE_SOURCE = {"how": "none"}


def resolve_feature_dir(repo: Path, explicit: Optional[str]) -> Optional[Path]:
    """Resolution order: --feature-dir, $SPECIFY_FEATURE, current git branch, newest specs/*/spec.md."""
    specs = repo / "specs"
    if explicit:
        p = Path(explicit)
        FEATURE_SOURCE["how"] = "--feature-dir"
        return p if p.is_absolute() else (repo / p)
    env = os.environ.get("SPECIFY_FEATURE")
    if env and (specs / env).is_dir():
        FEATURE_SOURCE["how"] = "SPECIFY_FEATURE"
        return specs / env
    branch = git(["rev-parse", "--abbrev-ref", "HEAD"], repo)
    if branch and (specs / branch).is_dir():
        FEATURE_SOURCE["how"] = "git-branch"
        return specs / branch
    if specs.is_dir():
        candidates = sorted((d for d in specs.iterdir() if d.is_dir() and (d / "spec.md").exists()),
                            key=lambda d: d.stat().st_mtime, reverse=True)
        if candidates:
            FEATURE_SOURCE["how"] = "newest-spec"
            return candidates[0]
    return None


def deep_update(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    for k, v in incoming.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_update(base[k], v)
        else:
            base[k] = v
    return base


def load_config(repo: Path) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}
    ext_manifest = EXT_ROOT / "extension.yml"
    if ext_manifest.exists():
        cfg = copy.deepcopy((load_yaml(ext_manifest).get("config") or {}).get("defaults") or {})
    ext_dir = repo / ".specify" / "extensions" / "attacktree"
    for name in ("attacktree-config.yml", "attacktree-config.local.yml"):
        p = ext_dir / name
        if p.exists():
            deep_update(cfg, load_yaml(p) or {})
    prefix = "SPECKIT_ATTACKTREE_"
    for key, value in os.environ.items():
        if key.startswith(prefix):
            name = key[len(prefix):].lower()
            if name == "enforcement":
                cfg["enforcement"] = value
            elif name == "profiles":
                cfg["profiles"] = [v.strip() for v in value.split(",") if v.strip()]
            elif name == "scenario":
                cfg.setdefault("risk", {})["scenario"] = value
    return cfg


def load_profiles(names: Iterable[str]) -> List[Dict[str, Any]]:
    out = []
    for n in names:
        p = PROFILES_DIR / f"{n}.yaml"
        if p.exists():
            out.append(load_yaml(p))
    return out


DEFAULT_SCALES: Dict[str, Any] = {
    "skill": ["novice", "intermediate", "advanced", "expert"],
    "resources": ["minimal", "moderate", "substantial", "extensive"],
    "access": ["external", "user", "insider", "privileged"],
    "risk_appetite": ["low", "medium", "high"],
    "complexity": {"trivial": {"skill": "novice", "likelihood": 90}, "low": {"skill": "novice", "likelihood": 75},
                   "medium": {"skill": "intermediate", "likelihood": 50}, "high": {"skill": "advanced", "likelihood": 30},
                   "extreme": {"skill": "expert", "likelihood": 10}},
    "cost_tiers": {"minimal": 1000, "moderate": 25000, "substantial": 250000, "extensive": None},
    "requires": {},
    "control_effect": {"low": 0.25, "medium": 0.5, "high": 0.8, "eliminates": 1.0},
    "control_cost": {"low": 1, "medium": 3, "high": 9},
    "impact_classes": ["business", "customer", "data", "compliance", "safety"],
    "impact_levels": ["low", "medium", "high", "critical"],
    "impact_weight": {"low": 1, "medium": 2, "high": 4, "critical": 8},
    "likelihood_levels": {"low": 0, "medium": 15, "high": 40, "very-high": 70},
    "risk_matrix": {
        "very-high": {"low": "medium", "medium": "high", "high": "critical", "critical": "critical"},
        "high": {"low": "low", "medium": "medium", "high": "high", "critical": "critical"},
        "medium": {"low": "low", "medium": "medium", "high": "medium", "critical": "high"},
        "low": {"low": "low", "medium": "low", "high": "medium", "critical": "high"},
    },
}


def scales_of(profiles: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The default profile's scales are always the base; the first active profile declaring `scales` overlays them."""
    out = copy.deepcopy(DEFAULT_SCALES)
    base = PROFILES_DIR / "default.yaml"
    if base.exists():
        deep_update(out, copy.deepcopy(load_yaml(base).get("scales") or {}))
    for prof in profiles:
        if prof.get("scales"):
            deep_update(out, copy.deepcopy(prof["scales"]))
            break
    return out


def rank(scale: List[str], value: Optional[str]) -> int:
    return scale.index(value) if value in scale else -1


def likelihood_level(value: float, scales: Dict[str, Any]) -> str:
    levels = scales["likelihood_levels"]
    lvl = "low"
    for name in ("low", "medium", "high", "very-high"):
        if value >= levels.get(name, DEFAULT_SCALES["likelihood_levels"][name]):
            lvl = name
    return lvl


def impact_level(goal: Dict[str, Any], scales: Dict[str, Any]) -> str:
    imp = goal.get("impact")
    order = scales["impact_levels"]
    if isinstance(imp, str):
        return imp if imp in order else "medium"
    if isinstance(imp, dict) and imp:
        return max((v for v in imp.values() if v in order), key=lambda v: order.index(v), default="medium")
    return "medium"


def risk_level(likelihood: float, impact: str, scales: Dict[str, Any]) -> str:
    return scales["risk_matrix"].get(likelihood_level(likelihood, scales), {}).get(impact, "low")


class Paths:
    def __init__(self, repo: Path, feature: Optional[Path], otm: Optional[str] = None):
        self.repo = repo
        self.feature = feature
        self.spec = feature / "spec.md" if feature else None
        self.plan = feature / "plan.md" if feature else None
        self.tasks = feature / "tasks.md" if feature else None
        self.model = feature / MODEL_FILE if feature else None
        self.render = feature / RENDER_FILE if feature else None
        self.security = feature / SECURITY_DIR if feature else None
        # Optional Open Threat Model file (config model.otm), relative to the feature directory or the repository
        self.otm: Optional[Path] = None
        if otm:
            cand = Path(otm)
            if cand.is_absolute():
                self.otm = cand
            elif feature and (feature / cand).exists():
                self.otm = feature / cand
            else:
                self.otm = repo / cand
        self.constitution = repo / ".specify" / "memory" / "constitution.md"

    def as_dict(self) -> Dict[str, Any]:
        def s(p: Optional[Path]) -> Optional[str]:
            return str(p) if p else None
        return {
            "REPO_ROOT": str(self.repo),
            "FEATURE_DIR": s(self.feature),
            "SPEC": s(self.spec), "PLAN": s(self.plan), "TASKS": s(self.tasks),
            "MODEL": s(self.model), "RENDER": s(self.render), "SECURITY_DIR": s(self.security),
            "OTM": s(self.otm), "CONSTITUTION": s(self.constitution),
            "EXISTS": {k: bool(p and p.exists()) for k, p in
                       (("spec", self.spec), ("plan", self.plan), ("tasks", self.tasks), ("model", self.model),
                        ("otm", self.otm), ("constitution", self.constitution))},
            "FEATURE_SOURCE": FEATURE_SOURCE["how"],
            "EXTENSION_ROOT": str(EXT_ROOT),
        }


def get_paths(args: argparse.Namespace, cfg: Optional[Dict[str, Any]] = None) -> Paths:
    repo = find_repo_root(Path(getattr(args, "repo", None) or os.getcwd()))
    cfg = cfg if cfg is not None else load_config(repo)
    feature = resolve_feature_dir(repo, getattr(args, "feature_dir", None))
    return Paths(repo, feature, (cfg.get("model") or {}).get("otm") or None)


# --------------------------------------------------------------------------- model helpers

def empty_model(project_id: str, name: str, profiles: List[str], baseline: Optional[str]) -> Dict[str, Any]:
    return {
        "attacktree": {"version": "0.1", "generated": now_iso(), "profiles": list(profiles), "extends": baseline,
                       "sources": [], "exclusions": []},
        "project": {"id": project_id, "name": name},
        "actors": [], "assets": [], "goals": [], "nodes": [], "controls": [], "requirements": [],
        "verification": [], "decisions": [],
    }


def load_model(path: Path) -> Dict[str, Any]:
    model = load_yaml(path)
    if not isinstance(model, dict):
        raise SystemExit(f"attacktree: {path} is not a mapping")
    return model


def load_baseline(model: Dict[str, Any], model_path: Path) -> Optional[Dict[str, Any]]:
    ext = (model.get("attacktree") or {}).get("extends")
    if not ext:
        return None
    p = Path(ext)
    if not p.is_absolute():
        p = (model_path.parent / p).resolve()
    if not p.exists():
        return None
    return load_yaml(p)


def merged_view(model: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Union of baseline and feature tree for reference resolution; the feature wins on id clash."""
    if not baseline:
        return model
    view = copy.deepcopy(model)
    for key in ("actors", "assets", "goals", "nodes", "controls", "requirements", "verification", "decisions"):
        ids = {i.get("id") for i in view.get(key) or []}
        for item in baseline.get(key) or []:
            if item.get("id") not in ids:
                view.setdefault(key, []).append(item)
    return view


def index_by_id(items: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    return {i["id"]: i for i in (items or []) if isinstance(i, dict) and "id" in i}


def strip_managed_blocks(text: str) -> str:
    """Remove every extension-managed block so no extension's render counts as drift."""
    return MANAGED_BLOCK_RE.sub("", text)


def source_hash(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".md":
        text = strip_managed_blocks(text)
    return hashlib.sha256(text.rstrip("\n").encode("utf-8")).hexdigest()


def sources_for(paths: Paths) -> List[Dict[str, str]]:
    out = []
    for p in (paths.spec, paths.plan, paths.otm):
        if p and p.exists():
            out.append({"path": p.name, "sha256": source_hash(p)})
    return out


def active(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [i for i in items or [] if i.get("status") != "retired"]


# --------------------------------------------------------------------------- tree structure

class Tree:
    """Structural view of goals and nodes: children, leaves, ancestors, cycle detection."""

    def __init__(self, view: Dict[str, Any]):
        all_goals = index_by_id(view.get("goals"))
        all_nodes = index_by_id(view.get("nodes"))
        self.errors: List[str] = []
        # a retired goal or node takes its whole subtree with it
        retired = {i for i, g in all_goals.items() if g.get("status") == "retired"}
        retired |= {i for i, n in all_nodes.items() if n.get("status") == "retired"}
        self.goal_of: Dict[str, Optional[str]] = {}
        for nid in sorted(all_nodes):
            root, chain = self._root(nid, all_nodes, all_goals)
            self.goal_of[nid] = root
            if any(x in retired for x in chain) or root in retired:
                retired.add(nid)
        self.goals = {i: g for i, g in all_goals.items() if i not in retired}
        self.nodes = {i: n for i, n in all_nodes.items() if i not in retired}
        self.children: Dict[str, List[str]] = {}
        for nid in sorted(self.nodes):
            self.children.setdefault(self.nodes[nid].get("parent"), []).append(nid)

    def _root(self, nid: str, nodes: Dict[str, Dict[str, Any]], goals: Dict[str, Dict[str, Any]]) -> Tuple[Optional[str], List[str]]:
        seen: List[str] = []
        cur: Optional[str] = nid
        while cur is not None and cur in nodes:
            if cur in seen:
                self.errors.append(f"node {nid} is part of a parent cycle: {' -> '.join(seen + [cur])}")
                return None, seen
            seen.append(cur)
            cur = nodes[cur].get("parent")
        if cur in goals:
            return cur, seen
        if cur is not None and cur not in nodes:
            self.errors.append(f"node {nid} parent chain reaches unknown id '{cur}'")
        return None, seen

    def is_leaf(self, nid: str) -> bool:
        return nid in self.nodes and not self.children.get(nid)

    def gate(self, nid: str) -> str:
        item = self.goals.get(nid) or self.nodes.get(nid) or {}
        return "and" if item.get("gate") == "and" else "or"

    def ancestors(self, nid: str) -> List[str]:
        out: List[str] = []
        cur = self.nodes.get(nid, {}).get("parent")
        while cur in self.nodes:
            out.append(cur)
            cur = self.nodes[cur].get("parent")
        if cur in self.goals:
            out.append(cur)
        return out

    def leaves_under(self, root: str) -> List[str]:
        out: List[str] = []
        stack = list(self.children.get(root, []))
        while stack:
            n = stack.pop()
            if self.is_leaf(n):
                out.append(n)
            else:
                stack.extend(self.children.get(n, []))
        return sorted(out)


# --------------------------------------------------------------------------- validation

def builtin_validate(model: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    for key in ("attacktree", "project"):
        if key not in model:
            errors.append(f"missing required key '{key}'")
    patterns = {
        "actors": r"^actor\.", "assets": r"^asset\.", "goals": r"^goal\.", "nodes": r"^node\.",
        "controls": r"^control\.", "requirements": r"^CR-\d{3,}$", "verification": r"^verification\.",
        "decisions": r"^decision\.",
    }
    for key, pat in patterns.items():
        for i, item in enumerate(model.get(key) or []):
            if not isinstance(item, dict) or "id" not in item:
                errors.append(f"{key}[{i}] has no id")
                continue
            if not re.match(pat, str(item["id"])):
                errors.append(f"{key}[{i}] id '{item['id']}' does not match {pat}")
    for g in model.get("goals") or []:
        if isinstance(g, dict) and not g.get("impact"):
            errors.append(f"goal {g.get('id')} impact is required")
    for n in model.get("nodes") or []:
        if isinstance(n, dict) and not n.get("parent"):
            errors.append(f"node {n.get('id')} parent is required")
        at = (n.get("attack") if isinstance(n, dict) else None) or {}
        lk = at.get("likelihood")
        if lk is not None and (not isinstance(lk, int) or not 0 <= lk <= 100):
            errors.append(f"node {n.get('id')} attack.likelihood must be an integer 0–100")
    for c in model.get("controls") or []:
        if isinstance(c, dict) and not c.get("nodes"):
            errors.append(f"control {c.get('id')} nodes is required")
    for r in model.get("requirements") or []:
        if isinstance(r, dict) and not r.get("controls"):
            errors.append(f"requirement {r.get('id')} controls is required")
    for d in model.get("decisions") or []:
        if isinstance(d, dict):
            for k in ("target", "status", "owner", "rationale", "expires"):
                if not d.get(k):
                    errors.append(f"decision {d.get('id')} missing '{k}'")
    return errors


def schema_validate(model: Dict[str, Any]) -> List[str]:
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return builtin_validate(model)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    errors = []
    for err in sorted(validator.iter_errors(model), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in err.path) or "<root>"
        errors.append(f"{loc}: {err.message}")
    return errors + builtin_validate(model)


def reference_errors(view: Dict[str, Any], scales: Optional[Dict[str, Any]] = None) -> List[str]:
    errs: List[str] = []
    actors = index_by_id(view.get("actors"))
    assets = index_by_id(view.get("assets"))
    goals = index_by_id(view.get("goals"))
    nodes = index_by_id(view.get("nodes"))
    controls = index_by_id(view.get("controls"))
    reqs = index_by_id(view.get("requirements"))
    targets = set(goals) | set(nodes)

    def need(ref: Any, table: Dict[str, Any], where: str, kind: str) -> None:
        if ref is not None and ref not in table:
            errs.append(f"{where} references unknown {kind} '{ref}'")

    for g in view.get("goals") or []:
        for a in g.get("assets") or []:
            need(a, assets, f"goal {g.get('id')}", "asset")
    for n in view.get("nodes") or []:
        where = f"node {n.get('id')}"
        if n.get("parent") not in targets:
            errs.append(f"{where} parent '{n.get('parent')}' is not a known goal or node")
        for a in (n.get("attack") or {}).get("actors") or []:
            need(a, actors, where, "actor")
        if scales:
            for tag in (n.get("attack") or {}).get("requires") or []:
                if tag not in (scales.get("requires") or {}):
                    errs.append(f"{where} attack.requires tag '{tag}' is not defined by the profile")
    for c in view.get("controls") or []:
        where = f"control {c.get('id')}"
        for t in c.get("nodes") or []:
            if t not in targets:
                errs.append(f"{where} is attached to unknown node or goal '{t}'")
        for t in c.get("effects") or {}:
            if t not in (c.get("nodes") or []):
                errs.append(f"{where} has an effect for '{t}' but is not attached to it")
        for r in c.get("requirements") or []:
            need(r, reqs, where, "requirement")
    for r in view.get("requirements") or []:
        for c in r.get("controls") or []:
            need(c, controls, f"requirement {r.get('id')}", "control")
    for v in view.get("verification") or []:
        need(v.get("requirement"), reqs, f"verification {v.get('id')}", "requirement")
    for d in view.get("decisions") or []:
        if d.get("target") not in targets:
            errs.append(f"decision {d.get('id')} target '{d.get('target')}' is not a known goal or node")
    tree = Tree(view)
    errs += tree.errors
    for nid, n in tree.nodes.items():
        if tree.children.get(nid) and n.get("attack"):
            errs.append(f"node {nid} has children and an attack block; attack vectors are leaves")
    return errs


# --------------------------------------------------------------------------- tasks & spec parsing

def parse_tasks(path: Optional[Path]) -> List[Dict[str, Any]]:
    if not path or not path.exists():
        return []
    out = []
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = TASK_RE.match(line)
        if not m:
            continue
        done, tid, rest = m.group(1).lower() == "x", m.group(2), m.group(3)
        tagged = {cr for group in CR_TAG_RE.findall(rest) for cr in CR_RE.findall(group)}
        out.append({"id": tid, "done": done, "line": n, "text": rest.strip(), "crs": sorted(tagged),
                    "mentions": sorted(set(CR_RE.findall(rest)) - tagged)})
    return out


def tasks_for_requirement(tasks: List[Dict[str, Any]], req: Dict[str, Any]) -> List[Dict[str, Any]]:
    declared = set(req.get("tasks") or [])
    rid = req.get("id")
    return [t for t in tasks if t["id"] in declared or rid in t["crs"]]


# --------------------------------------------------------------------------- simulation

def active_decisions(view: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Decisions whose expiry has not passed; expired ones protect nothing."""
    return [d for d in view.get("decisions") or [] if str(d.get("expires", "0000")) >= str(today())]


def control_factor(control: Dict[str, Any], scales: Dict[str, Any], node: Optional[str] = None) -> float:
    """Fraction of the attached node's likelihood that survives the control (1.0 = no effect).

    A measured `bypass_rate` wins; otherwise `effects[node]` (per-node level) or the control's `effect`.
    """
    if control.get("bypass_rate") is not None:
        return max(0.0, min(1.0, float(control["bypass_rate"]) / 100.0))
    level = (control.get("effects") or {}).get(node) if node else None
    eff = scales["control_effect"].get(level or control.get("effect") or "medium", 0.5)
    return max(0.0, 1.0 - float(eff))


def active_control_ids(view: Dict[str, Any], scenario: str, apply: Iterable[str] = (), remove: Iterable[str] = ()) -> Set[str]:
    statuses = STATUS_SETS.get(scenario, STATUS_SETS["current"])
    ids = {c["id"] for c in view.get("controls") or [] if (c.get("status") or "proposed") in statuses}
    ids |= {a for a in apply if a}
    ids -= set(remove)
    rejected = {c["id"] for c in view.get("controls") or [] if c.get("status") == "rejected"}
    return ids - rejected


def leaf_feasible(leaf: Dict[str, Any], actor: Dict[str, Any], scales: Dict[str, Any]) -> bool:
    at = leaf.get("attack") or {}
    if at.get("actors") and actor["id"] not in at["actors"]:
        return False
    caps = actor.get("capabilities") or {}
    # a missing capability is unconstrained (check A15 reports unrated or partially rated actors)
    cx = scales["complexity"].get(at.get("complexity") or "medium") or {}
    need_skill = cx.get("skill") if isinstance(cx, dict) else None
    if need_skill and caps.get("skill") and rank(scales["skill"], caps["skill"]) < rank(scales["skill"], need_skill):
        return False
    cost = at.get("cost")
    if isinstance(cost, (int, float)) and caps.get("resources"):
        for tier in scales["resources"]:
            bound = scales["cost_tiers"].get(tier)
            if bound is None or cost <= bound:
                if rank(scales["resources"], caps["resources"]) < rank(scales["resources"], tier):
                    return False
                break
    for tag in at.get("requires") or []:
        for cap, minimum in (scales["requires"].get(tag) or {}).items():
            if caps.get(cap) and rank(scales.get(cap, []), caps[cap]) < rank(scales.get(cap, []), minimum):
                return False
    return True


def base_likelihood(leaf: Dict[str, Any], scales: Dict[str, Any]) -> float:
    at = leaf.get("attack") or {}
    if at.get("likelihood") is not None:
        return float(at["likelihood"])
    cx = scales["complexity"].get(at.get("complexity") or "medium") or {}
    return float(cx.get("likelihood", 50)) if isinstance(cx, dict) else 50.0


class SimContext:
    def __init__(self, view: Dict[str, Any], scales: Dict[str, Any], controls: Set[str], max_paths: int,
                 leaf_overrides: Optional[Dict[str, float]] = None, factor_overrides: Optional[Dict[str, float]] = None):
        self.view = view
        self.decided_nodes = {d.get("target") for d in active_decisions(view) if str(d.get("target", "")).startswith("node.")}
        self.scales = scales
        self.tree = Tree(view)
        self.actors = active(view.get("actors"))
        self.controls = index_by_id(view.get("controls"))
        self.active = controls
        self.max_paths = max_paths
        self.truncated: Set[str] = set()
        self.leaf_overrides = leaf_overrides or {}
        self.factor_overrides = factor_overrides or {}
        self.by_node: Dict[str, List[str]] = {}
        for cid in sorted(controls):
            c = self.controls.get(cid)
            if c:
                for t in c.get("nodes") or []:
                    self.by_node.setdefault(t, []).append(cid)

    def factor_at(self, nid: str) -> float:
        f = 1.0
        for cid in self.by_node.get(nid, []):
            base = control_factor(self.controls[cid], self.scales, nid)
            if cid in self.factor_overrides and 0.0 < base < 1.0:
                base = max(0.0, min(1.0, base + self.factor_overrides[cid]))  # sampled jitter, per node effect kept
            f *= base
        return f

    def weight(self, actors: Set[str]) -> float:
        """Occurrence of the most active actor able to run the path (1.0 when actors carry no occurrence)."""
        if not actors or "*" in actors:
            return 1.0
        best = 0.0
        for a in self.actors:
            if a["id"] in actors:
                occ = a.get("occurrence")
                best = max(best, (float(occ) / 100.0) if isinstance(occ, (int, float)) else 1.0)
        return best

    def feasible_actors(self, leaf: Dict[str, Any]) -> Set[str]:
        if not self.actors:
            return {"*"}
        return {a["id"] for a in self.actors if leaf_feasible(leaf, a, self.scales)}


def _prune(paths: List[Dict[str, Any]], ctx: SimContext, nid: str) -> List[Dict[str, Any]]:
    """Cap the path list while keeping, for every actor, that actor's most likely paths (so a parent AND never
    loses the paths its actor intersection needs)."""
    if len(paths) <= ctx.max_paths:
        return paths
    ctx.truncated.add(nid)
    keep: Dict[int, Dict[str, Any]] = {}
    for actor in sorted({a for p in paths for a in p["actors"]}):
        mine = sorted((p for p in paths if actor in p["actors"]), key=lambda p: (-p["raw_likelihood"], p["cost"], p["leaves"]))
        for p in mine[: ctx.max_paths]:
            keep[id(p)] = p
    return list(keep.values())


def _combine_and(groups: List[List[Dict[str, Any]]], ctx: SimContext, nid: str) -> List[Dict[str, Any]]:
    result: Optional[List[Dict[str, Any]]] = None
    for group in groups:
        if result is None:
            result = [dict(p) for p in group]
            continue
        combos: List[Dict[str, Any]] = []
        for p in result:
            for q in group:
                actors = set(p["actors"]) & set(q["actors"])
                if not actors:
                    continue
                raw = p["raw_likelihood"] * q["raw_likelihood"] / 100.0
                combos.append({"leaves": sorted(set(p["leaves"]) | set(q["leaves"])), "nodes": sorted(set(p["nodes"]) | set(q["nodes"])),
                               "likelihood": raw, "raw_likelihood": raw, "cost": p["cost"] + q["cost"], "actors": actors})
        result = _prune(combos, ctx, nid)
        if not result:
            return []
    return result or []


def evaluate(ctx: SimContext, nid: str) -> Dict[str, Any]:
    """Returns {feasible, likelihood (0–100), cost, paths[]} for a goal or node id.

    Path `likelihood` is the actor-weighted value the tree reports; `raw_likelihood` is before the
    strongest feasible actor's occurrence weight is applied.
    """
    tree = ctx.tree
    if tree.is_leaf(nid):
        leaf = tree.nodes[nid]
        if leaf.get("status") == "needs-clarification":
            # an open question, not a rated step: the rest of the tree is evaluated without it
            return {"feasible": False, "unknown": True, "likelihood": 0.0, "cost": None, "paths": [], "assumed": [nid]}
        if not leaf.get("attack"):
            return {"feasible": False, "likelihood": 0.0, "cost": None, "paths": []}
        actors = ctx.feasible_actors(leaf)
        if not actors:
            return {"feasible": False, "likelihood": 0.0, "cost": None, "paths": []}
        raw = ctx.leaf_overrides.get(nid, base_likelihood(leaf, ctx.scales)) * ctx.factor_at(nid)
        lk = raw * ctx.weight(actors)
        cost = int((leaf.get("attack") or {}).get("cost") or 0)
        paths = [{"leaves": [nid], "nodes": [nid], "likelihood": lk, "raw_likelihood": raw, "cost": cost, "actors": actors}]
        return {"feasible": True, "likelihood": lk, "cost": cost, "paths": paths}

    if nid in tree.nodes and tree.nodes[nid].get("status") == "needs-clarification":
        return {"feasible": False, "unknown": True, "likelihood": 0.0, "cost": None, "paths": [], "assumed": [nid]}
    kids = [evaluate(ctx, k) for k in tree.children.get(nid, [])]
    assumed = sorted({a for k in kids for a in k.get("assumed", [])})
    rated = [k for k in kids if not k.get("unknown")]        # unknown subtrees are left out of the gate
    feasible_kids = [k for k in rated if k["feasible"]]
    gate = tree.gate(nid)
    if kids and not rated:
        return {"feasible": False, "unknown": True, "likelihood": 0.0, "cost": None, "paths": [], "assumed": assumed}
    if not kids or (gate == "and" and len(feasible_kids) != len(rated)) or (gate == "or" and not feasible_kids):
        return {"feasible": False, "likelihood": 0.0, "cost": None, "paths": [], "assumed": assumed}
    factor = ctx.factor_at(nid)
    if gate == "or":
        paths = [dict(p) for k in feasible_kids for p in k["paths"]]
        lk = max(k["likelihood"] for k in feasible_kids)
        cost = min(k["cost"] for k in feasible_kids if k["cost"] is not None)
    else:
        paths = _combine_and([k["paths"] for k in feasible_kids], ctx, nid)
        if not paths:
            return {"feasible": False, "likelihood": 0.0, "cost": None, "paths": []}
    for p in paths:
        p["raw_likelihood"] *= factor
        p["likelihood"] = p["raw_likelihood"] * ctx.weight(p["actors"])
        p["nodes"] = sorted(set(p["nodes"]) | {nid})
    paths = _prune(paths, ctx, nid)
    paths.sort(key=lambda p: (-p["likelihood"], p["cost"], p["leaves"]))
    lk = max(p["likelihood"] for p in paths)
    cost = min(p["cost"] for p in paths)
    return {"feasible": True, "likelihood": lk, "cost": cost, "paths": paths, "assumed": assumed}


def goal_snapshot(ctx: SimContext, gid: str) -> Dict[str, Any]:
    goal = ctx.tree.goals[gid]
    res = evaluate(ctx, gid)
    scales = ctx.scales
    imp = impact_level(goal, scales)
    paths = res["paths"]
    n = len(paths)
    all_nodes = [set(p["nodes"]) - {gid} for p in paths]
    choke = sorted(set.intersection(*all_nodes)) if all_nodes else []
    leaf_stats: Dict[str, Dict[str, float]] = {}
    for p in paths:
        for l in p["leaves"]:
            st = leaf_stats.setdefault(l, {"count": 0, "lk": 0.0})
            st["count"] += 1
            st["lk"] += p["likelihood"]
    achilles = sorted(
        ({"node": l, "paths": int(st["count"]), "share": st["count"] / n, "criticality": (st["count"] / n) * (st["lk"] / st["count"])}
         for l, st in leaf_stats.items()),
        key=lambda x: (-x["criticality"], x["node"]))[:5]
    per_actor = {}
    actor_ids = [a["id"] for a in ctx.actors] or ["*"]
    for aid in actor_ids:
        ap = [p for p in paths if aid in p["actors"]]
        if ap:
            w = ctx.weight({aid})
            ml = max(ap, key=lambda p: (p["raw_likelihood"] * w, -p["cost"]))
            ch = min(ap, key=lambda p: (p["cost"], -p["raw_likelihood"]))
            per_actor[aid] = {"paths": len(ap), "likelihood": round(ml["raw_likelihood"] * w, 1), "most_likely": ml["leaves"],
                              "cheapest": ch["leaves"], "cheapest_cost": ch["cost"]}
    under = {gid} | {n for n, g in ctx.tree.goal_of.items() if g == gid}
    strongest = max(per_actor.items(), key=lambda kv: (kv[1]["likelihood"], kv[0]), default=(None, None))
    lk = round(res["likelihood"] if res["feasible"] else 0.0, 1)
    unknown = bool(res.get("unknown"))
    uncontrolled = [p for p in paths if not any(ctx.by_node.get(x) for x in p["nodes"])]
    accepted = [p for p in paths if any(x in ctx.decided_nodes for x in p["nodes"])]
    undecided_lk = round(max((p["likelihood"] for p in paths if p not in accepted), default=0.0), 1)
    return {
        "id": gid, "name": goal.get("name"), "impact": imp, "feasible": res["feasible"], "unknown": unknown,
        "assumed": res.get("assumed", []),
        "likelihood": lk, "likelihood_level": "unknown" if unknown else likelihood_level(lk, scales),
        "risk": "unknown" if unknown else (risk_level(lk, imp, scales) if res["feasible"] else "low"),
        "accepted_paths": len(accepted),
        "residual_risk": "unknown" if unknown else (risk_level(undecided_lk, imp, scales) if paths else "low"),
        "paths": [{"leaves": p["leaves"], "nodes": p["nodes"], "likelihood": round(p["likelihood"], 1),
                   "raw_likelihood": round(p["raw_likelihood"], 1), "cost": p["cost"],
                   "actors": sorted(p["actors"]),
                   "controls": sorted({c for x in p["nodes"] for c in ctx.by_node.get(x, [])}),
                   "accepted": p in accepted} for p in paths],
        "path_count": n, "truncated": bool(ctx.truncated & under),
        "choke_points": choke, "achilles_heels": achilles, "per_actor": per_actor,
        "strongest_actor": strongest[0],
        "most_likely_path": strongest[1]["most_likely"] if strongest[1] else [],
        "cheapest_path": min(paths, key=lambda p: (p["cost"], -p["likelihood"]))["leaves"] if paths else [],
        "cheapest_cost": min((p["cost"] for p in paths), default=None),
        "uncontrolled_paths": len(uncontrolled),
    }


def goal_likelihoods(view: Dict[str, Any], scales: Dict[str, Any], controls: Set[str], max_paths: int,
                     **kw: Any) -> Dict[str, float]:
    ctx = SimContext(view, scales, controls, max_paths, **kw)
    return {gid: evaluate(ctx, gid)["likelihood"] for gid in sorted(ctx.tree.goals)}


def goal_path_sums(view: Dict[str, Any], scales: Dict[str, Any], controls: Set[str], max_paths: int) -> Dict[str, float]:
    """Sum of path likelihoods per goal: what a control cuts even when it does not lower the goal's best path."""
    ctx = SimContext(view, scales, controls, max_paths)
    return {gid: sum(p["likelihood"] for p in evaluate(ctx, gid)["paths"]) for gid in sorted(ctx.tree.goals)}


def risk_weight(view: Dict[str, Any], scales: Dict[str, Any]) -> Dict[str, float]:
    return {g["id"]: float(scales["impact_weight"].get(impact_level(g, scales), 1)) for g in active(view.get("goals"))}


def pearson(xs: List[float], ys: List[float]) -> float:
    n = len(xs)
    if n < 2:
        return 0.0
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    syy = sum((y - my) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return 0.0
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / math.sqrt(sxx * syy)


def monte_carlo(view: Dict[str, Any], scales: Dict[str, Any], controls: Set[str], cfg: Dict[str, Any]) -> Dict[str, Any]:
    sim_cfg = cfg.get("simulation") or {}
    iterations = int(sim_cfg.get("iterations", 2000) or 0)
    if iterations <= 0:
        return {"iterations": 0, "goals": {}}
    rng = random.Random(int(sim_cfg.get("seed", 42)))
    max_paths = int((cfg.get("risk") or {}).get("max_paths", 200))
    spread = float(sim_cfg.get("likelihood_spread", 15))
    tree = Tree(view)
    leaves = [n for n in sorted(tree.nodes) if tree.is_leaf(n) and tree.nodes[n].get("attack")]
    ctrl_index = index_by_id(view.get("controls"))
    prob_controls = [c for c in sorted(controls) if c in ctrl_index and ctrl_index[c].get("probabilistic")]
    samples: Dict[str, List[float]] = {gid: [] for gid in tree.goals}
    leaf_samples: Dict[str, List[float]] = {l: [] for l in leaves}
    for _ in range(iterations):
        lo_: Dict[str, float] = {}
        for l in leaves:
            at = tree.nodes[l].get("attack") or {}
            base = base_likelihood(tree.nodes[l], scales)
            rng_ = at.get("likelihood_range")
            lo, hi = (float(rng_[0]), float(rng_[1])) if rng_ else (max(0.0, base - spread), min(100.0, base + spread))
            mode = min(max(base, lo), hi)
            lo_[l] = rng.triangular(lo, hi, mode) if hi > lo else base
            leaf_samples[l].append(lo_[l])
        fo: Dict[str, float] = {c: rng.triangular(-0.15, 0.15, 0.0) for c in prob_controls}
        res = goal_likelihoods(view, scales, controls, max_paths, leaf_overrides=lo_, factor_overrides=fo)
        for gid, lk in res.items():
            samples[gid].append(lk)
    out: Dict[str, Any] = {}
    high_threshold = float(scales["likelihood_levels"].get("high", 40))
    for gid, xs in samples.items():
        if not xs:
            continue
        s = sorted(xs)
        drivers = sorted(((l, pearson(leaf_samples[l], xs)) for l in leaves if leaf_samples[l]),
                         key=lambda kv: (-kv[1], kv[0]))
        out[gid] = {"mean": round(sum(xs) / len(xs), 1), "p50": round(s[len(s) // 2], 1),
                    "p90": round(s[min(len(s) - 1, int(len(s) * 0.9))], 1),
                    "p_at_least_high": round(sum(1 for x in xs if x >= high_threshold) / len(xs), 3),
                    "drivers": [{"node": l, "correlation": round(r, 2)} for l, r in drivers if r > 0.05][:5]}
    return {"iterations": iterations, "seed": int(sim_cfg.get("seed", 42)), "spread": spread,
            "probabilistic_controls": prob_controls, "goals": out}


def simulate(view: Dict[str, Any], cfg: Dict[str, Any], scales: Dict[str, Any], scenario: Optional[str] = None,
             apply: Iterable[str] = (), remove: Iterable[str] = (), with_monte_carlo: bool = True) -> Dict[str, Any]:
    risk_cfg = cfg.get("risk") or {}
    scenario = scenario or risk_cfg.get("scenario") or "current"
    max_paths = int(risk_cfg.get("max_paths", 200))
    apply, remove = list(apply), list(remove)
    ctrl_index = index_by_id(view.get("controls"))
    unknown = [c for c in apply + remove if c not in ctrl_index]
    if unknown:
        raise SystemExit(f"attacktree: unknown control(s): {', '.join(unknown)}")
    rejected = [c for c in apply if ctrl_index[c].get("status") == "rejected"]
    if rejected:
        raise SystemExit(f"attacktree: cannot apply rejected control(s): {', '.join(rejected)}; change the status first")
    controls = active_control_ids(view, scenario, apply, remove)
    ctx = SimContext(view, scales, controls, max_paths)
    goals = [goal_snapshot(ctx, gid) for gid in sorted(ctx.tree.goals)]
    weights = risk_weight(view, scales)
    before = goal_likelihoods(view, scales, controls, max_paths)  # unrounded, so deltas compare like with like
    decided = {d.get("target"): d for d in active_decisions(view)}
    block_on = set(risk_cfg.get("block_on") or ["critical"])

    def total(lk: Dict[str, float]) -> float:
        return sum(weights.get(g, 1.0) * lk.get(g, 0.0) / 100.0 for g in weights)

    # what-if per inactive control, then a greedy roadmap
    what_if = []
    sums_before = goal_path_sums(view, scales, controls, max_paths)
    for cid in sorted(ctrl_index):
        c = ctrl_index[cid]
        if cid in controls or c.get("status") == "rejected":
            continue
        after = goal_likelihoods(view, scales, controls | {cid}, max_paths)
        delta = total(before) - total(after)
        sums_after = goal_path_sums(view, scales, controls | {cid}, max_paths)
        depth = sum(weights.get(g, 1.0) * (sums_before[g] - sums_after.get(g, 0.0)) / 100.0 for g in weights)
        cw = float(scales["control_cost"].get(c.get("cost") or "medium", 3))
        affected = sorted(g for g in before if after.get(g, 0) < before[g] - 1e-9)
        deepened = sorted(g for g in weights if sums_after.get(g, 0.0) < sums_before[g] - 1e-9)
        what_if.append({"control": cid, "name": c.get("name"), "status": c.get("status", "proposed"), "cost": c.get("cost", "medium"),
                        "risk_reduction": round(delta, 3), "depth_reduction": round(depth, 3), "efficiency": round(delta / cw, 4),
                        "goals": affected, "goals_deepened": deepened, "residual": {g: round(after[g], 1) for g in affected}})
    positive = [w["risk_reduction"] for w in what_if if w["risk_reduction"] > 0]
    median = sorted(positive)[len(positive) // 2] if positive else 0.0
    for w in what_if:
        cheap = float(scales["control_cost"].get(w["cost"], 3)) <= 3
        if w["risk_reduction"] <= 0 and w["depth_reduction"] > 0:
            w["class"] = "defence in depth"
        elif w["risk_reduction"] <= 0:
            w["class"] = "no effect"
        elif w["risk_reduction"] >= median and cheap:
            w["class"] = "quick win"
        elif w["risk_reduction"] >= median:
            w["class"] = "strategic"
        elif cheap:
            w["class"] = "fill-in"
        else:
            w["class"] = "deprioritize"
    what_if.sort(key=lambda w: (-w["efficiency"], -w["risk_reduction"], -w["depth_reduction"], w["control"]))

    roadmap = []
    cur = set(controls)
    cur_lk = dict(before)
    candidates = [w["control"] for w in what_if if w["risk_reduction"] > 0]
    for step in range(1, min(len(candidates), 10) + 1):
        best = None
        for cid in candidates:
            if cid in cur:
                continue
            after = goal_likelihoods(view, scales, cur | {cid}, max_paths)
            delta = total(cur_lk) - total(after)
            cw = float(scales["control_cost"].get(ctrl_index[cid].get("cost") or "medium", 3))
            if delta > 1e-9 and (best is None or delta / cw > best[1]):
                best = (cid, delta / cw, delta, after)
        if not best:
            break
        cid, eff, delta, after = best
        cur.add(cid)
        cur_lk = after
        roadmap.append({"step": step, "control": cid, "risk_reduction": round(delta, 3), "efficiency": round(eff, 4),
                        "residual": {g: {"likelihood": round(after[g], 1),
                                         "risk": risk_level(after[g], impact_level(ctx.tree.goals[g], scales), scales)}
                                     for g in sorted(after)}})

    # single points of failure among active controls
    spof = []
    for cid in sorted(controls):
        if cid not in ctrl_index:
            continue
        after = goal_likelihoods(view, scales, controls - {cid}, max_paths)
        raised = [g for g in before if RISK_ORDER[risk_level(after[g], impact_level(ctx.tree.goals[g], scales), scales)]
                  > RISK_ORDER[risk_level(before[g], impact_level(ctx.tree.goals[g], scales), scales)]]
        if raised:
            spof.append({"control": cid, "goals": raised, "without": {g: round(after[g], 1) for g in raised}})

    blocking = [g["id"] for g in goals if g["residual_risk"] in block_on and g["id"] not in decided]
    unknown_goals = [g["id"] for g in goals if g["unknown"]]
    by_risk: Dict[str, int] = {}
    for g in goals:
        by_risk[g["risk"]] = by_risk.get(g["risk"], 0) + 1
    result = {
        "scenario": scenario, "applied": apply, "removed": remove, "active_controls": sorted(controls),
        "block_on": sorted(block_on), "blocking_goals": blocking, "unknown_goals": unknown_goals, "decided_goals": sorted(decided),
        "goals": goals, "goals_by_risk": by_risk, "what_if": what_if, "roadmap": roadmap,
        "single_points_of_failure": spof, "truncated": sorted(ctx.truncated),
        "uncovered_choke_points": sorted({(g["id"], n) for g in goals for n in g["choke_points"] if not ctx.by_node.get(n)}),
    }
    result["uncovered_choke_points"] = [{"goal": g, "node": n} for g, n in result["uncovered_choke_points"]]
    if with_monte_carlo:
        result["monte_carlo"] = monte_carlo(view, scales, controls, cfg)
    return result


def simulation_md(sim: Dict[str, Any], feature: Optional[str]) -> str:
    L = [f"## AttackTree Simulation — {feature}", "",
         f"Scenario: `{sim['scenario']}` · Active controls: {len(sim['active_controls'])}"
         + (f" · Applied: {', '.join(f'`{c}`' for c in sim['applied'])}" if sim["applied"] else "")
         + (f" · Removed: {', '.join(f'`{c}`' for c in sim['removed'])}" if sim["removed"] else ""), ""]
    L += ["### Goals", "", "| Goal | Impact | Likelihood | Risk | Strongest actor | Paths | Uncontrolled | Choke points | Most likely path |",
          "|---|---|---|---|---|---|---|---|---|"]
    for g in sim["goals"]:
        acc = f" ({g['accepted_paths']} accepted)" if g.get("accepted_paths") else ""
        L.append(f"| `{g['id']}` | {g['impact']} | {g['likelihood']} ({g['likelihood_level']}) | **{g['risk']}** | "
                 f"{g['strongest_actor'] or '—'} | {g['path_count']}{' (truncated)' if g['truncated'] else ''}{acc} | {g['uncontrolled_paths']} | "
                 f"{', '.join(f'`{c}`' for c in g['choke_points']) or '—'} | {' + '.join(f'`{l}`' for l in g['most_likely_path']) or '—'} |")
    L.append("")
    if sim["blocking_goals"]:
        L.append(f"**Blocking** (risk in {', '.join(sim['block_on'])} without an unexpired decision): "
                 + ", ".join(f"`{g}`" for g in sim["blocking_goals"]))
        L.append("")
    if sim["unknown_goals"]:
        L.append("**Unknown** (every path runs through an open question; answer it before rating): "
                 + ", ".join(f"`{g}`" for g in sim["unknown_goals"]))
        L.append("")
    assumed = sorted({(g["id"], n) for g in sim["goals"] for n in g["assumed"] if not g["unknown"]})
    if assumed:
        L.append("Evaluated without these open questions (needs-clarification nodes): "
                 + ", ".join(f"`{n}` ({g})" for g, n in assumed))
        L.append("")
    for g in sim["goals"]:
        if not g["paths"]:
            continue
        L += [f"### Paths — `{g['id']}`", "", "| # | Leaves | Likelihood | Cost | Feasible for | Controls on path |", "|---|---|---|---|---|---|"]
        for i, p in enumerate(g["paths"][:10], 1):
            L.append(f"| P{i} | {' + '.join(f'`{l}`' for l in p['leaves'])}{' (accepted)' if p.get('accepted') else ''} | {p['likelihood']} | {p['cost']} | "
                     f"{', '.join(p['actors'])} | {', '.join(f'`{c}`' for c in p['controls']) or '— none —'} |")
        if len(g["paths"]) > 10:
            L.append(f"| … | {len(g['paths']) - 10} more paths | | | | |")
        if g["achilles_heels"]:
            L.append("")
            L.append("Achilles heels: " + ", ".join(f"`{a['node']}` ({a['paths']}/{g['path_count']} paths)" for a in g["achilles_heels"]))
        L.append("")
    if sim["uncovered_choke_points"]:
        L += ["### Uncovered choke points", "", "Every feasible path to the goal crosses this node and no control is attached to it in this scenario:", ""]
        for u in sim["uncovered_choke_points"]:
            L.append(f"- `{u['goal']}` → `{u['node']}`")
        L.append("")
    if sim["single_points_of_failure"]:
        L += ["### Single points of failure", "", "Removing this control alone raises a goal's risk level:", ""]
        for s in sim["single_points_of_failure"]:
            L.append(f"- `{s['control']}` protects {', '.join(f'`{g}`' for g in s['goals'])} (likelihood without it: "
                     + ", ".join(f"{g} {v}" for g, v in s["without"].items()) + ")")
        L.append("")
    if sim["what_if"]:
        L += ["### What-if: inactive controls", "",
              "Risk reduction lowers a goal's best path; depth reduction cuts alternative paths the attacker would take once the best one is closed.", "",
              "| Rank | Control | Status | Cost | Risk reduction | Depth reduction | Efficiency | Class | Goals |", "|---|---|---|---|---|---|---|---|---|"]
        for i, w in enumerate(sim["what_if"], 1):
            L.append(f"| {i} | `{w['control']}` | {w['status']} | {w['cost']} | {w['risk_reduction']} | {w['depth_reduction']} | {w['efficiency']} | {w['class']} | "
                     f"{', '.join(f'`{g}`' for g in (w['goals'] or w['goals_deepened'])) or '—'} |")
        L.append("")
    if sim["roadmap"]:
        L += ["### Roadmap (greedy, most risk reduction per cost first)", "", "| Step | Control | Risk reduction | Residual risk per goal |", "|---|---|---|---|"]
        for r in sim["roadmap"]:
            L.append(f"| {r['step']} | `{r['control']}` | {r['risk_reduction']} | "
                     + ", ".join(f"{g} {v['likelihood']} ({v['risk']})" for g, v in r["residual"].items()) + " |")
        L.append("")
    mc = sim.get("monte_carlo") or {}
    if mc.get("iterations"):
        L += [f"### Monte Carlo ({mc['iterations']} iterations, seed {mc['seed']}, ±{mc['spread']} points"
              + (f", probabilistic controls: {', '.join(f'`{c}`' for c in mc['probabilistic_controls'])}" if mc.get("probabilistic_controls") else "") + ")", "",
              "| Goal | Mean | P50 | P90 | P(≥ high) | Drivers |", "|---|---|---|---|---|---|"]
        for gid, m in sorted(mc["goals"].items()):
            L.append(f"| `{gid}` | {m['mean']} | {m['p50']} | {m['p90']} | {m['p_at_least_high']} | "
                     + (", ".join(f"`{d['node']}` ({d['correlation']})" for d in m["drivers"]) or "—") + " |")
        L.append("")
    if sim["truncated"]:
        L.append(f"Path enumeration truncated at `risk.max_paths` under: {', '.join(f'`{t}`' for t in sim['truncated'])}.")
        L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------- checks

class Finding:
    def __init__(self, check: str, severity: str, location: str, summary: str, recommendation: str):
        self.check, self.severity, self.location, self.summary, self.recommendation = (
            check, severity, location, summary, recommendation)

    def as_dict(self) -> Dict[str, str]:
        return {"check": self.check, "severity": self.severity, "location": self.location,
                "summary": self.summary, "recommendation": self.recommendation}


CHECK_NAMES = {
    "A1": "Schema validation", "A2": "Dangling reference or broken tree", "A3": "Goal without attack path",
    "A4": "Attack vector without rating", "A5": "Degenerate gate", "A6": "Uncontrolled feasible path",
    "A7": "Control without requirement", "A8": "Requirement without task", "A9": "Requirement without verification",
    "A10": "Incomplete or expired decision", "A11": "Source drift", "A12": "Control status without evidence",
    "A13": "Link to unknown OTM entity", "A14": "Node needs clarification", "A15": "Actor without capabilities",
    "A16": "Path enumeration truncated",
}


def run_checks(paths: Paths, cfg: Dict[str, Any]) -> Tuple[List[Finding], Dict[str, Any]]:
    findings: List[Finding] = []
    if not paths.model or not paths.model.exists():
        findings.append(Finding("A1", "critical", MODEL_FILE, "attack-tree.yaml is missing", "Run the model command first"))
        return findings, {}
    model = load_model(paths.model)
    loc = MODEL_FILE
    for e in schema_validate(model):
        findings.append(Finding("A1", "critical", loc, f"Schema: {e}", "Fix the tree structure"))
    baseline = load_baseline(model, paths.model)
    view = merged_view(model, baseline)
    profiles = load_profiles((model.get("attacktree") or {}).get("profiles") or cfg.get("profiles") or ["default"])
    scales = scales_of(profiles)
    for e in reference_errors(view, scales):
        findings.append(Finding("A2", "critical", loc, e, "Point the reference at an existing id or add the entity"))
    structural = any(f.check in ("A1", "A2") for f in findings)

    tree = Tree(view)
    ctrl_by_node: Dict[str, List[str]] = {}
    for c in view.get("controls") or []:
        if c.get("status") != "rejected":
            for t in c.get("nodes") or []:
                ctrl_by_node.setdefault(t, []).append(c["id"])
    decided = {d.get("target"): d for d in active_decisions(view)}
    reqs_by_ctrl: Dict[str, List[str]] = {}
    for r in view.get("requirements") or []:
        for c in r.get("controls") or []:
            reqs_by_ctrl.setdefault(c, []).append(r["id"])
    for c in view.get("controls") or []:
        for r in c.get("requirements") or []:
            reqs_by_ctrl.setdefault(c["id"], []).append(r)

    # A3 goals without nodes, A14 clarification nodes, A4/A5 node ratings and gates
    for g in active(model.get("goals")):
        if not tree.children.get(g["id"]):
            findings.append(Finding("A3", "medium", f"{loc}#{g['id']}", f"Goal '{g['id']}' has no attack path modelled",
                                    "Add nodes under the goal or retire it with a reason"))
        elif g.get("gate") == "and" and len(tree.children.get(g["id"], [])) == 1:
            findings.append(Finding("A5", "low", f"{loc}#{g['id']}", f"Goal '{g['id']}' has a single child; its AND gate is meaningless",
                                    "Add the missing step or make the goal an OR"))
    for n in active(model.get("nodes")):
        nid = n["id"]
        if n.get("status") == "needs-clarification":
            findings.append(Finding("A14", "medium", f"{loc}#{nid}", f"Node '{nid}' needs clarification: {n.get('name', '')}",
                                    "Resolve the question in the spec (clarify command), then re-run the model command"))
            continue
        if tree.is_leaf(nid):
            at = n.get("attack") or {}
            missing = [k for k in ("actors", "complexity") if not at.get(k)]
            if not n.get("attack") or missing:
                findings.append(Finding("A4", "high", f"{loc}#{nid}",
                                        f"Attack vector '{nid}' is missing {', '.join(missing) if missing else 'its attack block'}",
                                        "Rate the leaf: actors, complexity, likelihood, cost, requires"))
        elif len(tree.children.get(nid, [])) == 1:
            findings.append(Finding("A5", "low", f"{loc}#{nid}", f"Node '{nid}' has a single child; its {tree.gate(nid).upper()} gate is meaningless",
                                    "Merge the node with its child or add the missing alternative or step"))

    # A6 uncontrolled feasible paths (any non-rejected control counts)
    if not structural:
        try:
            sim = simulate(view, cfg, scales, scenario="all", with_monte_carlo=False)
        except SystemExit:
            sim = None
        for g in (sim or {}).get("goals", []):
            if g["truncated"]:
                findings.append(Finding("A16", "low", f"{loc}#{g['id']}",
                                        f"Path enumeration for '{g['id']}' was truncated at risk.max_paths; choke points and coverage are computed on a sample",
                                        "Raise risk.max_paths or split the goal into smaller subgoals"))
            if g["id"] in decided or not g["feasible"]:
                continue
            open_paths = [p for p in g["paths"] if not p["controls"] and not p.get("accepted")]
            if open_paths:
                sev = "critical" if g["impact"] == "critical" else "high"
                sample = " + ".join(open_paths[0]["leaves"])
                findings.append(Finding("A6", sev, f"{loc}#{g['id']}",
                                        f"Goal '{g['id']}' ({g['impact']} impact) has {len(open_paths)} feasible path(s) without any control, e.g. {sample}",
                                        "Attach a control to a node on the path (a choke point covers every path) or record a decision"))

    # A7 controls without requirement, A12 status claims
    verifications: Dict[str, List[Dict[str, Any]]] = {}
    for v in view.get("verification") or []:
        verifications.setdefault(v.get("requirement"), []).append(v)
    for c in model.get("controls") or []:
        cid = c["id"]
        if c.get("status") == "rejected":
            continue
        if not reqs_by_ctrl.get(cid):
            findings.append(Finding("A7", "high", f"{loc}#{cid}", f"Control '{cid}' has no control requirement",
                                    "Derive a CR-### with acceptance criteria"))
        if c.get("status") == "verified":
            ok = any(any(v.get("verdict") == "verified" or v.get("result") == "pass" for v in verifications.get(r, []))
                     for r in reqs_by_ctrl.get(cid, []))
            if not ok:
                findings.append(Finding("A12", "high", f"{loc}#{cid}", f"Control '{cid}' is marked verified but no requirement of it has a passing verification entry",
                                        "Run the converge command; claims are not evidence"))

    # A8/A9 requirements
    tasks = parse_tasks(paths.tasks)
    ctrl_index = index_by_id(view.get("controls"))
    goal_impact = {g["id"]: impact_level(g, scales) for g in active(view.get("goals"))}
    for r in model.get("requirements") or []:
        rid = r["id"]
        ctrls = [ctrl_index.get(c) for c in r.get("controls") or []]
        if ctrls and all(c and c.get("status") == "rejected" for c in ctrls):
            continue
        worst = "low"
        for c in ctrls:
            for t in (c or {}).get("nodes") or []:
                gid = t if t in tree.goals else tree.goal_of.get(t)
                lvl = goal_impact.get(gid or "", "low")
                if RISK_ORDER[lvl] > RISK_ORDER[worst]:
                    worst = lvl
        rtasks = tasks_for_requirement(tasks, r)
        if paths.tasks and paths.tasks.exists() and not rtasks:
            findings.append(Finding("A8", "high", f"{loc}#{rid}", f"Requirement '{rid}' has no task in tasks.md",
                                    f"Add a task tagged [{rid}] or list task ids under requirements[].tasks"))
        if not verifications.get(rid):
            if rtasks and all(t["done"] for t in rtasks):
                sev, note = ("high" if RISK_ORDER[worst] >= 2 else "medium"), "all tasks are done but nothing verifies it"
            elif rtasks and any(t["done"] for t in rtasks):
                sev, note = "medium", "implementation in progress"
            else:
                sev, note = "low", "implementation not started"
            findings.append(Finding("A9", sev, f"{loc}#{rid}", f"Requirement '{rid}' has no verification entry ({note})",
                                    "Run the converge command after implementation or record evidence"))

    # A10 decisions
    max_days = int((cfg.get("risk_acceptance") or {}).get("max_duration_days", 180))
    require_owner = bool((cfg.get("risk_acceptance") or {}).get("require_owner", True))
    for d in model.get("decisions") or []:
        did = d.get("id")
        missing = [k for k in ("owner", "rationale", "expires") if not d.get(k)]
        if not require_owner and "owner" in missing:
            missing.remove("owner")
        if missing:
            findings.append(Finding("A10", "high", f"{loc}#{did}", f"Decision '{did}' is missing {', '.join(missing)}", "Complete the decision record"))
            continue
        try:
            exp = _dt.date.fromisoformat(str(d["expires"]))
        except ValueError:
            findings.append(Finding("A10", "high", f"{loc}#{did}", f"Decision '{did}' has an invalid expiry", "Use YYYY-MM-DD"))
            continue
        if exp < today():
            findings.append(Finding("A10", "high", f"{loc}#{did}", f"Decision '{did}' expired on {exp}", "Re-decide, control, or extend with a new rationale"))
        elif (exp - today()).days > max_days:
            findings.append(Finding("A10", "medium", f"{loc}#{did}", f"Decision '{did}' exceeds max_duration_days ({max_days})", "Shorten the acceptance window"))

    # A11 drift
    recorded = {s.get("path"): s.get("sha256") for s in (model.get("attacktree") or {}).get("sources") or []}
    for src in sources_for(paths):
        if recorded.get(src["path"]) and recorded[src["path"]] != src["sha256"]:
            findings.append(Finding("A11", "medium", src["path"], f"{src['path']} changed since the tree was generated",
                                    "Re-run the model command to refresh the attack tree"))
        elif not recorded.get(src["path"]):
            findings.append(Finding("A11", "low", src["path"], f"{src['path']} was not hashed when the tree was generated", "Re-run the model command"))

    # A13 links into the threat model
    if paths.otm and paths.otm.exists():
        tm = load_yaml(paths.otm)
        known = {"threats": {t.get("id") for t in tm.get("threats") or []},
                 "mitigations": {m.get("id") for m in tm.get("mitigations") or []}}
        for kind in ("goals", "nodes"):
            for item in active(model.get(kind)):
                for key, ids in (item.get("links") or {}).items():
                    for ref in ids or []:
                        if key in known and ref not in known[key]:
                            findings.append(Finding("A13", "medium", f"{loc}#{item['id']}",
                                                    f"'{item['id']}' links to unknown {key[:-1]} '{ref}' in {paths.otm.name}",
                                                    "Fix the link or re-run the model command after the OTM file changed"))

    # A15 actors
    for a in active(model.get("actors")):
        missing = [k for k in ("skill", "resources", "access", "risk_appetite") if not (a.get("capabilities") or {}).get(k)]
        if missing:
            findings.append(Finding("A15", "medium", f"{loc}#{a['id']}",
                                    f"Actor '{a['id']}' is not rated for {', '.join(missing)}; that capability never limits which attack vectors it can run",
                                    "Rate skill, resources, access, and risk_appetite (see the profile's actor_archetypes)"))

    findings = aggregate_a9(findings, loc)
    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.check, f.location))
    metrics = summarize(view, model, tasks, verifications, findings, cfg, scales)
    return findings, metrics


def aggregate_a9(findings: List[Finding], loc: str) -> List[Finding]:
    pending = [f for f in findings if f.check == "A9" and f.severity == "low"]
    if len(pending) <= 3:
        return findings
    ids = [f.location.split("#", 1)[1] for f in pending]
    rest = [f for f in findings if f not in pending]
    rest.append(Finding("A9", "low", f"{loc}#requirements",
                        f"{len(ids)} requirements have no verification entry yet (implementation not started): {', '.join(ids)}",
                        "Expected before implementation; run the converge command afterwards"))
    return rest


def summarize(view: Dict[str, Any], model: Dict[str, Any], tasks: List[Dict[str, Any]],
              verifications: Dict[str, List[Dict[str, Any]]], findings: List[Finding], cfg: Dict[str, Any],
              scales: Dict[str, Any]) -> Dict[str, Any]:
    tree = Tree(view)
    goals = active(model.get("goals"))
    nodes = active(model.get("nodes"))
    leaves = [n for n in nodes if tree.is_leaf(n["id"]) and n.get("status") != "needs-clarification"]
    by_status: Dict[str, int] = {}
    for c in model.get("controls") or []:
        by_status[c.get("status", "proposed")] = by_status.get(c.get("status", "proposed"), 0) + 1
    by_risk: Dict[str, int] = {}
    if not any(f.check in ("A1", "A2") for f in findings):
        try:
            for g in simulate(view, cfg, scales, with_monte_carlo=False)["goals"]:
                by_risk[g["risk"]] = by_risk.get(g["risk"], 0) + 1
        except SystemExit:
            pass
    reqs = model.get("requirements") or []
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "goals": len(goals), "goals_by_risk": by_risk, "nodes": len(nodes), "attack_vectors": len(leaves),
        "needs_clarification": sum(1 for n in nodes if n.get("status") == "needs-clarification"),
        "controls": len(model.get("controls") or []), "controls_by_status": by_status,
        "requirements": len(reqs), "requirements_with_tasks": sum(1 for r in reqs if tasks_for_requirement(tasks, r)),
        "requirements_verified": sum(1 for r in reqs if any(v.get("verdict") == "verified" or v.get("result") == "pass"
                                                             for v in verifications.get(r["id"], []))),
        "decisions": len(model.get("decisions") or []), "findings": counts,
    }


def worst_severity(findings: List[Finding]) -> str:
    return max((f.severity for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0), default="none")


def exit_code_for(findings: List[Finding], strict: bool) -> int:
    worst = worst_severity(findings)
    if worst == "critical":
        return 2
    if worst == "high" or (strict and worst == "medium"):
        return 1
    return 0


def report_md(findings: List[Finding], metrics: Dict[str, Any], paths: Paths, enforcement: str) -> str:
    lines = ["## AttackTree Check Report", ""]
    lines.append(f"Feature: `{paths.feature.name if paths.feature else '?'}` · Tree: `{MODEL_FILE}` · Enforcement: `{enforcement}`")
    lines.append("")
    if findings:
        lines += ["| ID | Check | Severity | Location | Summary | Recommendation |", "|---|---|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            lines.append(f"| F{i} | {f.check} | {f.severity.upper()} | `{f.location}` | {md_escape(f.summary)} | {md_escape(f.recommendation)} |")
    else:
        lines.append("No findings. The control chain is structurally complete.")
    lines += ["", "**Metrics**", ""]
    for k in ("goals", "attack_vectors", "controls", "requirements", "requirements_with_tasks", "requirements_verified", "decisions"):
        lines.append(f"- {k.replace('_', ' ')}: {metrics.get(k, 0)}")
    if metrics.get("goals_by_risk"):
        lines.append("- goals by residual risk: " + ", ".join(f"{k} {v}" for k, v in sorted(metrics["goals_by_risk"].items(), key=lambda kv: -RISK_ORDER.get(kv[0], 0))))
    if metrics.get("controls_by_status"):
        lines.append("- controls by status: " + ", ".join(f"{k} {v}" for k, v in sorted(metrics["controls_by_status"].items())))
    if metrics.get("findings"):
        lines.append("- findings: " + ", ".join(f"{k} {v}" for k, v in sorted(metrics["findings"].items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))))
    worst = worst_severity(findings)
    lines += ["", "**Next actions**", ""]
    if worst == "critical":
        lines.append("- CRITICAL findings exist. " + ("Do NOT proceed to implement until resolved (enforcement: strict)." if enforcement == "strict" else "Resolve before implementing."))
    elif worst in ("high", "medium"):
        lines.append("- Resolve HIGH findings before implementation; MEDIUM may proceed with a note.")
    else:
        lines.append("- Proceed.")
    return "\n".join(lines) + "\n"


def report_sarif(findings: List[Finding], paths: Paths) -> str:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules: Dict[str, Any] = {}
    results = []
    for f in findings:
        rules.setdefault(f.check, {"id": f.check, "name": f"attacktree/{f.check}", "shortDescription": {"text": CHECK_NAMES.get(f.check, f.check)}})
        uri = f.location.split("#", 1)[0]
        if paths.feature and (paths.feature / uri).exists():
            try:
                uri = (paths.feature / uri).relative_to(paths.repo).as_posix()
            except ValueError:
                uri = (paths.feature / uri).as_posix()
        results.append({
            "ruleId": f.check, "level": level.get(f.severity, "warning"),
            "message": {"text": f"{f.summary}. {f.recommendation}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri.replace(os.sep, "/")}}}],
            "properties": {"severity": f.severity, "fragment": f.location.split("#", 1)[1] if "#" in f.location else ""},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "attacktree", "version": "0.1.0",
                                       "informationUri": "https://github.com/hupe1980/spec-kit-attacktree",
                                       "rules": list(rules.values())}},
                  "results": results}],
    }
    return json.dumps(sarif, indent=2) + "\n"


# --------------------------------------------------------------------------- merge

HUMAN_GOAL_FIELDS = ("retired_reason", "notes")
HUMAN_NODE_FIELDS = ("retired_reason", "notes")
HUMAN_CONTROL_FIELDS = ("status", "evidence", "bypass_rate", "notes")


def merge_models(existing: Dict[str, Any], incoming: Dict[str, Any], paths: Paths) -> Tuple[Dict[str, Any], Dict[str, int]]:
    stats = {"added": 0, "updated": 0, "retired": 0, "kept": 0}
    result = copy.deepcopy(incoming)
    result["project"] = deep_update(copy.deepcopy(existing.get("project") or {}), incoming.get("project") or {})
    ts_old = existing.get("attacktree") or {}
    ts_new = result.setdefault("attacktree", {})
    ts_new["version"] = "0.1"
    ts_new["generated"] = now_iso()
    ts_new["profiles"] = ts_new.get("profiles") or ts_old.get("profiles") or ["default"]
    ts_new["extends"] = ts_new.get("extends") or ts_old.get("extends")
    ts_new["sources"] = sources_for(paths)
    seen_ex = {str(e.get("entity")) for e in ts_new.get("exclusions") or []}
    ts_new["exclusions"] = list(ts_new.get("exclusions") or []) + [e for e in ts_old.get("exclusions") or [] if str(e.get("entity")) not in seen_ex]

    def merge_list(key: str, human: Tuple[str, ...], retire: bool, keep_statuses: Tuple[str, ...] = ()) -> None:
        old = index_by_id(existing.get(key))
        new = index_by_id(result.get(key))
        for iid, o in old.items():
            if iid in new:
                n = new[iid]
                for f in human:  # human-owned fields: the existing tree wins, whatever the incoming file says
                    if f in o:
                        n[f] = o[f]
                    elif f in n and n[f] is None:
                        del n[f]
                if o.get("status") == "retired":  # it came back: revive it
                    n["status"] = "open"
                    n.pop("retired_reason", None)
                elif o.get("status") in keep_statuses:
                    n["status"] = o["status"]
                stats["updated" if n != o else "kept"] += 1
            elif retire:
                r = copy.deepcopy(o)
                if r.get("status") != "retired":
                    r["status"] = "retired"
                    r.setdefault("retired_reason", "Not present in the regenerated tree")
                    stats["retired"] += 1
                result.setdefault(key, []).append(r)
            else:
                result.setdefault(key, []).append(o)
        stats["added"] += sum(1 for iid in new if iid not in old)

    merge_list("goals", HUMAN_GOAL_FIELDS, retire=True, keep_statuses=("open", "accepted", "transferred", "mitigated"))
    merge_list("nodes", HUMAN_NODE_FIELDS, retire=True, keep_statuses=("open", "needs-clarification"))
    merge_list("controls", HUMAN_CONTROL_FIELDS, retire=False, keep_statuses=("proposed", "planned", "implemented", "verified", "rejected"))
    merge_list("actors", ("occurrence", "notes"), retire=False)
    merge_list("assets", (), retire=False)
    old_r = index_by_id(existing.get("requirements"))
    for r in result.get("requirements") or []:
        o = old_r.get(r["id"])
        if o and o.get("tasks") and not r.get("tasks"):
            r["tasks"] = o["tasks"]
    for r in old_r.values():
        if r["id"] not in index_by_id(result.get("requirements")):
            result.setdefault("requirements", []).append(r)
    for key in ("verification", "decisions"):
        merged = index_by_id(existing.get(key))
        for item in result.get(key) or []:
            merged.setdefault(item["id"], item)
        result[key] = list(merged.values())
    for g in result.get("goals") or []:
        g.setdefault("status", "open")
    for n in result.get("nodes") or []:
        n.setdefault("status", "open")
        if n["status"] != "needs-clarification" and str(n.get("name", "")).startswith("[NEEDS CLARIFICATION"):
            n["status"] = "needs-clarification"
    retired = {g["id"] for g in result.get("goals") or [] if g.get("status") == "retired"}
    retired |= {n["id"] for n in result.get("nodes") or [] if n.get("status") == "retired"}
    changed = True
    while changed:  # a retired subtree root takes its descendants with it
        changed = False
        for n in result.get("nodes") or []:
            if n.get("parent") in retired and n.get("status") != "retired":
                n["status"] = "retired"
                n.setdefault("retired_reason", f"Parent {n.get('parent')} was retired")
                retired.add(n["id"])
                stats["retired"] += 1
                changed = True
    for c in result.get("controls") or []:
        c.setdefault("status", "proposed")
        c.setdefault("evidence", "assumed")
    for key in ("actors", "assets", "goals", "nodes", "controls", "requirements"):
        result.setdefault(key, [])
    return result, stats


# --------------------------------------------------------------------------- seed from OTM

def seed_from_otm(otm: Dict[str, Any], project_id: str, name: str, profiles: List[str]) -> Dict[str, Any]:
    """Assets and candidate goals from an Open Threat Model document; the LLM defines actors and builds the paths."""
    model = empty_model(project_id, name, profiles, None)
    src = otm.get("_source", "otm")
    for a in otm.get("assets") or []:
        at = a.get("attributes") or {}
        aid = a["id"] if re.match(r"^asset\.[a-z0-9.-]+$", str(a["id"])) else "asset." + slug(str(a["id"]))
        model["assets"].append({"id": aid, "name": a.get("name", a["id"]),
                                "type": "technical" if at.get("type") in ("tool", "model", "configuration", "source-code") else "data",
                                **({"classification": at["classification"]} if at.get("classification") else {}),
                                "source": at.get("source", src)})
    asset_ids = {a["id"] for a in model["assets"]}
    asset_alias = {str(a["id"]): (a["id"] if re.match(r"^asset\.[a-z0-9.-]+$", str(a["id"])) else "asset." + slug(str(a["id"])))
                   for a in otm.get("assets") or []}
    for t in otm.get("threats") or []:
        at = t.get("attributes") or {}
        if at.get("status") == "retired" or at.get("disposition") == "needs-clarification":
            continue
        imp = int((t.get("risk") or {}).get("impact", 50))
        level = "critical" if imp >= 85 else "high" if imp >= 67 else "medium" if imp >= 34 else "low"
        model["goals"].append({"id": "goal." + slug(str(t["id"]).split(".", 1)[1] if "." in str(t["id"]) else str(t["id"])),
                               "name": t.get("name", t["id"]), "gate": "or",
                               "impact": {"business": level},
                               "assets": sorted({asset_alias.get(a, a) for a in at.get("assets") or [] if asset_alias.get(a, a) in asset_ids}),
                               "links": {"threats": [t["id"]]}, "source": at.get("source", src), "status": "open"})
    return model


# --------------------------------------------------------------------------- render

def mermaid_goal(tree: Tree, gid: str, controls: List[Dict[str, Any]], active_ids: Set[str], scales: Dict[str, Any]) -> str:
    def nid(i: str) -> str:
        return re.sub(r"[^A-Za-z0-9_]", "_", i)

    def label(text: str) -> str:
        return str(text).replace('"', "'")

    lines = ["flowchart TD", f'    {nid(gid)}(["{label(tree.goals[gid].get("name", gid))}"])']
    stack = [gid]
    seen: Set[str] = set()
    while stack:
        cur = stack.pop()
        for k in tree.children.get(cur, []):
            n = tree.nodes[k]
            name = label(n.get("name", k))
            if tree.is_leaf(k):
                at = n.get("attack") or {}
                lines.append(f'    {nid(k)}["{name}<br/>{at.get("complexity", "?")} · {int(base_likelihood(n, scales))} %"]')
            elif tree.gate(k) == "and":
                lines.append(f'    {nid(k)}{{{{"AND · {name}"}}}}')
            else:
                lines.append(f'    {nid(k)}("OR · {name}")')
            lines.append(f"    {nid(cur)} --> {nid(k)}")
            seen.add(k)
            stack.append(k)
    scope = seen | {gid}
    for c in controls:
        targets = [t for t in c.get("nodes") or [] if t in scope]
        if not targets:
            continue
        cid = nid(c["id"])
        lines.append(f'    {cid}[/"{label(c.get("name", c["id"]))}<br/>{c.get("status", "proposed")}"/]')
        for t in targets:
            lines.append(f"    {cid} -.-> {nid(t)}")
        lines.append(f"    class {cid} {'active' if c['id'] in active_ids else 'inactive'}")
    lines.append("    classDef active fill:#d4edda,stroke:#2e7d32,color:#1b5e20")
    lines.append("    classDef inactive fill:#fff3cd,stroke:#b26a00,color:#663c00,stroke-dasharray: 4 3")
    return "\n".join(lines)


def outline(tree: Tree, root: str, ctrl_by_node: Dict[str, List[Dict[str, Any]]], scales: Dict[str, Any], depth: int = 0) -> List[str]:
    out: List[str] = []
    for k in tree.children.get(root, []):
        n = tree.nodes[k]
        pad = "  " * depth
        ctrls = " ".join(f"🛡 `{c['id']}` ({c.get('status', 'proposed')})" for c in ctrl_by_node.get(k, []))
        if tree.is_leaf(k):
            at = n.get("attack") or {}
            bits = [", ".join(f"`{a}`" for a in at.get("actors") or []) or "any actor", str(at.get("complexity", "?")),
                    f"{int(base_likelihood(n, scales))} %"]
            if at.get("cost") is not None:
                bits.append(f"cost {at['cost']}")
            if at.get("requires"):
                bits.append("requires " + ", ".join(at["requires"]))
            refs = ", ".join(f"{k2}: {', '.join(v)}" for k2, v in (at.get("references") or {}).items())
            if refs:
                bits.append(refs)
            flag = " ❓" if n.get("status") == "needs-clarification" else ""
            out.append(f"{pad}- `{k}` {md_escape(n.get('name'))}{flag} — {' · '.join(bits)}{(' · ' + ctrls) if ctrls else ''}")
        else:
            out.append(f"{pad}- **{tree.gate(k).upper()}** `{k}` {md_escape(n.get('name'))}{(' · ' + ctrls) if ctrls else ''}")
            out += outline(tree, k, ctrl_by_node, scales, depth + 1)
    return out


def render_markdown(model: Dict[str, Any], view: Dict[str, Any], paths: Paths, cfg: Dict[str, Any]) -> str:
    ts = model.get("attacktree") or {}
    proj = model.get("project") or {}
    profiles = load_profiles(ts.get("profiles") or cfg.get("profiles") or ["default"])
    scales = scales_of(profiles)
    tree = Tree(view)
    scenario = (cfg.get("risk") or {}).get("scenario") or "current"
    valid = not schema_validate(model) and not reference_errors(view, scales)
    sim = simulate(view, cfg, scales, scenario=scenario, with_monte_carlo=False) if valid else None
    planned = simulate(view, cfg, scales, scenario="planned", with_monte_carlo=False) if valid else None
    sim_goals = {g["id"]: g for g in (sim or {}).get("goals", [])}
    planned_goals = {g["id"]: g for g in (planned or {}).get("goals", [])}
    active_ids = set((sim or {}).get("active_controls", []))
    controls = active(view.get("controls"))
    ctrl_by_node: Dict[str, List[Dict[str, Any]]] = {}
    for c in controls:
        for t in c.get("nodes") or []:
            ctrl_by_node.setdefault(t, []).append(c)
    reqs = view.get("requirements") or []
    tasks = parse_tasks(paths.tasks)
    ver: Dict[str, List[Dict[str, Any]]] = {}
    for v in view.get("verification") or []:
        ver.setdefault(v.get("requirement"), []).append(v)
    decisions = {d.get("target"): d for d in view.get("decisions") or []}

    L: List[str] = [f"# Attack Tree: {proj.get('name', proj.get('id', ''))}", "",
                    f"**Feature**: `{paths.feature.name if paths.feature else proj.get('id', '')}` · **Generated**: {ts.get('generated', '')} · "
                    f"**Profiles**: {', '.join(ts.get('profiles') or [])} · **Scenario**: {scenario} · **Canonical**: `{MODEL_FILE}`", "",
                    "> Rendered by AttackTree. Edit `attack-tree.yaml`, not this file.", ""]
    goals = active(view.get("goals"))
    by_risk: Dict[str, int] = {}
    for g in goals:
        r = sim_goals.get(g["id"], {}).get("risk", "?")
        by_risk[r] = by_risk.get(r, 0) + 1
    leaves = [n for n in active(view.get("nodes")) if tree.is_leaf(n["id"]) and n.get("status") != "needs-clarification"]
    st: Dict[str, int] = {}
    for c in controls:
        st[c.get("status", "proposed")] = st.get(c.get("status", "proposed"), 0) + 1
    L += ["## Summary", "",
          "| Goals | Critical | High | Medium | Low | Attack vectors | Controls (active / planned / proposed) | Requirements | Decisions |",
          "|---|---|---|---|---|---|---|---|---|",
          f"| {len(goals)} | {by_risk.get('critical', 0)} | {by_risk.get('high', 0)} | {by_risk.get('medium', 0)} | {by_risk.get('low', 0)} | "
          f"{len(leaves)} | {len(active_ids)} / {st.get('planned', 0)} / {st.get('proposed', 0)} | {len(reqs)} | {len(view.get('decisions') or [])} |", ""]
    if not valid:
        L += ["> The tree has schema or reference errors; risk columns are empty until `attacktree.sh validate` passes.", ""]
    questions = [n for n in active(view.get("nodes")) if n.get("status") == "needs-clarification"]
    if questions:
        L += ["### Needs clarification", ""]
        for n in questions:
            L.append(f"- `{n['id']}` — {md_escape(n.get('name'))} ({md_escape(n.get('source', ''))})")
        L.append("")
    if view.get("actors"):
        L += ["## Threat Actors", "", "| ID | Name | Skill | Resources | Access | Risk appetite | Occurrence | Motivation |", "|---|---|---|---|---|---|---|---|"]
        for a in active(view.get("actors")):
            c = a.get("capabilities") or {}
            L.append(f"| `{a['id']}` | {md_escape(a.get('name'))} | {c.get('skill', '')} | {c.get('resources', '')} | {c.get('access', '')} | "
                     f"{c.get('risk_appetite', '')} | {a.get('occurrence', 100)} | {md_escape(a.get('motivation', ''))} |")
        L.append("")
    if view.get("assets"):
        L += ["## Assets", "", "| ID | Name | Type | Classification | Source |", "|---|---|---|---|---|"]
        for a in view["assets"]:
            L.append(f"| `{a['id']}` | {md_escape(a.get('name'))} | {a.get('type', '')} | {a.get('classification', '')} | {md_escape(a.get('source', ''))} |")
        L.append("")
    L += ["## Goals", ""]
    if not goals:
        L += ["No goals recorded yet.", ""]
    for g in sorted(goals, key=lambda x: (-RISK_ORDER.get(sim_goals.get(x["id"], {}).get("risk", "low"), 0), x["id"])):
        gid = g["id"]
        sg, pg = sim_goals.get(gid), planned_goals.get(gid)
        imp = g.get("impact")
        imp_txt = ", ".join(f"{k} {v}" for k, v in imp.items()) if isinstance(imp, dict) else str(imp)
        L.append(f"### `{gid}` — {md_escape(g.get('name'))}")
        L.append("")
        head = [f"**Impact**: {imp_txt} → **{impact_level(g, scales)}**"]
        if sg:
            head.append(f"**Residual risk ({scenario})**: **{sg['risk']}** (likelihood {sg['likelihood']}"
                        + (f", strongest actor `{sg['strongest_actor']}`" if sg.get("strongest_actor") and sg["strongest_actor"] != "*" else "") + ")")
        if pg and sg and pg["risk"] != sg["risk"]:
            head.append(f"**With planned controls**: {pg['risk']} ({pg['likelihood']})")
        if gid in decisions:
            expired = str(decisions[gid].get("expires", "9999")) < str(today())
            head.append(f"**Decision**: {decisions[gid].get('status')} until {decisions[gid].get('expires')}{' (expired)' if expired else ''}")
        if (g.get("links") or {}).get("threats"):
            head.append("**Threats**: " + ", ".join(f"`{t}`" for t in g["links"]["threats"]))
        if g.get("source"):
            head.append(f"**Source**: {md_escape(g['source'])}")
        L.append(" · ".join(head))
        L.append("")
        if g.get("description"):
            L += [md_escape(g["description"]), ""]
        gctrls = " ".join(f"🛡 `{c['id']}` ({c.get('status', 'proposed')})" for c in ctrl_by_node.get(gid, []))
        L.append(f"- **{tree.gate(gid).upper()}** {md_escape(g.get('name'))}{(' · ' + gctrls) if gctrls else ''}")
        L += outline(tree, gid, ctrl_by_node, scales, 1)
        L.append("")
        if (cfg.get("model") or {}).get("diagram", "mermaid") == "mermaid" and tree.children.get(gid):
            L += ["```mermaid", mermaid_goal(tree, gid, controls, active_ids, scales), "```", ""]
        if sg and sg["paths"]:
            L.append(f"**Most likely path**: {' + '.join(f'`{l}`' for l in sg['most_likely_path'])} (likelihood {sg['likelihood']}) · "
                     f"**Cheapest path**: {' + '.join(f'`{l}`' for l in sg['cheapest_path'])} (cost {sg['cheapest_cost']})")
            L.append(f"**Choke points**: {', '.join(f'`{c}`' for c in sg['choke_points']) or '— none —'} · "
                     f"**Achilles heels**: {', '.join(f'`{a['node']}` ({a['paths']}/{sg['path_count']} paths)' for a in sg['achilles_heels']) or '—'}")
            L += ["", "| Path | Leaves | Likelihood | Cost | Feasible for | Controls on path |", "|---|---|---|---|---|---|"]
            for i, p in enumerate(sg["paths"][:10], 1):
                L.append(f"| P{i} | {' + '.join(f'`{l}`' for l in p['leaves'])} | {p['likelihood']} | {p['cost']} | {', '.join(p['actors'])} | "
                         f"{', '.join(f'`{c}`' for c in p['controls']) or '— none —'} |")
            if sg["path_count"] > 10:
                L.append(f"| … | {sg['path_count'] - 10} more | | | | |")
            L.append("")
        elif sg and sg["unknown"]:
            L += ["Every path runs through an open question; the goal cannot be rated until it is answered.", ""]
        elif sg:
            L += ["No feasible path for the modelled actors in this scenario.", ""]
    if controls:
        L += ["## Controls", "", "| ID | Control | Kind | Attached to | Effect | Cost | Status | Evidence | Requirements | Touchpoints |", "|---|---|---|---|---|---|---|---|---|---|"]
        for c in controls:
            rs = sorted(set((c.get("requirements") or []) + [r["id"] for r in reqs if c["id"] in (r.get("controls") or [])]))
            eff = f"bypass {c['bypass_rate']} %" if c.get("bypass_rate") is not None else c.get("effect", "")
            if c.get("effects") and c.get("bypass_rate") is None:
                eff += " (" + ", ".join(f"{k}: {v}" for k, v in sorted(c["effects"].items())) + ")"
            if c.get("probabilistic"):
                eff += " (probabilistic)"
            L.append(f"| `{c['id']}` | {md_escape(c.get('name'))} | {c.get('kind', '')} | {', '.join(f'`{t}`' for t in c.get('nodes') or [])} | {eff} | "
                     f"{c.get('cost', '')} | {c.get('status', 'proposed')} | {c.get('evidence', 'assumed')} | {', '.join(rs)} | "
                     f"{', '.join(f'`{p}`' for p in c.get('touchpoints') or [])} |")
        L.append("")
    if sim and sim["what_if"]:
        L += ["## Roadmap (what-if)", "", "| Rank | Control | Status | Cost | Risk reduction | Depth reduction | Class | Goals affected |", "|---|---|---|---|---|---|---|---|"]
        for i, w in enumerate(sim["what_if"], 1):
            L.append(f"| {i} | `{w['control']}` | {w['status']} | {w['cost']} | {w['risk_reduction']} | {w['depth_reduction']} | {w['class']} | "
                     f"{', '.join(f'`{g}`' for g in (w['goals'] or w['goals_deepened'])) or '—'} |")
        L.append("")
    if sim and sim["single_points_of_failure"]:
        L += ["**Single points of failure**: " + "; ".join(f"`{s['control']}` for {', '.join(f'`{g}`' for g in s['goals'])}" for s in sim["single_points_of_failure"]), ""]
    L += ["## Control Requirements", ""]
    if reqs:
        for r in sorted(reqs, key=lambda x: x["id"]):
            rt = tasks_for_requirement(tasks, r)
            vs = ver.get(r["id"], [])
            state = "verified" if any(v.get("verdict") == "verified" or v.get("result") == "pass" for v in vs) else ("has-evidence" if vs else "unverified")
            L += [f"### {r['id']} ({r.get('priority', 'P2')}) — {state}", "", r.get("statement", ""), ""]
            for ac in r.get("acceptance") or []:
                L.append(f"- **Given** {ac.get('given')}, **when** {ac.get('when')}, **then** {ac.get('then')}")
            L.append(f"- Controls: {', '.join(f'`{c}`' for c in r.get('controls') or [])}")
            L.append(f"- Tasks: {', '.join(t['id'] + (' ✓' if t['done'] else '') for t in rt) or '— none —'}")
            for v in vs:
                L.append(f"- Verification `{v.get('id')}`: {v.get('method')} → {v.get('result')} ({v.get('verdict', '')}) — `{v.get('evidence')}`")
            L.append("")
    else:
        L += ["No control requirements yet.", ""]
    if view.get("decisions"):
        L += ["## Risk Decisions", "", "| ID | Target | Status | Owner | Expires | Rationale |", "|---|---|---|---|---|---|"]
        for d in view["decisions"]:
            L.append(f"| `{d['id']}` | `{d.get('target')}` | {d.get('status')} | {d.get('owner')} | {d.get('expires')} | {md_escape(d.get('rationale'))} |")
        L.append("")
    return "\n".join(L)


def cr_block(model: Dict[str, Any]) -> str:
    reqs = sorted(model.get("requirements") or [], key=lambda r: r["id"])
    ctrls = index_by_id(model.get("controls"))
    tree = Tree(model)
    L = [BEGIN_MARK, "### Control Requirements *(managed by AttackTree — edit attack-tree.yaml)*", ""]
    if not reqs:
        L.append("- No control requirements derived yet. Run the AttackTree model command.")
    for r in reqs:
        L.append(f"- **{r['id']}** ({r.get('priority', 'P2')}): {r.get('statement', '')}")
        goals = sorted({(t if t in tree.goals else tree.goal_of.get(t)) or t for c in r.get("controls") or []
                        for t in (ctrls.get(c, {}).get("nodes") or [])})
        if goals:
            L.append(f"  - Cuts: {', '.join(f'`{g}`' for g in goals)} via {', '.join(f'`{c}`' for c in r.get('controls') or [])}")
        for ac in r.get("acceptance") or []:
            L.append(f"  - Given {ac.get('given')}, when {ac.get('when')}, then {ac.get('then')}")
    L.append(END_MARK)
    return "\n".join(L)


def upsert_cr_block(spec_path: Path, block: str) -> str:
    text = spec_path.read_text(encoding="utf-8")
    if BEGIN_MARK in text and END_MARK in text:
        start, end = text.index(BEGIN_MARK), text.index(END_MARK) + len(END_MARK)
        new = text[:start] + block + text[end:]
        action = "updated"
    else:
        anchor = re.search(r"^## Success Criteria.*$", text, re.M) or re.search(r"^## Assumptions.*$", text, re.M)
        if anchor:
            new = text[:anchor.start()] + block + "\n\n" + text[anchor.start():]
        else:
            new = text.rstrip("\n") + "\n\n" + block + "\n"
        action = "inserted"
    if new != text:
        spec_path.write_text(new, encoding="utf-8")
    return action


# --------------------------------------------------------------------------- converge

EVIDENCE_SKIP_DIRS = {"__pycache__", "node_modules", "dist", "build", "target", "vendor", "coverage"}
EVIDENCE_SKIP_SUFFIXES = {".pyc", ".pyo", ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".bin", ".so", ".dylib", ".dll",
                          ".zip", ".gz", ".tar", ".class", ".jar", ".wasm", ".lock"}


def find_evidence(repo: Path, rid: str, cfg: Dict[str, Any], touchpoints: List[str]) -> Dict[str, Any]:
    dirs = (cfg.get("verification") or {}).get("test_dirs") or ["tests", "test", "spec", "__tests__"]
    markers = (cfg.get("verification") or {}).get("evidence_markers") or ["CR-"]
    hits: List[str] = []
    number = rid.split("-", 1)[1]
    pat = re.compile("|".join(re.escape(m.rstrip("-_")) + r"[-_]?" + re.escape(number) + r"(?!\d)" for m in markers), re.I)
    for d in dirs:
        base = repo / d
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.stat().st_size > 2_000_000 or p.suffix in EVIDENCE_SKIP_SUFFIXES:
                continue
            if any(part in EVIDENCE_SKIP_DIRS or part.startswith(".") for part in p.relative_to(base).parts[:-1]):
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if pat.search(content):
                hits.append(p.relative_to(repo).as_posix())
    return {"test_files": sorted(hits), "touchpoints": [{"path": t, "exists": (repo / t).exists()} for t in touchpoints]}


def converge_scan(paths: Paths, cfg: Dict[str, Any]) -> Dict[str, Any]:
    if not paths.model or not paths.model.exists():
        raise SystemExit("attacktree: attack-tree.yaml not found; run the model command first")
    model = load_model(paths.model)
    view = merged_view(model, load_baseline(model, paths.model))
    tasks = parse_tasks(paths.tasks)
    ctrls = index_by_id(view.get("controls"))
    ver: Dict[str, List[Dict[str, Any]]] = {}
    for v in view.get("verification") or []:
        ver.setdefault(v.get("requirement"), []).append(v)
    items = []
    for r in sorted(model.get("requirements") or [], key=lambda x: x["id"]):
        touch = sorted({t for c in r.get("controls") or [] for t in (ctrls.get(c, {}).get("touchpoints") or [])})
        validation = [s for c in r.get("controls") or [] for s in (ctrls.get(c, {}).get("validation") or [])]
        rt = tasks_for_requirement(tasks, r)
        items.append({
            "id": r["id"], "statement": r.get("statement"), "priority": r.get("priority", "P2"),
            "acceptance": r.get("acceptance") or [], "controls": r.get("controls") or [],
            "control_status": {c: ctrls.get(c, {}).get("status") for c in r.get("controls") or []},
            "probabilistic": any(ctrls.get(c, {}).get("probabilistic") for c in r.get("controls") or []),
            "validation_steps": validation,
            "tasks": [{"id": t["id"], "done": t["done"], "text": t["text"]} for t in rt],
            "all_tasks_done": bool(rt) and all(t["done"] for t in rt),
            "existing_verification": ver.get(r["id"], []),
            "evidence": find_evidence(paths.repo, r["id"], cfg, touch),
        })
    findings, metrics = run_checks(paths, cfg)
    profiles = load_profiles((model.get("attacktree") or {}).get("profiles") or cfg.get("profiles") or ["default"])
    sim = simulate(view, cfg, scales_of(profiles), scenario="verified", with_monte_carlo=False) if not any(f.check in ("A1", "A2") for f in findings) else None
    return {
        "feature": paths.feature.name if paths.feature else None,
        "commit": git(["rev-parse", "--short", "HEAD"], paths.repo),
        "requirements": items,
        "residual_with_verified_controls": {g["id"]: {"likelihood": g["likelihood"], "risk": g["risk"]} for g in (sim or {}).get("goals", [])},
        "blocking_goals": (sim or {}).get("blocking_goals", []),
        "decisions": model.get("decisions") or [],
        "check_findings": [f.as_dict() for f in findings],
        "metrics": metrics,
        "config": {"verification": cfg.get("verification") or {}, "enforcement": cfg.get("enforcement", "warn"),
                   "block_on": (cfg.get("risk") or {}).get("block_on") or ["critical"],
                   "config_file": str(paths.repo / ".specify" / "extensions" / "attacktree" / "attacktree-config.yml")},
        "verdict_schema": {"requirement": "CR-###", "verdict": "verified | implemented-unverified | partial | missing",
                            "method": "test | review | scan | simulation | manual | evidence", "evidence": "path::test or record",
                            "result": "pass | fail | partial | inconclusive", "bypass_rate": "0-100, optional, measured bypass of a probabilistic control",
                            "justification": "one sentence"},
    }


def open_convergence_tasks(tasks_text: str) -> Dict[str, List[str]]:
    reqs: List[str] = []
    goals: List[str] = []
    in_section = False
    for line in tasks_text.splitlines():
        if line.startswith("## "):
            in_section = "Control Convergence" in line
            continue
        if not in_section:
            continue
        m = TASK_RE.match(line)
        if not m or m.group(1).lower() == "x":
            continue
        rest = m.group(3)
        reqs += [cr for group in CR_TAG_RE.findall(rest) for cr in CR_RE.findall(group)]
        goals += re.findall(r"`(goal\.[a-z0-9.-]+)`", rest)
    return {"requirements": sorted(set(reqs)), "goals": sorted(set(goals))}


def next_phase_number(tasks_text: str) -> int:
    nums = [int(n) for n in re.findall(r"^## Phase (\d+)", tasks_text, re.M)]
    return (max(nums) + 1) if nums else 1


def next_task_id(tasks: List[Dict[str, Any]], tasks_text: str) -> int:
    ids = [int(t["id"][1:]) for t in tasks] + [int(n) for n in re.findall(r"\bT(\d{3,})\b", tasks_text)]
    return (max(ids) + 1) if ids else 1


RESULT_FOR_VERDICT = {"verified": "pass", "implemented-unverified": "inconclusive", "partial": "partial", "missing": "fail"}


def latest_verification(model: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    latest: Dict[str, Dict[str, Any]] = {}
    for v in model.get("verification") or []:
        rid = v.get("requirement")
        if rid and (rid not in latest or str(v.get("verified_at", "")) >= str(latest[rid].get("verified_at", ""))):
            latest[rid] = v
    return latest


def converge_apply(paths: Paths, cfg: Dict[str, Any], verdicts_path: Path, commit: Optional[str],
                   only: Optional[List[str]] = None) -> Dict[str, Any]:
    model = load_model(paths.model)
    raw = load_yaml(verdicts_path)
    verdicts = raw.get("verdicts") if isinstance(raw, dict) else raw
    if not isinstance(verdicts, list):
        raise SystemExit("attacktree: verdicts file must be a list or {verdicts: [...]}")
    reqs = index_by_id(model.get("requirements"))
    if only:
        unknown = [r for r in only if r not in reqs]
        if unknown:
            raise SystemExit(f"attacktree: --only names unknown requirement(s): {', '.join(unknown)}")
        outside = [v.get("requirement") for v in verdicts if v.get("requirement") not in only]
        if outside:
            raise SystemExit(f"attacktree: verdicts outside --only scope: {', '.join(outside)}")
    previous = latest_verification(model)
    commit = commit or git(["rev-parse", "--short", "HEAD"], paths.repo) or "unknown"
    stamp = now_iso()
    existing_ids = {v.get("id") for v in model.get("verification") or []}
    results: Dict[str, Dict[str, Any]] = {}
    ctrls = index_by_id(model.get("controls"))
    for v in verdicts:
        rid = v.get("requirement")
        if rid not in reqs:
            raise SystemExit(f"attacktree: verdict references unknown requirement {rid}")
        verdict = v.get("verdict")
        if verdict not in RESULT_FOR_VERDICT:
            raise SystemExit(f"attacktree: invalid verdict '{verdict}' for {rid}")
        if verdict == "verified" and not v.get("evidence"):
            raise SystemExit(f"attacktree: {rid} cannot be 'verified' without an evidence pointer")
        n = 1
        vid = f"verification.{rid.lower()}.{stamp[:10]}"
        while vid in existing_ids:
            n += 1
            vid = f"verification.{rid.lower()}.{stamp[:10]}-{n}"
        existing_ids.add(vid)
        entry = {"id": vid, "requirement": rid, "method": v.get("method", "evidence"), "evidence": v.get("evidence") or "none",
                 "result": v.get("result") or RESULT_FOR_VERDICT[verdict], "verdict": verdict,
                 "justification": v.get("justification", ""), "verified_at": stamp, "commit": commit}
        if v.get("bypass_rate") is not None:
            entry["bypass_rate"] = int(v["bypass_rate"])
            for c in reqs[rid].get("controls") or []:
                if c in ctrls and ctrls[c].get("probabilistic"):  # a measured rate only means something for a probabilistic control
                    ctrls[c]["bypass_rate"] = int(v["bypass_rate"])
        model.setdefault("verification", []).append(entry)
        results[rid] = entry
    for rid in reqs:
        if rid in results:
            continue
        prev = previous.get(rid)
        if prev and prev.get("verdict"):
            results[rid] = {**prev, "carried_forward": True}
        else:
            results[rid] = {"requirement": rid, "verdict": "missing", "evidence": "none", "justification": "No verdict supplied", "synthetic": True}

    # control roll-up: verified when every requirement of the control is verified
    req_by_ctrl: Dict[str, List[str]] = {}
    for r in model.get("requirements") or []:
        for c in r.get("controls") or []:
            req_by_ctrl.setdefault(c, []).append(r["id"])
    for cid, c in ctrls.items():  # the reverse link counts too, as in check A7
        for r in c.get("requirements") or []:
            if r in reqs and r not in req_by_ctrl.get(cid, []):
                req_by_ctrl.setdefault(cid, []).append(r)
    for cid, c in ctrls.items():
        if c.get("status") == "rejected":
            continue
        rids = req_by_ctrl.get(cid, [])
        if rids and all(results.get(r, {}).get("verdict") == "verified" for r in rids):
            c["status"] = "verified"
            methods = {results[r].get("method") for r in rids}
            best = max((EVIDENCE_FOR_METHOD.get(m, "lab-validated") for m in methods),
                       key=lambda e: ["assumed", "design-reviewed", "lab-validated", "end-to-end-validated", "regression-tested"].index(e))
            c["evidence"] = best if c.get("evidence") != "regression-tested" else "regression-tested"
        elif c.get("status") == "verified":
            c["status"] = "implemented"
            c["evidence"] = "design-reviewed" if any(results.get(r, {}).get("verdict") == "implemented-unverified" for r in rids) else "assumed"
        elif rids and c.get("status") in ("proposed", "planned") and any(
                results.get(r, {}).get("verdict") in ("verified", "implemented-unverified", "partial") for r in rids):
            c["status"] = "implemented"  # evidence of code at the touchpoint moves the roadmap forward
            c["evidence"] = "design-reviewed"

    profiles = load_profiles((model.get("attacktree") or {}).get("profiles") or cfg.get("profiles") or ["default"])
    scales = scales_of(profiles)
    view = merged_view(model, load_baseline(model, paths.model))
    sim = simulate(view, cfg, scales, scenario="verified", with_monte_carlo=False)
    block_on = set((cfg.get("risk") or {}).get("block_on") or ["critical"])
    decided = {d.get("target"): d for d in active_decisions(model)}
    for g in model.get("goals") or []:
        if g.get("status") == "retired":
            continue
        snap = next((s for s in sim["goals"] if s["id"] == g["id"]), None)
        if g["id"] in decided:  # an expired decision no longer holds the status
            g["status"] = decided[g["id"]].get("status")
        elif snap and not snap["unknown"] and snap["path_count"] > 0 and snap["risk"] not in block_on and snap["uncontrolled_paths"] == 0:
            g["status"] = "mitigated"
        else:
            g["status"] = "open"
    open_blocking = sim["blocking_goals"]
    expired = [d["id"] for d in model.get("decisions") or [] if str(d.get("expires", "9999")) < str(today())]
    unverified = sorted(r for r, v in results.items() if v.get("verdict") != "verified"
                        and not (reqs[r].get("controls") and all(ctrls.get(c, {}).get("status") == "rejected" for c in reqs[r]["controls"])))
    recorded = {x.get("path"): x.get("sha256") for x in (model.get("attacktree") or {}).get("sources") or []}
    drift = [s["path"] + ("" if recorded.get(s["path"]) else " (never hashed: re-run the model command)")
             for s in sources_for(paths) if recorded.get(s["path"]) != s["sha256"]]
    converged = not open_blocking and not unverified and not expired and not drift
    write_text(paths.model, dump_yaml(model))

    appended: List[str] = []
    already_open: List[str] = []
    if paths.tasks and paths.tasks.exists() and (unverified or open_blocking):
        text = paths.tasks.read_text(encoding="utf-8")
        tasks = parse_tasks(paths.tasks)
        open_conv = open_convergence_tasks(text)
        pending_reqs = [rid for rid in unverified if rid not in open_conv["requirements"]]
        pending_goals = [g for g in open_blocking if g not in open_conv["goals"]]
        already_open = sorted(set(unverified) & set(open_conv["requirements"])) + [g for g in open_blocking if g in open_conv["goals"]]
        tid = next_task_id(tasks, text)
        phase = next_phase_number(text)
        lines = ["", f"## Phase {phase}: Control Convergence", "",
                 f"**Purpose**: Close control gaps found by AttackTree converge on {stamp[:10]} (commit {commit}).", ""]
        for rid in pending_reqs:
            v = results[rid]
            req = reqs[rid]
            touch = sorted({p for c in req.get("controls") or [] for p in (ctrls.get(c, {}).get("touchpoints") or [])})
            what = {"missing": "Implement", "partial": "Complete", "implemented-unverified": "Add a test for"}.get(v.get("verdict"), "Address")
            where = f" — touchpoints: {', '.join(touch)}" if touch else ""
            why = f"; {v.get('justification')}" if v.get("justification") else ""
            statement = str(req.get("statement", "")).rstrip(".")
            lines.append(f"- [ ] T{tid:03d} [{rid}] {what} {rid} ({statement}){where} [converge: {v.get('verdict')}{why}]")
            appended.append(f"T{tid:03d}")
            tid += 1
        for gid in pending_goals:
            lines.append(f"- [ ] T{tid:03d} [attacktree] Reduce residual risk of goal `{gid}` below {', '.join(sorted(block_on))}: add or verify a control on its paths, or record a decision in attack-tree.yaml")
            appended.append(f"T{tid:03d}")
            tid += 1
        if appended:
            paths.tasks.write_text(text.rstrip("\n") + "\n" + "\n".join(lines) + "\n", encoding="utf-8")

    summary = {
        "feature": paths.feature.name if paths.feature else None, "commit": commit, "timestamp": stamp,
        "status": "CONVERGED" if converged else "NOT CONVERGED",
        "goals": {"total": len(active(model.get("goals"))), "open_blocking": open_blocking,
                  "residual": {g["id"]: {"likelihood": g["likelihood"], "risk": g["risk"]} for g in sim["goals"]}},
        "controls": {"verified": sorted(c for c, x in ctrls.items() if x.get("status") == "verified")},
        "requirements": {"total": len(reqs),
                         "verified": sorted(r for r, v in results.items() if v.get("verdict") == "verified"),
                         "implemented_unverified": sorted(r for r, v in results.items() if v.get("verdict") == "implemented-unverified"),
                         "partial": sorted(r for r, v in results.items() if v.get("verdict") == "partial"),
                         "missing": sorted(r for r, v in results.items() if v.get("verdict") == "missing")},
        "expired_decisions": expired, "drift": drift, "appended_tasks": appended, "already_open_tasks_for": already_open,
        "verdicts": {r: {k: v.get(k) for k in ("verdict", "method", "evidence", "justification")} for r, v in results.items()},
    }
    if paths.security:
        write_text(paths.security / "attacktree-convergence-report.json", json.dumps(summary, indent=2) + "\n")
        write_text(paths.security / "attacktree-convergence-report.md", convergence_md(summary))
    return summary


def convergence_md(s: Dict[str, Any]) -> str:
    r = s["requirements"]
    L = [f"## Control Convergence — {s.get('feature')}", "", f"Commit `{s.get('commit')}` · {s.get('timestamp')}", "",
         "| Metric | Value |", "|---|---|",
         f"| Goals (active) | {s['goals']['total']} |",
         f"| Goals at blocking residual risk (verified controls only) | {len(s['goals']['open_blocking'])} {', '.join(s['goals']['open_blocking'])} |",
         f"| Control requirements | {r['total']} |",
         f"| verified | {len(r['verified'])} |",
         f"| implemented, unverified | {len(r['implemented_unverified'])} {', '.join(r['implemented_unverified'])} |",
         f"| partial | {len(r['partial'])} {', '.join(r['partial'])} |",
         f"| missing | {len(r['missing'])} {', '.join(r['missing'])} |",
         f"| Expired decisions | {len(s['expired_decisions'])} {', '.join(s['expired_decisions'])} |",
         f"| Source drift | {', '.join(s['drift']) or 'none'} |",
         "", f"**Status: {s['status']}**", ""]
    if s["goals"]["residual"]:
        L += ["| Goal | Likelihood (verified controls) | Residual risk |", "|---|---|---|"]
        for gid, v in sorted(s["goals"]["residual"].items()):
            L.append(f"| `{gid}` | {v['likelihood']} | {v['risk']} |")
        L.append("")
    if s["appended_tasks"]:
        L += [f"Appended tasks: {', '.join(s['appended_tasks'])}", ""]
    L += ["| Requirement | Verdict | Method | Evidence | Justification |", "|---|---|---|---|---|"]
    for rid, v in sorted(s["verdicts"].items()):
        L.append(f"| {rid} | {v.get('verdict')} | {v.get('method') or ''} | `{v.get('evidence') or ''}` | {md_escape(v.get('justification') or '')} |")
    return "\n".join(L) + "\n"


def scoreboard(s: Dict[str, Any]) -> str:
    r = s["requirements"]
    lines = [f"Control Convergence — {s.get('feature')}", "",
             f"Goals (active)                 {s['goals']['total']:>4}",
             f"  at blocking residual risk    {len(s['goals']['open_blocking']):>4}   {' '.join(s['goals']['open_blocking'])}".rstrip(),
             f"Control requirements           {r['total']:>4}",
             f"  verified                     {len(r['verified']):>4}",
             f"  implemented, unverified      {len(r['implemented_unverified']):>4}   {' '.join(r['implemented_unverified'])}".rstrip(),
             f"  partial                      {len(r['partial']):>4}   {' '.join(r['partial'])}".rstrip(),
             f"  missing                      {len(r['missing']):>4}   {' '.join(r['missing'])}".rstrip(),
             f"Expired decisions              {len(s['expired_decisions']):>4}",
             f"Source drift                   {'yes' if s['drift'] else 'no':>4}", "",
             f"Status: {s['status']}"]
    if s["appended_tasks"]:
        lines.append(f"Appended {len(s['appended_tasks'])} task(s) to tasks.md: {', '.join(s['appended_tasks'])}")
    if s.get("already_open_tasks_for"):
        lines.append(f"Open convergence tasks already exist for: {', '.join(s['already_open_tasks_for'])} (not duplicated)")
    return "\n".join(lines)


# --------------------------------------------------------------------------- CLI

def _model_scales(model: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    return scales_of(load_profiles((model.get("attacktree") or {}).get("profiles") or cfg.get("profiles") or ["default"]))


def cmd_paths(args: argparse.Namespace) -> int:
    p = get_paths(args)
    d = p.as_dict()
    if args.json:
        print(json.dumps(d, indent=2))
    else:
        for k, v in d.items():
            print(f"{k}: {v}")
    return 0 if p.feature else 1


def cmd_init(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("attacktree: no feature directory found; pass --feature-dir")
    cfg = load_config(p.repo)
    if p.model.exists() and not args.force:
        print(f"exists: {p.model}")
        return 0
    baseline_cfg = (cfg.get("model") or {}).get("baseline")
    baseline = None
    if baseline_cfg and (p.repo / baseline_cfg).exists():
        baseline = Path(os.path.relpath(p.repo / baseline_cfg, p.feature)).as_posix()
    model = empty_model(args.project_id or p.feature.name, args.name or p.feature.name, cfg.get("profiles") or ["default"], baseline)
    model["attacktree"]["sources"] = sources_for(p)
    write_text(p.model, dump_yaml(model))
    print(f"created: {p.model}")
    return 0


def cmd_seed(args: argparse.Namespace) -> int:
    p = get_paths(args)
    cfg = load_config(p.repo)
    src = Path(args.otm) if args.otm else p.otm
    if not src or not src.exists():
        raise SystemExit("attacktree: no OTM file found; pass --otm <file> or set model.otm in the config")
    otm = load_yaml(src)
    otm["_source"] = src.name
    feature_name = p.feature.name if p.feature else (otm.get("project") or {}).get("id", "feature")
    model = seed_from_otm(otm, feature_name, (otm.get("project") or {}).get("name") or feature_name, cfg.get("profiles") or ["default"])
    text = dump_yaml(model)
    if args.output:
        write_text(Path(args.output), text)
        print(f"written: {args.output}")
    else:
        sys.stdout.write(text)
    print(json.dumps({"actors": len(model["actors"]), "assets": len(model["assets"]), "goals": len(model["goals"])}), file=sys.stderr)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.model)
    model = load_model(path)
    cfg = load_config(find_repo_root(path.parent))
    errors = schema_validate(model)
    errors += reference_errors(merged_view(model, load_baseline(model, path)), _model_scales(model, cfg))
    if args.json:
        print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
    else:
        for e in errors:
            print(f"ERROR: {e}")
        print("valid" if not errors else f"{len(errors)} error(s)")
    return 0 if not errors else 1


def cmd_merge(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("attacktree: no feature directory found; pass --feature-dir")
    cfg = load_config(p.repo)
    incoming = load_model(Path(args.incoming))
    existing = load_model(p.model) if p.model.exists() else empty_model(p.feature.name, p.feature.name, cfg.get("profiles") or ["default"], None)
    merged, stats = merge_models(existing, incoming, p)
    errors = schema_validate(merged) + reference_errors(merged_view(merged, load_baseline(merged, p.model)), _model_scales(merged, cfg))
    if errors and not args.allow_invalid:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        print(f"attacktree: merge rejected, {len(errors)} validation error(s); fix the incoming tree", file=sys.stderr)
        return 1
    if args.dry_run:
        print(dump_yaml(merged))
    else:
        write_text(p.model, dump_yaml(merged))
        print(f"merged: {p.model}")
    print(json.dumps(stats))
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature or not p.model.exists():
        raise SystemExit("attacktree: attack-tree.yaml not found; run init or merge first")
    cfg = load_config(p.repo)
    model = load_model(p.model)
    view = merged_view(model, load_baseline(model, p.model))
    out = []
    if (cfg.get("model") or {}).get("render_markdown", True) and not args.no_markdown:
        write_text(p.render, render_markdown(model, view, p, cfg))
        out.append(str(p.render))
    if (cfg.get("model") or {}).get("write_requirements_to_spec", True) and not args.no_spec and p.spec.exists():
        action = upsert_cr_block(p.spec, cr_block(model))
        out.append(f"{p.spec} ({action} CR block)")
    for o in out:
        print(f"rendered: {o}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("attacktree: no feature directory found; pass --feature-dir")
    cfg = load_config(p.repo)
    enforcement = args.enforcement or cfg.get("enforcement", "warn")
    if args.strict:
        enforcement = "strict"
    findings, metrics = run_checks(p, cfg)
    if args.format == "json":
        text = json.dumps({"findings": [f.as_dict() for f in findings], "metrics": metrics,
                           "worst": worst_severity(findings), "enforcement": enforcement}, indent=2) + "\n"
    elif args.format == "sarif":
        text = report_sarif(findings, p)
    else:
        text = report_md(findings, metrics, p, enforcement)
    if args.output:
        write_text(Path(args.output), text)
        print(f"written: {args.output}")
    else:
        sys.stdout.write(text)
    if args.persist and p.security:
        write_text(p.security / "attacktree-check-report.md", report_md(findings, metrics, p, enforcement))
    return exit_code_for(findings, strict=(enforcement == "strict") or args.strict)


def cmd_simulate(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature or not p.model.exists():
        raise SystemExit("attacktree: attack-tree.yaml not found; run the model command first")
    cfg = load_config(p.repo)
    model = load_model(p.model)
    view = merged_view(model, load_baseline(model, p.model))
    scales = _model_scales(model, cfg)
    errors = schema_validate(model) + reference_errors(view, scales)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(f"attacktree: cannot simulate, {len(errors)} validation error(s)")
    if args.iterations is not None:
        cfg.setdefault("simulation", {})["iterations"] = args.iterations
    if args.seed is not None:
        cfg.setdefault("simulation", {})["seed"] = args.seed
    apply = [s.strip() for s in (args.apply or "").split(",") if s.strip()]
    remove = [s.strip() for s in (args.remove or "").split(",") if s.strip()]
    sim = simulate(view, cfg, scales, scenario=args.scenario, apply=apply, remove=remove, with_monte_carlo=not args.no_monte_carlo)
    text = json.dumps(sim, indent=2) + "\n" if args.format == "json" else simulation_md(sim, p.feature.name)
    if args.output:
        write_text(Path(args.output), text)
        print(f"written: {args.output}")
    else:
        sys.stdout.write(text)
    if args.persist and p.security:
        write_text(p.security / "attacktree-simulation.md", simulation_md(sim, p.feature.name))
        write_text(p.security / "attacktree-simulation.json", json.dumps(sim, indent=2) + "\n")
    return 1 if sim["blocking_goals"] else 0


def cmd_converge_scan(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature:
        raise SystemExit("attacktree: no feature directory found; pass --feature-dir")
    data = converge_scan(p, load_config(p.repo))
    if args.output:
        write_text(Path(args.output), json.dumps(data, indent=2) + "\n")
        print(f"written: {args.output}")
    else:
        print(json.dumps(data, indent=2))
    return 0


def cmd_converge_apply(args: argparse.Namespace) -> int:
    p = get_paths(args)
    if not p.feature or not p.model.exists():
        raise SystemExit("attacktree: attack-tree.yaml not found")
    cfg = load_config(p.repo)
    only = [s.strip() for s in args.only.split(",") if s.strip()] if args.only else None
    summary = converge_apply(p, cfg, Path(args.verdicts), args.commit, only)
    if not args.no_render:
        model = load_model(p.model)
        write_text(p.render, render_markdown(model, merged_view(model, load_baseline(model, p.model)), p, cfg))
    print(scoreboard(summary))
    return 0 if summary["status"] == "CONVERGED" else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="attacktree", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", help="Repository root (default: auto-detect from cwd)")
    ap.add_argument("--feature-dir", help="Feature directory (default: SPECIFY_FEATURE, current branch, or newest spec)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("paths", help="Resolve artifact paths"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_paths)
    s = sub.add_parser("init", help="Create an empty attack tree"); s.add_argument("--project-id"); s.add_argument("--name")
    s.add_argument("--force", action="store_true"); s.set_defaults(fn=cmd_init)
    s = sub.add_parser("seed", help="Derive assets and candidate goals from an Open Threat Model (OTM) file")
    s.add_argument("--otm", help="OTM file (default: model.otm from the config)"); s.add_argument("--output"); s.set_defaults(fn=cmd_seed)
    s = sub.add_parser("validate", help="Validate a tree file"); s.add_argument("model"); s.add_argument("--json", action="store_true"); s.set_defaults(fn=cmd_validate)
    s = sub.add_parser("merge", help="Merge an incoming tree into the feature tree"); s.add_argument("--incoming", required=True)
    s.add_argument("--dry-run", action="store_true"); s.add_argument("--allow-invalid", action="store_true"); s.set_defaults(fn=cmd_merge)
    s = sub.add_parser("render", help="Render Markdown and the CR block"); s.add_argument("--no-spec", action="store_true")
    s.add_argument("--no-markdown", action="store_true"); s.set_defaults(fn=cmd_render)
    s = sub.add_parser("check", help="Run gap checks"); s.add_argument("--format", choices=["md", "json", "sarif"], default="md")
    s.add_argument("--output"); s.add_argument("--persist", action="store_true"); s.add_argument("--strict", action="store_true")
    s.add_argument("--enforcement", choices=["warn", "strict"]); s.set_defaults(fn=cmd_check)
    s = sub.add_parser("simulate", help="Attack paths, residual risk, choke points, what-if roadmap, Monte Carlo")
    s.add_argument("--format", choices=["md", "json"], default="md"); s.add_argument("--output"); s.add_argument("--persist", action="store_true")
    s.add_argument("--scenario", choices=["none", "current", "verified", "planned", "all"]); s.add_argument("--apply", help="Comma-separated control ids to add (what-if)")
    s.add_argument("--remove", help="Comma-separated control ids to remove (what-if)"); s.add_argument("--iterations", type=int); s.add_argument("--seed", type=int)
    s.add_argument("--no-monte-carlo", action="store_true"); s.set_defaults(fn=cmd_simulate)
    s = sub.add_parser("converge-scan", help="Collect evidence facts per requirement"); s.add_argument("--output"); s.set_defaults(fn=cmd_converge_scan)
    s = sub.add_parser("converge-apply", help="Record verdicts and write the convergence report"); s.add_argument("--verdicts", required=True)
    s.add_argument("--commit"); s.add_argument("--no-render", action="store_true")
    s.add_argument("--only", help="Comma-separated CR ids judged in this run; others keep their last verdict"); s.set_defaults(fn=cmd_converge_apply)
    return ap


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
