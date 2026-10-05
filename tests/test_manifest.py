import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
COMMAND_RE = re.compile(r"^speckit\.[a-z0-9-]+\.[a-z0-9-]+$")


def load_manifest():
    return yaml.safe_load((ROOT / "extension.yml").read_text(encoding="utf-8"))


def test_manifest_core_fields():
    m = load_manifest()
    assert m["schema_version"] == "1.0"
    ext = m["extension"]
    assert re.match(r"^[a-z0-9-]+$", ext["id"])
    assert re.match(r"^\d+\.\d+\.\d+$", ext["version"])
    for key in ("name", "description", "author", "repository", "license"):
        assert ext[key]
    assert re.match(r"^(>=|==|<=|>|<)\d", m["requires"]["speckit_version"])


def test_commands_are_namespaced_and_files_exist():
    m = load_manifest()
    ext_id = m["extension"]["id"]
    for cmd in m["provides"]["commands"]:
        assert COMMAND_RE.match(cmd["name"]), cmd["name"]
        assert cmd["name"].split(".")[1] == ext_id
        path = ROOT / cmd["file"]
        assert path.exists(), path
        text = path.read_text(encoding="utf-8")
        assert text.startswith("---\ndescription:"), "command needs frontmatter with description"
        assert "$ARGUMENTS" in text
        for literal in ("/speckit.attacktree.", "/speckit-attacktree-"):
            assert literal not in text, f"{cmd['file']} hard-codes a slash invocation"


def test_command_tokens_resolve_to_known_commands():
    """Every __SPECKIT_COMMAND_ATTACKTREE_*__ token must name a command this extension provides."""
    m = load_manifest()
    provided = {c["name"].split(".", 2)[2].upper() for c in m["provides"]["commands"]}
    for path in (ROOT / "commands").glob("*.md"):
        for token in re.findall(r"__SPECKIT_COMMAND_ATTACKTREE_([A-Z-]+)__", path.read_text(encoding="utf-8")):
            assert token in provided, f"{path.name} references unknown command token {token}"


def test_templates_scripts_config_exist():
    m = load_manifest()
    for section in ("templates", "scripts"):
        for entry in m["provides"][section]:
            assert re.match(r"^[a-z0-9-]+$", entry["name"])
            assert "strategy" not in entry, "extensions may not declare a strategy"
            assert (ROOT / entry["file"]).exists(), entry["file"]
    for cfg in m["provides"]["config"]:
        assert (ROOT / cfg["template"]).exists()


def test_hooks_reference_provided_commands():
    m = load_manifest()
    provided = {c["name"] for c in m["provides"]["commands"]}
    for event, hook in m["hooks"].items():
        entries = hook if isinstance(hook, list) else [hook]
        for h in entries:
            assert h["command"] in provided, f"{event} references unknown command {h['command']}"
            assert h.get("optional") is True, f"{event} must default to optional"
            assert h.get("prompt")


def test_defaults_live_under_config():
    m = load_manifest()
    assert "defaults" not in m, "the CLI reads config.defaults, not a top-level defaults key"
    assert m["config"]["defaults"]["profiles"]
    assert m["config"]["defaults"]["risk"]["scenario"] in ("current", "verified", "planned")


def test_config_template_agrees_with_manifest_defaults():
    m = load_manifest()
    tpl = yaml.safe_load((ROOT / "config-template.yml").read_text(encoding="utf-8"))
    defaults = m["config"]["defaults"]
    for key in ("enforcement", "risk", "simulation", "risk_acceptance", "model", "verification"):
        assert key in tpl, key
    assert set(tpl["risk"]) == set(defaults["risk"])
    assert set(tpl["simulation"]) == set(defaults["simulation"])
    assert set(tpl["verification"]) == set(defaults["verification"])


def test_manifest_validates_with_specify_cli_if_installed():
    try:
        from specify_cli.extensions import ExtensionManifest  # type: ignore
    except Exception:  # pragma: no cover
        import pytest
        pytest.skip("specify_cli not importable in this interpreter")
    manifest = ExtensionManifest(ROOT / "extension.yml")
    assert manifest.id == "attacktree"
    assert len(manifest.commands) == 4


def test_description_and_tags_meet_publishing_guide():
    m = load_manifest()
    assert len(m["extension"]["description"]) < 120, "publishing guide: keep the description short"
    assert 2 <= len(m["tags"]) <= 5, "publishing guide: 2–5 tags"
    assert all(t == t.lower() and re.match(r"^[a-z0-9-]+$", t) for t in m["tags"])


def test_catalog_json_agrees_with_manifest():
    m = load_manifest()
    cat = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
    entry = cat["extensions"]["attacktree"]
    assert entry["version"] == m["extension"]["version"]
    assert entry["download_url"].endswith(f"/v{m['extension']['version']}.zip"), "download_url must be tag-pinned to the manifest version"
    assert entry["description"] == m["extension"]["description"]
    assert entry["tags"] == m["tags"]
    assert entry["provides"]["commands"] == len(m["provides"]["commands"])
    hooks = sum(len(h) if isinstance(h, list) else 1 for h in m["hooks"].values())
    assert entry["provides"]["hooks"] == hooks
    assert entry["requires"]["speckit_version"] == m["requires"]["speckit_version"]
    assert entry["license"] == m["extension"]["license"] and entry["repository"] == m["extension"]["repository"]


def test_extensionignore_excludes_development_content():
    ignore = (ROOT / ".extensionignore").read_text(encoding="utf-8").splitlines()
    for entry in ("tests/", "site/", "examples/", "preset/", "workflow/", ".github/", "action.yml", "catalog.json"):
        assert entry in ignore, entry
