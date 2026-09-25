import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"

# Fixture repos contain their own test files; never collect them as part of this suite.
collect_ignore_glob = ["fixtures/*"]


def _load_engine():
    spec = importlib.util.spec_from_file_location("attacktree", ROOT / "scripts" / "python" / "attacktree.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["attacktree"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


@pytest.fixture(scope="session")
def engine():
    return _load_engine()


@pytest.fixture
def agent_repo(tmp_path: Path) -> Path:
    """A throwaway copy of the agent-assistant fixture repo (it carries its own .specify marker)."""
    dst = tmp_path / "agent"
    shutil.copytree(FIXTURES / "agent-assistant", dst)
    (dst / ".specify").mkdir(exist_ok=True)
    return dst


@pytest.fixture
def agent_feature(agent_repo: Path) -> Path:
    return agent_repo / "specs" / "007-agent-assistant"
