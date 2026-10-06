from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml
from traust_contracts.config import (
    TRAUST_CONFIG_HOME_DEFAULT,
    deployment_config_dir,
    load_section,
)

# Capture the operator config home before the suite replaces TRAUST_CONFIG_HOME.
_OPERATOR_CONFIG_HOME = deployment_config_dir()
if _OPERATOR_CONFIG_HOME is not None:
    os.environ["TRAUST_OPERATOR_CONFIG_HOME"] = str(_OPERATOR_CONFIG_HOME)

# The suite must never run against an operator's full config home (corpus-config,
# feeds, etc.). Build a private home from fixtures and isolated temp data trees.
# progress_tracker is borrowed from the operator locations.yaml when set — same
# path production uses, so compliance tests exercise the real loader contract.
# HARNESS_TEST_FIXTURE_CONFIG=1 so live smokes skip when no sibling checkout.
_TEST_HOME = Path(tempfile.mkdtemp(prefix="traust-app-test-cfg-"))
shutil.copytree(Path(__file__).parent / "fixtures" / "config", _TEST_HOME, dirs_exist_ok=True)
_ISO = Path(tempfile.mkdtemp(prefix="traust-app-test-data-"))
(_ISO / "ws").mkdir(parents=True, exist_ok=True)
(_ISO / "progress-tracker").mkdir(parents=True, exist_ok=True)


def _progress_tracker_from_operator_config() -> Path | None:
    if _OPERATOR_CONFIG_HOME is None:
        return None
    locs = load_section(
        "locations.yaml",
        config_home=_OPERATOR_CONFIG_HOME,
        required=False,
    )
    if locs is None or not locs.progress_tracker:
        return None
    return Path(locs.progress_tracker)


def _resolve_progress_tracker() -> Path:
    configured = _progress_tracker_from_operator_config()
    if configured is not None:
        return configured
    return (_ISO / "progress-tracker").resolve()


(_TEST_HOME / "locations.yaml").write_text(
    yaml.safe_dump(
        {
            "workspace": str(_ISO / "ws"),
            "analysis_results": str(_ISO / "analysis-results"),
            "progress_tracker": str(_resolve_progress_tracker()),
        }
    ),
    encoding="utf-8",
)
os.environ["TRAUST_CONFIG_HOME"] = str(_TEST_HOME)
os.environ["HARNESS_TEST_FIXTURE_CONFIG"] = "1"

# Ledger >=0.7 verifies the actor on every write. Give the suite a real local
# identity (auto-minted ES256, iss=local) in an isolated config dir so it never
# reads the developer's ~/.config/traust-ledger. The ledger's config_dir() is
# $HOME/.config/traust-ledger with no override, hence HOME. See CONTRIBUTING.md
# "Ledger auth in tests".
_LEDGER_HOME = _TEST_HOME / "ledger-home"
_LEDGER_HOME.mkdir(parents=True, exist_ok=True)
os.environ["HOME"] = str(_LEDGER_HOME)
for _k in ("LAAS_TOKEN", "LEDGER_TOKEN", "LEDGER_TOKEN_PATH", "LEDGER_LOCAL_MACHINE"):
    os.environ.pop(_k, None)
os.environ["LEDGER_LOCAL_IDENTITY"] = "test@traust.local"
# Ledger 0.9.0: local tokens are no longer identity_verified by default (one
# person could otherwise hold two local identities and satisfy the two-person
# rule alone). This suite's fixture identity stands in for a human reviewer
# on purpose, so opt this test deployment back in -- same flag a real
# solo/offline deployment sets. See ledger CHANGELOG.md [0.9.0] Security.
os.environ["LEDGER_TRUST_LOCAL_IDENTITY"] = "1"

try:
    from traust_ledger.auth.config import resolve_auth

    _ledger_auth_source = resolve_auth().source
except Exception as _exc:
    raise pytest.UsageError(
        f"ledger local auth could not be provisioned ({_exc}); "
        'see CONTRIBUTING.md "Ledger auth in tests"'
    ) from _exc
if _ledger_auth_source != "auto-mint":
    raise pytest.UsageError(
        f"ledger auth resolved from {_ledger_auth_source!r}, expected the suite's "
        'auto-minted local identity; see CONTRIBUTING.md "Ledger auth in tests"'
    )
assert _TEST_HOME.resolve() != TRAUST_CONFIG_HOME_DEFAULT.resolve(), (
    "test suite must not inherit ~/.traust/config"
)

from traust.paths import skill_dir

# Tier 0: traust-engine, traust-contracts, traust-ledger via uv workspace.
# Tier 2: skill scripts import traust_engine.* directly (no flat aliases).

# Resolved by skill NAME, not by a hardcoded depth: a workflow skill sits at
# harnessing/<N>-<stage>/<skill>/ and the rest at harnessing/<skill>/, and
# skill_dir() spans both. Still an explicit list rather than every skill --
# these go on sys.path and skills share module basenames (plan.py,
# coverage.py), so widening it would change which module an import resolves
# to. Entries are (skill,) or (skill, "scripts").
_SKILL_SCRIPT_ENTRIES = [
    ("track-findings",),
    ("track-findings", "scripts"),
    ("verify-remediation", "scripts"),
    ("remediate-finding", "scripts"),
    ("recall-benchmark", "scripts"),
    ("secure-code-audit", "scripts"),
    ("refresh-dashboards", "scripts"),
    ("financial-tracking", "scripts"),
    ("threat-model", "scripts"),
    ("census", "scripts"),
    ("compliance-check", "scripts"),
    ("mine-ledger", "scripts"),
    ("impact-analysis", "scripts"),
    ("triage", "scripts"),
    ("portfolio-graph", "scripts"),
    ("dependency-watch",),
    ("dependency-watch", "scripts"),
    ("pqc-readiness",),
    ("pqc-readiness", "scripts"),
    ("attack-coverage", "scripts"),
    ("fleet-fix", "scripts"),
    ("findings-trends", "scripts"),
    ("executive-summary-findings", "scripts"),
    ("corpus-intake", "scripts"),
    ("isolation-review", "scripts"),
    ("validate-browser-finding", "scripts"),
    ("threat-register",),
    ("threat-register", "scripts"),
    ("vuln-scan", "scripts"),
    ("validate-findings",),
]

SKILL_SCRIPT_DIRS = [skill_dir(skill).joinpath(*rest) for skill, *rest in _SKILL_SCRIPT_ENTRIES]

for path in SKILL_SCRIPT_DIRS:
    entry = str(path)
    if entry not in sys.path:
        sys.path.insert(0, entry)


def _can_git_init():
    """Probe whether git init works in a temp directory."""
    probe = None
    try:
        probe = tempfile.mkdtemp(prefix="_git_probe_")
        subprocess.run(
            ["git", "init", "-q", probe],
            capture_output=True,
            timeout=10,
            check=True,
        )
        return True
    except Exception:
        return False
    finally:
        if probe:
            shutil.rmtree(probe, ignore_errors=True)


CAN_GIT_INIT = _can_git_init()


@pytest.fixture(autouse=True)
def _skip_if_no_git(request):
    if request.node.get_closest_marker("requires_git") and not CAN_GIT_INIT:
        pytest.skip("git init blocked in this environment")
