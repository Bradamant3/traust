"""`traust reporting render` refuses to erase threat-model prose.

A threat-model JSON that lacks members its Markdown has (the 2026-09-20
backfill wrote only system/provenance/threats) re-renders to a document with
empty sections. Overwriting the .md with that silently deletes the model's
context, assets and entry points, which is how the first OWASP write-back
went wrong. The guard makes that a refusal unless the caller says the
removal is intended.
"""

import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path

from traust.cli.groups.reporting import call_render, lost_sections

FULL = {
    "system": "example",
    "provenance": {"mode": "bootstrap", "date": "2026-10-01", "target": "repo @ abc1234"},
    "system_context": "Decodes user-supplied audio.",
    "assets": [{"asset": "host", "description": "decoder memory", "sensitivity": "critical"}],
    "entry_points": [
        {
            "entry_point": "upload",
            "description": "WAV decode",
            "trust_boundary": "file -> memory",
            "reachable_assets": "host",
        }
    ],
    "threats": [
        {
            "id": "T1",
            "threat": "RCE via audio parsing",
            "actor": ["remote_unauth"],
            "surface": "upload",
            "asset": "host",
            "impact": "critical",
            "likelihood": "likely",
            "status": "unmitigated",
            "controls": "none",
            "evidence": [],
            "attack_refs": ["T1203"],
        }
    ],
    "deprioritized": [{"threat": "physical access", "reason": "out of scope"}],
    "open_questions": ["Is the decoder sandboxed?"],
}
THIN = {k: FULL[k] for k in ("system", "provenance", "threats")}


class _Engine:
    class reporting:  # mimics the engine facade attribute
        @staticmethod
        def render(path):
            from traust_engine.reporting.render import render_threat_model

            return render_threat_model(json.loads(Path(path).read_text()))


def _render(tmp_path: Path, document: dict, existing: str | None, allow: bool = False):
    src = tmp_path / "repo-threat-model.json"
    src.write_text(json.dumps(document))
    out = tmp_path / "repo-threat-model.md"
    if existing is not None:
        out.write_text(existing)
    rc = call_render(_Engine, Namespace(report=src, out=out, allow_section_loss=allow))
    return rc, out.read_text()


def _full_markdown(tmp_path: Path) -> str:
    rc, md = _render(tmp_path, FULL, None)
    assert rc == 0
    return md


def test_thin_json_does_not_overwrite_a_full_model(tmp_path: Path) -> None:
    full_md = _full_markdown(tmp_path)
    rc, md = _render(tmp_path, THIN, full_md)
    assert rc == 1
    assert md == full_md, "the existing .md must be left untouched"


def test_lost_sections_names_what_would_go(tmp_path: Path) -> None:
    from traust_engine.reporting.render import render_threat_model

    lost = lost_sections(_full_markdown(tmp_path), render_threat_model(THIN))
    assert {"1. System context", "2. Assets", "3. Entry points & trust boundaries"} <= set(lost)
    assert "4. Threats" not in lost


def test_complete_json_overwrites_normally(tmp_path: Path) -> None:
    full_md = _full_markdown(tmp_path)
    rated = json.loads(json.dumps(FULL))
    rated["threats"][0]["status"] = "partially_mitigated"
    rc, md = _render(tmp_path, rated, full_md)
    assert rc == 0 and "partially_mitigated" in md


def test_intended_removal_needs_the_flag(tmp_path: Path) -> None:
    full_md = _full_markdown(tmp_path)
    fewer = {k: v for k, v in FULL.items() if k != "deprioritized"}
    assert _render(tmp_path, fewer, full_md)[0] == 1
    rc, md = _render(tmp_path, fewer, full_md, allow=True)
    assert rc == 0 and "physical access" not in md


def test_scheduled_check_up_applies_ratings() -> None:
    """The quarterly and release-review lanes write OWASP ratings and leave
    everything else report-only (decided 2026-10-01)."""
    path = (
        Path(__file__).resolve().parents[1]
        / "harnessing/2-threat-model/threat-model/scripts/emit_drain_tranche.py"
    )
    spec = importlib.util.spec_from_file_location("emit_drain_tranche", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("emit_drain_tranche", module)
    spec.loader.exec_module(module)
    for lane in ("threat-model-quarterly", "threat-model-review"):
        assert module._DISPATCH[lane] == "/threat-model review <clone> --auto --apply-ratings"
