"""The UI attack atlas (src/ui/vehicle.js) states a static GÖK-GW1 verdict per attack.
It must agree with the gateway model's measured verdict, otherwise the Atlas and Kapsam tabs contradict each other."""
import re
from pathlib import Path

from src.coverage import run_coverage

UI_TO_MODEL = {"block": "blocks", "partial": "partial", "none": "cannot"}


def test_atlas_verdicts_match_gateway_model():
    js = (Path(__file__).resolve().parent.parent / "src" / "ui" / "vehicle.js").read_text(encoding="utf-8")
    atlas = {}
    for m in re.finditer(r"^    (\w+): \{ tgt:.*?\n      gw: \[[^\]]*\], v: \"(\w+)\"", js, re.S | re.M):
        atlas[m.group(1)] = UI_TO_MODEL[m.group(2)]
    report = run_coverage()
    measured = {r["id"]: r["gateway"]["verdict"] for r in report["results"]}
    assert set(atlas) == set(measured)
    assert atlas == measured
