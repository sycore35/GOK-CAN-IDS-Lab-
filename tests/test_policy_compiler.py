import copy
import json
import subprocess
import sys

import pytest
import yaml

from tools import policy_compiler as pc


@pytest.fixture(scope="module")
def sources():
    return pc.load_sources()


def test_committed_header_is_fresh():
    assert pc.main(["--check"]) == 0


def test_output_is_deterministic():
    assert pc.compile_policy() == pc.compile_policy()
    assert "DO NOT EDIT" in pc.compile_policy()


def test_model_matches_dbc(sources):
    m = pc.build_model(*sources)
    by = {x["id"]: x for x in m["msgs"]}
    assert sorted(by) == [0x0C4, 0x180, 0x200, 0x244, 0x2A0, 0x320, 0x3C0]
    assert by[0x320]["flags"] == pc.F_A_ALLOWED and by[0x3C0]["flags"] == pc.F_A_ALLOWED
    assert by[0x0C4]["flags"] & pc.F_CRITICAL and by[0x180]["flags"] & pc.F_CRITICAL
    assert by[0x200]["flags"] == pc.F_CRITICAL | pc.F_COUNTER_CRC
    assert (by[0x200]["cnt_start"], by[0x200]["cnt_len"], by[0x200]["crc_byte"]) == (48, 4, 7)
    assert by[0x244]["flags"] == 0
    assert by[0x320]["rate_fps"] == 20 and by[0x0C4]["rate_fps"] == 200      # 2 x 1000 / cycle
    sig = {(s["msg"], s["name"]): s for s in m["sigs"]}
    assert sig[(0x244, "speed_kmh")]["raw_max"] == 26000                      # 260 km/h / 0.01
    assert (sig[(0x0C4, "steering_angle_deg")]["raw_min"], sig[(0x0C4, "steering_angle_deg")]["raw_max"]) == (0, 10000)
    assert sig[(0x180, "engine_temp")]["raw_max"] == 190                      # 150 C + 40 offset
    assert m["total_rate_fps"] == 200 and m["id_burst"] == 4 and 0x6F1 in m["uds_ids"] and 0x34 in m["dangerous"]
    assert sum(x["sig_n"] for x in m["msgs"]) == len(m["sigs"])


def test_ranges_round_inwards(sources):
    signals, config = copy.deepcopy(sources[0]), sources[1]
    for msg in signals["messages"]:
        if msg["id_hex"] == "0x180":
            for s in msg["signals"]:
                if s["name"] == "throttle_pct":
                    s["max"] = 99          # 99 / 0.392 = 252.55 -> raw 252, never 253
    m = pc.build_model(signals, config)
    assert [s for s in m["sigs"] if s["name"] == "throttle_pct"][0]["raw_max"] == 252


@pytest.mark.parametrize("edit,msg", [
    (lambda s, c: c["gateway"].update(a_to_b_ids=[0x320, 0x200]), "both"),
    (lambda s, c: c["gateway"].update(a_to_b_ids=[0x320, 0x320]), "duplicates"),
    (lambda s, c: c["gateway"].update(a_to_b_ids=[0x555]), "not in the DBC"),
    (lambda s, c: c["gateway"].update(total_rate_fps=0), "total_rate_fps"),
    (lambda s, c: c["gateway"].update(a_to_b_ids=[0x320, 0x7E0]), "UDS"),
    (lambda s, c: s["messages"][0]["signals"][0].update(endian="big"), "little-endian"),
    (lambda s, c: s["messages"][0]["signals"][0].update(length=40), "length"),
    (lambda s, c: c.pop("gateway"), "gateway"),
])
def test_unsafe_sources_are_rejected(sources, edit, msg):
    signals, config = copy.deepcopy(sources[0]), copy.deepcopy(sources[1])
    edit(signals, config)
    with pytest.raises(pc.PolicyError, match=msg):
        pc.build_model(signals, config)


def test_check_detects_stale_header(tmp_path):
    out = tmp_path / "policy_generated.h"
    assert pc.main(["--out", str(out)]) == 0
    assert pc.main(["--check", "--out", str(out)]) == 0
    out.write_text(out.read_text() + "/* edited */\n")
    assert pc.main(["--check", "--out", str(out)]) == 1


def test_header_hash_follows_gateway_section_only(tmp_path):
    cfg = yaml.safe_load(open(pc.DEFAULT_CONFIG))
    p1 = tmp_path / "a.yaml"
    p1.write_text(yaml.safe_dump(cfg))
    cfg["server"]["port"] = 9999                  # unrelated section: header must not go stale
    p2 = tmp_path / "b.yaml"
    p2.write_text(yaml.safe_dump(cfg))
    assert pc.compile_policy(config_path=p1) == pc.compile_policy(config_path=p2)
    cfg["gateway"]["total_burst"] = 41            # gateway section: header changes
    p3 = tmp_path / "c.yaml"
    p3.write_text(yaml.safe_dump(cfg))
    assert pc.compile_policy(config_path=p1) != pc.compile_policy(config_path=p3)


def test_cli_runs_as_script(tmp_path):
    r = subprocess.run([sys.executable, str(pc.ROOT / "tools" / "policy_compiler.py"), "--out", str(tmp_path / "x.h")],
                       capture_output=True, text=True)
    assert r.returncode == 0 and (tmp_path / "x.h").exists()
