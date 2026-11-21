"""C firmware vs Python model: runs `make -C firmware/gokguard test` (skipped when no C compiler/make)."""
import os
import shutil
import subprocess

import pytest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FW = os.path.join(BASE, "firmware", "gokguard")


@pytest.mark.skipif(not (shutil.which("cc") and shutil.which("make")), reason="no C compiler / make")
def test_c_firmware_tests_and_parity_with_python_vectors():
    r = subprocess.run(["make", "-C", FW, "test"], capture_output=True, text=True, timeout=300)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out[-3000:]
    assert "RESULT: PASS" in out and " 0 failed" in out
    assert "0 mismatches" in out and "26 cases" in out


def test_generated_policy_header_is_fresh():
    from tools import policy_compiler
    assert policy_compiler.main(["--check"]) == 0
