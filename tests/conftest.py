"""Test isolation: persist state (SQLite, live DBC, custom rules) in a temp dir, never in the user's data/."""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="can_lab_tests_")
os.environ.setdefault("CAN_LAB_DATA_DIR", _TMP)
