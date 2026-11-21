#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
export CAN_LAB_PORT="${CAN_LAB_PORT:-8003}"
[ -x .venv/bin/python ] || python3 -m venv .venv || exit 1
.venv/bin/pip install -q -r requirements.txt || exit 1
(sleep 3; open "http://127.0.0.1:$CAN_LAB_PORT") &
.venv/bin/python -m uvicorn src.api:app --host 127.0.0.1 --port "$CAN_LAB_PORT"
