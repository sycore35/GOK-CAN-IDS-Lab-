"""DBC Editor: CRUD over CAN messages/signals, validation, .dbc text import/export, persistence.

The editor mutates the *live* DBCDecoder, so the decoder, the IDS whitelist (Layer 1) and the
timing layer (Layer 2) immediately use the edited database.
"""
import copy
import json
import os
import re
from typing import Any, Dict, List, Optional

from src.dbc_decoder import DBCDecoder, extract_raw, signal_bit_positions

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _num(x: Any) -> str:
    x = float(x)
    return str(int(x)) if x == int(x) else repr(round(x, 9))


def _bool(v: Any, name: str) -> bool:
    """JSON booleans, 0/1 and the strings true/false/1/0. bool("false") would silently be True."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in ("true", "false", "1", "0", "yes", "no"):
        return v.strip().lower() in ("true", "1", "yes")
    raise ValueError(f"{name} must be true or false")


def normalize_message(msg: Dict[str, Any]) -> Dict[str, Any]:
    m = copy.deepcopy(msg)
    ext = _bool(m.get("is_extended", False), "is_extended")
    if "id_dec" not in m and "id_hex" in m:
        m["id_dec"] = int(str(m["id_hex"]), 16)
    m["id_dec"] = int(m["id_dec"])
    m["is_extended"] = ext
    m["id_hex"] = f"0x{m['id_dec']:08X}" if ext else f"0x{m['id_dec']:03X}"
    m["id_raw"] = m["id_dec"] | (0x80000000 if ext else 0)
    m["dlc"] = int(m.get("dlc", 8))
    m.setdefault("transmitter", "Vector__XXX")
    if m.get("cycle_time_ms") is not None:
        m["cycle_time_ms"] = int(m["cycle_time_ms"])
    sigs = []
    for s in m.get("signals", []):
        sigs.append(normalize_signal(s))
    m["signals"] = sigs
    return m


def normalize_signal(sig: Dict[str, Any]) -> Dict[str, Any]:
    s = dict(sig)
    s["name"] = str(s.get("name", ""))
    s["start_bit"] = int(s.get("start_bit", 0))
    s["length"] = int(s.get("length", 1))
    s["endian"] = "big" if str(s.get("endian", "little")).lower() in ("big", "motorola", "0") else "little"
    s["is_signed"] = _bool(s.get("is_signed", False), "is_signed")
    s["scale"] = float(s.get("scale", 1.0))
    s["offset"] = float(s.get("offset", 0.0))
    s["min"] = float(s.get("min", 0.0))
    s["max"] = float(s.get("max", 0.0))
    s["unit"] = str(s.get("unit", ""))
    return s


def validate_message(msg: Dict[str, Any]) -> List[str]:
    """Return a list of human-readable problems (empty list = valid)."""
    issues: List[str] = []
    name = msg.get("name", "")
    if not _IDENT.match(str(name)):
        issues.append(f"Message name '{name}' is not a valid identifier (letters, digits, underscore).")
    limit = 0x1FFFFFFF if msg.get("is_extended") else 0x7FF
    if not (0 <= int(msg["id_dec"]) <= limit):
        issues.append(f"CAN ID {msg['id_dec']} outside 0..{limit:#x}.")
    if not (0 <= msg["dlc"] <= 64):
        issues.append(f"DLC {msg['dlc']} outside 0..64.")
    seen: Dict[int, str] = {}
    names = set()
    max_bit = msg["dlc"] * 8
    for s in msg.get("signals", []):
        n = s["name"]
        if not _IDENT.match(n):
            issues.append(f"Signal name '{n}' is not a valid identifier.")
        if n in names:
            issues.append(f"Duplicate signal name '{n}'.")
        names.add(n)
        if not (1 <= s["length"] <= 64):
            issues.append(f"Signal '{n}': length {s['length']} outside 1..64.")
            continue
        if s["scale"] == 0:
            issues.append(f"Signal '{n}': factor (scale) must not be 0.")
        if s["max"] < s["min"]:
            issues.append(f"Signal '{n}': max < min.")
        if s["start_bit"] < 0:
            issues.append(f"Signal '{n}': negative start bit.")
            continue
        for b in signal_bit_positions(s["start_bit"], s["length"], s["endian"]):
            if b < 0 or b >= max_bit:
                issues.append(f"Signal '{n}' exceeds the {msg['dlc']}-byte payload (bit {b}).")
                break
            if b in seen:
                issues.append(f"Signal '{n}' overlaps '{seen[b]}' at bit {b}.")
                break
            seen[b] = n
    return issues


def export_dbc_text(config: Dict[str, Any]) -> str:
    msgs = config.get("messages", [])
    nodes = []
    for m in msgs:
        t = m.get("transmitter", "Vector__XXX")
        if t not in nodes:
            nodes.append(t)
    for m in msgs:
        for s in m.get("signals", []):
            for r in str(s.get("receivers", "")).split(","):
                if r.strip() and r.strip() not in nodes:
                    nodes.append(r.strip())
    out = ['VERSION ""', "", "NS_ :", "", "BS_:", "", "BU_: " + " ".join(nodes), ""]
    for m in msgs:
        m = normalize_message(m)
        out.append(f"BO_ {m['id_raw']} {m['name']}: {m['dlc']} {m['transmitter']}")
        for s in m["signals"]:
            order = "1" if s["endian"] == "little" else "0"
            sign = "-" if s["is_signed"] else "+"
            rcv = (str(s.get("receivers", "")).strip() or "Vector__XXX")
            out.append(
                f" SG_ {s['name']} : {s['start_bit']}|{s['length']}@{order}{sign} "
                f"({_num(s['scale'])},{_num(s['offset'])}) [{_num(s['min'])}|{_num(s['max'])}] "
                f"\"{s['unit']}\" {rcv}")
        out.append("")
    if any(m.get("cycle_time_ms") for m in msgs):
        out.append('BA_DEF_ BO_ "GenMsgCycleTime" INT 0 65535;')
        out.append('BA_DEF_DEF_ "GenMsgCycleTime" 0;')
        for m in msgs:
            if m.get("cycle_time_ms"):
                out.append(f'BA_ "GenMsgCycleTime" BO_ {normalize_message(m)["id_raw"]} {int(m["cycle_time_ms"])};')
        out.append("")
    for m in msgs:
        for sig, table in (config.get("val_tables", {}).get(m.get("id_dec"), {}) or {}).items():
            pairs = " ".join(f'{k} "{v}"' for k, v in sorted(table.items()))
            out.append(f"VAL_ {m['id_dec']} {sig} {pairs} ;")
    return "\n".join(out).rstrip() + "\n"


class DBCEditor:
    def __init__(self, decoder: DBCDecoder, persist_path: Optional[str] = None):
        self.decoder = decoder
        self.persist_path = persist_path
        # Normalise the loaded config once so edits and exports see a uniform schema.
        self._commit(self._working_copy(), save=False)

    def _working_copy(self) -> Dict[str, Any]:
        cfg = copy.deepcopy(self.decoder.config)
        cfg["messages"] = [normalize_message(m) for m in cfg.get("messages", [])]
        return cfg

    def _commit(self, cfg: Dict[str, Any], save: bool = True) -> None:
        self.decoder.load_config(cfg)
        if save:
            self.save()

    @staticmethod
    def _find(cfg: Dict[str, Any], msg_id: int) -> Dict[str, Any]:
        for m in cfg["messages"]:
            if m["id_dec"] == msg_id:
                return m
        raise KeyError(f"message {msg_id:#x} not found")

    def _check(self, cfg: Dict[str, Any]) -> None:
        issues: List[str] = []
        ids = [m["id_dec"] for m in cfg["messages"]]
        names = [m["name"] for m in cfg["messages"]]
        for i in set(ids):
            if ids.count(i) > 1:
                issues.append(f"Duplicate CAN ID {i:#x}.")
        for n in set(names):
            if names.count(n) > 1:
                issues.append(f"Duplicate message name '{n}'.")
        for m in cfg["messages"]:
            issues += [f"{m['name']}: {x}" for x in validate_message(m)]
        if issues:
            raise ValueError("; ".join(issues))

    def snapshot(self) -> Dict[str, Any]:
        cfg = self._working_copy()
        return {"bus_name": cfg.get("bus_name", "Virtual_CAN"), "nominal_bitrate_kbps": cfg.get("nominal_bitrate_kbps", 500),
                "messages": cfg["messages"], "integrity": self.decoder.validate_dbc_integrity()}

    def get_message(self, msg_id: int) -> Dict[str, Any]:
        return self._find(self._working_copy(), msg_id)

    def add_message(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self._working_copy()
        cfg["messages"].append(normalize_message(msg))
        self._check(cfg)
        self._commit(cfg)
        return self._find(cfg, normalize_message(msg)["id_dec"])

    def update_message(self, msg_id: int, patch: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self._working_copy()
        m = self._find(cfg, msg_id)
        patch = {k: v for k, v in patch.items() if k != "signals"}
        if "id_dec" not in patch and "id_hex" in patch:
            patch["id_dec"] = int(str(patch["id_hex"]), 16)
        merged = normalize_message({**m, **patch})
        cfg["messages"][cfg["messages"].index(m)] = merged
        self._check(cfg)
        self._commit(cfg)
        return merged

    def delete_message(self, msg_id: int) -> None:
        cfg = self._working_copy()
        m = self._find(cfg, msg_id)
        cfg["messages"].remove(m)
        cfg.get("val_tables", {}).pop(msg_id, None)
        self._commit(cfg)

    def add_signal(self, msg_id: int, sig: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self._working_copy()
        m = self._find(cfg, msg_id)
        m["signals"].append(normalize_signal(sig))
        self._check(cfg)
        self._commit(cfg)
        return m

    def update_signal(self, msg_id: int, name: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self._working_copy()
        m = self._find(cfg, msg_id)
        for i, s in enumerate(m["signals"]):
            if s["name"] == name:
                m["signals"][i] = normalize_signal({**s, **patch})
                break
        else:
            raise KeyError(f"signal {name!r} not found in {m['name']}")
        self._check(cfg)
        self._commit(cfg)
        return m

    def delete_signal(self, msg_id: int, name: str) -> Dict[str, Any]:
        cfg = self._working_copy()
        m = self._find(cfg, msg_id)
        before = len(m["signals"])
        m["signals"] = [s for s in m["signals"] if s["name"] != name]
        if len(m["signals"]) == before:
            raise KeyError(f"signal {name!r} not found in {m['name']}")
        self._commit(cfg)
        return m

    def export_text(self) -> str:
        return export_dbc_text(self._working_copy())

    def import_text(self, text: str) -> Dict[str, Any]:
        parsed = DBCDecoder.parse_dbc_text(text)
        if not parsed["messages"]:
            raise ValueError("No BO_ message definitions found in the supplied DBC text.")
        cfg = {"bus_name": self.decoder.config.get("bus_name", "Imported_DBC"),
               "nominal_bitrate_kbps": parsed.get("nominal_bitrate_kbps", 500),
               "messages": [normalize_message(m) for m in parsed["messages"]],
               "val_tables": parsed.get("val_tables", {})}
        self._check(cfg)
        self._commit(cfg)
        return {"messages": len(cfg["messages"]), "signals": sum(len(m["signals"]) for m in cfg["messages"])}

    def decode_preview(self, msg_id: int, data_hex: str) -> Dict[str, Any]:
        from src.can_frame import CANFrame
        data = bytes.fromhex(re.sub(r"[^0-9A-Fa-f]", "", data_hex))
        return self.decoder.decode_frame(CANFrame(msg_id, data))

    def save(self) -> None:
        if not self.persist_path:
            return
        os.makedirs(os.path.dirname(self.persist_path) or ".", exist_ok=True)
        cfg = copy.deepcopy(self.decoder.config)
        cfg["val_tables"] = {str(k): {s: {str(c): t for c, t in tb.items()} for s, tb in v.items()}
                             for k, v in cfg.get("val_tables", {}).items()}
        cfg.pop("mul_val_tables", None)
        tmp = self.persist_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.persist_path)

    @staticmethod
    def load_persisted(path: str) -> Optional[Dict[str, Any]]:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        cfg["val_tables"] = {int(k): {s: {int(c): t for c, t in tb.items()} for s, tb in v.items()}
                             for k, v in cfg.get("val_tables", {}).items()}
        return cfg
