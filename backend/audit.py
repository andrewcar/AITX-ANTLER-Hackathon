"""
Append-only audit log.

One JSON object per line. Records are never rewritten or deleted. A scan line
covers who started or stopped a scan; a request line covers one outbound call
an agent made (method, URL, status). Bodies are not stored — login posts carry
lab passwords.

Override the file with VULNSWARM_AUDIT_LOG. The default lives under backend/var,
which is gitignored.
"""
import json
import os
import threading
import time
from pathlib import Path

_lock = threading.Lock()


def log_path() -> Path:
    raw = os.environ.get("VULNSWARM_AUDIT_LOG", "")
    if raw:
        return Path(raw)
    return Path(__file__).resolve().parent / "var" / "audit.jsonl"


def record(kind: str, **fields) -> dict:
    """Append one record and return it. `kind` is 'scan' or 'request'."""
    row = {"ts": time.time(), "kind": kind, **fields}
    path = log_path()
    line = json.dumps(row, ensure_ascii=False, default=str)
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())
    return row


def recent(limit: int = 40) -> list[dict]:
    """Newest records first. Missing file or a torn last line yields what it can."""
    limit = max(1, min(int(limit), 200))
    path = log_path()
    if not path.exists():
        return []
    # A demo log stays small. Cap the read so a runaway file cannot stall /audit.
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size > 262_144:
            fh.seek(size - 262_144)
            fh.readline()  # drop the partial line we landed in
        text = fh.read().decode("utf-8", "replace")
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return list(reversed(rows[-limit:]))
