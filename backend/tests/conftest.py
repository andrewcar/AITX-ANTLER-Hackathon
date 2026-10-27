import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _isolate_guardrails(monkeypatch, tmp_path):
    """Keep tests off the real audit file, the network pace, and a full slot table."""
    monkeypatch.setenv("VULNSWARM_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("VULNSWARM_MAX_CONCURRENT_SCANS", "8")
    monkeypatch.setenv("VULNSWARM_REQUEST_INTERVAL_MS", "0")
    monkeypatch.setenv("VULNSWARM_GLOBAL_REQUEST_INTERVAL_MS", "0")
    import control
    control.testing_reset()
    yield
    control.testing_reset()
