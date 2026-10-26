"""
ScanContext — the shared state every agent reads/writes through.

This is what makes the swarm 'synchronized': one surface map, one findings store
(guarded by a lock so parallel agents can append safely), one run identity. Swap the
in-process store for Redis later to run agents across multiple machines unchanged.
"""
import threading
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class ScanContext:
    url: str                                   # original target
    recon_root: dict                           # recon.scan(url)
    surface: dict = field(default_factory=dict)
    fingerprint: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    run_id: str = field(default_factory=lambda: "run_" + uuid.uuid4().hex[:10])
    started: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, items: list[dict], agent: str, section: dict | None = None):
        """Thread-safe: parallel specialists land findings here."""
        for f in items:
            f.setdefault("agent", agent)
            if section:
                f.setdefault("section", section)
        with self._lock:
            self.findings.extend(items)
