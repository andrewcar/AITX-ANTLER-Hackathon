"""
Kill switch, concurrency cap, and outbound pacing.

A scan holds a ScanLease. Stopping that lease — from the dashboard, from a
disconnect, or from stop-all — sets one threading.Event. Recon polls it while
an HTTP call is in flight and checks it again before every new call, so a stop
lands inside a phase instead of waiting for the phase barrier.

VULNSWARM_MAX_CONCURRENT_SCANS   default 2. Extra scans get HTTP 429.
VULNSWARM_REQUEST_INTERVAL_MS    default 50. Minimum gap between requests in one scan.
VULNSWARM_GLOBAL_REQUEST_INTERVAL_MS
                                 default 25. Minimum gap between any two requests.
"""
import contextlib
import os
import threading
import time
import uuid
from contextvars import ContextVar

import audit

_lease: ContextVar["ScanLease | None"] = ContextVar("vulnswarm_lease", default=None)
_agent: ContextVar[str] = ContextVar("vulnswarm_agent", default="scan")

_registry_lock = threading.Lock()
_active: dict[str, "ScanLease"] = {}


class ScanStopped(Exception):
    """The lease was stopped. Callers turn this into a cancelled scan, not a 502."""


class BusyError(Exception):
    """The concurrency cap is full."""

    def __init__(self, active: int, limit: int):
        self.active = active
        self.limit = limit
        super().__init__(
            f"too many scans in progress ({active}/{limit}); stop one or retry"
        )


class _Gate:
    def __init__(self):
        self.lock = threading.Lock()
        self.next_at = 0.0


_global_gate = _Gate()


def max_concurrent() -> int:
    try:
        n = int(os.environ.get("VULNSWARM_MAX_CONCURRENT_SCANS", "2"))
    except ValueError:
        n = 2
    return max(1, n)


def request_interval_s() -> float:
    return _ms_env("VULNSWARM_REQUEST_INTERVAL_MS", 50)


def global_interval_s() -> float:
    return _ms_env("VULNSWARM_GLOBAL_REQUEST_INTERVAL_MS", 25)


def _ms_env(name: str, default: float) -> float:
    try:
        ms = float(os.environ.get(name, str(default)))
    except ValueError:
        ms = default
    return max(0.0, ms) / 1000.0


class ScanLease:
    def __init__(self, run_id: str, target: str, actor: str):
        self.run_id = run_id
        self.target = target
        self.actor = actor
        self.event = threading.Event()
        self._gate = _Gate()

    def stop(self) -> None:
        self.event.set()

    def stopped(self) -> bool:
        return self.event.is_set()

    def pace(self) -> None:
        _wait(self._gate, request_interval_s())


def acquire(target: str, actor: str, run_id: str | None = None) -> ScanLease:
    """Reserve a scan slot. Raises BusyError when the cap is full."""
    run_id = run_id or ("run_" + uuid.uuid4().hex[:10])
    with _registry_lock:
        limit = max_concurrent()
        if len(_active) >= limit:
            raise BusyError(len(_active), limit)
        lease = ScanLease(run_id, target, actor)
        _active[run_id] = lease
        return lease


def release(run_id: str) -> None:
    with _registry_lock:
        _active.pop(run_id, None)


def stop(run_id: str) -> bool:
    """Stop one scan. False when that run is not in flight."""
    with _registry_lock:
        lease = _active.get(run_id)
    if lease is None:
        return False
    lease.stop()
    return True


def stop_all() -> list[str]:
    """Stop every scan that is currently in flight. New scans are unaffected."""
    with _registry_lock:
        leases = list(_active.values())
    for lease in leases:
        lease.stop()
    return [lease.run_id for lease in leases]


def active_ids() -> list[str]:
    with _registry_lock:
        return list(_active)


def current_lease() -> ScanLease | None:
    return _lease.get()


def current_agent() -> str:
    return _agent.get()


def stopped() -> bool:
    lease = _lease.get()
    return bool(lease and lease.stopped())


def checkpoint() -> None:
    """Raise ScanStopped when the current scan has been told to stop."""
    if stopped():
        raise ScanStopped()


def pace() -> None:
    """Sleep out the global gap and this scan's gap. Returns quickly once stopped."""
    checkpoint()
    _wait(_global_gate, global_interval_s())
    lease = _lease.get()
    if lease is not None:
        lease.pace()
    checkpoint()


def note_request(action: str, url: str, status: int) -> None:
    """Audit one outbound call when it belongs to a leased scan."""
    lease = _lease.get()
    if lease is None:
        return
    audit.record(
        "request",
        run_id=lease.run_id,
        target=lease.target,
        actor=lease.actor,
        agent=current_agent(),
        action=action,
        url=str(url)[:500],
        status=int(status),
    )


@contextlib.contextmanager
def scope(lease: ScanLease | None):
    token = _lease.set(lease)
    try:
        yield lease
    finally:
        _lease.reset(token)


@contextlib.contextmanager
def agent(name: str):
    token = _agent.set(name or "scan")
    try:
        yield
    finally:
        _agent.reset(token)


def testing_reset() -> None:
    """Drop in-flight leases. Tests only — not a product API."""
    with _registry_lock:
        _active.clear()
    _global_gate.next_at = 0.0


def _wait(gate: _Gate, interval: float) -> None:
    if interval <= 0:
        return
    while True:
        checkpoint()
        with gate.lock:
            now = time.monotonic()
            delay = gate.next_at - now
            if delay <= 0:
                gate.next_at = now + interval
                return
        time.sleep(min(delay, 0.05))
