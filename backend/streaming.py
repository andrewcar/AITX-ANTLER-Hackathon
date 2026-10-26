"""
Live scan stream (Server-Sent Events).

A scan is one request that pushes a finite sequence of events and then ends.
Nothing on the dashboard talks back mid-scan, so a WebSocket would add a second
connection and a second auth handshake for a channel that only flows one way.

SSE keeps the existing HTTP contract: Bearer token in the Authorization header,
target URL in a JSON body, allowlist enforced before any byte of the stream is
produced. EventSource cannot set that header, so the dashboard reads this
response with fetch.

This module does not decide which hosts are in scope. The caller must refuse
out-of-scope targets before start_scan_thread, and should check again inside
the worker so a streaming path cannot reach the orchestrator by skipping the
handler check.
"""
import asyncio
import json
import queue
import threading

# Comment frame large enough to push a buffering proxy into flushing.
_PRELUDE = ":" + (" " * 2048) + "\n\n"
_HEARTBEAT_SECONDS = 5
_SENTINEL = object()


def format_sse(event: dict) -> str:
    """One SSE message. `data` is a single line so evidence newlines stay escaped."""
    payload = json.dumps(event, default=str, ensure_ascii=False, separators=(",", ":"))
    kind = event.get("type") or "message"
    return f"event: {kind}\ndata: {payload}\n\n"


def start_scan_thread(produce) -> tuple[queue.Queue, threading.Event]:
    """Run produce(on_event, stop) on a daemon thread. on_event is thread-safe.

    produce owns the scan. When it returns or raises, a sentinel is queued and
    the stream ends. stop is set when the client goes away; produce should pass
    it to the orchestrator so later phases do not start.
    """
    events: queue.Queue = queue.Queue()
    stop = threading.Event()

    def worker():
        try:
            produce(events.put, stop)
        except Exception as e:
            events.put({
                "type": "error",
                "message": f"scan failed: {type(e).__name__}: {e}",
            })
        finally:
            events.put(_SENTINEL)

    threading.Thread(target=worker, name="vulnswarm-scan", daemon=True).start()
    return events, stop


async def sse_frames(events: queue.Queue, stop: threading.Event):
    """Yield SSE text until the scan thread signals completion or the client leaves."""
    loop = asyncio.get_running_loop()
    yield _PRELUDE
    try:
        while True:
            item = await loop.run_in_executor(None, _take, events)
            if item is _SENTINEL:
                break
            if item is None:
                if stop.is_set():
                    break
                yield ": ping\n\n"
                continue
            yield format_sse(item)
    finally:
        # Client disconnect, or the generator was closed. The scan thread
        # notices between phases. This is per-request cancel, not a global
        # kill switch — see the streaming endpoint notes.
        stop.set()


def _take(events: queue.Queue):
    try:
        return events.get(timeout=_HEARTBEAT_SECONDS)
    except queue.Empty:
        return None
