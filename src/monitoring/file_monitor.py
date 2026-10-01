"""
file_monitor.py — File system activity monitor using watchdog
Captures create / modify / rename / delete events and computes file entropy.
"""
import math
import time
import threading
from collections import defaultdict, deque
from pathlib import Path

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("[WARN] watchdog not installed — file monitoring disabled. "
          "Install with: pip install watchdog")


# ─── Internal event handler ───────────────────────────────────────────────────

class _Handler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, queue):
        self._q = queue
        if WATCHDOG_AVAILABLE:
            super().__init__()

    def on_created(self, event):
        if not event.is_directory:
            self._q.append({'type': 'create', 'path': event.src_path,
                            'ts': time.time(), 'bytes': 0})

    def on_modified(self, event):
        if not event.is_directory:
            size = 0
            try:
                size = Path(event.src_path).stat().st_size
            except OSError:
                pass
            self._q.append({'type': 'modify', 'path': event.src_path,
                            'ts': time.time(), 'bytes': size})

    def on_deleted(self, event):
        if not event.is_directory:
            self._q.append({'type': 'delete', 'path': event.src_path,
                            'ts': time.time(), 'bytes': 0})

    def on_moved(self, event):
        if not event.is_directory:
            src_ext  = Path(event.src_path).suffix.lower()
            dest_ext = Path(event.dest_path).suffix.lower()
            self._q.append({
                'type':       'rename',
                'path':       event.dest_path,
                'src':        event.src_path,
                'ext_change': src_ext != dest_ext,
                'src_ext':    src_ext,
                'dest_ext':   dest_ext,
                'ts':         time.time(),
                'bytes':      0,
            })


# ─── Public class ─────────────────────────────────────────────────────────────

class FileMonitor:
    """
    Watches a directory tree and exposes a sliding-window event list.

    Usage:
        mon = FileMonitor('/path/to/watch', window=5.0)
        mon.start()
        ...
        events = mon.get_events()
        entropies = mon.entropy_snapshot(events)
        mon.stop()
    """

    def __init__(self, watch_path: str, window: float = 5.0):
        self.watch_path = watch_path
        self.window     = window
        self._queue     = deque()
        self._observer  = None
        self._running   = False

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if not WATCHDOG_AVAILABLE:
            return
        handler = _Handler(self._queue)
        self._observer = Observer()
        self._observer.schedule(handler, self.watch_path, recursive=True)
        self._observer.start()
        self._running = True

    def stop(self):
        self._running = False
        if self._observer:
            self._observer.stop()
            self._observer.join()

    # ── data retrieval ────────────────────────────────────────────────────────

    def get_events(self) -> list:
        """Return events within the current sliding window, pruning stale ones."""
        cutoff = time.time() - self.window
        while self._queue and self._queue[0]['ts'] < cutoff:
            self._queue.popleft()
        return list(self._queue)

    # ── entropy helpers ───────────────────────────────────────────────────────

    @staticmethod
    def file_entropy(path: str, max_bytes: int = 65536) -> float:
        """
        Shannon entropy of a file (bits per byte, 0–8).
        High values (≥ 7.2) suggest encrypted / compressed content.
        """
        try:
            with open(path, 'rb') as fh:
                data = fh.read(max_bytes)
            if not data:
                return 0.0
            freq = defaultdict(int)
            for b in data:
                freq[b] += 1
            total = len(data)
            return -sum((c / total) * math.log2(c / total)
                        for c in freq.values())
        except OSError:
            return 0.0

    def entropy_snapshot(self, events: list) -> dict:
        """Map path → entropy for all create/modify events that still exist."""
        result = {}
        for ev in events:
            if ev['type'] in ('create', 'modify'):
                p = ev['path']
                if Path(p).exists():
                    result[p] = self.file_entropy(p)
        return result
