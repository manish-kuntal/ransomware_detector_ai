"""
process_monitor.py — Process and system-level metrics via psutil
Tracks CPU, memory, I/O counters, and newly spawned processes.
"""
import time
import threading
from collections import deque

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[WARN] psutil not installed — process/system monitoring disabled. "
          "Install with: pip install psutil")


class ProcessMonitor:
    """
    Samples process and system metrics on a fixed interval.

    Attributes
    ----------
    snapshots : deque
        Rolling list of metric snapshots (dicts), pruned to `window` seconds.
    """

    def __init__(self, window: float = 5.0, interval: float = 1.0):
        self.window   = window
        self.interval = interval
        self.snapshots: deque = deque()

        self._thread  = None
        self._stop_ev = threading.Event()
        self._known_pids: set = set()

        if PSUTIL_AVAILABLE:
            self._known_pids = {p.pid for p in psutil.process_iter()}

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if not PSUTIL_AVAILABLE:
            return
        self._stop_ev.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_ev.set()
        if self._thread:
            self._thread.join(timeout=self.interval * 2)

    # ── sampling loop ─────────────────────────────────────────────────────────

    def _loop(self):
        while not self._stop_ev.wait(self.interval):
            snap = self._sample()
            self.snapshots.append(snap)
            # Prune old snapshots
            cutoff = time.time() - self.window
            while self.snapshots and self.snapshots[0]['ts'] < cutoff:
                self.snapshots.popleft()

    def _sample(self) -> dict:
        ts = time.time()
        cpu = mem = 0.0
        io_read = io_write = io_write_bytes = io_read_bytes = 0
        new_procs = 0

        try:
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory().percent

            io = psutil.disk_io_counters()
            if io:
                io_read        = io.read_count
                io_write       = io.write_count
                io_read_bytes  = io.read_bytes
                io_write_bytes = io.write_bytes

            current_pids = {p.pid for p in psutil.process_iter()}
            new_procs    = len(current_pids - self._known_pids)
            self._known_pids = current_pids

        except Exception:
            pass

        return {
            'ts':              ts,
            'cpu_percent':     cpu,
            'memory_percent':  mem,
            'io_read_count':   io_read,
            'io_write_count':  io_write,
            'io_read_bytes':   io_read_bytes,
            'io_write_bytes':  io_write_bytes,
            'new_process_count': new_procs,
        }

    # ── aggregation ───────────────────────────────────────────────────────────

    def aggregate(self) -> dict:
        """
        Return aggregated metrics over the current window.
        Used by FeatureExtractor.
        """
        if not self.snapshots:
            return {k: 0.0 for k in [
                'cpu_percent', 'memory_percent',
                'io_read_count', 'io_write_count',
                'io_write_bytes', 'new_process_count',
            ]}

        snaps = list(self.snapshots)
        return {
            'cpu_percent':       sum(s['cpu_percent']      for s in snaps) / len(snaps),
            'memory_percent':    sum(s['memory_percent']   for s in snaps) / len(snaps),
            'io_read_count':     sum(s['io_read_count']    for s in snaps),
            'io_write_count':    sum(s['io_write_count']   for s in snaps),
            'io_write_bytes':    sum(s['io_write_bytes']   for s in snaps),
            'new_process_count': sum(s['new_process_count'] for s in snaps),
        }
