"""
extractor.py — Converts raw monitoring events into a fixed-length feature vector.

Feature vector layout (18 features) — see config.FEATURE_NAMES for the index map:
    [0]  file_create_count
    [1]  file_modify_count
    [2]  file_rename_count
    [3]  file_delete_count
    [4]  extension_change_count
    [5]  avg_entropy
    [6]  entropy_spike_count
    [7]  high_entropy_ratio
    [8]  bytes_written
    [9]  unique_extensions
    [10] write_ops_per_sec
    [11] rename_to_modify_ratio
    [12] cpu_percent
    [13] memory_percent
    [14] new_process_count
    [15] io_read_count
    [16] io_write_count
    [17] io_write_bytes
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from config import ENTROPY_HIGH_THRESHOLD, FEATURE_WINDOW


class FeatureExtractor:
    """
    Pulls data from FileMonitor + ProcessMonitor and returns
    one feature vector (list of 18 floats).

    Parameters
    ----------
    file_monitor    : FileMonitor instance
    process_monitor : ProcessMonitor instance
    window          : time window in seconds (default: config.FEATURE_WINDOW)
    """

    def __init__(self, file_monitor, process_monitor, window: float = FEATURE_WINDOW):
        self.fm     = file_monitor
        self.pm     = process_monitor
        self.window = window

    # ── public API ────────────────────────────────────────────────────────────

    def extract(self) -> list:
        """Return a list of 18 float features for the current window."""

        events = self.fm.get_events() if self.fm else []
        sys_agg = self.pm.aggregate() if self.pm else {}

        # ── file event counts ─────────────────────────────────────────────────
        create_count  = sum(1 for e in events if e['type'] == 'create')
        modify_count  = sum(1 for e in events if e['type'] == 'modify')
        rename_count  = sum(1 for e in events if e['type'] == 'rename')
        delete_count  = sum(1 for e in events if e['type'] == 'delete')
        ext_change    = sum(1 for e in events
                           if e['type'] == 'rename' and e.get('ext_change', False))

        # ── entropy ───────────────────────────────────────────────────────────
        entropies = list(self.fm.entropy_snapshot(events).values()) if self.fm else []
        if entropies:
            avg_entropy      = sum(entropies) / len(entropies)
            spike_count      = sum(1 for v in entropies if v >= ENTROPY_HIGH_THRESHOLD)
            high_ratio       = spike_count / len(entropies)
        else:
            avg_entropy = spike_count = high_ratio = 0.0

        # ── bytes written (from modify events) ────────────────────────────────
        bytes_written = sum(e.get('bytes', 0) for e in events
                           if e['type'] in ('create', 'modify'))

        # ── extension diversity ────────────────────────────────────────────────
        exts = set()
        for e in events:
            if e['type'] == 'rename':
                exts.add(e.get('dest_ext', ''))
                exts.add(e.get('src_ext', ''))
            else:
                from pathlib import Path
                exts.add(Path(e['path']).suffix.lower())
        unique_exts = len(exts - {''})

        # ── rate features ─────────────────────────────────────────────────────
        write_ops_per_sec    = (modify_count + create_count) / max(self.window, 1)
        rename_to_mod_ratio  = rename_count / (modify_count + 1)

        # ── system metrics ────────────────────────────────────────────────────
        cpu        = sys_agg.get('cpu_percent',      0.0)
        mem        = sys_agg.get('memory_percent',   0.0)
        new_procs  = sys_agg.get('new_process_count', 0)
        io_read    = sys_agg.get('io_read_count',    0)
        io_write   = sys_agg.get('io_write_count',   0)
        io_wbytes  = sys_agg.get('io_write_bytes',   0)

        return [
            float(create_count),
            float(modify_count),
            float(rename_count),
            float(delete_count),
            float(ext_change),
            avg_entropy,
            float(spike_count),
            high_ratio,
            float(bytes_written),
            float(unique_exts),
            write_ops_per_sec,
            rename_to_mod_ratio,
            cpu,
            mem,
            float(new_procs),
            float(io_read),
            float(io_write),
            float(io_wbytes),
        ]

    # ── static helper ─────────────────────────────────────────────────────────

    @staticmethod
    def feature_names() -> list:
        from config import FEATURE_NAMES
        return FEATURE_NAMES
