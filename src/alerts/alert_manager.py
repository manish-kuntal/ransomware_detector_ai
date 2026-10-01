"""
alert_manager.py — Central alert hub.
Receives detection events, logs them, and dispatches to registered handlers.

Handlers are plain callables that accept an alert dict:
  {
    'ts':       float    (Unix timestamp),
    'score':    float    (0–1 ransomware probability),
    'level':    str      ('LOW'|'MEDIUM'|'HIGH'|'CRITICAL'),
    'features': dict     (feature_name -> value)
  }
"""
import os
import csv
import time
import threading
import logging
from collections import deque
from datetime import datetime

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import LOGS_DIR, ALERT_THRESHOLD


class AlertManager:
    """
    Usage:
        am = AlertManager()
        am.add_handler(my_callback)
        am.start()

        # In detector loop:
        am.dispatch(alert_dict)
    """

    def __init__(self, log_path: str = None):
        self.log_path = log_path or os.path.join(LOGS_DIR, 'alerts.csv')
        self.handlers = []
        self.history  = deque(maxlen=1000)
        self._lock    = threading.Lock()
        self._logger  = self._setup_logger()
        self._init_csv()

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        self._logger.info("AlertManager started")
        return self

    def stop(self):
        self._logger.info("AlertManager stopped")

    # ── handler registry ──────────────────────────────────────────────────────

    def add_handler(self, fn):
        """Register a callable that will be invoked on each alert."""
        self.handlers.append(fn)

    # ── dispatch ──────────────────────────────────────────────────────────────

    def dispatch(self, alert: dict):
        """
        Called by the detector on each monitoring tick.
        Always logs to CSV; only invokes handlers when score ≥ threshold.
        """
        with self._lock:
            self.history.append(alert)
            self._append_csv(alert)

        level = alert.get('level', 'OK')
        if level != 'OK':
            self._logger.warning(
                f"[{level}] score={alert['score']:.3f} | "
                f"rename={alert['features'].get('file_rename_count', 0):.0f} | "
                f"entropy={alert['features'].get('avg_entropy', 0):.2f}"
            )
            for fn in self.handlers:
                try:
                    fn(alert)
                except Exception as e:
                    self._logger.error(f"Handler error: {e}")

    # ── summary ───────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return aggregated statistics over recorded history."""
        with self._lock:
            h = list(self.history)
        if not h:
            return {}
        scores = [e['score'] for e in h]
        levels = [e['level'] for e in h if e['level'] != 'OK']
        return {
            'total_readings':  len(h),
            'total_alerts':    len(levels),
            'avg_score':       sum(scores) / len(scores),
            'max_score':       max(scores),
            'level_counts':    {lv: levels.count(lv)
                                for lv in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']},
        }

    # ── private ───────────────────────────────────────────────────────────────

    def _setup_logger(self) -> logging.Logger:
        log_file = os.path.join(LOGS_DIR, 'detector.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(),
            ],
        )
        return logging.getLogger('ransomware_detector')

    def _init_csv(self):
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'datetime', 'score', 'level',
                    'rename_count', 'avg_entropy', 'write_ops_per_sec',
                    'extension_change_count', 'cpu_percent',
                ])

    def _append_csv(self, alert: dict):
        feat = alert.get('features', {})
        row  = [
            alert['ts'],
            datetime.fromtimestamp(alert['ts']).strftime('%Y-%m-%d %H:%M:%S'),
            round(alert['score'], 4),
            alert['level'],
            feat.get('file_rename_count', 0),
            round(feat.get('avg_entropy', 0), 4),
            round(feat.get('write_ops_per_sec', 0), 4),
            feat.get('extension_change_count', 0),
            round(feat.get('cpu_percent', 0), 1),
        ]
        with open(self.log_path, 'a', newline='') as f:
            csv.writer(f).writerow(row)
