"""
detector.py — Real-time ransomware detector.

Loads the best trained model, continuously extracts features from
live monitors, and fires alerts when ransomware-like behaviour is detected.
"""
import os
import sys
import time
import pickle
import threading
import numpy as np
from collections import deque

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import (FEATURE_NAMES, MODELS_DIR, FEATURE_WINDOW,
                    ALERT_THRESHOLD, ALERT_LEVELS, MONITOR_INTERVAL)


class RansomwareDetector:
    """
    Parameters
    ----------
    watch_path    : directory to monitor
    model_path    : path to saved best_model.pkl (default: models/saved/best_model.pkl)
    alert_callback: callable(alert_dict) invoked on each detection event
    """

    def __init__(self, watch_path: str,
                 model_path: str = None,
                 alert_callback=None):
        self.watch_path     = watch_path
        self.model_path     = model_path or os.path.join(MODELS_DIR, 'best_model.pkl')
        self.alert_callback = alert_callback or self._default_alert

        self._model_name = 'Unknown'
        self._pipeline   = None
        self._running    = False

        # History for dashboard
        self.score_history = deque(maxlen=120)   # last 120 readings
        self.alert_log     = deque(maxlen=50)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def load_model(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                f"Model not found: {self.model_path}\n"
                "Run: python train_models.py  first"
            )
        with open(self.model_path, 'rb') as f:
            saved = pickle.load(f)
        self._pipeline   = saved['pipeline']
        self._model_name = saved['name']
        print(f"[✓] Model loaded: {self._model_name}")
        return self

    def start(self):
        """Start monitoring loop in a background thread."""
        from src.monitoring.file_monitor    import FileMonitor
        from src.monitoring.process_monitor import ProcessMonitor
        from src.features.extractor         import FeatureExtractor

        self._fm  = FileMonitor(self.watch_path, window=FEATURE_WINDOW)
        self._pm  = ProcessMonitor(window=FEATURE_WINDOW)
        self._ext = FeatureExtractor(self._fm, self._pm, window=FEATURE_WINDOW)

        self._fm.start()
        self._pm.start()
        self._running = True

        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        print(f"[*] Monitoring: {self.watch_path}")
        print(f"[*] Model     : {self._model_name}")
        print(f"[*] Threshold : {ALERT_THRESHOLD}")

    def stop(self):
        self._running = False
        if hasattr(self, '_fm'):  self._fm.stop()
        if hasattr(self, '_pm'):  self._pm.stop()

    # ── main loop ─────────────────────────────────────────────────────────────

    def _loop(self):
        while self._running:
            try:
                features = self._ext.extract()
                score    = self._score(features)
                level    = self._alert_level(score)
                ts       = time.time()

                reading  = {
                    'ts':       ts,
                    'score':    score,
                    'level':    level,
                    'features': dict(zip(FEATURE_NAMES, features)),
                }
                self.score_history.append(reading)

                if score >= ALERT_THRESHOLD:
                    self.alert_log.append(reading)
                    self.alert_callback(reading)

            except Exception as e:
                print(f"[ERROR] Detection loop: {e}")

            time.sleep(MONITOR_INTERVAL)

    # ── scoring ───────────────────────────────────────────────────────────────

    def _score(self, features: list) -> float:
        """Return ransomware probability (0–1)."""
        if self._pipeline is None:
            raise RuntimeError("Call load_model() first")
        X = np.array(features).reshape(1, -1)
        return float(self._pipeline.predict_proba(X)[0, 1])

    @staticmethod
    def _alert_level(score: float) -> str:
        for level in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if score >= ALERT_LEVELS[level]:
                return level
        return 'OK'

    # ── alert ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _default_alert(alert: dict):
        score = alert['score']
        level = alert['level']
        ts    = time.strftime('%H:%M:%S', time.localtime(alert['ts']))
        bar   = '█' * int(score * 20)
        print(f"\n  🚨 [{ts}] RANSOMWARE ALERT — {level}")
        print(f"     Score: {score:.3f}  {bar}")
        top = sorted(alert['features'].items(),
                     key=lambda x: abs(x[1]), reverse=True)[:5]
        print(f"     Top signals: {', '.join(f'{k}={v:.1f}' for k, v in top)}")
