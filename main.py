"""
main.py — Real-time ransomware detection entry point.

Usage:
  python main.py --watch /home/user/Documents
  python main.py --watch /path/to/folder --threshold 0.65 --model models/saved/randomforest.pkl
  python main.py --watch . --demo    # generate ransomware-like activity in a sandbox for demo
"""
import os
import sys
import time
import signal
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import MODELS_DIR, ALERT_THRESHOLD, SANDBOX_DIR
from src.models.detector     import RansomwareDetector
from src.alerts.alert_manager import AlertManager


# ─── Signal handler for clean shutdown ────────────────────────────────────────

_detector = None
_am       = None

def _shutdown(sig, frame):
    print("\n\n[*] Shutting down...")
    if _detector:  _detector.stop()
    if _am:        _am.stop()
    if _detector:
        s = _detector.score_history
        if s:
            scores = [r['score'] for r in s]
            print(f"\nSession summary:")
            print(f"  Readings: {len(scores)}")
            print(f"  Max score: {max(scores):.3f}")
            print(f"  Alerts: {len(_detector.alert_log)}")
    sys.exit(0)

signal.signal(signal.SIGINT,  _shutdown)
signal.signal(signal.SIGTERM, _shutdown)


# ─── Demo mode ────────────────────────────────────────────────────────────────

def run_demo(watch_path: str):
    """
    Run a 30-second demo: first 10s normal behaviour, then 20s ransomware-like.
    Uses safe simulation — no actual ransomware.
    """
    import shutil
    from src.simulation.normal_behavior import NormalBehaviorSimulator
    from src.simulation.ransomware_sim  import RansomwareBehaviorSimulator

    demo_dir = os.path.join(SANDBOX_DIR, 'demo')
    os.makedirs(demo_dir, exist_ok=True)

    print(f"\n[DEMO] Phase 1: Normal behaviour (10 seconds)...")
    t = threading.Thread(target=NormalBehaviorSimulator(demo_dir).run,
                         kwargs={'duration': 10}, daemon=True)
    t.start(); t.join()

    print(f"\n[DEMO] Phase 2: Ransomware-like behaviour (20 seconds)...")
    t = threading.Thread(target=RansomwareBehaviorSimulator(demo_dir).run,
                         kwargs={'duration': 20}, daemon=True)
    t.start(); t.join()

    shutil.rmtree(demo_dir, ignore_errors=True)
    print("\n[DEMO] Complete.")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global _detector, _am

    parser = argparse.ArgumentParser(
        description='Real-time AI-based Ransomware Detector'
    )
    parser.add_argument('--watch',     required=True,
                        help='Directory to monitor')
    parser.add_argument('--model',     default=None,
                        help='Path to model .pkl (default: models/saved/best_model.pkl)')
    parser.add_argument('--threshold', type=float, default=ALERT_THRESHOLD,
                        help=f'Alert threshold (default: {ALERT_THRESHOLD})')
    parser.add_argument('--demo',      action='store_true',
                        help='Run built-in safe demo after starting monitor')
    args = parser.parse_args()

    if not os.path.isdir(args.watch):
        print(f"[ERROR] Watch path not found: {args.watch}")
        sys.exit(1)

    # Patch threshold from CLI
    import config as cfg
    cfg.ALERT_THRESHOLD = args.threshold

    # ── Setup ────────────────────────────────────────────────────────────────
    _am = AlertManager()
    _am.start()

    _detector = RansomwareDetector(
        watch_path     = args.watch,
        model_path     = args.model,
        alert_callback = _am.dispatch,
    )
    _detector.load_model()
    _detector.start()

    print("\n" + "="*55)
    print("  🛡️  AI Ransomware Detector — ACTIVE")
    print("="*55)
    print(f"  Watching  : {args.watch}")
    print(f"  Threshold : {args.threshold}")
    print(f"  Log file  : {_am.log_path}")
    print(f"  Press Ctrl+C to stop")
    print("="*55 + "\n")

    if args.demo:
        time.sleep(2)
        demo_thread = threading.Thread(target=run_demo, args=(args.watch,), daemon=True)
        demo_thread.start()

    # Keep main thread alive
    while True:
        time.sleep(5)
        s = _am.summary()
        if s:
            print(f"  [status] readings={s['total_readings']} "
                  f"alerts={s['total_alerts']} "
                  f"max_score={s['max_score']:.3f}")


if __name__ == '__main__':
    main()
