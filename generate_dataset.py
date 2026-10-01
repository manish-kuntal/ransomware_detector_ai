"""
generate_dataset.py — Dataset generation for ransomware detection research.

Two modes:
  --mode synthetic   Fast statistical generation (good for initial model testing)
  --mode simulation  Real file-system simulation (recommended for final paper)

Usage:
  python generate_dataset.py --mode synthetic --n 300
  python generate_dataset.py --mode simulation --n 100
"""
import os
import sys
import argparse
import shutil
import time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (FEATURE_NAMES, DATASET_DIR, SANDBOX_DIR,
                    SYNTHETIC_N_NORMAL, SYNTHETIC_N_RANSOM,
                    SIM_DURATION, SIM_FILE_COUNT, FEATURE_WINDOW)


# ═══════════════════════════════════════════════════════════════════════════════
# SYNTHETIC GENERATION  (no real file activity — pure statistics)
# ═══════════════════════════════════════════════════════════════════════════════

def _synthetic_normal(n: int, rng: np.random.Generator) -> np.ndarray:
    """
    Feature distributions derived from empirical observations of
    typical desktop workloads (document editing, browsing, coding).
    """
    N = n
    data = np.column_stack([
        rng.poisson(2,   N).astype(float),        # file_create_count
        rng.poisson(4,   N).astype(float),        # file_modify_count
        rng.poisson(0.4, N).astype(float),        # file_rename_count
        rng.poisson(0.2, N).astype(float),        # file_delete_count
        rng.poisson(0.05,N).astype(float),        # extension_change_count
        np.clip(rng.normal(4.2, 1.0, N), 0, 8),  # avg_entropy (text≈4)
        rng.poisson(0.1, N).astype(float),        # entropy_spike_count
        np.clip(rng.beta(1, 8, N), 0, 1),         # high_entropy_ratio
        np.clip(rng.normal(8_000, 4_000, N), 0, None),   # bytes_written
        np.clip(rng.poisson(2, N) + 1, 1, None).astype(float),  # unique_exts
        np.clip(rng.normal(1.0, 0.5, N), 0, None),  # write_ops_per_sec
        np.clip(rng.beta(1, 6, N), 0, 1),            # rename_to_modify_ratio
        np.clip(rng.normal(18, 8,  N), 0, 100),      # cpu_percent
        np.clip(rng.normal(42, 8,  N), 0, 100),      # memory_percent
        rng.poisson(0.5, N).astype(float),            # new_process_count
        np.clip(rng.normal(40, 15,  N), 0, None),    # io_read_count
        np.clip(rng.normal(15, 8,   N), 0, None),    # io_write_count
        np.clip(rng.normal(8_000, 3_000, N), 0, None),  # io_write_bytes
    ])
    return data


def _synthetic_ransomware(n: int, rng: np.random.Generator) -> np.ndarray:
    """
    Feature distributions reflecting known ransomware behavioural profiles
    from published research (CryptoDrop, ShieldFS, RWGuard literature).
    """
    N = n
    data = np.column_stack([
        rng.poisson(1,   N).astype(float),            # file_create_count (low)
        rng.poisson(25,  N).astype(float),            # file_modify_count (HIGH)
        rng.poisson(20,  N).astype(float),            # file_rename_count (HIGH)
        rng.poisson(8,   N).astype(float),            # file_delete_count (HIGH)
        rng.poisson(18,  N).astype(float),            # extension_change_count (HIGH)
        np.clip(rng.normal(7.5, 0.4, N), 0, 8),      # avg_entropy (near-random)
        np.clip(rng.poisson(15, N), 0, None).astype(float),  # entropy_spike_count
        np.clip(rng.beta(6, 1,  N), 0, 1),            # high_entropy_ratio (HIGH)
        np.clip(rng.normal(500_000, 150_000, N), 0, None),   # bytes_written (HIGH)
        np.clip(rng.poisson(6, N) + 3, 1, None).astype(float),  # unique_exts
        np.clip(rng.normal(30, 8,   N), 0, None),    # write_ops_per_sec (HIGH)
        np.clip(rng.normal(0.8, 0.15, N), 0, 1),     # rename_to_modify_ratio (HIGH)
        np.clip(rng.normal(72, 12,  N), 0, 100),      # cpu_percent (HIGH)
        np.clip(rng.normal(58, 12,  N), 0, 100),      # memory_percent
        rng.poisson(2, N).astype(float),               # new_process_count
        np.clip(rng.normal(400, 80,    N), 0, None),  # io_read_count (HIGH)
        np.clip(rng.normal(180, 40,    N), 0, None),  # io_write_count (HIGH)
        np.clip(rng.normal(500_000, 150_000, N), 0, None),  # io_write_bytes
    ])
    return data


def generate_synthetic(n_normal: int = SYNTHETIC_N_NORMAL,
                        n_ransom: int = SYNTHETIC_N_RANSOM,
                        seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    X_normal = _synthetic_normal(n_normal, rng)
    X_ransom = _synthetic_ransomware(n_ransom, rng)

    X = np.vstack([X_normal, X_ransom])
    y = np.array([0] * n_normal + [1] * n_ransom)

    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df['label'] = y
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
    return df


# ═══════════════════════════════════════════════════════════════════════════════
# SIMULATION GENERATION  (real file-system activity — better for paper)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_simulation(n_per_class: int = 100) -> pd.DataFrame:
    """
    Runs actual file-system simulations, collects real monitoring data.
    Requires: watchdog, psutil
    """
    try:
        from src.monitoring.file_monitor   import FileMonitor
        from src.monitoring.process_monitor import ProcessMonitor
        from src.features.extractor         import FeatureExtractor
        from src.simulation.normal_behavior import NormalBehaviorSimulator
        from src.simulation.ransomware_sim  import RansomwareBehaviorSimulator
    except ImportError as e:
        print(f"[ERROR] Missing dependency: {e}")
        print("       Run: pip install watchdog psutil")
        sys.exit(1)

    samples, labels = [], []

    for label, SimClass, tag in [
        (0, NormalBehaviorSimulator,      'normal'),
        (1, RansomwareBehaviorSimulator,  'ransomware'),
    ]:
        print(f"\n[*] Simulating {tag} behaviour ({n_per_class} samples)...")
        for i in range(n_per_class):
            sandbox = os.path.join(SANDBOX_DIR, f'{tag}_{i}')
            os.makedirs(sandbox, exist_ok=True)
            try:
                fm  = FileMonitor(sandbox, window=FEATURE_WINDOW)
                pm  = ProcessMonitor(window=FEATURE_WINDOW)
                ext = FeatureExtractor(fm, pm, window=FEATURE_WINDOW)

                fm.start();  pm.start()
                SimClass(sandbox, seed_files=SIM_FILE_COUNT).run(duration=SIM_DURATION)
                time.sleep(0.5)   # let final events settle

                feat = ext.extract()
                samples.append(feat)
                labels.append(label)

                fm.stop();  pm.stop()
            except Exception as e:
                print(f"  [WARN] sample {i} failed: {e}")
            finally:
                shutil.rmtree(sandbox, ignore_errors=True)

            if (i + 1) % 10 == 0:
                print(f"  {i+1}/{n_per_class} done")

    df = pd.DataFrame(samples, columns=FEATURE_NAMES)
    df['label'] = labels
    return df.sample(frac=1, random_state=42).reset_index(drop=True)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='Generate ransomware detection dataset')
    parser.add_argument('--mode', choices=['synthetic', 'simulation'],
                        default='synthetic',
                        help='synthetic = statistical (fast), simulation = real fs activity')
    parser.add_argument('--n', type=int, default=300,
                        help='samples per class')
    parser.add_argument('--output', type=str, default=None,
                        help='output CSV path')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()

    out = args.output or os.path.join(DATASET_DIR, f'dataset_{args.mode}.csv')

    print(f"[*] Mode   : {args.mode}")
    print(f"[*] N/class: {args.n}")
    print(f"[*] Output : {out}")

    if args.mode == 'synthetic':
        df = generate_synthetic(n_normal=args.n, n_ransom=args.n, seed=args.seed)
    else:
        df = generate_simulation(n_per_class=args.n)

    df.to_csv(out, index=False)
    print(f"\n[✓] Saved {len(df)} samples → {out}")
    print(f"    Normal: {(df.label == 0).sum()}  |  Ransomware: {(df.label == 1).sum()}")
    print("\nFeature statistics:")
    print(df.drop('label', axis=1).describe().to_string())


if __name__ == '__main__':
    main()
