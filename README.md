# 🛡️ AI-Based Early Ransomware Detection System

> **Research Prototype** — ML-based behavioral detection of ransomware-like activity
> before significant file damage occurs.

---

## Project Structure

```
ransomware_detector/
├── config.py                   ← Global settings (thresholds, window size, paths)
├── generate_dataset.py         ← Dataset generation (synthetic or simulation)
├── train_models.py             ← Train & evaluate all 4 ML models
├── main.py                     ← Real-time detection entry point
├── requirements.txt
│
├── src/
│   ├── monitoring/
│   │   ├── file_monitor.py     ← Watchdog-based file event capture + entropy
│   │   └── process_monitor.py  ← psutil CPU / memory / I-O / process tracking
│   │
│   ├── features/
│   │   └── extractor.py        ← 18-feature vector from sliding window
│   │
│   ├── simulation/
│   │   ├── normal_behavior.py  ← Safe normal file activity simulator
│   │   └── ransomware_sim.py   ← Safe ransomware-LIKE pattern simulator (no malware)
│   │
│   ├── models/
│   │   ├── trainer.py          ← Random Forest / XGBoost / SVM / MLP training
│   │   ├── evaluator.py        ← ROC curves, confusion matrices, feature importance
│   │   └── detector.py         ← Real-time scoring loop
│   │
│   └── alerts/
│       └── alert_manager.py    ← Alert dispatch, CSV logging, handler registry
│
├── dashboard/
│   └── app.py                  ← Flask real-time web dashboard
│
├── data/
│   ├── datasets/               ← Generated CSV datasets
│   └── sandbox/                ← Temporary simulation files (auto-cleaned)
│
├── models/saved/               ← Trained model .pkl files
├── logs/                       ← alerts.csv, detector.log
└── results/                    ← Evaluation plots for research paper
```

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate dataset
```bash
# Fast synthetic dataset (good for initial testing — 600 samples)
python generate_dataset.py --mode synthetic --n 300

# OR real file-system simulation (recommended for paper — takes ~30 min for n=100)
python generate_dataset.py --mode simulation --n 100
```

### 3. Train all 4 models + generate evaluation plots
```bash
python train_models.py --evaluate
```

### 4a. Real-time detection (CLI)
```bash
python main.py --watch /home/user/Documents
```

### 4b. Real-time detection (Web Dashboard)
```bash
python dashboard/app.py --watch /home/user/Documents
# → Open http://localhost:5000
```

### 5. Demo mode (safe built-in simulation)
```bash
python main.py --watch /tmp/test_folder --demo
```

---

## Behavioral Features (18 per 5-second window)

| # | Feature | Normal | Ransomware-like |
|---|---------|--------|-----------------|
| 0 | `file_create_count` | ~2 | ~1 |
| 1 | `file_modify_count` | ~4 | **~25** |
| 2 | `file_rename_count` | ~0.4 | **~20** |
| 3 | `file_delete_count` | ~0.2 | **~8** |
| 4 | `extension_change_count` | ~0.05 | **~18** |
| 5 | `avg_entropy` | ~4.2 bits | **~7.5 bits** |
| 6 | `entropy_spike_count` | ~0.1 | **~15** |
| 7 | `high_entropy_ratio` | ~0.1 | **~0.9** |
| 8 | `bytes_written` | ~8 KB | **~500 KB** |
| 9 | `unique_extensions` | ~2 | **~9** |
|10 | `write_ops_per_sec` | ~1 | **~30** |
|11 | `rename_to_modify_ratio` | ~0.1 | **~0.8** |
|12 | `cpu_percent` | ~18% | **~72%** |
|13 | `memory_percent` | ~42% | **~58%** |
|14 | `new_process_count` | ~0.5 | **~2** |
|15 | `io_read_count` | ~40 | **~400** |
|16 | `io_write_count` | ~15 | **~180** |
|17 | `io_write_bytes` | ~8 KB | **~500 KB** |

---

## ML Models

| Model | Strengths |
|-------|-----------|
| **Random Forest** | High accuracy, feature importance, handles non-linear patterns |
| **XGBoost** | Best overall performance, gradient boosting |
| **SVM (RBF)** | Strong with small datasets, good generalisation |
| **Neural Network (MLP)** | Captures complex patterns, baseline deep learning |

---

## Research Paper Metrics

After `python train_models.py --evaluate`, the following are generated:

- `logs/model_comparison.csv` — Table of all metrics (Accuracy / Precision / Recall / F1 / ROC-AUC / FPR)
- `results/roc_curves.png` — ROC curves for all models
- `results/confusion_matrices.png` — One per model
- `results/feature_importance.png` — RF & XGBoost feature rankings

These directly feed into the paper's **Results** section.

---

## Safety Notice

**No actual ransomware is used anywhere in this project.**

- `ransomware_sim.py` only mimics *file-system access patterns*
- High-entropy content is generated with `os.urandom()` (standard Python stdlib)
- All simulations run in isolated sandbox directories that are auto-deleted
- No network activity, no encryption libraries, no shellcode

---

## Configuration

Edit `config.py` to tune:

```python
FEATURE_WINDOW   = 5.0    # detection window (seconds)
ALERT_THRESHOLD  = 0.70   # probability above which alert fires
ENTROPY_HIGH_THRESHOLD = 7.2  # bits — marks a file as high-entropy
SIM_DURATION     = 10     # seconds per simulation run
```

---

## System Workflow

```
Computer Activity
      ↓
 FileMonitor (watchdog)       ProcessMonitor (psutil)
      ↓                              ↓
      └──────── FeatureExtractor ────┘
                      ↓
              18-feature vector
                      ↓
           ML Model (best of 4)
                      ↓
              Risk Score (0–1)
                      ↓
        Score ≥ 0.70 → 🚨 ALERT
```
