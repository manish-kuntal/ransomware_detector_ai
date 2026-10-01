"""
config.py — Global configuration for Ransomware Detection System
"""
import os

# ─── Directories ──────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(BASE_DIR, 'data')
SANDBOX_DIR = os.path.join(DATA_DIR, 'sandbox')
DATASET_DIR = os.path.join(DATA_DIR, 'datasets')
MODELS_DIR  = os.path.join(BASE_DIR, 'models', 'saved')
LOGS_DIR    = os.path.join(BASE_DIR, 'logs')

for _d in [SANDBOX_DIR, DATASET_DIR, MODELS_DIR, LOGS_DIR]:
    os.makedirs(_d, exist_ok=True)

# ─── Monitoring ───────────────────────────────────────────────────────────────
FEATURE_WINDOW   = 5.0   # seconds — sliding window for feature extraction
MONITOR_INTERVAL = 1.0   # seconds — polling interval

# ─── Entropy ──────────────────────────────────────────────────────────────────
ENTROPY_HIGH_THRESHOLD   = 7.2   # bits — encrypted/compressed content
ENTROPY_CHANGE_THRESHOLD = 2.0   # significant jump in entropy

# ─── Features (18 behavioural features per window) ────────────────────────────
FEATURE_NAMES = [
    'file_create_count',        # Files created in window
    'file_modify_count',        # Files modified in window
    'file_rename_count',        # Files renamed in window
    'file_delete_count',        # Files deleted in window
    'extension_change_count',   # Renames that changed the extension
    'avg_entropy',              # Mean entropy of modified files
    'entropy_spike_count',      # Files with entropy > ENTROPY_HIGH_THRESHOLD
    'high_entropy_ratio',       # Fraction with high entropy
    'bytes_written',            # Total bytes written in window
    'unique_extensions',        # Distinct extensions touched
    'write_ops_per_sec',        # Write operations per second
    'rename_to_modify_ratio',   # rename_count / (modify_count + 1)
    'cpu_percent',              # System CPU usage %
    'memory_percent',           # System memory usage %
    'new_process_count',        # New processes spawned in window
    'io_read_count',            # Disk read operations
    'io_write_count',           # Disk write operations
    'io_write_bytes',           # Disk bytes written (OS level)
]

# ─── ML Models ────────────────────────────────────────────────────────────────
RANDOM_STATE = 42
TEST_SIZE    = 0.20
CV_FOLDS     = 5

# ─── Alert Thresholds ─────────────────────────────────────────────────────────
ALERT_THRESHOLD = 0.70   # probability above which an alert fires
ALERT_LEVELS = {
    'LOW':      0.50,
    'MEDIUM':   0.65,
    'HIGH':     0.75,
    'CRITICAL': 0.90,
}

# ─── Simulation ───────────────────────────────────────────────────────────────
SIM_DURATION        = 10   # seconds per simulation run
SIM_FILE_COUNT      = 50   # seed files per simulation sandbox
SYNTHETIC_N_NORMAL  = 300  # synthetic samples for normal class
SYNTHETIC_N_RANSOM  = 300  # synthetic samples for ransomware-like class
