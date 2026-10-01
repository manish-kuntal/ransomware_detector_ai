<!--
RansomShield AI
A research-grade README for GitHub.
Replace image paths in /assets/ with the actual filenames you upload to the repository.
-->

<div align="center">

# 🛡️ RansomShield AI

### **Early Behavioral Ransomware Detection, Containment & Response**

<p>
  <strong>Machine Learning • Behavioral Analysis • Real-Time Monitoring • Incident Response</strong>
</p>

<p>
  <img src="https://img.shields.io/badge/Status-Research%20Prototype-8A2BE2?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white">
  <img src="https://img.shields.io/badge/ML-XGBoost%20%7C%20RF%20%7C%20SVM%20%7C%20MLP-FF6B00?style=for-the-badge">
  <img src="https://img.shields.io/badge/Security-Ransomware%20Detection-D7263D?style=for-the-badge">
</p>

<p>
  <img src="https://img.shields.io/badge/Behavioral%20Features-18-00B894?style=flat-square">
  <img src="https://img.shields.io/badge/Detection%20Window-5s-0984E3?style=flat-square">
  <img src="https://img.shields.io/badge/Alert%20Threshold-0.70-FDCB6E?style=flat-square">
  <img src="https://img.shields.io/badge/Safe%20Simulation-No%20Malware-00B894?style=flat-square">
</p>

<p>
  <em>RansomShield AI watches behavior, learns the difference between normal and ransomware-like activity, raises an early warning, and provides a foundation for automated containment.</em>
</p>

</div>

---

> [!IMPORTANT]
> **Research prototype — not a replacement for an enterprise EDR, antivirus, backup system, or incident-response platform.**
>
> The project uses **safe ransomware-like behavioral simulation**. It does **not** deploy real ransomware, malicious encryption, shellcode, or network-based malware.

---

## 🚨 What is RansomShield AI?

**RansomShield AI** is a Python-based cybersecurity research prototype designed to detect **ransomware-like behavior from system activity instead of relying only on malware signatures**.

Traditional signature-based detection looks for known malicious patterns. RansomShield AI takes a different route: it watches what the system is doing.

When a process rapidly modifies, renames, deletes, and rewrites many files — especially when file-content entropy and I/O activity change sharply — the system converts those observations into an **18-dimensional behavioral feature vector** and sends it through machine-learning classifiers.

The core concept is:

```text
                 COMPUTER ACTIVITY
                        │
          ┌─────────────┴─────────────┐
          │                           │
     File System                 System / Process
       Events                       Metrics
          │                           │
          └─────────────┬─────────────┘
                        ▼
               FEATURE EXTRACTION
                        │
                 18 FEATURES
                        │
                        ▼
               MACHINE LEARNING
       ┌────────┬────────┬────────┬────────┐
       │   RF   │ XGBoost│  SVM   │  MLP   │
       └────────┴────────┴────────┴────────┘
                        │
                        ▼
                 THREAT / RISK SCORE
                        │
              ┌─────────┴─────────┐
              │                   │
           NORMAL              HIGH RISK
              │                   │
          MONITOR              ALERT
                                  │
                                  ▼
                    CONTAINMENT / RESPONSE
```

The documented implementation uses a configurable **5-second sliding window** for behavioral aggregation.

---

# 🎯 The Problem

Ransomware can cause damage extremely quickly.

The dangerous gap is:

```text
Ransomware starts
      ↓
Files begin changing
      ↓
Encryption continues
      ↓
User notices something is wrong
      ↓
Ransom note appears
      ↓
Damage has already occurred
```

The goal of RansomShield AI is to move detection earlier:

```text
Ransomware starts
      ↓
Behavior changes
      ↓
RansomShield observes the pattern
      ↓
ML risk score rises
      ↓
🚨 EARLY ALERT
      ↓
Containment / response can begin
```

The research prototype evaluates whether behavioral signals can identify ransomware-like activity before significant file damage.

---

# 🧠 Core Idea

Ransomware has to perform operations to achieve its objective.

Typical behavioral signals include:

| Signal | Why it matters |
|---|---|
| `file_modify_count` | Bulk modification can indicate mass file processing |
| `file_rename_count` | Large-scale renaming is a strong behavioral signal |
| `extension_change_count` | Sudden extension changes can indicate ransomware-like activity |
| `avg_entropy` | Encrypted/randomized content tends toward high entropy |
| `entropy_spike_count` | Detects sudden increases in high-entropy files |
| `high_entropy_ratio` | Measures the fraction of files with high entropy |
| `bytes_written` | Bulk rewriting creates abnormal write volume |
| `write_ops_per_sec` | Rapid writes can indicate automated file processing |
| `io_read_count` | Files are typically read before being rewritten |
| `io_write_count` | Captures bulk write behavior |
| `io_write_bytes` | Measures the amount of data being written |
| `cpu_percent` | Cryptographic/bulk-processing workloads may change CPU activity |
| `memory_percent` | Captures system-level changes during activity |
| `new_process_count` | Additional process activity can provide context |
| `file_create_count` | Helps distinguish normal from abnormal filesystem activity |
| `file_delete_count` | File deletion can accompany replacement/rewriting |
| `unique_extensions` | Activity across many file types can be suspicious |
| `rename_to_modify_ratio` | Relates rename behavior to modification behavior |

---

# 🔬 Entropy — One of the Key Signals

RansomShield AI uses **Shannon entropy** as a behavioral signal.

Conceptually:

```text
Low / moderate entropy
        ↓
More predictable byte distribution
        ↓
Often seen in ordinary structured/text data

High entropy
        ↓
More uniform / random-looking byte distribution
        ↓
Can be consistent with encrypted or compressed content
```

The prototype uses a **7.2-bit high-entropy threshold** in its documented configuration.

> Entropy is **not proof of ransomware by itself**. Compressed files, encrypted archives, media, and other legitimate data can also have high entropy. RansomShield therefore combines entropy with filesystem and system-level signals.

---

# 🧩 18-Feature Behavioral Vector

Each observation window is converted into a fixed-length vector:

```text
[
  file_create_count,
  file_modify_count,
  file_rename_count,
  file_delete_count,
  extension_change_count,
  avg_entropy,
  entropy_spike_count,
  high_entropy_ratio,
  bytes_written,
  unique_extensions,
  write_ops_per_sec,
  rename_to_modify_ratio,
  cpu_percent,
  memory_percent,
  new_process_count,
  io_read_count,
  io_write_count,
  io_write_bytes
]
```

This makes the raw operating-system activity usable by conventional tabular ML models.

---

# 🤖 Machine Learning Layer

RansomShield AI compares four classifiers.

| Model | Role |
|---|---|
| 🌲 **Random Forest** | Ensemble baseline and feature-importance analysis |
| 🚀 **XGBoost** | Gradient-boosted tree model |
| 📐 **SVM (RBF)** | Kernel-based comparison model |
| 🧠 **MLP Neural Network** | Neural-network baseline |

### Research results on the behavioral simulation dataset

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | Avg. Latency |
|---|---:|---:|---:|---:|---:|---:|---:|
| **XGBoost** | **0.958** | **0.955** | **0.960** | **0.957** | **0.989** | **0.037** | 3.1s |
| Random Forest | 0.945 | 0.942 | 0.948 | 0.945 | 0.981 | 0.048 | **2.8s** |
| MLP Neural Network | 0.928 | 0.925 | 0.931 | 0.928 | 0.972 | 0.062 | 3.7s |
| SVM (RBF) | 0.912 | 0.908 | 0.915 | 0.911 | 0.961 | 0.079 | 4.2s |

### How to interpret this

- **XGBoost** produced the highest F1 and ROC-AUC in the documented simulation experiment.
- **Random Forest** produced the lowest average detection latency.
- The models do not always agree, which is visible in the live dashboard.
- The research therefore exposes **model consensus/disagreement** rather than assuming that every classifier will produce the same score.

---

# 📊 Research Visualizations

## Live Threat Dashboard

<p align="center">
  <img src="./assets/dashboard.png" alt="RansomShield AI real-time dashboard" width="100%">
</p>

The dashboard provides a real-time operational view including:

- Current threat score
- Session peak
- Alerts fired
- Detection latency
- Model consensus
- Threat timeline
- Individual model scores
- Signal breakdown
- Recent alerts
- Response Center
- Network state
- Evidence collection control
- Process termination control
- Network isolation control
- Quarantine control
- Network restoration control
- Combined response control

The visual state model is:

```text
SAFE
  ↓
LOW RISK
  ↓
SUSPICIOUS
  ↓
UNDER ATTACK
  ↓
CONTAINED
```

---

## ROC Curves

<p align="center">
  <img src="./assets/roc-curves.png" alt="RansomShield AI ROC curves" width="85%">
</p>

ROC curves visualize the trade-off between true-positive and false-positive rates across decision thresholds.

> [!NOTE]
> The supplied ROC visualization corresponds to the highly separable **synthetic dataset**, where the evaluated models achieved perfect or near-perfect metrics. These results should not be presented as evidence of equivalent real-world performance.

---

## Confusion Matrices

<p align="center">
  <img src="./assets/confusion-matrices.png" alt="RansomShield AI confusion matrices" width="85%">
</p>

The confusion matrices visualize:

- True Negatives
- False Positives
- False Negatives
- True Positives

The supplied synthetic evaluation shows perfect separation for the displayed models.

---

## Feature Importance

<p align="center">
  <img src="./assets/feature-importance.png" alt="RansomShield AI Random Forest feature importance" width="85%">
</p>

Feature importance helps answer:

> **Which behavioral signals are contributing most to the classifier's decision?**

The supplied visualization highlights I/O write bytes, rename activity, file modification activity, write operations, extension changes, entropy spikes, and related behavioral features.

---

# 🖥️ Real-Time Monitoring

The monitoring layer is built around two complementary information sources.

### File-system monitoring

The project uses **Watchdog** to capture events such as:

- file creation
- modification
- deletion
- rename events

Events are timestamped and aggregated inside a configurable sliding window.

### System/process monitoring

The project uses **psutil** for system-level measurements including:

- CPU utilization
- memory usage
- disk read/write counts
- disk I/O bytes
- newly spawned process counts

Combining both layers provides a richer behavioral representation than looking at a single signal.

---

# 🧪 Safe Dataset Generation

One of the most important research-design decisions is safety.

RansomShield AI does **not** require deploying real ransomware to build its initial behavioral dataset.

It uses two approaches.

## 1. Synthetic Dataset

Statistical distributions generate labeled feature vectors.

Documented configuration:

```text
Normal samples:       300
Ransomware-like:      300
Total:                600
Features:             18
Train split:          80%
Test split:           20%
Cross-validation:     5-fold stratified
```

This is useful for rapid model prototyping.

## 2. Behavioral Simulation Dataset

The simulator creates ransomware-like **filesystem behavior**, not malware.

The documented safe simulator:

- reads target files
- overwrites them with high-entropy random bytes
- performs ransomware-like renaming
- generates concurrent file activity
- creates labeled behavioral data

It contains:

```text
❌ No actual ransomware
❌ No encryption algorithm
❌ No shellcode
❌ No network activity
❌ No malicious payload
```

Instead, it focuses on the behavioral signals needed for ML experimentation.

---

# 📦 Project Structure

```text
ransomware_detector/
│
├── config.py
├── generate_dataset.py
├── train_models.py
├── main.py
├── requirements.txt
│
├── src/
│   ├── monitoring/
│   │   ├── file_monitor.py
│   │   └── process_monitor.py
│   │
│   ├── features/
│   │   └── extractor.py
│   │
│   ├── simulation/
│   │   ├── normal_behavior.py
│   │   └── ransomware_sim.py
│   │
│   ├── models/
│   │   ├── trainer.py
│   │   ├── evaluator.py
│   │   └── detector.py
│   │
│   └── alerts/
│       └── alert_manager.py
│
├── dashboard/
│   └── app.py
│
├── data/
│   ├── datasets/
│   └── sandbox/
│
├── models/
│   └── saved/
│
├── logs/
│
└── results/
```

---

# ⚙️ Technology Stack

| Layer | Technology |
|---|---|
| Language | **Python 3.11** |
| ML | **scikit-learn** |
| Gradient Boosting | **XGBoost** |
| File Monitoring | **Watchdog** |
| System Metrics | **psutil** |
| Web Dashboard | **Flask** |
| Dashboard Charts | **Chart.js** |
| Data Generation | **NumPy / Python** |
| Model Persistence | Python model serialization |
| Operating Systems | Windows 11 / Ubuntu 24.04 LTS |

Documented research environment:

```text
Python             3.11
scikit-learn       1.3
XGBoost            2.0
Watchdog           3.0
psutil             5.9
Flask              3.0
Chart.js            4.4
```

> **Dependency source of truth:** `requirements.txt`. Version numbers above describe the documented research environment and should not be interpreted as a guarantee that every future dependency release will be identical.

---

# 💻 System Requirements

## Minimum / documented research environment

```text
OS:
  Windows 11
  or Ubuntu 24.04 LTS

CPU:
  Intel Core i5-class processor

RAM:
  8 GB

Storage:
  SSD recommended

Python:
  3.11

Network:
  Not required for the safe local simulation itself
```

The project is designed around lightweight tabular ML rather than GPU-heavy deep learning.

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

## 2. Create a virtual environment

### Windows

```powershell
py -3.11 -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

## 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

# 🧪 Generate Training Data

## Fast synthetic dataset

```bash
python generate_dataset.py --mode synthetic --n 300
```

This generates a 600-sample balanced dataset:

```text
300 Normal
300 Ransomware-like
```

## Behavioral simulation

```bash
python generate_dataset.py --mode simulation --n 100
```

The documented research workflow uses real filesystem events generated by the safe simulator and can take significantly longer than synthetic generation.

---

# 🧠 Train the Models

```bash
python train_models.py --evaluate
```

This trains and evaluates:

```text
Random Forest
XGBoost
SVM
MLP Neural Network
```

It also generates research artifacts such as:

```text
logs/model_comparison.csv
results/roc_curves.png
results/confusion_matrices.png
results/feature_importance.png
```

---

# 👁️ Run Real-Time Detection

## CLI

```bash
python main.py --watch <DIRECTORY>
```

Example:

```bash
python main.py --watch ./data/sandbox
```

## Web Dashboard

```bash
python dashboard/app.py --watch <DIRECTORY>
```

Then open:

```text
http://localhost:5000
```

---

# 🧪 Safe Demo Mode

The project provides a built-in safe demonstration path.

```bash
python main.py --watch /tmp/test_folder --demo
```

For Windows, use an appropriate local test directory, for example:

```powershell
python main.py --watch .\data\sandbox --demo
```

Always use an isolated test directory for demonstrations.

---

# ⚡ Detection Configuration

The documented configuration includes:

```python
FEATURE_WINDOW = 5.0
ALERT_THRESHOLD = 0.70
ENTROPY_HIGH_THRESHOLD = 7.2
SIM_DURATION = 10
```

Meaning:

```text
5.0 sec
   ↓
Behavior observation window

0.70
   ↓
Alert probability threshold

7.2 bits
   ↓
High-entropy threshold
```

These values are **configuration parameters**, not universal security constants.

---

# 🛡️ Detection → Response Architecture

RansomShield AI is designed around a security pipeline rather than a single classifier.

```text
┌──────────────────────────────┐
│       COMPUTER ACTIVITY      │
└──────────────┬───────────────┘
               │
       ┌───────┴────────┐
       ▼                ▼
 FileMonitor       ProcessMonitor
  Watchdog             psutil
       │                │
       └───────┬────────┘
               ▼
      ┌─────────────────┐
      │ Feature Extractor│
      └────────┬────────┘
               ▼
        18 Behavioral
           Features
               │
               ▼
      ┌──────────────────┐
      │  ML Classification │
      └─────────┬────────┘
                ▼
          Risk / Threat Score
                │
        ┌───────┴─────────┐
        ▼                 ▼
      Normal             Alert
                            │
                            ▼
                     Response Center
                            │
          ┌─────────────────┼────────────────┐
          ▼                 ▼                ▼
      Evidence          Process           Network
      Collection        Control           Isolation
          │                 │                │
          └─────────────────┼────────────────┘
                            ▼
                       Quarantine
                            │
                            ▼
                         Logging
```

---

# 🚧 Containment & Response

The dashboard includes a Response Center with controls for:

```text
Evidence
Kill Process
Isolate Network
Quarantine
Restore Network
Respond All
```

These controls represent the project's containment/response direction.

### Intended incident-response sequence

```text
1. Detect abnormal behavior
2. Raise threat score
3. Confirm high-risk activity
4. Preserve evidence
5. Contain suspicious process
6. Isolate network connectivity
7. Quarantine suspicious artifacts
8. Protect recovery resources
9. Record incident
10. Begin controlled recovery
```

> [!WARNING]
> **Automatic response actions can have operational consequences.** Network isolation, process termination, quarantine, or recovery actions should be tested in an isolated environment before being enabled on production systems.

---

# 🌐 Why Network Isolation Matters

If ransomware is confirmed, simply detecting it is not enough.

A containment system may need to reduce the attacker's ability to:

- communicate with external infrastructure
- spread through network-connected resources
- access shared locations
- continue remote operations

Therefore, a mature version of RansomShield can move from:

```text
DETECT
```

toward:

```text
DETECT
   ↓
CONFIRM
   ↓
CONTAIN
   ↓
PROTECT
   ↓
RECOVER
```

The project should not assume that network disconnection alone protects local files; filesystem/process containment remains essential.

---

# 💾 Data Protection Strategy

A complete ransomware-defense architecture should consider multiple protection layers:

### Layer 1 — Detection

Identify abnormal behavior as early as possible.

### Layer 2 — Process Containment

Prevent the suspicious process from continuing its activity.

### Layer 3 — Network Containment

Reduce external and lateral communication.

### Layer 4 — File/Artifact Quarantine

Separate suspicious artifacts from normal system activity.

### Layer 5 — Backup Protection

Protect recovery resources from being modified or encrypted.

### Layer 6 — Evidence Collection

Preserve useful forensic information before cleanup.

### Layer 7 — Recovery

Restore from trusted recovery points after the incident is understood.

---

# 📈 Research Findings

The paper reports four main findings:

### 01 — Behavioral ML can detect ransomware-like activity

The simulation experiment demonstrates that filesystem and system-level behavior can provide useful signals for ransomware classification.

### 02 — Early detection is measurable

The documented models detected simulated ransomware-like behavior within approximately **2.8–4.2 seconds**, depending on the model.

### 03 — File-level signals are highly informative

Rename activity, extension changes, entropy, and I/O-related behavior provide important classification signals.

### 04 — Model disagreement is useful information

Different models can produce significantly different confidence scores for the same observation.

Instead of hiding this disagreement, a future ensemble response engine can use it as an explicit confidence signal.

---

# 🧮 Evaluation Metrics

RansomShield AI evaluates:

| Metric | Meaning |
|---|---|
| **Accuracy** | Overall proportion of correct predictions |
| **Precision** | How many positive alerts were actually positive |
| **Recall** | How many attacks were detected |
| **F1-Score** | Balance between precision and recall |
| **ROC-AUC** | Ranking/separation performance across thresholds |
| **FPR** | False-positive rate |
| **Detection Latency** | Time from attack commencement to alert |

For security systems, **accuracy alone is not enough**.

A detector that misses attacks or produces too many false alarms can still be operationally problematic.

---

# ⚠️ Important Research Limitations

This section is intentionally explicit because security research must be reproducible and honest.

## Dataset scale

The behavioral simulation dataset is relatively small compared with the diversity of real-world ransomware.

## Synthetic-data gap

The synthetic dataset is highly separable and produces perfect metrics for the evaluated classifiers. This does **not** mean real-world ransomware will be classified with perfect accuracy.

## Evasion

An attacker aware of the detection features could potentially modify behavior to reduce observable signals.

Examples include slower or less obvious file operations.

## Scope

The current research focuses on **file-encrypting ransomware-like behavior**.

Locker-style attacks and other ransomware behaviors may require additional features.

## Generalization

Real-world validation across:

- different ransomware families
- different operating systems
- different filesystem workloads
- large datasets
- enterprise environments
- benign high-I/O workloads

is required before making production-security claims.

---

# 🌍 Real-World Impact

Ransomware affects more than individual files.

A successful attack can disrupt:

```text
👤 Individuals
      ↓
💻 Personal computers
      ↓
🏢 Businesses
      ↓
🏥 Healthcare
      ↓
🏫 Education
      ↓
🏭 Industrial environments
      ↓
☁️ Cloud / shared infrastructure
```

A behavioral early-warning layer could potentially help organizations:

- reduce time-to-detection
- reduce time-to-containment
- identify suspicious activity before a user notices it
- provide security teams with behavioral evidence
- automate repetitive incident-response actions
- improve visibility into endpoint activity
- complement existing security controls

RansomShield should therefore be viewed as a **research direction toward endpoint ransomware resilience**, not as a claim that one ML model can solve ransomware by itself.

---

# 🔭 Future Roadmap

## Phase 1 — Current Research Prototype

- [x] File-system monitoring
- [x] System metrics
- [x] 18 behavioral features
- [x] Safe ransomware-like simulation
- [x] Synthetic dataset generation
- [x] Behavioral simulation dataset
- [x] Four ML models
- [x] Model evaluation
- [x] ROC curves
- [x] Confusion matrices
- [x] Feature-importance analysis
- [x] Real-time dashboard
- [x] Threat timeline
- [x] Model score comparison
- [x] Response Center UI

## Phase 2 — Stronger Detection

- [ ] Larger behavioral datasets
- [ ] Public ransomware behavioral datasets
- [ ] Cross-validation improvements
- [ ] Threshold calibration
- [ ] False-positive analysis
- [ ] Explainable ML
- [ ] Adaptive detection windows
- [ ] Better ensemble scoring

## Phase 3 — Stronger Containment

- [ ] Controlled process containment
- [ ] OS-aware network isolation
- [ ] Safe quarantine mechanism
- [ ] Backup protection
- [ ] Evidence packaging
- [ ] Incident timeline generation
- [ ] Recovery workflow

## Phase 4 — Advanced Research

- [ ] Temporal sequence models
- [ ] LSTM / Transformer experiments
- [ ] Network-level behavioral features
- [ ] eBPF-based Linux telemetry
- [ ] Windows kernel/minifilter telemetry
- [ ] Federated learning
- [ ] Large-scale benchmark datasets
- [ ] Adversarial/evasion testing

---

# 🔐 Security Philosophy

RansomShield AI follows a simple principle:

> **Observe first. Understand behavior. Detect early. Contain carefully. Preserve evidence. Recover safely.**

The project intentionally separates:

```text
Detection
    ≠
Response
    ≠
Recovery
```

This separation makes the architecture easier to test and evolve.

---

# 🧪 Research Reproducibility

The project is structured so that researchers can reproduce the major experimental stages:

```text
Generate Dataset
       ↓
Train Models
       ↓
Evaluate Models
       ↓
Generate Metrics
       ↓
Generate Plots
       ↓
Run Real-Time Detector
       ↓
Observe Dashboard
```

Generated research artifacts include:

```text
model_comparison.csv
roc_curves.png
confusion_matrices.png
feature_importance.png
```

---

# 📁 Generated Artifacts

| Path | Purpose |
|---|---|
| `data/datasets/` | Generated datasets |
| `data/sandbox/` | Safe simulation workspace |
| `models/saved/` | Trained model files |
| `logs/` | Detector and alert logs |
| `results/` | Research plots |
| `logs/model_comparison.csv` | Model metrics |

---

# 🧰 Configuration

The main configuration surface includes:

```python
FEATURE_WINDOW = 5.0
ALERT_THRESHOLD = 0.70
ENTROPY_HIGH_THRESHOLD = 7.2
SIM_DURATION = 10
```

Configuration should be tuned using validation experiments rather than copied blindly into production environments.

---

# 🧑‍💻 Developer Workflow

Recommended workflow:

```text
1. Create virtual environment
        ↓
2. Install requirements
        ↓
3. Generate safe dataset
        ↓
4. Train models
        ↓
5. Evaluate metrics
        ↓
6. Inspect plots
        ↓
7. Run detector
        ↓
8. Run isolated demo
        ↓
9. Inspect dashboard
       ↓
10. Test response controls safely
```

---

# 🧪 Safe Testing Rules

Always test simulations inside a dedicated directory.

Recommended:

```text
project/
└── data/
    └── sandbox/
```

Do not point experimental automation at:

```text
C:\
/home
/root
System folders
Production data
Shared company folders
Mounted backup drives
```

unless you have explicitly designed and tested the protection controls for that environment.

---

# 📚 Research Foundation

The research paper supporting this prototype covers:

- ransomware behavioral analysis
- dynamic detection
- machine-learning classification
- file entropy
- early detection
- detection latency
- automated response
- feature importance
- safe behavioral simulation
- limitations and future research

Key cited technologies and research areas include:

```text
Watchdog
psutil
scikit-learn
XGBoost
Shannon Entropy
Random Forest
SVM
MLP
Behavioral Analysis
```

---

# 🏗️ Architecture at a Glance

```text
                         ┌─────────────────────┐
                         │    RansomShield AI  │
                         └──────────┬──────────┘
                                    │
                 ┌──────────────────┴──────────────────┐
                 │                                     │
                 ▼                                     ▼
        ┌─────────────────┐                   ┌─────────────────┐
        │  File Monitor   │                   │ Process Monitor │
        │    Watchdog     │                   │     psutil      │
        └────────┬────────┘                   └────────┬────────┘
                 │                                     │
                 └──────────────────┬──────────────────┘
                                    ▼
                         ┌─────────────────────┐
                         │ Feature Extraction │
                         │     18 Signals     │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │   ML Classification│
                         ├─────────────────────┤
                         │ Random Forest      │
                         │ XGBoost             │
                         │ SVM                 │
                         │ MLP                 │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │   Risk Engine      │
                         └──────────┬──────────┘
                                    ▼
                         ┌─────────────────────┐
                         │  Threat Dashboard  │
                         └──────────┬──────────┘
                                    ▼
                 ┌──────────────────┴──────────────────┐
                 │                                     │
                 ▼                                     ▼
          🚨 ALERT / LOG                         RESPONSE CENTER
                                                       │
                     ┌─────────────────────────────────┼───────────────┐
                     ▼                                 ▼               ▼
                Evidence                         Containment      Quarantine
                                                     │
                                              Network Isolation
                                              Process Control
                                              Recovery
```

---

# 📊 Project Snapshot

| Category | RansomShield AI |
|---|---|
| Project Type | Cybersecurity research prototype |
| Primary Goal | Early ransomware-like behavior detection |
| Detection Style | Behavioral ML |
| Observation Window | 5 seconds |
| Features | 18 |
| Classifiers | 4 |
| Best documented F1 | 0.957 — XGBoost |
| Best documented ROC-AUC | 0.989 — XGBoost |
| Lowest documented latency | 2.8s — Random Forest |
| Safe simulation | Yes |
| Real ransomware | No |
| Dashboard | Flask + Chart.js |
| File monitoring | Watchdog |
| System monitoring | psutil |
| Primary language | Python 3.11 |
| Supported research OS | Windows 11 / Ubuntu 24.04 LTS |

---

# ❓ FAQ

### Does RansomShield AI contain real ransomware?

**No.**

The project uses safe ransomware-like behavioral simulation and does not contain actual ransomware, malicious encryption, shellcode, or network activity.

### Does high entropy automatically mean ransomware?

**No.**

Entropy is one signal among many.

### Why use multiple ML models?

To compare different classification approaches and expose model agreement/disagreement.

### Why is the synthetic dataset almost perfect?

Because the statistical distributions are deliberately highly separable. The research paper treats the behavioral simulation dataset as the more realistic evaluation.

### Can this replace antivirus software?

**No.**

It is a research prototype and should complement, not replace, established endpoint security, patching, access controls, backups, and incident-response processes.

### Can the system automatically disconnect the network?

The dashboard contains a network-isolation control and the architecture includes containment as a response direction. Any automatic network/process response must be implemented and tested carefully before production use.

### Can ransomware still cause damage before detection?

Yes.

No behavioral detector can guarantee zero damage. The engineering objective is to reduce detection and containment time.

---

# 📜 Research Paper

**RansomShield AI: An ML-Based Behavioral System for Early Ransomware Detection and Automated Response**

The paper documents the methodology, feature engineering, datasets, experimental setup, model evaluation, limitations, and future work behind the project.

---

# 🤝 Contributing

Contributions are welcome in areas such as:

- dataset engineering
- feature engineering
- ML evaluation
- false-positive reduction
- detection latency
- explainable AI
- endpoint telemetry
- containment architecture
- testing
- documentation
- security research

For security-sensitive changes, test inside isolated environments before proposing production-oriented automation.

---

# 📄 License

Add the repository's actual license here.

If this repository is intended to be open source, include a `LICENSE` file and keep the README license section synchronized with it.

---

# 👤 Author

<div align="center">

### **Manish Kuntal**

**Computer Science & Engineering • Cybersecurity / AI Research**

Building practical systems at the intersection of:

```text
Artificial Intelligence
        ×
Cybersecurity
        ×
Automation
        ×
Software Engineering
```

</div>

---

# ⭐ Final Note

RansomShield AI is built around a simple research question:

> **Can a computer recognize the behavioral footprint of ransomware early enough to give a defender time to respond?**

The current prototype explores that question using:

**18 behavioral features + 4 ML models + real-time monitoring + safe simulation + a response-oriented dashboard.**

The next step is not simply making the model more accurate.

It is making the entire system:

```text
More Realistic
      ↓
More Explainable
      ↓
More Resistant to Evasion
      ↓
Faster to Detect
      ↓
Safer to Contain
      ↓
Better to Recover
```

---

<div align="center">

**🛡️ RansomShield AI**

*Detect behavior. Understand risk. Contain carefully.*

</div>
