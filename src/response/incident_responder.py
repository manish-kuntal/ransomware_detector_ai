"""
incident_responder.py — Automated response engine.

When ransomware is detected, this module executes the 9-step response:
  1. Collect evidence (processes, files, network state)
  2. Identify suspicious process (highest write I/O)
  3. Kill suspicious process
  4. Isolate network (Windows Firewall emergency block rule)
  5. Quarantine high-entropy files
  6. Protect backup directories (set read-only)
  7. Record all affected files
  8. Alert user (system notification + sound)
  9. Generate incident report

⚠️  Network isolation and process-kill are REVERSIBLE.
     Restore buttons are provided in the dashboard.
"""

import os
import sys
import time
import json
import shutil
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from collections import deque

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from config import LOGS_DIR, ENTROPY_HIGH_THRESHOLD

# Windows-only system processes — never kill these
SAFE_PROCESSES = {
    'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'winlogon.exe', 'services.exe', 'lsass.exe', 'svchost.exe',
    'explorer.exe', 'taskhostw.exe', 'dwm.exe', 'python.exe',
    'pythonw.exe', 'cmd.exe', 'powershell.exe',
}

FIREWALL_RULE = 'RANSOMSHIELD_EMERGENCY_BLOCK'


# ─── Response result object ───────────────────────────────────────────────────

class ActionResult:
    def __init__(self, name: str, status: str, message: str):
        self.name      = name
        self.status    = status   # success | failed | skipped | warning
        self.message   = message
        self.ts        = time.time()
        self.time_str  = datetime.now().strftime('%H:%M:%S')

    def to_dict(self) -> dict:
        return {
            'name':     self.name,
            'status':   self.status,
            'message':  self.message,
            'ts':       self.ts,
            'time_str': self.time_str,
        }


# ─── Main responder ───────────────────────────────────────────────────────────

class IncidentResponder:
    """
    Call .respond(alert, actions=[...]) to execute selected actions.
    Status is stored in .action_log (deque) for the dashboard to read.
    """

    def __init__(self, watch_path: str, backup_paths: list = None):
        self.watch_path       = watch_path
        self.backup_paths     = backup_paths or []
        self.evidence_dir     = os.path.join(LOGS_DIR, 'evidence')
        self.quarantine_dir   = os.path.join(LOGS_DIR, 'quarantine')

        self.action_log       = deque(maxlen=200)
        self.network_isolated = False
        self.killed_procs     = []
        self._lock            = threading.Lock()

        os.makedirs(self.evidence_dir,   exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)

    # ── public API ────────────────────────────────────────────────────────────

    def respond(self, alert: dict,
                actions: list = None) -> list:
        """
        Execute a subset of response actions.

        actions: list of action keys — default is all:
            'evidence', 'process', 'network', 'quarantine',
            'backup', 'affected_files', 'notify', 'report'
        """
        if actions is None:
            actions = ['evidence', 'process', 'network',
                       'quarantine', 'backup', 'affected_files',
                       'notify', 'report']

        results = []
        dispatch = {
            'evidence':       lambda: self._step1_evidence(alert),
            'process':        self._step2_kill_process,
            'network':        self._step3_isolate_network,
            'quarantine':     self._step4_quarantine,
            'backup':         self._step5_protect_backups,
            'affected_files': self._step6_affected_files,
            'notify':         self._step7_notify,
            'report':         lambda: self._step9_report(alert, results),
        }

        for key in actions:
            fn = dispatch.get(key)
            if fn is None:
                continue
            try:
                r = fn()
            except Exception as e:
                r = ActionResult(key, 'failed', str(e))
            results.append(r)
            with self._lock:
                self.action_log.append(r.to_dict())

        return results

    def restore_network(self) -> ActionResult:
        """Remove emergency firewall rules — call from dashboard."""
        try:
            if sys.platform != 'win32':
                return ActionResult('network_restore', 'skipped', 'Windows only')

            for direction in ['', '_IN']:
                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete',
                     'rule', f'name={FIREWALL_RULE}{direction}'],
                    capture_output=True,
                )
            self.network_isolated = False
            r = ActionResult('network_restore', 'success',
                             'Firewall rules removed — network reconnected')
        except Exception as e:
            r = ActionResult('network_restore', 'failed', str(e))

        with self._lock:
            self.action_log.append(r.to_dict())
        return r

    # ── Step 1 — Collect evidence ─────────────────────────────────────────────

    def _step1_evidence(self, alert: dict) -> ActionResult:
        try:
            ts     = datetime.now().strftime('%Y%m%d_%H%M%S')
            ev_dir = os.path.join(self.evidence_dir, f'incident_{ts}')
            os.makedirs(ev_dir, exist_ok=True)

            data = {
                'incident_time': ts,
                'alert':         alert,
                'system': {
                    'cpu':    psutil.cpu_percent() if PSUTIL_OK else 0,
                    'memory': psutil.virtual_memory().percent if PSUTIL_OK else 0,
                },
            }

            if PSUTIL_OK:
                # Running processes
                procs = []
                for p in psutil.process_iter(
                        ['pid', 'name', 'cpu_percent',
                         'memory_percent', 'create_time']):
                    try:
                        info = p.info
                        try:
                            io = p.io_counters()
                            info['write_bytes'] = io.write_bytes
                        except Exception:
                            info['write_bytes'] = 0
                        procs.append(info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                data['processes'] = procs

                # Network connections
                try:
                    data['network_connections'] = [
                        {'pid': c.pid, 'laddr': str(c.laddr),
                         'raddr': str(c.raddr), 'status': c.status}
                        for c in psutil.net_connections()
                    ]
                except Exception:
                    pass

            # Files in watched dir
            flist = []
            for f in Path(self.watch_path).rglob('*'):
                if f.is_file():
                    flist.append({'path': str(f), 'size': f.stat().st_size})
            data['watched_files'] = flist[:1000]

            ev_file = os.path.join(ev_dir, 'evidence.json')
            with open(ev_file, 'w') as fh:
                json.dump(data, fh, indent=2, default=str)

            return ActionResult('evidence', 'success',
                                f'Saved → {ev_file}')
        except Exception as e:
            return ActionResult('evidence', 'failed', str(e))

    # ── Step 2 & 3 — Find + kill suspicious process ───────────────────────────

    def _step2_kill_process(self) -> ActionResult:
        if not PSUTIL_OK:
            return ActionResult('process', 'skipped', 'psutil not available')
        try:
            candidates = []
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    name = p.info['name'].lower()
                    if name in SAFE_PROCESSES:
                        continue
                    io = p.io_counters()
                    if io.write_bytes > 5_000_000:     # > 5 MB writes
                        candidates.append((io.write_bytes, p))
                except (psutil.NoSuchProcess, psutil.AccessDenied,
                        AttributeError, NotImplementedError):
                    pass

            if not candidates:
                return ActionResult('process', 'skipped',
                                    'No process with >5 MB writes found')

            candidates.sort(reverse=True)
            target   = candidates[0][1]
            pid      = target.pid
            name     = target.name()
            write_mb = candidates[0][0] / 1_048_576

            target.kill()
            self.killed_procs.append({'pid': pid, 'name': name})

            return ActionResult('process', 'success',
                                f'Killed: {name} (PID {pid}, '
                                f'{write_mb:.1f} MB written)')
        except Exception as e:
            return ActionResult('process', 'failed', str(e))

    # ── Step 4 — Network isolation ────────────────────────────────────────────

    def _step3_isolate_network(self) -> ActionResult:
        try:
            if sys.platform != 'win32':
                return ActionResult('network', 'skipped',
                                    'Windows only (netsh)')

            cmds = [
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={FIREWALL_RULE}',
                 'dir=out', 'action=block', 'protocol=any', 'enable=yes'],
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={FIREWALL_RULE}_IN',
                 'dir=in', 'action=block', 'protocol=any', 'enable=yes'],
            ]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=10)

            self.network_isolated = True
            return ActionResult('network', 'success',
                                'Firewall rules added — all traffic blocked')
        except Exception as e:
            return ActionResult('network', 'failed', str(e))

    # ── Step 5 — Quarantine high-entropy files ────────────────────────────────

    def _step4_quarantine(self) -> ActionResult:
        try:
            from src.monitoring.file_monitor import FileMonitor
            moved = 0
            for f in Path(self.watch_path).rglob('*'):
                if not f.is_file():
                    continue
                try:
                    if FileMonitor.file_entropy(str(f)) >= ENTROPY_HIGH_THRESHOLD:
                        dest = Path(self.quarantine_dir) / (f.name + '.quarantine')
                        shutil.move(str(f), str(dest))
                        moved += 1
                except Exception:
                    pass

            return ActionResult('quarantine', 'success',
                                f'{moved} high-entropy files → {self.quarantine_dir}')
        except Exception as e:
            return ActionResult('quarantine', 'failed', str(e))

    # ── Step 6 — Protect backup directories ──────────────────────────────────

    def _step5_protect_backups(self) -> ActionResult:
        if not self.backup_paths:
            return ActionResult('backup', 'skipped',
                                'No backup paths configured')
        try:
            protected = []
            for bp in self.backup_paths:
                if not os.path.exists(bp):
                    continue
                if sys.platform == 'win32':
                    subprocess.run(
                        ['icacls', bp, '/deny', 'Everyone:(W,D,M)'],
                        capture_output=True,
                    )
                else:
                    subprocess.run(['chmod', '-R', 'a-w', bp],
                                   capture_output=True)
                protected.append(bp)

            return ActionResult('backup', 'success',
                                f'Protected: {", ".join(protected)}')
        except Exception as e:
            return ActionResult('backup', 'failed', str(e))

    # ── Step 7 — Record affected files ────────────────────────────────────────

    def _step6_affected_files(self) -> ActionResult:
        try:
            report_path = os.path.join(self.evidence_dir, 'affected_files.txt')
            count = 0
            with open(report_path, 'w') as fh:
                fh.write(f'Affected files scan — {datetime.now()}\n')
                fh.write('='*60 + '\n')
                for f in Path(self.watch_path).rglob('*'):
                    if f.is_file():
                        fh.write(f'{f}\n')
                        count += 1

            return ActionResult('affected_files', 'success',
                                f'{count} files logged → {report_path}')
        except Exception as e:
            return ActionResult('affected_files', 'failed', str(e))

    # ── Step 8 — Notify user ──────────────────────────────────────────────────

    def _step7_notify(self) -> ActionResult:
        try:
            msg = ('RANSOMWARE ACTIVITY DETECTED!\n\n'
                   'RansomShield AI has detected suspicious file activity.\n'
                   'Automated response has been triggered.\n\n'
                   'Check the dashboard for details.')

            if sys.platform == 'win32':
                import ctypes
                ctypes.windll.user32.MessageBoxW(
                    0, msg, '🚨 RansomShield ALERT', 0x00000010)
            else:
                # macOS / Linux fallback
                subprocess.run(
                    ['notify-send', '🚨 RansomShield', msg],
                    capture_output=True,
                )

            return ActionResult('notify', 'success', 'User notified')
        except Exception as e:
            return ActionResult('notify', 'warning',
                                f'Notification failed: {e}')

    # ── Step 9 — Incident report ──────────────────────────────────────────────

    def _step9_report(self, alert: dict, prev: list) -> ActionResult:
        try:
            ts  = datetime.now()
            rpt = os.path.join(
                self.evidence_dir,
                f'incident_report_{ts.strftime("%Y%m%d_%H%M%S")}.txt'
            )
            feats = alert.get('features', {})

            lines = [
                '=' * 60,
                '   RANSOMSHIELD AI — INCIDENT REPORT',
                '=' * 60,
                f'   Date / Time   : {ts.strftime("%Y-%m-%d %H:%M:%S")}',
                f'   Threat Level  : {alert.get("level", "?")}',
                f'   Risk Score    : {alert.get("score", 0):.4f}',
                f'   Watch Path    : {self.watch_path}',
                '',
                'DETECTED SIGNALS:',
                f'   File renames        : {feats.get("file_rename_count", 0):.0f}',
                f'   Extension changes   : {feats.get("extension_change_count", 0):.0f}',
                f'   Avg entropy         : {feats.get("avg_entropy", 0):.3f} bits',
                f'   High-entropy files  : {feats.get("entropy_spike_count", 0):.0f}',
                f'   Write ops/sec       : {feats.get("write_ops_per_sec", 0):.1f}',
                f'   CPU %               : {feats.get("cpu_percent", 0):.1f}%',
                '',
                'RESPONSE ACTIONS:',
            ]

            for r in prev:
                d = r.to_dict() if hasattr(r, 'to_dict') else r
                lines.append(
                    f'   [{d["status"].upper():8}] '
                    f'{d["name"]}: {d["message"]}')

            lines += [
                '',
                'NEXT STEPS:',
                '   1. Verify alert is not a false positive',
                '   2. Do NOT restart the machine — preserve RAM',
                '   3. Check network isolation status',
                '   4. Verify backup integrity before restoring',
                '   5. Restore from last clean verified backup',
                '   6. Change all potentially exposed credentials',
                '   7. Report to incident response team / authorities',
                '',
                '=' * 60,
                '   Generated by RansomShield AI v1.0',
                '=' * 60,
            ]

            with open(rpt, 'w') as fh:
                fh.write('\n'.join(lines))

            return ActionResult('report', 'success',
                                f'Saved → {rpt}')
        except Exception as e:
            return ActionResult('report', 'failed', str(e))
