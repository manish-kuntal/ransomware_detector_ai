"""
ransomware_sim.py — Simulates BEHAVIOURAL patterns of ransomware.

⚠️  SAFETY NOTE:
    This module contains NO encryption algorithms, NO malicious code,
    and NO network activity. It only mimics the file-system access
    patterns that ransomware is known to exhibit:

    1. Rapid bulk rename with extension change  (e.g., .txt → .txt.locked)
    2. Replace file contents with high-entropy random bytes
       (simulates what encrypted output looks like — using os.urandom)
    3. High write frequency and volume
    4. Touches many different file extensions quickly

    The sole purpose is to produce a labelled dataset for ML training.
"""
import os
import time
import random
import threading


# ─── Content helper (high entropy) ───────────────────────────────────────────

def _random_bytes(min_kb: int = 10, max_kb: int = 100) -> bytes:
    """os.urandom produces near-maximum entropy — mirrors encrypted output."""
    return os.urandom(random.randint(min_kb * 1024, max_kb * 1024))


# ─── Simulator ────────────────────────────────────────────────────────────────

class RansomwareBehaviorSimulator:
    """
    Rapidly:
      • Reads each seed file
      • Overwrites it with high-entropy random data
      • Renames it with a fake 'encrypted' extension
      • Deletes the 'decryption key' placeholder
    Then loops, cycling through files, to sustain the pattern.
    """

    LOCKED_EXT     = '.locked'         # appended fake extension
    SEED_EXTENSIONS = ['.txt', '.doc', '.xls', '.pdf', '.jpg', '.db']

    def __init__(self, sandbox_dir: str, seed_files: int = 50):
        self.dir        = sandbox_dir
        self.seed_files = seed_files
        os.makedirs(self.dir, exist_ok=True)

    # ── public ────────────────────────────────────────────────────────────────

    def setup(self):
        """Populate sandbox with seed files (plain text — low entropy)."""
        text = b'A' * 4096   # low-entropy placeholder content
        for i in range(self.seed_files):
            ext  = random.choice(self.SEED_EXTENSIONS)
            path = os.path.join(self.dir, f'document_{i:04d}{ext}')
            with open(path, 'wb') as f:
                f.write(text)

    def run(self, duration: float = 10.0):
        """
        Run the ransomware-behaviour pattern for `duration` seconds.
        Uses a thread pool to increase concurrency (mimics real ransomware
        which spawns worker threads).
        """
        self.setup()
        end = time.time() + duration

        while time.time() < end:
            files = self._list_files()
            if not files:
                break

            # Process files in small rapid batches (aggressive pace)
            batch = random.sample(files, min(10, len(files)))
            threads = []
            for path in batch:
                t = threading.Thread(target=self._process_file, args=(path,), daemon=True)
                threads.append(t)
                t.start()
            for t in threads:
                t.join(timeout=2)

            time.sleep(random.uniform(0.05, 0.2))   # very short pause → high rate

        # Drop a fake 'ransom note' (creates an extra file event)
        note = os.path.join(self.dir, 'README_DECRYPT.txt')
        with open(note, 'w') as f:
            f.write('[SIMULATED RANSOM NOTE — NOT REAL]\n')

    # ── private helpers ───────────────────────────────────────────────────────

    def _list_files(self) -> list:
        """List files that have NOT yet been 'locked'."""
        try:
            return [
                os.path.join(self.dir, fn)
                for fn in os.listdir(self.dir)
                if os.path.isfile(os.path.join(self.dir, fn))
                and not fn.endswith(self.LOCKED_EXT)
                and fn != 'README_DECRYPT.txt'
            ]
        except OSError:
            return []

    def _process_file(self, path: str):
        """
        Mimic single-file ransomware operation:
          read → overwrite with random bytes → rename with .locked extension
        """
        try:
            # Step 1: Read original (ransomware reads to encrypt)
            with open(path, 'rb') as f:
                f.read()

            # Step 2: Overwrite with high-entropy content
            with open(path, 'wb') as f:
                f.write(_random_bytes(10, 50))

            # Step 3: Rename to signal 'encryption' complete
            locked_path = path + self.LOCKED_EXT
            os.rename(path, locked_path)

        except OSError:
            pass
