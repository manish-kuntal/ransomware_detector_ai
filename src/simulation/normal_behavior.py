"""
normal_behavior.py — Simulates typical user/application file activity.

Pattern characteristics (what ML learns as "normal"):
  • Low rename rate, no extension changes
  • Few files touched per second
  • Low file entropy (plain text content)
  • Gradual, irregular write cadence
  • Moderate CPU / memory
"""
import os
import time
import random
import string


# ─── Content helpers (low entropy — readable text) ────────────────────────────

_LOREM = (
    "Lorem ipsum dolor sit amet consectetur adipiscing elit sed do "
    "eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim "
    "ad minim veniam quis nostrud exercitation ullamco laboris nisi ut "
    "aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit "
    "in voluptate velit esse cillum dolore eu fugiat nulla pariatur "
    "excepteur sint occaecat cupidatat non proident sunt in culpa qui "
    "officia deserunt mollit anim id est laborum "
)


def _random_text(min_kb: int = 1, max_kb: int = 20) -> bytes:
    size = random.randint(min_kb * 1024, max_kb * 1024)
    base = _LOREM * (size // len(_LOREM) + 1)
    return base[:size].encode()


def _random_name(ext: str = '.txt') -> str:
    stem = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 12)))
    return stem + ext


# ─── Simulator ────────────────────────────────────────────────────────────────

class NormalBehaviorSimulator:
    """
    Creates seed files and then performs random normal operations:
    create, read, append, occasional rename (same extension), delete.
    """

    EXTENSIONS = ['.txt', '.log', '.csv', '.md', '.json', '.xml']

    def __init__(self, sandbox_dir: str, seed_files: int = 40):
        self.dir        = sandbox_dir
        self.seed_files = seed_files
        os.makedirs(self.dir, exist_ok=True)

    # ── public ────────────────────────────────────────────────────────────────

    def setup(self):
        """Populate sandbox with seed files."""
        for _ in range(self.seed_files):
            ext  = random.choice(self.EXTENSIONS)
            name = _random_name(ext)
            path = os.path.join(self.dir, name)
            with open(path, 'wb') as f:
                f.write(_random_text())

    def run(self, duration: float = 10.0):
        """Run simulation for `duration` seconds."""
        self.setup()
        end = time.time() + duration

        while time.time() < end:
            action = random.choices(
                ['read', 'modify', 'create', 'rename', 'delete'],
                weights=[40, 30, 15, 10, 5],
            )[0]

            files = self._list_files()
            if not files:
                self.setup()
                continue

            try:
                if action == 'read':
                    self._read(random.choice(files))
                elif action == 'modify':
                    self._modify(random.choice(files))
                elif action == 'create':
                    self._create()
                elif action == 'rename':
                    self._rename_same_ext(random.choice(files))
                elif action == 'delete' and len(files) > 10:
                    os.remove(random.choice(files))
            except OSError:
                pass

            time.sleep(random.uniform(0.2, 1.5))   # leisurely pace

    # ── private helpers ───────────────────────────────────────────────────────

    def _list_files(self) -> list:
        try:
            return [os.path.join(self.dir, f) for f in os.listdir(self.dir)
                    if os.path.isfile(os.path.join(self.dir, f))]
        except OSError:
            return []

    def _read(self, path: str):
        with open(path, 'rb') as f:
            f.read()

    def _modify(self, path: str):
        with open(path, 'ab') as f:
            f.write(b'\n' + _random_text(1, 5))

    def _create(self):
        ext  = random.choice(self.EXTENSIONS)
        path = os.path.join(self.dir, _random_name(ext))
        with open(path, 'wb') as f:
            f.write(_random_text())

    def _rename_same_ext(self, path: str):
        ext     = os.path.splitext(path)[1]
        new_path = os.path.join(self.dir, _random_name(ext))
        os.rename(path, new_path)
