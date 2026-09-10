"""PyInstaller entry point for hdwp."""
import sys
import os

# In frozen mode, ensure _MEIPASS is on sys.path so that
# importlib.metadata.entry_points finds the bundled dist-info.
if getattr(sys, "frozen", False):
    meipass = sys._MEIPASS  # type: ignore[attr-defined]
    if meipass not in sys.path:
        sys.path.insert(0, meipass)

from hdwp.cli.main import app

if __name__ == "__main__":
    app()
