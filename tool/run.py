"""Punto de entrada para `python -I tool/run.py` (con -I no se agrega la carpeta actual al path)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pes6pkg.cli import main  # noqa: E402

sys.exit(main())
