# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Project-wide ``pytest`` configuration shim.

This file exists in the repository root so that running ``pytest`` from the
project root automatically inserts ``./src`` on :data:`sys.path`. The
``pyproject.toml`` configuration also handles this through ``pythonpath``,
but having an explicit module here keeps simple ad-hoc invocations such as
``python -m pytest tests/test_kalyna.py`` robust against differing
``pytest`` versions.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if _SRC.is_dir():
    src_str = str(_SRC)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)
