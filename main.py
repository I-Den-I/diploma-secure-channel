# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Top-level launcher consumed by ``flet build`` / ``flet run``.

The diploma project keeps every Python source under :mod:`src`. The
Flet build CLI, by default, looks for a ``main.py`` (or a
``[tool.flet]`` configuration in ``pyproject.toml``) at the project
root. This file fulfils that contract by:

1. Inserting ``./src`` at the head of :data:`sys.path` so that the
   :mod:`gui` and :mod:`secure_channel` packages resolve at runtime.
2. Delegating to :func:`gui.main.main`, the same Flet entry coroutine
   used by the ``secure-channel-gui`` console-script and by the
   ``python -m gui`` invocation.

Doing the path bootstrap here --- rather than rearranging the
``src`` layout --- keeps unit tests, ``pip install -e .[gui]`` and
``flet build`` all happy with a single source of truth.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent
_SRC_DIRECTORY = _PROJECT_ROOT / "src"
if _SRC_DIRECTORY.is_dir():
    src_directory_string = str(_SRC_DIRECTORY)
    if src_directory_string not in sys.path:
        sys.path.insert(0, src_directory_string)

import flet as ft  # noqa: E402  (import after sys.path tweak)

from gui.main import main  # noqa: E402  (import after sys.path tweak)


if __name__ == "__main__":
    if hasattr(ft, "run"):
        ft.run(main)
    else:  # pragma: no cover -- legacy Flet (<0.80)
        ft.app(target=main)
