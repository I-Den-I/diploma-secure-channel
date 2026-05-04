# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Make the GUI runnable via ``python -m gui``.

The actual launcher logic lives in :func:`gui.main.run`; this file
exists only so that ``python -m gui`` resolves to the same coroutine
that the ``secure-channel-gui`` console-script entry point uses.
"""

from __future__ import annotations

from gui.main import run

if __name__ == "__main__":
    run()
