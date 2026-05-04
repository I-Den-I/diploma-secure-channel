# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Entry point for the Flet-based secure-channel GUI.

The :func:`main` coroutine is registered with :func:`flet.app` and is
called by Flet once the page has been instantiated. Its only
responsibilities are:

* configure global page-level properties (title, theme, default size);
* construct the shared :class:`AppState`;
* render the initial view (the connection screen) via the small router
  on :meth:`AppState.render_view`.

A blocking :func:`run` helper at the bottom of the module powers the
``secure-channel-gui`` console-script entry point declared in
``pyproject.toml`` (and also makes ``python -m gui`` work).
"""

from __future__ import annotations

from typing import Final

import flet as ft

from gui.app_state import AppState
from gui.connection_view import build_connection_view

_APP_WINDOW_TITLE: Final[str] = "DSTU Secure Channel"
_APP_WINDOW_DEFAULT_WIDTH: Final[int] = 720
_APP_WINDOW_DEFAULT_HEIGHT: Final[int] = 720


async def main(page: ft.Page) -> None:
    """Flet entry coroutine.

    :param page: The root page instance supplied by the Flet runtime.
    """
    page.title = _APP_WINDOW_TITLE
    page.theme_mode = ft.ThemeMode.SYSTEM
    page.padding = 0
    page.window.width = _APP_WINDOW_DEFAULT_WIDTH
    page.window.height = _APP_WINDOW_DEFAULT_HEIGHT
    page.window.min_width = 480
    page.window.min_height = 600

    application_state: AppState = AppState(page=page)

    async def shutdown_on_window_close(event: ft.WindowEvent) -> None:
        if event.type != ft.WindowEventType.CLOSE:
            return
        await application_state.shutdown_active_session()

    page.window.on_event = shutdown_on_window_close

    application_state.render_view(build_connection_view)


def run() -> None:
    """Launch the Flet desktop app.

    Wired up to the ``secure-channel-gui`` console-script entry point in
    ``pyproject.toml`` so that ``pip install -e .[gui]`` followed by
    ``secure-channel-gui`` boots the application without setting
    ``PYTHONPATH`` manually.

    Uses :func:`flet.run` (the modern Flet 0.80+ entry point); falls
    back to the deprecated :func:`flet.app` on older Flet builds.
    """
    if hasattr(ft, "run"):
        ft.run(main)
    else:
        ft.app(target=main)  # pragma: no cover -- legacy Flet (<0.80)


if __name__ == "__main__":
    run()
