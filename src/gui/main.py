# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Entry point for the Flet-based secure-channel GUI.

The :func:`main` coroutine is registered with :func:`flet.run` and is
called by Flet once the page has been instantiated. Its
responsibilities are:

* configure global page-level properties (title, theme, default size);
* register a *shared* :class:`flet.FilePicker` on the page overlay
  *before* any view is rendered, so that every subsequent
  ``pick_files`` call (identity loaders in the connection view,
  attachment picker in the chat view) targets a control already known
  to the Flet runtime --- this is mandatory on Android / iOS, where a
  late ``page.overlay.append(picker)`` triggers
  ``unknown control: File Picker`` at runtime;
* construct the shared :class:`AppState`, attach the file picker to it,
  and dispatch to the small router on :meth:`AppState.render_view`.
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
    # Default to dark mode for the messenger aesthetic. The chat view
    # exposes a runtime theme toggle, so the user can flip to light at
    # any time.
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 0
    page.window.width = _APP_WINDOW_DEFAULT_WIDTH
    page.window.height = _APP_WINDOW_DEFAULT_HEIGHT
    page.window.min_width = 480
    page.window.min_height = 600

    # ------------------------------------------------------------------
    # Mandatory: pre-register a single shared FilePicker on the page
    # overlay BEFORE any view is built. Mobile platforms refuse to open
    # ``pick_files`` dialogs on a control that was attached to the
    # overlay only after the first ``page.update()``; eager
    # registration here side-steps that limitation entirely.
    # ------------------------------------------------------------------
    shared_file_picker: ft.FilePicker = ft.FilePicker()
    page.overlay.append(shared_file_picker)
    page.update()

    application_state: AppState = AppState(
        page=page,
        shared_file_picker=shared_file_picker,
    )

    async def shutdown_on_window_close(event: ft.WindowEvent) -> None:
        if event.type != ft.WindowEventType.CLOSE:
            return
        await application_state.shutdown_active_session()

    page.window.on_event = shutdown_on_window_close

    application_state.render_view(build_connection_view)


def run() -> None:
    """Launch the Flet desktop / mobile app.

    Wired up to the ``secure-channel-gui`` console-script entry point in
    ``pyproject.toml``. Uses :func:`flet.run` (the modern Flet 0.80+
    entry point); falls back to the deprecated :func:`flet.app` only on
    legacy builds.
    """
    if hasattr(ft, "run"):
        ft.run(main)
    else:  # pragma: no cover -- legacy Flet (<0.80)
        ft.app(target=main)


if __name__ == "__main__":
    run()
