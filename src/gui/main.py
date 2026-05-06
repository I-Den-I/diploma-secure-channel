# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Entry point for the Flet-based secure-channel GUI.

The :func:`main` coroutine is registered with :func:`flet.run` and is
called by Flet once the page has been instantiated. Its
responsibilities are:

* configure global page-level properties (title, theme, default size);
* register a *shared* :class:`flet.FilePicker` instance on
  :attr:`flet.Page.services` *before* any view is rendered, so that
  every subsequent ``pick_files`` call (identity loaders in the
  connection view, attachment picker in the chat view) targets a
  service already known to the Flet runtime;
* construct the shared :class:`AppState`, attach the file picker to it,
  and dispatch to the small router on :meth:`AppState.render_view`.

.. note::
   In Flet 0.84 ``FilePicker`` lives in
   :mod:`flet.controls.services.file_picker` and is a *Service*, not a
   visual ``Control``. Registering a service on ``page.overlay`` (which
   is what older Flet tutorials show) makes the Flutter front-end try
   to render it as a widget --- it does not know how, and falls back
   to the red "Unknown control: FilePicker" banner visible in the top-
   left corner of the desktop window. The right home for it is
   :attr:`flet.Page.services`, accessed through the
   ``register_service`` API of the underlying ``ServiceRegistry``.
"""

from __future__ import annotations

from typing import Final

import flet as ft

from gui.app_state import AppState
from gui.connection_view import build_connection_view

_APP_WINDOW_TITLE: Final[str] = "DSTU Secure Channel"
_APP_WINDOW_DEFAULT_WIDTH: Final[int] = 720
_APP_WINDOW_DEFAULT_HEIGHT: Final[int] = 720


def _register_shared_file_picker(page: ft.Page) -> ft.FilePicker:
    """Create and register the application-wide :class:`ft.FilePicker`.

    The function is split out from :func:`main` so the registration
    contract is testable in isolation (the GUI smoke tests provide a
    page stub with a mock services registry).

    :param page: The root Flet page.
    :returns: The freshly registered :class:`ft.FilePicker`.
    """
    shared_file_picker: ft.FilePicker = ft.FilePicker()
    services_registry = page.services
    if hasattr(services_registry, "register_service"):
        # Flet 0.84+: services live in a ``ServiceRegistry``.
        services_registry.register_service(shared_file_picker)
    else:  # pragma: no cover -- defensive for older Flet builds
        services_registry.append(shared_file_picker)
    return shared_file_picker


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
    # services registry BEFORE any view is built. Putting the picker on
    # ``page.overlay`` (the Flet-0.27 / pre-services pattern) makes the
    # Flutter front-end render it as the red "Unknown control" banner
    # because in 0.84 ``FilePicker`` is a Service, not a Control.
    # ------------------------------------------------------------------
    shared_file_picker: ft.FilePicker = _register_shared_file_picker(page)

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
