# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Mutable runtime state shared across Flet views.

A single :class:`AppState` instance is passed to every view at
construction time. Views read identity-related bookkeeping from it,
write the resulting :class:`SecureChannelConnection` to it after a
successful handshake, and ask it to re-render the main page when a
view transition is required.

Keeping all mutable state in one place avoids the temptation to thread
``page``-objects, callbacks and futures through every view's
constructor and makes the data flow easy to inspect.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Final, Optional

import flet as ft

from secure_channel.network.connection import SecureChannelConnection
from secure_channel.network.server import SecureChannelServer


ViewBuilder = Callable[["AppState"], ft.Control]
"""Type of a callable that builds a top-level view's root control."""


def _default_download_directory() -> Path:
    """Return a writable per-user directory for files received over the channel.

    The convention --- ``~/DSTU_SecureChannel/received/`` --- avoids
    clobbering ``~/Downloads`` and keeps every file produced by the
    diploma demo under a single, easily inspectable folder.
    """
    return Path.home() / "DSTU_SecureChannel" / "received"



@dataclass
class AppState:
    """Container for runtime state shared between views.

    :param page: The root Flet :class:`flet.Page` instance.
    :param own_private_key_path: Filesystem path to the local user's
        ``private.json``, populated by the connection view as the user
        picks files.
    :param peer_public_key_path: Filesystem path to the peer's
        ``public.json``.
    :param secure_connection: Set after a successful handshake.
    :param secure_server: When acting as the responder, the server
        listening socket is held here so it can be closed cleanly on
        disconnect.
    :param server_shutdown_event: Asyncio event used to keep the
        responder's connection-handler coroutine alive while the chat
        view holds the connection.
    :param download_directory: Directory under which files received
        through the chat view are written. Created lazily on first
        write.
    :param identities_directory: Directory under which newly generated
        identity key pairs are saved. ``None`` until the connection view
        resolves the platform-specific path on first use (desktop falls
        back to ``~/DSTU_SecureChannel/identities/``; mobile uses the
        app documents directory from :attr:`flet.StoragePaths`).
    """

    page: ft.Page
    own_private_key_path: Optional[Path] = None
    peer_public_key_path: Optional[Path] = None
    secure_connection: Optional[SecureChannelConnection] = None
    secure_server: Optional[SecureChannelServer] = None
    server_shutdown_event: Optional[asyncio.Event] = None
    download_directory: Path = field(default_factory=_default_download_directory)
    identities_directory: Optional[Path] = None
    # A single FilePicker instance, registered once on the page overlay
    # by :func:`gui.main.main`, and reused by every view that needs to
    # open a native file dialog. Pre-registration is mandatory on
    # mobile platforms (Android / iOS), where Flet otherwise throws an
    # "unknown control: File Picker" error if the picker is appended
    # to the overlay lazily after the page has been rendered.
    shared_file_picker: Optional[ft.FilePicker] = None
    _current_view_builder: Optional[ViewBuilder] = field(default=None, repr=False)

    PAGE_TITLE: Final[str] = "DSTU Secure Channel"

    def render_view(self, view_builder: ViewBuilder) -> None:
        """Replace the page's contents with the output of ``view_builder``.

        :param view_builder: Callable returning the root :class:`ft.Control`
            of the new view.
        """
        self._current_view_builder = view_builder
        self.page.controls.clear()
        self.page.controls.append(view_builder(self))
        self.page.update()

    async def shutdown_active_session(self) -> None:
        """Close the active :class:`SecureChannelConnection` and server, if any.

        Idempotent. Safe to call from a view's "Disconnect" button or
        from the application's window-close handler.
        """
        if self.server_shutdown_event is not None:
            self.server_shutdown_event.set()
            self.server_shutdown_event = None
        if self.secure_connection is not None:
            try:
                await self.secure_connection.close()
            except Exception:  # noqa: BLE001  -- best-effort teardown
                pass
            self.secure_connection = None
        if self.secure_server is not None:
            try:
                await self.secure_server.close()
            except Exception:  # noqa: BLE001  -- best-effort teardown
                pass
            self.secure_server = None


HandshakeFinishedCallback = Callable[[SecureChannelConnection], Awaitable[None]]
"""Coroutine invoked once the SIGMA handshake has completed successfully."""
