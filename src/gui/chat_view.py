# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Placeholder post-handshake chat view.

Phase 6 wires the secure-channel handshake into the GUI but does not
yet render a chat interface; that work is scheduled for Phase 7. This
module provides a single :class:`ChatView` that displays a confirmation
banner and a "Disconnect" button so the user can return to the
connection view.

The placeholder is intentionally minimal: it lets the diploma examiner
verify visually that the full handshake completed end-to-end, and that
the GUI correctly transitions away from the connection screen.
"""

from __future__ import annotations

from typing import Final

import flet as ft

from gui.app_state import AppState


class ChatView:
    """Placeholder chat screen shown after a successful handshake.

    :param app_state: Shared mutable state of the running application.
    """

    PAGE_HEADLINE: Final[str] = "Connection Established"
    PAGE_DETAIL: Final[str] = "Chat UI coming in Phase 7."

    __slots__ = ("_app_state",)

    def __init__(self, app_state: AppState) -> None:
        self._app_state: Final[AppState] = app_state

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def build(self) -> ft.Control:
        """Compose and return the root :class:`flet.Control` of the view."""
        peer_address_label: str = self._format_peer_address_for_display()
        role_label: str = self._format_role_for_display()

        return ft.Container(
            expand=True,
            alignment=ft.Alignment.CENTER,
            padding=ft.Padding.all(48),
            content=ft.Column(
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=24,
                tight=True,
                controls=[
                    ft.Icon(
                        icon=ft.Icons.LOCK_PERSON,
                        size=72,
                        color=ft.Colors.GREEN_400,
                    ),
                    ft.Text(
                        value=self.PAGE_HEADLINE,
                        size=28,
                        weight=ft.FontWeight.W_600,
                    ),
                    ft.Text(
                        value=self.PAGE_DETAIL,
                        size=16,
                        color=ft.Colors.ON_SURFACE_VARIANT,
                    ),
                    ft.Container(
                        padding=ft.Padding.symmetric(vertical=8, horizontal=16),
                        bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
                        border_radius=12,
                        content=ft.Column(
                            tight=True,
                            spacing=4,
                            controls=[
                                ft.Text(
                                    value=f"Local role: {role_label}",
                                    size=13,
                                    color=ft.Colors.ON_SURFACE_VARIANT,
                                ),
                                ft.Text(
                                    value=f"Peer: {peer_address_label}",
                                    size=13,
                                    color=ft.Colors.ON_SURFACE_VARIANT,
                                ),
                            ],
                        ),
                    ),
                    ft.FilledTonalButton(
                        content="Disconnect",
                        icon=ft.Icons.LOGOUT,
                        on_click=self._handle_disconnect_click,
                    ),
                ],
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _format_role_for_display(self) -> str:
        connection = self._app_state.secure_connection
        if connection is None:
            return "(unknown)"
        return connection.secure_session.role.name

    def _format_peer_address_for_display(self) -> str:
        connection = self._app_state.secure_connection
        if connection is None:
            return "(unknown)"
        peer_address = connection.peer_address
        if peer_address is None:
            return "(unknown)"
        return str(peer_address)

    async def _handle_disconnect_click(self, event: ft.ControlEvent) -> None:
        """Tear down the active session and return to the connection view."""
        # Imported lazily to avoid a circular import with the connection view.
        from gui.connection_view import ConnectionView  # noqa: PLC0415

        await self._app_state.shutdown_active_session()
        self._app_state.render_view(lambda state: ConnectionView(state).build())


def build_chat_view(app_state: AppState) -> ft.Control:
    """Convenience factory used by :func:`AppState.render_view`."""
    return ChatView(app_state).build()


__all__: Final[list[str]] = ["ChatView", "build_chat_view"]
