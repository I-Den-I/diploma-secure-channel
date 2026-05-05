# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Full chat & file-transfer view of the secure-channel messenger.

This module replaces the Phase 6 placeholder. The view it builds is a
modern, responsive, dark-by-default messenger that wires the existing
:class:`SecureChannelConnection` (Phases 4 & 5) to a Flet UI:

* a *chat pane* with bubble-style messages aligned right (local
  user) or left (peer);
* a *system-log console* showing crypto / network events --- handshake
  completion, AEAD encryption, file-transfer SHA-256 verification, ...;
* a *composer* with a paperclip attach button and a Send button;
* a background asyncio task driving :func:`SecureChannelConnection.receive_message`
  and dispatching incoming :class:`TextMessage` /
  :class:`FileTransferBegin` records;
* a theme toggle (dark / light) and a Disconnect button that cleanly
  cancels the background listener.

The chat-pane and the log-console are laid out in a Flet
:class:`ResponsiveRow`: side-by-side on wide screens, stacked on
narrow ones.

All UI mutations triggered by the background listener funnel through a
single helper that calls :func:`flet.Page.update` --- safe under the
single-threaded asyncio model used by Flet.
"""

from __future__ import annotations

import asyncio
import datetime as _datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, Optional

import flet as ft

from gui.app_state import AppState
from secure_channel.crypto.kalyna_aead import AuthenticationFailed
from secure_channel.network.connection import (
    SecureChannelConnection,
    SecureChannelConnectionClosed,
)
from secure_channel.network.file_transfer import (
    FileTransferProtocolError,
    receive_file_over_secure_channel,
    send_file_over_secure_channel,
)
from secure_channel.network.messages import (
    FileTransferBegin,
    TextMessage,
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

ChatSender = Literal["self", "peer", "system"]
SystemLogLevel = Literal["info", "warn", "error"]


@dataclass(frozen=True, slots=True)
class ChatEntry:
    """One row in the scroll-back of the chat pane.

    :param timestamp: When the entry was produced.
    :param sender: ``"self"`` for messages composed locally,
        ``"peer"`` for messages from the remote side, ``"system"`` for
        chat-level notices (e.g. "Peer disconnected").
    :param text: The displayed text of the entry.
    """

    timestamp: _datetime.datetime
    sender: ChatSender
    text: str


@dataclass(frozen=True, slots=True)
class SystemLogEntry:
    """One row in the system-logs console.

    :param timestamp: When the event happened locally.
    :param level: Severity tier; renders in distinct colours.
    :param message: Human-readable event description (typically
        crypto-flavoured: "Kalyna AEAD encrypted 14 bytes",
        "SHA-256 verified", ...).
    """

    timestamp: _datetime.datetime
    level: SystemLogLevel
    message: str


# ---------------------------------------------------------------------------
# View
# ---------------------------------------------------------------------------


class ChatView:
    """Full Phase-7 chat & file-transfer screen.

    :param app_state: Shared mutable state of the running application.
        Must already carry a fully-initialised
        :class:`SecureChannelConnection`.
    """

    _SUPPORTED_PROTOCOL_LABEL: Final[str] = "DSTU 7624 (Kalyna) · DSTU 4145"
    _MAX_MESSAGE_BYTE_LENGTH: Final[int] = 32 * 1024
    _DEFAULT_CHUNK_BYTE_LENGTH: Final[int] = 64 * 1024

    __slots__ = (
        "_app_state",
        "_connection",
        "_listener_task",
        "_listener_running",
        "_chat_listview",
        "_logs_listview",
        "_composer_textfield",
        "_send_button",
        "_attach_button",
        "_theme_toggle_button",
        "_disconnect_button",
        "_status_chip",
        "_logs_panel_visible",
        "_logs_visibility_button",
        "_chat_entries",
        "_system_log_entries",
    )

    def __init__(self, app_state: AppState) -> None:
        if app_state.secure_connection is None:
            raise RuntimeError(
                "ChatView requires a fully-initialised SecureChannelConnection."
            )
        self._app_state: Final[AppState] = app_state
        self._connection: Final[SecureChannelConnection] = app_state.secure_connection
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._listener_running: bool = False

        # In-memory entry caches let us re-render after theme changes.
        self._chat_entries: list[ChatEntry] = []
        self._system_log_entries: list[SystemLogEntry] = []

        # Pre-construct the controls that mutate over time so the
        # listener can update them by reference.
        self._chat_listview = ft.ListView(
            expand=True,
            spacing=8,
            auto_scroll=True,
            padding=ft.Padding.symmetric(vertical=8, horizontal=4),
        )
        self._logs_listview = ft.ListView(
            expand=True,
            spacing=2,
            auto_scroll=True,
            padding=ft.Padding.all(8),
        )
        self._composer_textfield = ft.TextField(
            hint_text="Type a message and press Enter…",
            expand=True,
            multiline=False,
            max_length=self._MAX_MESSAGE_BYTE_LENGTH,
            on_submit=self._handle_composer_submit,
            border_radius=12,
            filled=True,
        )
        self._send_button = ft.IconButton(
            icon=ft.Icons.SEND,
            tooltip="Send",
            on_click=self._handle_send_button_click,
        )
        self._attach_button = ft.IconButton(
            icon=ft.Icons.ATTACH_FILE,
            tooltip="Attach a file",
            on_click=self._handle_attach_button_click,
        )
        self._theme_toggle_button = ft.IconButton(
            icon=self._select_theme_toggle_icon(),
            tooltip="Toggle dark / light theme",
            on_click=self._handle_theme_toggle_click,
        )
        self._disconnect_button = ft.FilledTonalButton(
            content="Disconnect",
            icon=ft.Icons.LOGOUT,
            on_click=self._handle_disconnect_click,
        )
        self._status_chip = ft.Container(
            content=ft.Row(
                tight=True,
                spacing=6,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=[
                    ft.Icon(
                        icon=ft.Icons.LOCK,
                        size=14,
                        color=ft.Colors.GREEN_400,
                    ),
                    ft.Text(
                        value="Secure session active",
                        size=12,
                        color=ft.Colors.ON_SURFACE_VARIANT,
                    ),
                ],
            ),
            padding=ft.Padding.symmetric(vertical=4, horizontal=10),
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
            border_radius=999,
        )
        self._logs_panel_visible: bool = True
        self._logs_visibility_button = ft.IconButton(
            icon=ft.Icons.TERMINAL,
            tooltip="Toggle system / crypto log panel",
            on_click=self._handle_logs_visibility_toggle,
        )
        # No private FilePicker: the chat view re-uses the application-
        # wide one registered on the page overlay by ``gui.main.main``
        # and exposed via :attr:`AppState.shared_file_picker`. This
        # also means there is nothing to attach to ``page.overlay``
        # inside :meth:`build`.

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def build(self) -> ft.Control:
        """Compose and return the root :class:`flet.Control` of the view."""
        # The shared :class:`ft.FilePicker` is already attached to the
        # page overlay by :func:`gui.main.main`; the chat view simply
        # re-uses it via :attr:`AppState.shared_file_picker`. No
        # ``page.overlay`` mutation needed here.
        self._render_initial_system_log_entries()
        self._render_chat_listview_from_cache()
        self._render_logs_listview_from_cache()

        self._launch_background_receive_loop()

        chat_pane: ft.Control = self._build_chat_pane()
        logs_pane: ft.Control = self._build_logs_pane()

        responsive_body = ft.ResponsiveRow(
            spacing=16,
            run_spacing=16,
            expand=True,
            controls=[
                ft.Container(
                    content=chat_pane,
                    col={"sm": 12, "md": 12, "lg": 8},
                    expand=True,
                ),
                ft.Container(
                    content=logs_pane,
                    col={"sm": 12, "md": 12, "lg": 4},
                    expand=True,
                ),
            ],
        )

        return ft.Container(
            expand=True,
            padding=ft.Padding.all(16),
            content=ft.Column(
                expand=True,
                spacing=12,
                controls=[
                    self._build_header(),
                    ft.Divider(height=1),
                    responsive_body,
                ],
            ),
        )

    # ------------------------------------------------------------------
    # Header / panes
    # ------------------------------------------------------------------

    def _build_header(self) -> ft.Control:
        peer_address_label: str = self._format_peer_address_for_display()
        role_label: str = self._format_role_for_display()
        return ft.Row(
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            controls=[
                ft.Row(
                    spacing=10,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        ft.Icon(
                            icon=ft.Icons.SHIELD_OUTLINED,
                            color=ft.Colors.PRIMARY,
                            size=22,
                        ),
                        ft.Column(
                            tight=True,
                            spacing=0,
                            controls=[
                                ft.Text(
                                    value="Secure channel",
                                    size=16,
                                    weight=ft.FontWeight.W_600,
                                ),
                                ft.Text(
                                    value=(
                                        f"role: {role_label}    "
                                        f"peer: {peer_address_label}    "
                                        f"protocol: {self._SUPPORTED_PROTOCOL_LABEL}"
                                    ),
                                    size=11,
                                    color=ft.Colors.ON_SURFACE_VARIANT,
                                ),
                            ],
                        ),
                    ],
                ),
                ft.Row(
                    spacing=8,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        self._status_chip,
                        self._logs_visibility_button,
                        self._theme_toggle_button,
                        self._disconnect_button,
                    ],
                ),
            ],
        )

    def _build_chat_pane(self) -> ft.Control:
        return ft.Container(
            expand=True,
            border_radius=16,
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
            padding=ft.Padding.all(12),
            content=ft.Column(
                expand=True,
                spacing=8,
                controls=[
                    self._chat_listview,
                    ft.Container(
                        padding=ft.Padding.symmetric(vertical=4),
                        content=ft.Row(
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            controls=[
                                self._attach_button,
                                self._composer_textfield,
                                self._send_button,
                            ],
                        ),
                    ),
                ],
            ),
        )

    def _build_logs_pane(self) -> ft.Control:
        return ft.Container(
            expand=True,
            border_radius=16,
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
            padding=ft.Padding.only(top=8, bottom=8, left=4, right=4),
            visible=self._logs_panel_visible,
            content=ft.Column(
                expand=True,
                spacing=4,
                controls=[
                    ft.Container(
                        padding=ft.Padding.symmetric(horizontal=12),
                        content=ft.Row(
                            vertical_alignment=ft.CrossAxisAlignment.CENTER,
                            spacing=8,
                            controls=[
                                ft.Icon(
                                    icon=ft.Icons.TERMINAL,
                                    color=ft.Colors.PRIMARY,
                                    size=18,
                                ),
                                ft.Text(
                                    value="System / crypto log",
                                    weight=ft.FontWeight.W_600,
                                    size=14,
                                ),
                            ],
                        ),
                    ),
                    ft.Divider(height=1),
                    ft.Container(
                        expand=True,
                        bgcolor=ft.Colors.SURFACE_CONTAINER_LOW,
                        border_radius=12,
                        padding=ft.Padding.all(2),
                        content=self._logs_listview,
                    ),
                ],
            ),
        )

    # ------------------------------------------------------------------
    # Chat / log entry rendering
    # ------------------------------------------------------------------

    def _render_initial_system_log_entries(self) -> None:
        """Seed the log panel with the events known at view-mount time."""
        if self._system_log_entries:
            return  # already populated (e.g. theme toggle re-renders)
        self._append_system_log_entry(
            "info", "Handshake completed (DSTU 4145 mutual auth)"
        )
        self._append_system_log_entry(
            "info", "Session keys derived (Kalyna(128, 256) AEAD x 2)"
        )
        self._append_system_log_entry(
            "info", f"Receiver freshness window armed; replay window enabled"
        )

    def _render_chat_listview_from_cache(self) -> None:
        """Re-build the chat list-view contents from the in-memory cache."""
        self._chat_listview.controls = [
            self._render_chat_entry(entry) for entry in self._chat_entries
        ]

    def _render_logs_listview_from_cache(self) -> None:
        """Re-build the log list-view contents from the in-memory cache."""
        self._logs_listview.controls = [
            self._render_system_log_entry(entry)
            for entry in self._system_log_entries
        ]

    @staticmethod
    def _render_chat_entry(entry: ChatEntry) -> ft.Control:
        timestamp_label: str = entry.timestamp.strftime("%H:%M:%S")
        if entry.sender == "system":
            return ft.Container(
                alignment=ft.Alignment.CENTER,
                padding=ft.Padding.symmetric(vertical=2, horizontal=8),
                content=ft.Text(
                    value=f"— {entry.text} —",
                    size=11,
                    italic=True,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
            )
        is_self: bool = entry.sender == "self"
        bubble_bgcolor = (
            ft.Colors.PRIMARY_CONTAINER if is_self else ft.Colors.SURFACE_CONTAINER_HIGH
        )
        bubble_textcolor = (
            ft.Colors.ON_PRIMARY_CONTAINER if is_self else ft.Colors.ON_SURFACE
        )
        sender_label: str = "you" if is_self else "peer"
        return ft.Row(
            alignment=ft.MainAxisAlignment.END if is_self else ft.MainAxisAlignment.START,
            controls=[
                ft.Container(
                    bgcolor=bubble_bgcolor,
                    padding=ft.Padding.symmetric(vertical=8, horizontal=12),
                    border_radius=14,
                    margin=(
                        ft.Margin.only(left=80) if is_self else ft.Margin.only(right=80)
                    ),
                    content=ft.Column(
                        tight=True,
                        spacing=2,
                        horizontal_alignment=(
                            ft.CrossAxisAlignment.END
                            if is_self
                            else ft.CrossAxisAlignment.START
                        ),
                        controls=[
                            ft.Text(
                                value=entry.text,
                                color=bubble_textcolor,
                                selectable=True,
                                size=14,
                            ),
                            ft.Text(
                                value=f"{sender_label} · {timestamp_label}",
                                size=10,
                                color=ft.Colors.ON_SURFACE_VARIANT,
                            ),
                        ],
                    ),
                ),
            ],
        )

    @staticmethod
    def _render_system_log_entry(entry: SystemLogEntry) -> ft.Control:
        level_color = {
            "info": ft.Colors.ON_SURFACE_VARIANT,
            "warn": ft.Colors.AMBER_400,
            "error": ft.Colors.RED_400,
        }[entry.level]
        timestamp_label: str = entry.timestamp.strftime("%H:%M:%S")
        return ft.Row(
            spacing=8,
            controls=[
                ft.Text(
                    value=timestamp_label,
                    size=11,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                    font_family="monospace",
                ),
                ft.Text(
                    value=entry.level.upper(),
                    size=11,
                    weight=ft.FontWeight.W_600,
                    color=level_color,
                    font_family="monospace",
                ),
                ft.Text(
                    value=entry.message,
                    size=11,
                    color=level_color,
                    selectable=True,
                    expand=True,
                    font_family="monospace",
                ),
            ],
        )

    # ------------------------------------------------------------------
    # State-mutating helpers (call ``page.update()`` at the end!)
    # ------------------------------------------------------------------

    def _append_chat_entry(self, sender: ChatSender, text: str) -> None:
        entry = ChatEntry(
            timestamp=_datetime.datetime.now(),
            sender=sender,
            text=text,
        )
        self._chat_entries.append(entry)
        self._chat_listview.controls.append(self._render_chat_entry(entry))
        self._safely_update_page()

    def _append_system_log_entry(self, level: SystemLogLevel, message: str) -> None:
        entry = SystemLogEntry(
            timestamp=_datetime.datetime.now(),
            level=level,
            message=message,
        )
        self._system_log_entries.append(entry)
        self._logs_listview.controls.append(self._render_system_log_entry(entry))
        self._safely_update_page()

    def _safely_update_page(self) -> None:
        """Invoke :func:`flet.Page.update` and swallow shutdown-time errors.

        Background tasks may still be holding control-tree references
        when the page is being torn down. The defensive ``try`` keeps
        such races out of the user-facing log.
        """
        try:
            self._app_state.page.update()
        except Exception:  # noqa: BLE001
            pass

    # ------------------------------------------------------------------
    # Background listener
    # ------------------------------------------------------------------

    def _launch_background_receive_loop(self) -> None:
        """Schedule the receive loop on the running asyncio event loop.

        When the view is constructed without a running event loop
        (typical in unit-test harnesses) the scheduling is silently
        skipped: the UI still renders, just no listener is started.
        """
        if self._listener_running:
            return
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._listener_running = True
        self._listener_task = running_loop.create_task(self._background_receive_loop())

    async def _background_receive_loop(self) -> None:
        """Continuously pull records off the secure connection."""
        try:
            while True:
                try:
                    message = await self._connection.receive_message()
                except SecureChannelConnectionClosed:
                    self._append_system_log_entry(
                        "warn", "Peer closed the connection"
                    )
                    self._append_chat_entry("system", "Peer disconnected.")
                    return
                except AuthenticationFailed as authentication_error:
                    self._append_system_log_entry(
                        "error", f"Record rejected: {authentication_error}"
                    )
                    continue

                if isinstance(message, TextMessage):
                    self._append_chat_entry("peer", message.text)
                    self._append_system_log_entry(
                        "info",
                        f"Received {len(message.text)} chars (Kalyna AEAD verified)",
                    )
                elif isinstance(message, FileTransferBegin):
                    await self._receive_file_continuation(message)
                else:
                    self._append_system_log_entry(
                        "warn",
                        f"Ignoring unsupported message type: "
                        f"{type(message).__name__}",
                    )
        except asyncio.CancelledError:
            # Normal shutdown path: triggered by the disconnect button.
            return
        except Exception as unexpected_error:  # noqa: BLE001
            self._append_system_log_entry(
                "error", f"Listener crashed: {unexpected_error!r}"
            )

    async def _receive_file_continuation(
        self, file_transfer_begin: FileTransferBegin
    ) -> None:
        """Drive the chunked file reception after a peer announces a transfer."""
        self._append_system_log_entry(
            "info",
            f"Incoming file '{file_transfer_begin.filename}' "
            f"({file_transfer_begin.total_byte_length:,} bytes, "
            f"chunk = {file_transfer_begin.chunk_byte_length:,})",
        )
        self._append_chat_entry(
            "system",
            f"Receiving file: {file_transfer_begin.filename}…",
        )
        try:
            self._app_state.download_directory.mkdir(parents=True, exist_ok=True)
            destination_file_path = await receive_file_over_secure_channel(
                connection=self._connection,
                destination_directory=self._app_state.download_directory,
                file_transfer_begin=file_transfer_begin,
                overwrite_existing_file=True,
            )
        except FileTransferProtocolError as protocol_error:
            self._append_system_log_entry(
                "error", f"File transfer rejected: {protocol_error}"
            )
            return
        except (OSError, AuthenticationFailed) as transport_error:
            self._append_system_log_entry(
                "error", f"File transfer aborted: {transport_error}"
            )
            return
        self._append_chat_entry(
            "peer", f"📎 {destination_file_path.name}"
        )
        self._append_system_log_entry(
            "info",
            f"File written to {destination_file_path} (SHA-256 verified)",
        )

    async def _cancel_background_receive_loop(self) -> None:
        """Cancel the background listener and wait for it to exit cleanly."""
        if self._listener_task is None:
            return
        self._listener_running = False
        self._listener_task.cancel()
        try:
            await self._listener_task
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
        self._listener_task = None

    # ------------------------------------------------------------------
    # User actions
    # ------------------------------------------------------------------

    async def _handle_composer_submit(self, event: ft.ControlEvent) -> None:
        await self._dispatch_text_compose_action()

    async def _handle_send_button_click(self, event: ft.ControlEvent) -> None:
        await self._dispatch_text_compose_action()

    async def _dispatch_text_compose_action(self) -> None:
        text_to_send: str = (self._composer_textfield.value or "").strip()
        if not text_to_send:
            return
        self._composer_textfield.value = ""
        self._safely_update_page()
        try:
            await self._connection.send_message(TextMessage(text=text_to_send))
        except SecureChannelConnectionClosed:
            self._append_system_log_entry(
                "error", "Cannot send message: peer disconnected"
            )
            return
        self._append_chat_entry("self", text_to_send)
        self._append_system_log_entry(
            "info",
            f"Sent {len(text_to_send)} chars (Kalyna AEAD encrypt-then-MAC)",
        )

    async def _handle_attach_button_click(self, event: ft.ControlEvent) -> None:
        shared_file_picker = self._app_state.shared_file_picker
        if shared_file_picker is None:
            self._append_system_log_entry(
                "error",
                "Shared FilePicker missing from AppState; cannot attach a file.",
            )
            return
        picked_files = await shared_file_picker.pick_files(
            allow_multiple=False,
            dialog_title="Attach a file",
        )
        chosen_path: Optional[Path] = self._extract_picked_path(picked_files)
        if chosen_path is None:
            return
        await self._dispatch_file_send_action(chosen_path)

    async def _dispatch_file_send_action(self, file_path: Path) -> None:
        try:
            file_byte_length: int = file_path.stat().st_size
        except OSError as stat_error:
            self._append_system_log_entry(
                "error", f"Cannot stat {file_path}: {stat_error}"
            )
            return
        self._append_system_log_entry(
            "info",
            f"Sending '{file_path.name}' ({file_byte_length:,} bytes, "
            f"chunk = {self._DEFAULT_CHUNK_BYTE_LENGTH:,})…",
        )
        self._append_chat_entry(
            "system", f"Sending file: {file_path.name}…"
        )
        try:
            digest_bytes = await send_file_over_secure_channel(
                connection=self._connection,
                source_file_path=file_path,
                chunk_byte_length=self._DEFAULT_CHUNK_BYTE_LENGTH,
            )
        except SecureChannelConnectionClosed:
            self._append_system_log_entry(
                "error", "File send aborted: peer disconnected"
            )
            return
        except OSError as os_error:
            self._append_system_log_entry(
                "error", f"File send failed (I/O): {os_error}"
            )
            return
        self._append_chat_entry("self", f"📎 {file_path.name}")
        self._append_system_log_entry(
            "info",
            f"File '{file_path.name}' transmitted; SHA-256 = "
            f"{digest_bytes.hex()[:16]}…",
        )

    def _handle_theme_toggle_click(self, event: ft.ControlEvent) -> None:
        page = self._app_state.page
        page.theme_mode = (
            ft.ThemeMode.LIGHT
            if page.theme_mode == ft.ThemeMode.DARK
            else ft.ThemeMode.DARK
        )
        self._theme_toggle_button.icon = self._select_theme_toggle_icon()
        self._safely_update_page()

    def _select_theme_toggle_icon(self) -> str:
        page = self._app_state.page
        if getattr(page, "theme_mode", None) == ft.ThemeMode.LIGHT:
            return ft.Icons.DARK_MODE
        return ft.Icons.LIGHT_MODE

    def _handle_logs_visibility_toggle(self, event: ft.ControlEvent) -> None:
        self._logs_panel_visible = not self._logs_panel_visible
        # The pane is rebuilt on every render_view; toggle it here for
        # the live tree as well.
        self._app_state.render_view(lambda state: ChatView(state).build())

    async def _handle_disconnect_click(self, event: ft.ControlEvent) -> None:
        # Lazy import to avoid a circular import with the connection view.
        from gui.connection_view import ConnectionView  # noqa: PLC0415

        await self._cancel_background_receive_loop()
        await self._app_state.shutdown_active_session()
        self._app_state.render_view(lambda state: ConnectionView(state).build())

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _format_role_for_display(self) -> str:
        return self._connection.secure_session.role.name

    def _format_peer_address_for_display(self) -> str:
        peer_address = self._connection.peer_address
        if peer_address is None:
            return "(unknown)"
        return str(peer_address)

    @staticmethod
    def _extract_picked_path(picked_files: object) -> Optional[Path]:
        if picked_files is None:
            return None
        if not isinstance(picked_files, (list, tuple)):
            return None
        if len(picked_files) == 0:
            return None
        candidate = picked_files[0]
        candidate_path: Optional[str] = getattr(candidate, "path", None) or getattr(
            candidate, "name", None
        )
        if not candidate_path:
            return None
        return Path(candidate_path)


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------


def build_chat_view(app_state: AppState) -> ft.Control:
    """Convenience factory used by :func:`AppState.render_view`."""
    return ChatView(app_state).build()


__all__: Final[list[str]] = [
    "ChatEntry",
    "ChatSender",
    "ChatView",
    "SystemLogEntry",
    "SystemLogLevel",
    "build_chat_view",
]
