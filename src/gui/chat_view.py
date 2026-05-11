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
    MessageMetrics,
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


_MOBILE_PLATFORMS: Final[frozenset[ft.PagePlatform]] = frozenset({
    ft.PagePlatform.ANDROID,
    ft.PagePlatform.ANDROID_TV,
    ft.PagePlatform.IOS,
})


@dataclass(frozen=True, slots=True)
class ChatEntry:
    """One row in the scroll-back of the chat pane.

    :param timestamp: When the entry was produced.
    :param sender: ``"self"`` for messages composed locally,
        ``"peer"`` for messages from the remote side, ``"system"`` for
        chat-level notices (e.g. "Peer disconnected").
    :param text: The displayed text of the entry.
    :param verified: ``True`` if the message passed Kalyna AEAD MAC
        verification (or, for outgoing self-messages, was successfully
        sealed without error). ``False`` for tampered records — those
        get a red ✗ icon and the literal text "Tampered!".
    :param metrics: Per-message crypto stats (encryption time, sealed
        size). ``None`` for non-payload entries (system notices,
        tamper records that never decrypted successfully).
    :param file_path: Filesystem path of the attached file, if this is
        a file-transfer bubble. Set for both outgoing (source path)
        and incoming (destination path) attachments. ``None`` for
        plain text messages and system notices. When set, the bubble
        renders as a clickable affordance that opens an
        Open-file / Show-folder / Copy-path dialog.
    """

    timestamp: _datetime.datetime
    sender: ChatSender
    text: str
    verified: bool = True
    metrics: Optional[MessageMetrics] = None
    file_path: Optional[Path] = None


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
        "_tamper_button",
        "_export_logs_button",
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
        self._tamper_button = ft.IconButton(
            icon=ft.Icons.BUG_REPORT,
            tooltip="Simulate tamper: corrupt the next incoming record",
            on_click=self._handle_tamper_click,
        )
        self._export_logs_button = ft.IconButton(
            icon=ft.Icons.DOWNLOAD,
            tooltip="Export chat & system log as JSON",
            on_click=self._handle_export_logs_click,
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
        is_mobile: bool = (
            getattr(self._app_state.page, "platform", None) in _MOBILE_PLATFORMS
        )
        return (
            self._build_mobile_header() if is_mobile else self._build_desktop_header()
        )

    def _build_desktop_header(self) -> ft.Control:
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
                        self._tamper_button,
                        self._export_logs_button,
                        self._logs_visibility_button,
                        self._theme_toggle_button,
                        self._disconnect_button,
                    ],
                ),
            ],
        )

    def _build_mobile_header(self) -> ft.Control:
        """Compact header tailored for narrow phone screens.

        The previous version of this method tried to fold the action
        buttons into an ``ft.PopupMenuButton``. On Flet 0.84 / Android
        the popup-menu trigger raised during view construction, which
        ate the entire chat-view transition (the user saw
        "Connection established" but no chat appeared — see the
        regression report on PR #19).

        Replaced with a wrapping ``ft.Row`` of plain ``ft.IconButton``s
        — exactly the same control types the desktop header uses, just
        permitted to wrap when narrow. No platform-specific widgets, no
        special-cased event plumbing, and no behavioural divergence
        between mobile and desktop other than line-breaks.
        """
        peer_address_label: str = self._format_peer_address_for_display()
        role_label: str = self._format_role_for_display()
        return ft.Column(
            tight=True,
            spacing=4,
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
                        ft.Text(
                            value="Secure channel",
                            size=16,
                            weight=ft.FontWeight.W_600,
                        ),
                    ],
                ),
                ft.Text(
                    value=f"role: {role_label}",
                    size=11,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                    no_wrap=False,
                ),
                ft.Text(
                    value=f"peer: {peer_address_label}",
                    size=11,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                    no_wrap=False,
                ),
                ft.Text(
                    value=f"protocol: {self._SUPPORTED_PROTOCOL_LABEL}",
                    size=11,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                    no_wrap=False,
                ),
                # All actions on one wrap=True row → guarantees nothing
                # gets clipped on narrow screens and every control type
                # is one Flet already renders on Android.
                ft.Row(
                    spacing=6,
                    wrap=True,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        self._status_chip,
                        self._tamper_button,
                        self._export_logs_button,
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
        """Seed the log panel with the events known at view-mount time.

        Called from :meth:`build` *before* the new root control is
        appended to the page. Using the regular
        :meth:`_append_system_log_entry` (which calls
        :meth:`_safely_update_page`) here would trigger one
        ``page.update()`` per entry on a tree that isn't mounted yet
        — wasted work on desktop and a documented source of black-screen
        renders on Flet 0.84 / Android. We seed the cache + listview
        directly, then let the caller's single post-build
        ``render_view`` -> ``page.update()`` paint everything once.
        """
        if self._system_log_entries:
            return  # already populated (e.g. theme toggle re-renders)
        for seed_message in (
            "Handshake completed (DSTU 4145 mutual auth)",
            "Session keys derived (Kalyna(128, 256) AEAD x 2)",
            "Receiver freshness window armed; replay window enabled",
        ):
            entry = SystemLogEntry(
                timestamp=_datetime.datetime.now(),
                level="info",
                message=seed_message,
            )
            self._system_log_entries.append(entry)
            self._logs_listview.controls.append(
                self._render_system_log_entry(entry)
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

    def _render_chat_entry(self, entry: ChatEntry) -> ft.Control:
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
        is_tampered: bool = not entry.verified
        if is_tampered:
            bubble_bgcolor = ft.Colors.ERROR_CONTAINER
            bubble_textcolor = ft.Colors.ON_ERROR_CONTAINER
        else:
            bubble_bgcolor = (
                ft.Colors.PRIMARY_CONTAINER
                if is_self
                else ft.Colors.SURFACE_CONTAINER_HIGH
            )
            bubble_textcolor = (
                ft.Colors.ON_PRIMARY_CONTAINER if is_self else ft.Colors.ON_SURFACE
            )
        sender_label: str = "you" if is_self else "peer"

        # Integrity indicator: green ✓ on success, red ✗ when MAC failed.
        integrity_icon = ft.Icon(
            icon=ft.Icons.CANCEL if is_tampered else ft.Icons.VERIFIED,
            color=ft.Colors.RED_400 if is_tampered else ft.Colors.GREEN_400,
            size=14,
            tooltip=(
                "Tampered! MAC verification failed."
                if is_tampered
                else "Integrity verified (Kalyna AEAD)"
            ),
        )

        # Footer row: sender · timestamp · integrity icon (+ optional metrics).
        footer_controls: list[ft.Control] = [
            ft.Text(
                value=f"{sender_label} · {timestamp_label}",
                size=10,
                color=ft.Colors.ON_SURFACE_VARIANT,
            ),
            integrity_icon,
        ]
        bubble_children: list[ft.Control] = [
            ft.Text(
                value=entry.text,
                color=bubble_textcolor,
                selectable=True,
                size=14,
            ),
            ft.Row(
                spacing=4,
                tight=True,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                controls=footer_controls,
            ),
        ]
        if entry.metrics is not None:
            crypto_action = "Encrypted" if is_self else "Decrypted+verified"
            bubble_children.append(
                ft.Text(
                    value=(
                        f"{crypto_action} with Kalyna in "
                        f"{entry.metrics.crypto_duration_milliseconds:.2f} ms · "
                        f"{entry.metrics.sealed_byte_length} B on the wire"
                    ),
                    size=9,
                    italic=True,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                )
            )

        # File-attachment bubbles get an on_click that opens the
        # Open / Show-folder / Copy-path dialog. Capture file_path in
        # the lambda's default-arg slot so re-renders don't share a
        # late-binding closure (each bubble has its own path).
        bubble_on_click = None
        bubble_tooltip: Optional[str] = None
        if entry.file_path is not None:
            captured_file_path: Path = entry.file_path

            def _open_file_options(
                _event: ft.ControlEvent,
                _path: Path = captured_file_path,
            ) -> None:
                self._show_file_options_dialog(_path)

            bubble_on_click = _open_file_options
            bubble_tooltip = "Tap to open / show in folder / copy path"

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
                        controls=bubble_children,
                    ),
                    on_click=bubble_on_click,
                    tooltip=bubble_tooltip,
                    ink=bubble_on_click is not None,
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

    def _append_chat_entry(
        self,
        sender: ChatSender,
        text: str,
        *,
        verified: bool = True,
        metrics: Optional[MessageMetrics] = None,
        file_path: Optional[Path] = None,
    ) -> None:
        entry = ChatEntry(
            timestamp=_datetime.datetime.now(),
            sender=sender,
            text=text,
            verified=verified,
            file_path=file_path,
            metrics=metrics,
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
                    message, metrics = (
                        await self._connection.receive_message_with_metrics()
                    )
                except SecureChannelConnectionClosed:
                    self._append_system_log_entry(
                        "warn", "Peer closed the connection"
                    )
                    self._append_chat_entry("system", "Peer disconnected.")
                    return
                except AuthenticationFailed as authentication_error:
                    # Surface the bad record both in the log AND as a
                    # red-bubble chat entry so the user sees clearly
                    # that the integrity check rejected the message.
                    # This is the visible payoff of the Simulate-tamper
                    # debug button.
                    self._append_system_log_entry(
                        "error",
                        f"Tampered record rejected: {authentication_error}",
                    )
                    self._append_chat_entry(
                        "peer",
                        "Tampered! (MAC verification failed)",
                        verified=False,
                    )
                    continue

                if isinstance(message, TextMessage):
                    self._append_chat_entry(
                        "peer", message.text, verified=True, metrics=metrics
                    )
                    self._append_system_log_entry(
                        "info",
                        f"Received {len(message.text)} chars "
                        f"(Kalyna AEAD verified in "
                        f"{metrics.crypto_duration_milliseconds:.2f} ms; "
                        f"{metrics.sealed_byte_length} B sealed)",
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
            destination_directory = await self._resolve_download_directory()
            destination_directory.mkdir(parents=True, exist_ok=True)
            destination_file_path = await receive_file_over_secure_channel(
                connection=self._connection,
                destination_directory=destination_directory,
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
        size_label: str = self._format_byte_count(
            file_transfer_begin.total_byte_length
        )
        self._append_chat_entry(
            "peer",
            f"📎 {destination_file_path.name} ({size_label})",
            file_path=destination_file_path,
        )
        self._append_system_log_entry(
            "info",
            f"File written to {destination_file_path} (SHA-256 verified)",
        )

    async def _resolve_download_directory(self) -> Path:
        """Pick a writable destination for received files.

        On Android ``Path.home()`` resolves to ``/data`` (or worse,
        depending on the device), which the app cannot write to —
        the previous behaviour bailed mid-transfer with
        ``PermissionError`` (errno 13). This resolver mirrors the
        public-key-export logic in :class:`gui.connection_view.ConnectionView`
        so received files land **next to** the exported public keys
        (``/storage/emulated/0/Download/<name>``) — the only spot every
        stock file manager reliably exposes as "Downloads" on every
        Android version. No ``DSTU_SecureChannel`` subfolder: the user
        explicitly asked for files to land at the same path as the
        exported public keys, not in a separate hidden tree.

        Order of attempts:

        1. ``/storage/emulated/0/Download`` — the literal AOSP path.
           Confirmed working everywhere we've tested; same target as
           ``ConnectionView._try_save_to_public_downloads``. Each
           candidate is probed with a ``touch`` + ``unlink`` write
           test, so we never report success on a path that will then
           500 on the actual file write.
        2. ``StoragePaths.get_downloads_directory()`` — Flet's helper,
           kept as a last-resort for iOS / unusual Android forks where
           the AOSP path is missing.
        3. App-private documents (``<docs>/DSTU_SecureChannel/received/``)
           — guaranteed writable but invisible to file managers; used
           only when both public locations fail.

        The resolved path is cached on
        :attr:`AppState.download_directory` so subsequent transfers
        reuse it without another probe.

        Desktop behaviour is unchanged (``~/DSTU_SecureChannel/received``)
        so the existing smoke test keeps passing.
        """
        page = self._app_state.page
        is_mobile: bool = (
            getattr(page, "platform", None) in _MOBILE_PLATFORMS
        )

        # Desktop default already pointed at home — keep it (test pins
        # this behaviour and Path.home() is writable on every desktop OS).
        if not is_mobile:
            current = self._app_state.download_directory
            current.mkdir(parents=True, exist_ok=True)
            return current

        async def _attempt(target_dir: Path) -> bool:
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                probe = target_dir / ".dstu_write_probe"
                await asyncio.to_thread(probe.touch)
                await asyncio.to_thread(probe.unlink)
                return True
            except OSError:
                return False

        # 1. AOSP public Downloads — same target as the public-key export.
        candidate = Path("/storage/emulated/0/Download")
        if await _attempt(candidate):
            self._app_state.download_directory = candidate
            return candidate

        # 2. Flet's helper for iOS / unusual Android forks.
        try:
            dl_str: Optional[str] = (
                await page.storage_paths.get_downloads_directory()
            )
            if dl_str:
                candidate = Path(dl_str)
                if await _attempt(candidate):
                    self._app_state.download_directory = candidate
                    return candidate
        except Exception:  # noqa: BLE001 — API may be missing on this build
            pass

        # 3. Last-resort app-private documents — always writable but
        # only visible via ADB / Files-app-with-show-system on Android.
        docs_str = await page.storage_paths.get_application_documents_directory()
        fallback = Path(docs_str) / "DSTU_SecureChannel" / "received"
        fallback.mkdir(parents=True, exist_ok=True)
        self._app_state.download_directory = fallback
        return fallback

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
            metrics = await self._connection.send_message_with_metrics(
                TextMessage(text=text_to_send)
            )
        except SecureChannelConnectionClosed:
            self._append_system_log_entry(
                "error", "Cannot send message: peer disconnected"
            )
            return
        self._append_chat_entry(
            "self", text_to_send, verified=True, metrics=metrics
        )
        self._append_system_log_entry(
            "info",
            f"Sent {len(text_to_send)} chars "
            f"(Kalyna AEAD encrypt-then-MAC in "
            f"{metrics.crypto_duration_milliseconds:.2f} ms; "
            f"{metrics.sealed_byte_length} B sealed)",
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
        size_label: str = self._format_byte_count(file_byte_length)
        self._append_chat_entry(
            "self",
            f"📎 {file_path.name} ({size_label})",
            file_path=file_path,
        )
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

    def _show_file_options_dialog(self, file_path: Path) -> None:
        """Show an Open / Show-folder / Copy-path modal for a file bubble.

        Tapping a file-attachment chat bubble routes here. The dialog
        is the cross-platform escape hatch from "the file is on disk
        somewhere but how do I open it?":

        - **Open file** — :meth:`flet.Page.launch_url` with the
          ``file://`` URI. Hands off to the OS default handler on
          desktop (Preview, TextEdit, …). On Android this may fail
          (FileUriExposedException for non-FileProvider URIs); the
          failure is caught and a SnackBar nudges the user to use
          *Copy path* + a file manager.
        - **Show in folder** — same trick but with the parent dir.
          Lets the user reveal the file in Finder / file-manager
          even when the OS refuses to open the file directly.
        - **Copy path** — last resort that always works: drops the
          absolute path on the clipboard so the user can paste it
          into a file manager / terminal.

        File existence is *not* re-validated here — the file may have
        been moved between save and click; if launch_url fails the
        SnackBar surfaces the OS error verbatim.
        """
        page = self._app_state.page

        def _close() -> None:
            dialog.open = False
            self._safely_update_page()

        def _on_open_file(_event: ft.ControlEvent) -> None:
            try:
                page.launch_url(file_path.as_uri())
            except Exception as exc:  # noqa: BLE001 — surface to user
                self._append_system_log_entry(
                    "warn", f"Could not open file: {exc}"
                )
                self._show_snackbar(
                    f"Could not open file: {exc}. Try 'Copy path' instead."
                )
            _close()

        def _on_open_folder(_event: ft.ControlEvent) -> None:
            try:
                page.launch_url(file_path.parent.as_uri())
            except Exception as exc:  # noqa: BLE001 — surface to user
                self._append_system_log_entry(
                    "warn", f"Could not open folder: {exc}"
                )
                self._show_snackbar(
                    f"Could not open folder: {exc}. Try 'Copy path' instead."
                )
            _close()

        async def _on_copy_path(_event: ft.ControlEvent) -> None:
            try:
                await page.set_clipboard_async(str(file_path))
            except Exception:  # noqa: BLE001 — fall back to sync API
                page.set_clipboard(str(file_path))
            self._show_snackbar(f"Copied to clipboard: {file_path.name}")
            _close()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text(file_path.name, size=15, weight=ft.FontWeight.W_600),
            content=ft.Container(
                width=480,
                content=ft.Column(
                    tight=True,
                    spacing=8,
                    controls=[
                        ft.Text(
                            "Saved at:",
                            size=12,
                            color=ft.Colors.ON_SURFACE_VARIANT,
                        ),
                        ft.Text(
                            str(file_path),
                            size=11,
                            selectable=True,
                            no_wrap=False,
                            color=ft.Colors.PRIMARY,
                        ),
                    ],
                ),
            ),
            actions=[
                ft.TextButton(
                    "Copy path",
                    icon=ft.Icons.CONTENT_COPY,
                    on_click=_on_copy_path,
                ),
                ft.TextButton(
                    "Show in folder",
                    icon=ft.Icons.FOLDER_OPEN,
                    on_click=_on_open_folder,
                ),
                ft.FilledButton(
                    content="Open file",
                    icon=ft.Icons.OPEN_IN_NEW,
                    on_click=_on_open_file,
                ),
                ft.TextButton("Close", on_click=lambda _e: _close()),
            ],
        )
        page.show_dialog(dialog)

    def _show_snackbar(self, message: str) -> None:
        """Best-effort SnackBar from the chat view (mid-render races OK)."""
        try:
            self._app_state.page.show_dialog(
                ft.SnackBar(content=ft.Text(message, no_wrap=False), duration=4000)
            )
        except Exception:  # noqa: BLE001
            pass

    def _handle_tamper_click(self, event: ft.ControlEvent) -> None:
        """Arm the connection so the next incoming record fails MAC.

        Sets :attr:`SecureChannelConnection.tamper_next_incoming_record`,
        which causes one byte of the next sealed record to be flipped
        before AEAD verification — guaranteed to raise
        :class:`AuthenticationFailed` and trigger the red-bubble
        "Tampered!" path in the listener loop. The flag auto-resets
        after one use.
        """
        self._connection.tamper_next_incoming_record = True
        self._append_system_log_entry(
            "warn",
            "Tamper armed: the next incoming record will be corrupted "
            "before MAC verification (debug demo)",
        )

    async def _handle_export_logs_click(self, event: ft.ControlEvent) -> None:
        """Export chat entries + system log as a JSON document.

        On every platform we surface the JSON in a copyable-content
        dialog (works regardless of storage permissions). On platforms
        where we can also write a file we append the saved path.
        """
        json_payload = self._build_export_payload_json()
        suggested_filename = (
            f"secure_channel_log_"
            f"{_datetime.datetime.now().strftime('%Y%m%dT%H%M%S')}.json"
        )
        saved_path = await self._try_save_logs_file(
            suggested_filename, json_payload
        )
        self._show_export_logs_dialog(
            suggested_filename, json_payload, saved_path
        )

    def _build_export_payload_json(self) -> str:
        """Serialise the full session log into a JSON string.

        Includes session metadata (role, peer, protocol), every chat
        entry with its verification status and crypto metrics, and
        every system-log line. Designed for offline analysis: load the
        file in pandas / matplotlib to graph crypto duration vs
        plaintext size for the diploma write-up.
        """
        import json  # noqa: PLC0415 — local import keeps module load lean

        peer_address = self._connection.peer_address
        peer_address_str = str(peer_address) if peer_address is not None else None

        chat_entries_json = [
            {
                "timestamp": entry.timestamp.isoformat(),
                "sender": entry.sender,
                "text": entry.text,
                "verified": entry.verified,
                "metrics": (
                    {
                        "plaintext_byte_length": entry.metrics.plaintext_byte_length,
                        "sealed_byte_length": entry.metrics.sealed_byte_length,
                        "crypto_duration_ms": (
                            entry.metrics.crypto_duration_milliseconds
                        ),
                    }
                    if entry.metrics is not None
                    else None
                ),
            }
            for entry in self._chat_entries
        ]
        system_log_json = [
            {
                "timestamp": entry.timestamp.isoformat(),
                "level": entry.level,
                "message": entry.message,
            }
            for entry in self._system_log_entries
        ]
        payload = {
            "exported_at": _datetime.datetime.now().isoformat(),
            "session": {
                "role": self._format_role_for_display(),
                "peer_address": peer_address_str,
                "protocol": self._SUPPORTED_PROTOCOL_LABEL,
            },
            "chat_entries": chat_entries_json,
            "system_log": system_log_json,
        }
        return json.dumps(payload, indent=2, ensure_ascii=False)

    async def _try_save_logs_file(
        self, suggested_filename: str, payload: str
    ) -> Optional[Path]:
        """Best-effort write of *payload* to a user-visible location.

        Tries the same destinations as the public-key export (public
        Downloads on Android; ~/Downloads on desktop). Returns the
        actual path on success, ``None`` on any failure — the caller
        falls back to the always-available copy-to-clipboard option in
        the export dialog.
        """
        page = self._app_state.page
        is_mobile: bool = (
            getattr(page, "platform", None) in _MOBILE_PLATFORMS
        )

        async def _attempt(target_dir: Path) -> Optional[Path]:
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                dest = target_dir / suggested_filename
                await asyncio.to_thread(dest.write_text, payload)
                return dest
            except OSError:
                return None

        if not is_mobile:
            return await _attempt(Path.home() / "Downloads")

        hit = await _attempt(Path("/storage/emulated/0/Download"))
        if hit is not None:
            return hit
        try:
            dl_str = await page.storage_paths.get_downloads_directory()
            if dl_str:
                return await _attempt(Path(dl_str))
        except Exception:  # noqa: BLE001
            pass
        return None

    def _show_export_logs_dialog(
        self,
        file_name: str,
        json_payload: str,
        saved_path: Optional[Path],
    ) -> None:
        """Modal dialog showing the JSON + Copy + optional saved-path info."""
        page = self._app_state.page

        def _close(event: ft.ControlEvent) -> None:
            dialog.open = False
            page.update()

        async def _copy(event: ft.ControlEvent) -> None:
            try:
                await page.set_clipboard_async(json_payload)
            except Exception:  # noqa: BLE001
                page.set_clipboard(json_payload)
            copy_button.content = "Copied to clipboard"
            copy_button.icon = ft.Icons.CHECK
            page.update()

        content_field = ft.TextField(
            value=json_payload,
            read_only=True,
            multiline=True,
            min_lines=6,
            max_lines=14,
            text_size=10,
        )
        copy_button = ft.FilledButton(
            content="Copy JSON",
            icon=ft.Icons.CONTENT_COPY,
            on_click=_copy,
        )
        controls: list[ft.Control] = [
            ft.Text(f"Filename: {file_name}", weight=ft.FontWeight.W_500),
            ft.Text(
                "Use this JSON for offline analysis (e.g. graph crypto "
                "duration vs message size in pandas / matplotlib).",
                size=12,
                color=ft.Colors.ON_SURFACE_VARIANT,
                no_wrap=False,
            ),
            content_field,
            copy_button,
        ]
        if saved_path is not None:
            controls.extend([
                ft.Divider(height=1, color=ft.Colors.OUTLINE_VARIANT),
                ft.Text(
                    "Also saved as file:",
                    size=12,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
                ft.Text(
                    str(saved_path),
                    size=11,
                    selectable=True,
                    color=ft.Colors.PRIMARY,
                    no_wrap=False,
                ),
            ])
        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Export logs"),
            content=ft.Container(
                width=560,
                content=ft.Column(
                    tight=True,
                    spacing=10,
                    scroll=ft.ScrollMode.AUTO,
                    controls=controls,
                ),
            ),
            actions=[ft.TextButton("Close", on_click=_close)],
        )
        page.show_dialog(dialog)

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
    def _format_byte_count(byte_count: int) -> str:
        """Render an integer byte count in a human-friendly unit."""
        for unit in ("B", "KB", "MB", "GB"):
            if byte_count < 1024 or unit == "GB":
                if unit == "B":
                    return f"{byte_count} {unit}"
                return f"{byte_count:.1f} {unit}"
            byte_count = byte_count / 1024  # type: ignore[assignment]
        return f"{byte_count:.1f} GB"

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
