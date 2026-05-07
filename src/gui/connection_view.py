# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Pre-handshake connection screen.

The view collects the four pieces of information that drive a SIGMA
handshake:

1. The local user's ``private.json`` (file picker).
2. The peer's ``public.json`` (file picker).
3. The local *role* --- "Listen as server" or "Connect as client" ---
   selected through a segmented toggle.
4. A host (only meaningful in client mode) and a port.

Once all required inputs are valid, a primary "Connect" / "Listen"
button kicks off the appropriate asyncio coroutine without freezing
the Flet UI thread. On success the resulting
:class:`SecureChannelConnection` is stashed inside the shared
:class:`AppState` and the view router transitions the page to the
placeholder chat screen.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Final, Optional

import flet as ft

from gui.app_state import AppState
from gui.chat_view import build_chat_view
from secure_channel.crypto.dstu4145 import Dstu4145SignatureScheme
from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB
from secure_channel.identity_io import (
    PRIVATE_KEY_FILE_NAME,
    PUBLIC_KEY_FILE_NAME,
    assemble_handshake_credentials,
    save_private_key_to_file,
    save_public_key_to_file,
)
from secure_channel.network.client import connect_secure_channel
from secure_channel.network.connection import SecureChannelConnection
from secure_channel.network.server import SecureChannelServer
from secure_channel.session.handshake import HandshakeError


_DEFAULT_HOST_VALUE: Final[str] = "127.0.0.1"
_DEFAULT_PORT_VALUE: Final[str] = "9000"
_OWN_FILE_PICKER_DIALOG_TITLE: Final[str] = "Select your private.json"
_PEER_FILE_PICKER_DIALOG_TITLE: Final[str] = "Select the peer's public.json"
_MOBILE_PLATFORMS: Final[frozenset[ft.PagePlatform]] = frozenset({
    ft.PagePlatform.ANDROID,
    ft.PagePlatform.ANDROID_TV,
    ft.PagePlatform.IOS,
})


class ConnectionView:
    """Top-level connection / listen screen.

    :param app_state: Shared mutable runtime state.
    """

    __slots__ = (
        "_app_state",
        "_role_segmented_button",
        "_host_text_field",
        "_port_text_field",
        "_own_private_key_path_text",
        "_peer_public_key_path_text",
        "_saved_keys_dropdown",
        "_status_text",
        "_progress_indicator",
        "_primary_action_button",
        "_generate_identity_button",
        "_identity_name_text_field",
        "_export_public_key_button",
        "_in_progress",
    )

    def __init__(self, app_state: AppState) -> None:
        self._app_state: Final[AppState] = app_state
        self._in_progress: bool = False

        # The connection view does **not** create its own
        # ``ft.FilePicker``: a single shared instance is registered on
        # ``page.overlay`` upfront by :func:`gui.main.main`, and reused
        # for every ``pick_files`` call. Pre-registration is mandatory
        # on Android / iOS, where late overlay attachment surfaces as
        # "unknown control: File Picker" at runtime.

        initial_own_path: Optional[Path] = app_state.own_private_key_path
        initial_peer_path: Optional[Path] = app_state.peer_public_key_path

        self._own_private_key_path_text = ft.Text(
            value=self._format_path_for_display(initial_own_path),
            size=12,
            color=ft.Colors.ON_SURFACE_VARIANT,
            selectable=True,
            no_wrap=False,
        )
        self._peer_public_key_path_text = ft.Text(
            value=self._format_path_for_display(initial_peer_path),
            size=12,
            color=ft.Colors.ON_SURFACE_VARIANT,
            selectable=True,
            no_wrap=False,
        )

        self._saved_keys_dropdown = ft.Dropdown(
            label="Saved identities",
            hint_text="No saved identities",
            dense=True,
            options=[],
            on_select=self._handle_key_selected,
        )

        self._role_segmented_button = ft.SegmentedButton(
            allow_multiple_selection=False,
            allow_empty_selection=False,
            # ``selected`` is serialised over msgpack to the Flet front-end,
            # which in 0.84 does not handle ``set`` instances. A plain list
            # round-trips cleanly.
            selected=["client"],
            on_change=self._handle_role_change,
            segments=[
                ft.Segment(
                    value="client",
                    label=ft.Text("Connect as client"),
                    icon=ft.Icon(ft.Icons.CALL_MADE),
                ),
                ft.Segment(
                    value="server",
                    label=ft.Text("Listen as server"),
                    icon=ft.Icon(ft.Icons.WIFI_TETHERING),
                ),
            ],
        )
        self._host_text_field = ft.TextField(
            label="Host",
            value=_DEFAULT_HOST_VALUE,
            hint_text="IP address, hostname, or 0.0.0.0 (server)",
            expand=True,
            prefix_icon=ft.Icons.PUBLIC,
        )
        self._port_text_field = ft.TextField(
            label="Port",
            value=_DEFAULT_PORT_VALUE,
            hint_text="1..65535",
            width=120,
            keyboard_type=ft.KeyboardType.NUMBER,
        )

        self._status_text = ft.Text(
            value="", size=13, selectable=True, no_wrap=False
        )
        self._progress_indicator = ft.ProgressRing(
            visible=False, width=18, height=18, stroke_width=2
        )
        self._primary_action_button = ft.FilledButton(
            content="Connect",
            icon=ft.Icons.LOCK_OPEN,
            on_click=self._handle_primary_action_click,
        )
        self._generate_identity_button = ft.OutlinedButton(
            content="Generate New Identity",
            icon=ft.Icons.KEY,
            on_click=self._handle_generate_identity_click,
        )
        self._identity_name_text_field = ft.TextField(
            label="Identity Name",
            hint_text="Leave empty to use 'default'",
        )
        self._export_public_key_button = ft.OutlinedButton(
            content="Export Public Key",
            icon=ft.Icons.UPLOAD_FILE,
            on_click=self._handle_export_public_key_click,
        )

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def build(self) -> ft.Control:
        """Compose and return the root :class:`flet.Control` of the view."""
        # No need to touch ``page.overlay`` here: a single shared
        # ``ft.FilePicker`` is registered upfront by ``gui.main.main``
        # and lives on :attr:`AppState.shared_file_picker`. Both the
        # local-private-key and peer-public-key dialogs reuse it.

        identity_section: ft.Control = self._build_identity_section()
        role_section: ft.Control = self._build_role_section()
        action_section: ft.Control = self._build_action_section()

        root = ft.Container(
            expand=True,
            alignment=ft.Alignment.CENTER,
            padding=ft.Padding.all(48),
            content=ft.Column(
                width=560,
                horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
                spacing=20,
                scroll=ft.ScrollMode.AUTO,
                controls=[
                    self._build_header(),
                    identity_section,
                    role_section,
                    action_section,
                ],
            ),
        )
        # Load saved key history asynchronously so the dropdown is
        # populated once the page's storage-paths service is ready.
        self._app_state.page.run_task(self._populate_key_history)
        return root

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_header() -> ft.Control:
        return ft.Column(
            tight=True,
            spacing=4,
            controls=[
                ft.Row(
                    spacing=12,
                    controls=[
                        ft.Icon(
                            icon=ft.Icons.SHIELD_OUTLINED,
                            color=ft.Colors.PRIMARY,
                            size=32,
                        ),
                        ft.Text(
                            value="DSTU Secure Channel",
                            size=24,
                            weight=ft.FontWeight.W_600,
                        ),
                    ],
                ),
                ft.Text(
                    value="Load your long-term identity, choose a role, and"
                    " start the SIGMA handshake.",
                    size=13,
                    color=ft.Colors.ON_SURFACE_VARIANT,
                ),
            ],
        )

    def _build_identity_section(self) -> ft.Control:
        return ft.Container(
            padding=ft.Padding.all(16),
            border_radius=12,
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
            content=ft.Column(
                tight=True,
                spacing=12,
                controls=[
                    ft.Text(
                        value="Identity files",
                        size=14,
                        weight=ft.FontWeight.W_500,
                    ),
                    ft.Row(
                        controls=[
                            ft.OutlinedButton(
                                content=f"Pick own {PRIVATE_KEY_FILE_NAME}",
                                icon=ft.Icons.VPN_KEY,
                                on_click=self._open_own_file_picker,
                            ),
                            self._own_private_key_path_text,
                        ],
                        spacing=12,
                        wrap=True,
                    ),
                    self._saved_keys_dropdown,
                    ft.Row(
                        controls=[self._export_public_key_button],
                        wrap=True,
                    ),
                    ft.Row(
                        controls=[
                            ft.OutlinedButton(
                                content=f"Pick peer's {PUBLIC_KEY_FILE_NAME}",
                                icon=ft.Icons.PERSON_OUTLINE,
                                on_click=self._open_peer_file_picker,
                            ),
                            self._peer_public_key_path_text,
                        ],
                        spacing=12,
                        wrap=True,
                    ),
                    ft.Divider(height=1, color=ft.Colors.OUTLINE_VARIANT),
                    ft.Row(
                        controls=[
                            self._identity_name_text_field,
                            self._generate_identity_button,
                        ],
                        spacing=12,
                        wrap=True,
                    ),
                ],
            ),
        )

    def _build_role_section(self) -> ft.Control:
        return ft.Container(
            padding=ft.Padding.all(16),
            border_radius=12,
            bgcolor=ft.Colors.SURFACE_CONTAINER_HIGHEST,
            content=ft.Column(
                tight=True,
                spacing=12,
                controls=[
                    ft.Text(
                        value="Role and endpoint",
                        size=14,
                        weight=ft.FontWeight.W_500,
                    ),
                    self._role_segmented_button,
                    ft.Row(
                        controls=[
                            self._host_text_field,
                            self._port_text_field,
                        ],
                        spacing=12,
                    ),
                ],
            ),
        )

    def _build_action_section(self) -> ft.Control:
        return ft.Column(
            spacing=8,
            controls=[
                ft.Row(
                    spacing=12,
                    vertical_alignment=ft.CrossAxisAlignment.CENTER,
                    controls=[
                        self._primary_action_button,
                        self._progress_indicator,
                    ],
                ),
                self._status_text,
            ],
        )

    # ------------------------------------------------------------------
    # File-picker handlers
    # ------------------------------------------------------------------

    async def _open_own_file_picker(self, event: ft.ControlEvent) -> None:
        """Open the native file dialog for the local user's private key."""
        chosen_path: Optional[Path] = await self._invoke_shared_file_picker(
            dialog_title=_OWN_FILE_PICKER_DIALOG_TITLE
        )
        if chosen_path is None:
            return
        self._app_state.own_private_key_path = chosen_path
        self._own_private_key_path_text.value = self._format_path_for_display(
            chosen_path
        )
        self._app_state.page.update()

    async def _open_peer_file_picker(self, event: ft.ControlEvent) -> None:
        """Open the native file dialog for the peer's public key."""
        chosen_path: Optional[Path] = await self._invoke_shared_file_picker(
            dialog_title=_PEER_FILE_PICKER_DIALOG_TITLE
        )
        if chosen_path is None:
            return
        self._app_state.peer_public_key_path = chosen_path
        self._peer_public_key_path_text.value = self._format_path_for_display(
            chosen_path
        )
        self._app_state.page.update()

    async def _invoke_shared_file_picker(
        self, *, dialog_title: str
    ) -> Optional[Path]:
        """Drive the shared :class:`ft.FilePicker` for one identity slot.

        The view never owns its own picker; instead it asks the
        application-wide instance attached to :attr:`AppState.shared_file_picker`
        (registered in :func:`gui.main.main`) to open a native dialog
        with the supplied title.
        """
        shared_file_picker = self._app_state.shared_file_picker
        if shared_file_picker is None:
            raise RuntimeError(
                "Shared FilePicker missing from AppState; "
                "gui.main.main must register it on the page overlay."
            )
        picked_files = await shared_file_picker.pick_files(
            allow_multiple=False,
            dialog_title=dialog_title,
            allowed_extensions=["json"],
            file_type=ft.FilePickerFileType.CUSTOM,
        )
        return self._extract_picked_path(picked_files)

    @staticmethod
    def _extract_picked_path(picked_files: object) -> Optional[Path]:
        """Pull a single ``Path`` out of the heterogeneous Flet 0.84 result.

        Different Flet builds return either ``None``, an empty list, or
        a list of :class:`flet.FilePickerFile`-like objects. We tolerate
        all three so the GUI works across point releases.
        """
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

    # ------------------------------------------------------------------
    # Identity generation and key-history handlers
    # ------------------------------------------------------------------

    async def _resolve_identities_directory(self) -> Path:
        """Return a platform-appropriate writable directory for key pairs.

        On Android and iOS ``Path.home()`` is either non-existent or
        permission-denied. :meth:`flet.StoragePaths.get_application_documents_directory`
        is the correct writable location on those platforms. Desktop
        platforms keep the original ``~/DSTU_SecureChannel/identities/``
        path so any keys already on disk are found without migration.

        The resolved path is cached in :attr:`AppState.identities_directory`
        so that both the generator and the history scanner use the same root.
        """
        if self._app_state.identities_directory is not None:
            return self._app_state.identities_directory

        if getattr(self._app_state.page, "platform", None) in _MOBILE_PLATFORMS:
            base_str: str = (
                await self._app_state.page.storage_paths.get_application_documents_directory()
            )
            resolved = Path(base_str) / "DSTU_SecureChannel" / "identities"
        else:
            resolved = Path.home() / "DSTU_SecureChannel" / "identities"

        self._app_state.identities_directory = resolved
        return resolved

    async def _try_save_to_public_downloads(
        self, public_key_path: Path, public_key_name: str
    ) -> Optional[Path]:
        """Best-effort copy to the public Downloads folder.

        Returns the destination path on success, ``None`` if no writable
        location was found. We deliberately *don't* try
        ``Android/data/<package>/files/...`` — Android 11+ blocks file
        managers from browsing those directories, so a "saved to" message
        pointing there would be useless to the user.
        """
        is_mobile: bool = (
            getattr(self._app_state.page, "platform", None) in _MOBILE_PLATFORMS
        )

        async def _attempt(target_dir: Path) -> Optional[Path]:
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                dest = target_dir / public_key_name
                await asyncio.to_thread(shutil.copy2, str(public_key_path), str(dest))
                return dest
            except OSError:
                return None

        if not is_mobile:
            return await _attempt(Path.home() / "Downloads")

        # Android — write straight to the public Downloads folder. This is
        # the only location all stock file managers (Files, Mi File Manager,
        # Total Commander, …) reliably show on every Android version.
        # MANAGE_EXTERNAL_STORAGE / WRITE_EXTERNAL_STORAGE are declared in
        # pyproject.toml so the write succeeds on devices that grant either.
        hit = await _attempt(Path("/storage/emulated/0/Download"))
        if hit is not None:
            return hit

        # Last resort: ask Flet for the platform's idea of Downloads.
        # Useful on iOS / unusual Android forks where the AOSP path is
        # absent; harmless when it isn't.
        try:
            dl_str = await self._app_state.page.storage_paths.get_downloads_directory()
            if dl_str:
                return await _attempt(Path(dl_str))
        except Exception:  # noqa: BLE001 — API may be missing on this build
            pass

        return None

    def _show_export_dialog(
        self,
        file_name: str,
        file_content: str,
        saved_path: Optional[Path],
    ) -> None:
        """Modal dialog with copyable JSON + optional saved-path info.

        Showing the JSON content directly with a Copy button works on
        *every* platform regardless of storage permissions — the user
        can paste it into any messenger and the peer saves it as a
        file with the displayed filename.
        """
        page = self._app_state.page

        def _close(event: ft.ControlEvent) -> None:
            dialog.open = False
            page.update()

        async def _copy(event: ft.ControlEvent) -> None:
            try:
                await page.set_clipboard_async(file_content)
            except Exception:  # noqa: BLE001 — fall back to sync API
                page.set_clipboard(file_content)
            copy_button.content = "Copied to clipboard"
            copy_button.icon = ft.Icons.CHECK
            page.update()

        content_field = ft.TextField(
            value=file_content,
            read_only=True,
            multiline=True,
            min_lines=4,
            max_lines=10,
            text_size=11,
        )
        copy_button = ft.FilledButton(
            content="Copy JSON",
            icon=ft.Icons.CONTENT_COPY,
            on_click=_copy,
        )

        controls: list[ft.Control] = [
            ft.Text(f"Filename: {file_name}", weight=ft.FontWeight.W_500),
            ft.Text(
                "Copy the JSON below and send it to your peer (Telegram,"
                " email, …). Your peer saves it as a file with the name"
                " above, then loads it via 'Pick peer's public.json'.",
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
            title=ft.Text("Export public key"),
            content=ft.Container(
                width=500,
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

    async def _handle_export_public_key_click(self, event: ft.ControlEvent) -> None:
        """Surface the current identity's public key for sharing.

        Always shows the JSON content with a Copy button — guaranteed to
        work on every Android version and every desktop. As a bonus, also
        attempts to drop a file in public Downloads; if that succeeds, the
        path is shown in the same dialog.
        """
        own_path = self._app_state.own_private_key_path
        if own_path is None:
            self._show_status("Select an identity first.", error=True)
            return

        public_key_name = own_path.name.replace("private", "public", 1)
        public_key_path = own_path.parent / public_key_name

        if not public_key_path.exists():
            self._show_status(
                f"Public key not found: {public_key_name}", error=True
            )
            return

        try:
            public_key_content = await asyncio.to_thread(public_key_path.read_text)
        except OSError as exc:
            self._show_status(f"Cannot read public key: {exc}", error=True)
            return

        # Best-effort file copy alongside the always-works clipboard option.
        saved_path = await self._try_save_to_public_downloads(
            public_key_path, public_key_name
        )

        self._show_status(
            f"Exported {public_key_name}"
            + (f" → {saved_path}" if saved_path else " (use Copy JSON to share)")
        )
        self._show_export_dialog(public_key_name, public_key_content, saved_path)

    async def _populate_key_history(self) -> None:
        """Scan the identities directory and refresh the saved-keys dropdown.

        Called once from :meth:`build` (via ``page.run_task``) and again
        after every successful key generation. Silently no-ops if the
        directory does not yet exist.
        """
        try:
            identities_dir = await self._resolve_identities_directory()
        except Exception:  # noqa: BLE001 — storage_paths not ready yet
            return

        if not identities_dir.exists():
            return

        private_files: list[Path] = sorted(
            identities_dir.glob("private_*.json"), reverse=True
        )
        if not private_files:
            return

        current_path = self._app_state.own_private_key_path
        self._saved_keys_dropdown.options = [
            ft.dropdown.Option(key=str(p), text=p.name) for p in private_files
        ]
        if current_path is not None and str(current_path) in {
            str(p) for p in private_files
        }:
            self._saved_keys_dropdown.value = str(current_path)
        self._app_state.page.update()

    def _handle_key_selected(self, event: ft.ControlEvent) -> None:
        """Load the key chosen from the saved-identities dropdown."""
        selected_value: Optional[str] = getattr(event, "data", None)
        if not selected_value:
            return
        chosen_path = Path(selected_value)
        self._app_state.own_private_key_path = chosen_path
        self._own_private_key_path_text.value = self._format_path_for_display(
            chosen_path
        )
        self._app_state.page.update()

    async def _handle_generate_identity_click(self, event: ft.ControlEvent) -> None:
        """Generate a fresh DSTU 4145 key pair and save it to disk.

        Key generation is offloaded to a worker thread so the Flet event
        loop stays responsive during the CPU-bound scalar multiplication.
        On success the new private-key path is loaded into :attr:`AppState`
        and the saved-identities dropdown is refreshed and auto-selected.
        """
        if self._in_progress:
            return
        self._set_in_progress(True)
        name = (self._identity_name_text_field.value or "").strip() or "default"
        try:
            identities_dir = await self._resolve_identities_directory()
            private_key_path, public_key_path = await asyncio.to_thread(
                self._generate_and_save_identity,
                identities_dir,
                name,
            )
        except (OSError, Exception) as exc:  # noqa: BLE001
            self._show_status(f"Could not generate identity: {exc}", error=True)
            return
        finally:
            self._set_in_progress(False)

        self._app_state.own_private_key_path = private_key_path
        self._own_private_key_path_text.value = self._format_path_for_display(
            private_key_path
        )
        await self._populate_key_history()
        self._saved_keys_dropdown.value = str(private_key_path)
        self._app_state.page.update()

        self._app_state.page.show_dialog(
            ft.SnackBar(
                content=ft.Text(
                    f"Identity generated!\n"
                    f"Private: {private_key_path.name}\n"
                    f"Public:  {public_key_path.name}\n"
                    f"Tap 'Export Public Key' to save it where you can find it."
                ),
                duration=7000,
            )
        )

    @staticmethod
    def _generate_and_save_identity(
        identities_dir: Path, name: str
    ) -> tuple[Path, Path]:
        """Create a named key-pair and write both JSON files.

        Runs in a thread pool executor (see caller). Returns the two paths
        so the event-loop thread can update the UI without touching the
        filesystem itself. If files with the given name already exist, a
        numeric suffix (_1, _2, …) is appended until a free slot is found.
        """
        identities_dir.mkdir(parents=True, exist_ok=True)
        private_key_path = identities_dir / f"private_{name}.json"
        public_key_path = identities_dir / f"public_{name}.json"
        if private_key_path.exists() or public_key_path.exists():
            n = 1
            while True:
                private_key_path = identities_dir / f"private_{name}_{n}.json"
                public_key_path = identities_dir / f"public_{name}_{n}.json"
                if not private_key_path.exists() and not public_key_path.exists():
                    break
                n += 1
        scheme = Dstu4145SignatureScheme(DSTU4145_M163_PB)
        private_key, public_key = scheme.generate_key_pair()
        save_private_key_to_file(private_key, private_key_path)
        save_public_key_to_file(public_key, public_key_path)
        return private_key_path, public_key_path

    # ------------------------------------------------------------------
    # Role / button handlers
    # ------------------------------------------------------------------

    def _handle_role_change(self, event: ft.ControlEvent) -> None:
        if self._is_server_role_selected():
            self._primary_action_button.content = "Listen"
            self._primary_action_button.icon = ft.Icons.WIFI_TETHERING
            self._host_text_field.label = "Bind address"
            if self._host_text_field.value == "127.0.0.1":
                self._host_text_field.value = "0.0.0.0"
        else:
            self._primary_action_button.content = "Connect"
            self._primary_action_button.icon = ft.Icons.LOCK_OPEN
            self._host_text_field.label = "Host"
            if self._host_text_field.value == "0.0.0.0":
                self._host_text_field.value = "127.0.0.1"
        self._app_state.page.update()

    async def _handle_primary_action_click(self, event: ft.ControlEvent) -> None:
        if self._in_progress:
            return
        validation_error: Optional[str] = self._validate_inputs()
        if validation_error is not None:
            self._show_status(validation_error, error=True)
            return
        try:
            self._set_in_progress(True)
            credentials = assemble_handshake_credentials(
                own_private_key_path=self._app_state.own_private_key_path,  # type: ignore[arg-type]
                peer_public_key_path=self._app_state.peer_public_key_path,  # type: ignore[arg-type]
            )
        except (OSError, ValueError) as load_error:
            self._set_in_progress(False)
            self._show_status(
                f"Could not load identity files: {load_error}", error=True
            )
            return

        host_value: str = self._host_text_field.value or ""
        port_value_raw: str = self._port_text_field.value or ""
        try:
            port_value: int = int(port_value_raw)
            if not (1 <= port_value <= 65535):
                raise ValueError("port out of range")
        except ValueError:
            self._set_in_progress(False)
            self._show_status(
                f"Invalid port: {port_value_raw!r} (expected 1..65535)",
                error=True,
            )
            return

        try:
            if self._is_server_role_selected():
                self._show_status(
                    f"Listening on {host_value}:{port_value} for an incoming peer..."
                )
                connection = await self._listen_and_handoff(
                    credentials=credentials,
                    bind_host=host_value,
                    bind_port=port_value,
                )
            else:
                self._show_status(
                    f"Connecting to {host_value}:{port_value} ..."
                )
                connection = await connect_secure_channel(
                    host=host_value,
                    port=port_value,
                    credentials=credentials,
                )
        except HandshakeError as handshake_error:
            self._set_in_progress(False)
            self._show_status(
                f"Handshake rejected: {handshake_error}", error=True
            )
            return
        except ConnectionRefusedError:
            self._set_in_progress(False)
            self._show_status("Connection refused.", error=True)
            self._app_state.page.show_dialog(
                ft.SnackBar(
                    content=ft.Text(
                        "Connection refused (Errno 111): Check the target IP"
                        " and ensure the server is listening."
                    ),
                    duration=6000,
                )
            )
            return
        except (TimeoutError, asyncio.TimeoutError):
            self._set_in_progress(False)
            self._show_status("Connection timed out.", error=True)
            self._app_state.page.show_dialog(
                ft.SnackBar(
                    content=ft.Text(
                        "Connection timed out. Check the target IP and port."
                    ),
                    duration=6000,
                )
            )
            return
        except OSError as transport_error:
            self._set_in_progress(False)
            self._show_status(
                f"Transport error: {transport_error}", error=True
            )
            return
        except Exception as unexpected_error:  # noqa: BLE001
            self._set_in_progress(False)
            self._show_status(
                f"Unexpected error: {unexpected_error}", error=True
            )
            return

        self._app_state.secure_connection = connection
        self._show_status(
            f"Connection established with {connection.peer_address}.",
            error=False,
        )
        self._set_in_progress(False)
        self._app_state.render_view(build_chat_view)

    # ------------------------------------------------------------------
    # Server-side listen helper
    # ------------------------------------------------------------------

    async def _listen_and_handoff(
        self,
        credentials,  # type: ignore[no-untyped-def]
        bind_host: str,
        bind_port: int,
    ) -> SecureChannelConnection:
        """Start a one-shot responder and hand off the resulting connection.

        The :class:`SecureChannelServer` invokes a connection handler in
        its own task. To extract the established
        :class:`SecureChannelConnection` and feed it to the GUI we use
        the standard *future + event* hand-off pattern: the handler
        sets a ``Future`` with the connection, then waits on a
        :class:`asyncio.Event` until the chat view tells it to shut
        down.
        """
        connection_ready_future: asyncio.Future[SecureChannelConnection] = (
            asyncio.get_event_loop().create_future()
        )
        shutdown_event: asyncio.Event = asyncio.Event()

        async def connection_handler(connection: SecureChannelConnection) -> None:
            connection_ready_future.set_result(connection)
            await shutdown_event.wait()

        secure_server: SecureChannelServer = SecureChannelServer(
            credentials=credentials, connection_handler=connection_handler
        )
        await secure_server.start(host=bind_host, port=bind_port)
        self._app_state.secure_server = secure_server
        self._app_state.server_shutdown_event = shutdown_event
        return await connection_ready_future

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _is_server_role_selected(self) -> bool:
        selected = self._role_segmented_button.selected or []
        return "server" in selected

    def _validate_inputs(self) -> Optional[str]:
        if self._app_state.own_private_key_path is None:
            return "Please select your own private.json."
        if self._app_state.peer_public_key_path is None:
            return "Please select the peer's public.json."
        if not (self._host_text_field.value or "").strip():
            return "Please enter a host or bind address."
        if not (self._port_text_field.value or "").strip():
            return "Please enter a TCP port."
        return None

    def _set_in_progress(self, in_progress: bool) -> None:
        self._in_progress = in_progress
        self._primary_action_button.disabled = in_progress
        self._generate_identity_button.disabled = in_progress
        self._export_public_key_button.disabled = in_progress
        self._progress_indicator.visible = in_progress
        self._app_state.page.update()

    def _show_status(self, status_message: str, *, error: bool = False) -> None:
        self._status_text.value = status_message
        self._status_text.color = (
            ft.Colors.ERROR if error else ft.Colors.ON_SURFACE_VARIANT
        )
        self._app_state.page.update()

    @staticmethod
    def _format_path_for_display(file_path: Optional[Path]) -> str:
        if file_path is None:
            return "(no file selected)"
        return file_path.name


def build_connection_view(app_state: AppState) -> ft.Control:
    """Convenience factory used by :func:`AppState.render_view`."""
    return ConnectionView(app_state).build()


__all__: Final[list[str]] = ["ConnectionView", "build_connection_view"]
