# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Smoke tests for the Flet GUI shell.

These tests are intentionally lightweight: they construct each view
with a mocked :class:`flet.Page` (and, where required, a mocked
:class:`SecureChannelConnection`) and assert that the resulting
control tree is a non-``None`` :class:`flet.Control`. The goal is to
catch import-time errors and constructor-signature regressions across
Flet point releases without spinning up an actual desktop window.

End-to-end visual integration tests (clicking buttons, completing a
real SIGMA handshake from the GUI, full file transfer through the UI)
are tracked separately and intentionally not part of this smoke
fixture.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

flet = pytest.importorskip("flet")

from gui.app_state import AppState  # noqa: E402  -- import after pytest.importorskip
from gui.chat_view import (  # noqa: E402
    ChatEntry,
    SystemLogEntry,
    build_chat_view,
)
from gui.connection_view import build_connection_view  # noqa: E402
from secure_channel.network.connection import (  # noqa: E402
    SecureChannelConnection,
)


class _FakeServiceRegistry:
    """Tiny stand-in for :class:`flet.controls.page.ServiceRegistry`.

    Only exposes the surface the GUI code touches: a
    ``register_service`` method and a ``_services`` list inspectable
    by the smoke tests.
    """

    def __init__(self) -> None:
        self._services: list[object] = []

    def register_service(self, service: object) -> None:
        self._services.append(service)


def _build_mock_page() -> object:
    """Create a fake :class:`flet.Page` with the attributes the views use."""
    fake_page = MagicMock(spec=flet.Page)
    fake_page.controls = []
    fake_page.overlay = []
    fake_page.services = _FakeServiceRegistry()
    fake_page.update = lambda: None
    fake_page.theme_mode = flet.ThemeMode.DARK
    return fake_page


def _build_mock_secure_connection() -> object:
    """Create a stub :class:`SecureChannelConnection` good enough for build()."""
    fake_connection = MagicMock(spec=SecureChannelConnection)
    fake_session = MagicMock()
    fake_session.role.name = "initiator"
    fake_connection.secure_session = fake_session
    fake_connection.peer_address = ("127.0.0.1", 9000)
    return fake_connection


def test_app_state_holds_the_page() -> None:
    fake_page = _build_mock_page()
    state = AppState(page=fake_page)
    assert state.page is fake_page
    assert state.secure_connection is None
    assert state.secure_server is None
    assert state.own_private_key_path is None
    assert state.peer_public_key_path is None


def test_app_state_provides_a_default_download_directory() -> None:
    state = AppState(page=_build_mock_page())
    assert isinstance(state.download_directory, Path)
    assert state.download_directory.parts[-2:] == ("DSTU_SecureChannel", "received")


def test_connection_view_root_is_a_flet_control() -> None:
    state = AppState(page=_build_mock_page())
    root = build_connection_view(state)
    assert isinstance(root, flet.Control)


def test_chat_view_requires_secure_connection() -> None:
    state = AppState(page=_build_mock_page())
    with pytest.raises(RuntimeError):
        build_chat_view(state)


def test_chat_view_root_is_a_flet_control_when_connection_is_present() -> None:
    state = AppState(page=_build_mock_page())
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]
    root = build_chat_view(state)
    assert isinstance(root, flet.Control)


def test_chat_view_seeds_initial_system_log_entries() -> None:
    state = AppState(page=_build_mock_page())
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]
    # Re-construct directly so we can introspect the cache.
    from gui.chat_view import ChatView

    chat_view = ChatView(state)
    chat_view.build()
    assert len(chat_view._system_log_entries) >= 3  # type: ignore[attr-defined]
    handshake_log: SystemLogEntry = chat_view._system_log_entries[0]  # type: ignore[attr-defined]
    assert "Handshake" in handshake_log.message
    assert handshake_log.level == "info"


def test_chat_view_appends_chat_entry_renders_a_bubble() -> None:
    state = AppState(page=_build_mock_page())
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]
    from gui.chat_view import ChatView

    chat_view = ChatView(state)
    chat_view.build()
    chat_view._append_chat_entry("self", "hello")  # type: ignore[attr-defined]
    last_entry: ChatEntry = chat_view._chat_entries[-1]  # type: ignore[attr-defined]
    assert last_entry.sender == "self"
    assert last_entry.text == "hello"
    # Plain text entries don't carry a file_path.
    assert last_entry.file_path is None


def test_chat_entry_default_file_path_is_none() -> None:
    """ChatEntry's file_path defaults to None for non-file messages."""
    import datetime as _dt

    entry = ChatEntry(timestamp=_dt.datetime.now(), sender="self", text="hi")
    assert entry.file_path is None


def test_chat_entry_carries_file_path_when_provided(tmp_path: Path) -> None:
    """ChatEntry round-trips an explicit file_path via the constructor."""
    import datetime as _dt

    sample = tmp_path / "demo.txt"
    sample.write_text("ok")
    entry = ChatEntry(
        timestamp=_dt.datetime.now(),
        sender="peer",
        text=f"📎 {sample.name} (2 B)",
        file_path=sample,
    )
    assert entry.file_path == sample


def test_append_chat_entry_with_file_path_threads_it_onto_entry(
    tmp_path: Path,
) -> None:
    """_append_chat_entry forwards file_path into the stored ChatEntry."""
    state = AppState(page=_build_mock_page())
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]
    from gui.chat_view import ChatView

    chat_view = ChatView(state)
    chat_view.build()
    sample = tmp_path / "received.bin"
    sample.write_bytes(b"x" * 16)

    chat_view._append_chat_entry(  # type: ignore[attr-defined]
        "peer",
        f"📎 {sample.name} (16 B)",
        file_path=sample,
    )
    last_entry: ChatEntry = chat_view._chat_entries[-1]  # type: ignore[attr-defined]
    assert last_entry.file_path == sample


def test_render_chat_entry_attaches_on_click_for_file_bubbles(
    tmp_path: Path,
) -> None:
    """File-attachment bubbles render with on_click + ink so they're tappable.

    Non-file bubbles must not have on_click set, otherwise plain text
    messages would surface a stray ripple effect.
    """
    import datetime as _dt

    state = AppState(page=_build_mock_page())
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]
    from gui.chat_view import ChatView

    chat_view = ChatView(state)
    chat_view.build()

    plain_entry = ChatEntry(
        timestamp=_dt.datetime.now(), sender="self", text="just text"
    )
    plain_row = chat_view._render_chat_entry(plain_entry)  # type: ignore[attr-defined]
    plain_container = plain_row.controls[0]  # type: ignore[attr-defined]
    assert plain_container.on_click is None
    assert plain_container.ink is False

    sample = tmp_path / "att.json"
    sample.write_text("{}")
    file_entry = ChatEntry(
        timestamp=_dt.datetime.now(),
        sender="peer",
        text=f"📎 {sample.name} (2 B)",
        file_path=sample,
    )
    file_row = chat_view._render_chat_entry(file_entry)  # type: ignore[attr-defined]
    file_container = file_row.controls[0]  # type: ignore[attr-defined]
    assert callable(file_container.on_click)
    assert file_container.ink is True
    assert file_container.tooltip is not None


def test_show_file_options_dialog_attaches_dialog_to_page(
    tmp_path: Path,
) -> None:
    """_show_file_options_dialog hands an AlertDialog to page.show_dialog."""
    state = AppState(page=_build_mock_page())
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]
    from gui.chat_view import ChatView

    chat_view = ChatView(state)
    chat_view.build()
    sample = tmp_path / "att.json"
    sample.write_text("{}")
    chat_view._show_file_options_dialog(sample)  # type: ignore[attr-defined]
    state.page.show_dialog.assert_called_once()  # type: ignore[attr-defined]
    dialog_arg = state.page.show_dialog.call_args.args[0]  # type: ignore[attr-defined]
    assert isinstance(dialog_arg, flet.AlertDialog)
    # Three primary actions + Close = four buttons.
    assert len(dialog_arg.actions) == 4


def test_render_view_calls_page_update_exactly_once() -> None:
    fake_page = _build_mock_page()
    update_calls: list[str] = []
    fake_page.update = lambda: update_calls.append("update")

    state = AppState(page=fake_page)
    state.render_view(build_connection_view)

    assert update_calls == ["update"]
    assert len(fake_page.controls) == 1


def test_connection_view_does_not_mutate_page_overlay() -> None:
    """The shared FilePicker is registered by gui.main.main, not by the views."""
    fake_page = _build_mock_page()
    state = AppState(page=fake_page)

    build_connection_view(state)
    # The connection view must not append its own FilePicker -- mobile
    # platforms reject pickers added to the overlay after the first
    # ``page.update()``. The single shared instance lives on
    # ``AppState.shared_file_picker``, registered by ``gui.main.main``.
    assert fake_page.overlay == []


def test_chat_view_does_not_mutate_page_overlay() -> None:
    fake_page = _build_mock_page()
    state = AppState(page=fake_page)
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]

    build_chat_view(state)
    assert fake_page.overlay == []


def test_app_state_carries_shared_file_picker_when_provided() -> None:
    fake_page = _build_mock_page()
    shared_file_picker = flet.FilePicker()
    state = AppState(page=fake_page, shared_file_picker=shared_file_picker)
    assert state.shared_file_picker is shared_file_picker


def test_app_state_identities_directory_is_none_by_default() -> None:
    state = AppState(page=_build_mock_page())
    assert state.identities_directory is None


async def test_generate_identity_creates_key_files_and_updates_state(
    tmp_path: Path,
) -> None:
    """Clicking 'Generate New Identity' writes two JSON files and updates AppState."""
    from gui.connection_view import ConnectionView

    fake_page = _build_mock_page()
    state = AppState(page=fake_page, identities_directory=tmp_path)
    view = ConnectionView(state)
    view.build()

    await view._handle_generate_identity_click(MagicMock())  # type: ignore[attr-defined]

    private_files = sorted(tmp_path.glob("private_*.json"))
    public_files = sorted(tmp_path.glob("public_*.json"))
    assert len(private_files) == 1, "Expected exactly one private key file"
    assert len(public_files) == 1, "Expected exactly one public key file"
    assert state.own_private_key_path == private_files[0]


async def test_generate_identity_called_twice_produces_distinct_files(
    tmp_path: Path,
) -> None:
    """Each invocation creates a uniquely named key pair (numeric suffix on collision)."""
    from gui.connection_view import ConnectionView

    fake_page = _build_mock_page()
    state = AppState(page=fake_page, identities_directory=tmp_path)
    view = ConnectionView(state)
    view.build()

    await view._handle_generate_identity_click(MagicMock())  # type: ignore[attr-defined]
    await view._handle_generate_identity_click(MagicMock())  # type: ignore[attr-defined]

    assert len(list(tmp_path.glob("private_*.json"))) == 2
    assert len(list(tmp_path.glob("public_*.json"))) == 2


async def test_generate_identity_auto_selects_in_dropdown(
    tmp_path: Path,
) -> None:
    """After generation the saved-keys dropdown value matches the new key path."""
    from gui.connection_view import ConnectionView

    fake_page = _build_mock_page()
    state = AppState(page=fake_page, identities_directory=tmp_path)
    view = ConnectionView(state)
    view.build()

    await view._handle_generate_identity_click(MagicMock())  # type: ignore[attr-defined]

    private_files = sorted(tmp_path.glob("private_*.json"))
    assert view._saved_keys_dropdown.value == str(private_files[0])  # type: ignore[attr-defined]


async def test_key_history_populated_for_existing_files(
    tmp_path: Path,
) -> None:
    """_populate_key_history fills the dropdown from an existing identities dir."""
    from gui.connection_view import ConnectionView

    fake_page = _build_mock_page()
    state = AppState(page=fake_page, identities_directory=tmp_path)
    view = ConnectionView(state)
    view.build()

    # Pre-create two key files directly (simulating a previous session).
    await view._handle_generate_identity_click(MagicMock())  # type: ignore[attr-defined]
    await view._handle_generate_identity_click(MagicMock())  # type: ignore[attr-defined]

    assert len(view._saved_keys_dropdown.options) == 2  # type: ignore[attr-defined]


def test_handle_key_selected_updates_state_and_path_text(
    tmp_path: Path,
) -> None:
    """Selecting an item from the dropdown updates AppState and the path label."""
    import asyncio

    from gui.connection_view import ConnectionView

    fake_page = _build_mock_page()
    state = AppState(page=fake_page, identities_directory=tmp_path)
    view = ConnectionView(state)
    view.build()

    # Generate one key so the file exists.
    asyncio.run(view._handle_generate_identity_click(MagicMock()))  # type: ignore[attr-defined]
    private_files = sorted(tmp_path.glob("private_*.json"))
    assert private_files

    # Simulate a dropdown change event.
    state.own_private_key_path = None  # reset
    fake_event = MagicMock()
    fake_event.data = str(private_files[0])
    view._handle_key_selected(fake_event)  # type: ignore[attr-defined]

    assert state.own_private_key_path == private_files[0]


def test_render_view_keeps_current_view_when_builder_raises() -> None:
    """Regression: render_view must not blank the page if the builder throws.

    Before the fix, ``render_view`` cleared the page first, then called
    the builder. A builder failure (e.g. ``ChatView`` rejecting a
    missing connection) left the page empty — the "gray screen" bug
    seen on Android after a botched chat-view transition. The fixed
    implementation builds first and only swaps controls if the build
    succeeded.
    """
    fake_page = _build_mock_page()
    state = AppState(page=fake_page)
    state.render_view(build_connection_view)
    assert len(fake_page.controls) == 1
    placeholder_root = fake_page.controls[0]

    def deliberately_failing_builder(_state: AppState) -> flet.Control:
        raise RuntimeError("boom — builder under test")

    with pytest.raises(RuntimeError, match="boom"):
        state.render_view(deliberately_failing_builder)

    # Critical assertion — the original view must still be mounted.
    assert len(fake_page.controls) == 1
    assert fake_page.controls[0] is placeholder_root


def test_connection_view_cancel_button_is_hidden_until_in_progress() -> None:
    """The Cancel button only appears once a connect/listen attempt starts."""
    from gui.connection_view import ConnectionView

    state = AppState(page=_build_mock_page())
    view = ConnectionView(state)
    view.build()

    assert view._cancel_button.visible is False  # type: ignore[attr-defined]
    assert view._primary_action_button.disabled is False  # type: ignore[attr-defined]

    view._set_in_progress(True)  # type: ignore[attr-defined]
    assert view._cancel_button.visible is True  # type: ignore[attr-defined]
    assert view._primary_action_button.disabled is True  # type: ignore[attr-defined]
    assert view._progress_indicator.visible is True  # type: ignore[attr-defined]

    view._set_in_progress(False)  # type: ignore[attr-defined]
    assert view._cancel_button.visible is False  # type: ignore[attr-defined]
    assert view._primary_action_button.disabled is False  # type: ignore[attr-defined]
    assert view._progress_indicator.visible is False  # type: ignore[attr-defined]


async def test_cancel_click_aborts_pending_action_task_and_resets_ui() -> None:
    """_handle_cancel_click cancels the in-flight task and the awaiter cleans up.

    Simulates the full cancellation flow without standing up a real
    socket: a long-sleep coroutine stands in for the real connect /
    listen call so we can verify that pressing Cancel:

    1. cancels the pending task,
    2. lets the awaiter observe the CancelledError,
    3. flips the UI back to its idle state (Cancel hidden, primary
       action re-enabled, status text reads "Cancelled.").
    """
    import asyncio

    from gui.connection_view import ConnectionView

    state = AppState(page=_build_mock_page())
    view = ConnectionView(state)
    view.build()

    async def fake_long_running_action() -> None:
        await asyncio.sleep(60)

    view._set_in_progress(True)  # type: ignore[attr-defined]
    view._pending_action_task = asyncio.create_task(  # type: ignore[attr-defined]
        fake_long_running_action()
    )

    # Run the awaiter side of _handle_primary_action_click in parallel.
    async def awaiter_side() -> None:
        try:
            await view._pending_action_task  # type: ignore[attr-defined]
        except asyncio.CancelledError:
            view._show_status("Cancelled.", error=False)  # type: ignore[attr-defined]
            view._set_in_progress(False)  # type: ignore[attr-defined]

    awaiter_task = asyncio.create_task(awaiter_side())
    await asyncio.sleep(0)  # let the awaiter actually start awaiting

    # User clicks Cancel.
    view._handle_cancel_click(MagicMock())  # type: ignore[attr-defined]
    await asyncio.wait_for(awaiter_task, timeout=2.0)

    assert view._in_progress is False  # type: ignore[attr-defined]
    assert view._cancel_button.visible is False  # type: ignore[attr-defined]
    assert view._primary_action_button.disabled is False  # type: ignore[attr-defined]
    assert view._status_text.value == "Cancelled."  # type: ignore[attr-defined]


def test_cancel_click_is_a_noop_when_no_action_is_pending() -> None:
    """Pressing Cancel with nothing in flight must not raise."""
    from gui.connection_view import ConnectionView

    state = AppState(page=_build_mock_page())
    view = ConnectionView(state)
    view.build()

    # Pre-condition: nothing pending.
    assert view._pending_action_task is None  # type: ignore[attr-defined]

    # Should not raise.
    view._handle_cancel_click(MagicMock())  # type: ignore[attr-defined]


def test_chat_view_build_does_not_call_page_update_before_mount() -> None:
    """Regression: ChatView.build() must not call page.update() during construction.

    The previous implementation called ``_append_system_log_entry`` for
    each of the three seed log entries; ``_append_system_log_entry``
    calls ``_safely_update_page``. On Flet 0.84 / Android this
    triggered ``page.update()`` against a control tree that did **not**
    yet contain ChatView's logs_listview (because ``render_view``
    appends the new root only after the builder returns). The Android
    runtime appears to handle that race by leaving the page on the
    *previous* view, which is exactly what the user reported: the
    "Connection established" status was visible but the chat view never
    appeared.

    Pinning this contract: build() should fully populate the in-memory
    caches and child controls but leave the single ``page.update()``
    call to the caller (``render_view``).
    """
    fake_page = _build_mock_page()
    update_calls: list[str] = []
    fake_page.update = lambda: update_calls.append("update")
    state = AppState(page=fake_page)
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]

    root = build_chat_view(state)
    assert isinstance(root, flet.Control)
    assert update_calls == [], (
        f"build() called page.update() {len(update_calls)} time(s) before "
        f"the new view was mounted — this regresses the Android no-chat-view bug."
    )


def test_chat_view_build_seeds_initial_logs_into_listview_controls() -> None:
    """Seed log entries must be present in the listview even though
    build() doesn't call page.update() during construction."""
    state = AppState(page=_build_mock_page())
    state.secure_connection = _build_mock_secure_connection()  # type: ignore[assignment]
    from gui.chat_view import ChatView

    chat_view = ChatView(state)
    chat_view.build()
    assert len(chat_view._system_log_entries) >= 3  # type: ignore[attr-defined]
    assert len(chat_view._logs_listview.controls) >= 3  # type: ignore[attr-defined]


def test_validate_pasted_peer_key_accepts_correct_schema() -> None:
    import json as _json

    from gui.connection_view import ConnectionView

    valid_json = _json.dumps(
        {
            "version": 1,
            "curve": "DSTU4145_M163_PB",
            "x_coordinate_hex": "deadbeef",
            "y_coordinate_hex": "cafebabe",
        }
    )
    assert ConnectionView._validate_pasted_peer_key("alice", valid_json) is None  # type: ignore[attr-defined]


def test_validate_pasted_peer_key_rejects_empty_name() -> None:
    from gui.connection_view import ConnectionView

    error = ConnectionView._validate_pasted_peer_key("", '{"version": 1}')  # type: ignore[attr-defined]
    assert error is not None
    assert "name" in error.lower()


def test_validate_pasted_peer_key_rejects_invalid_json() -> None:
    from gui.connection_view import ConnectionView

    error = ConnectionView._validate_pasted_peer_key("alice", "not json {")  # type: ignore[attr-defined]
    assert error is not None
    assert "JSON" in error


def test_validate_pasted_peer_key_lists_missing_fields() -> None:
    from gui.connection_view import ConnectionView

    error = ConnectionView._validate_pasted_peer_key(  # type: ignore[attr-defined]
        "alice",
        '{"version": 1, "curve": "DSTU4145_M163_PB"}',
    )
    assert error is not None
    assert "x_coordinate_hex" in error
    assert "y_coordinate_hex" in error


def test_sanitize_identity_name_strips_filesystem_hostile_chars() -> None:
    from gui.connection_view import ConnectionView

    sanitize = ConnectionView._sanitize_identity_name  # type: ignore[attr-defined]
    assert sanitize("alice/2024") == "alice_2024"
    assert sanitize("../etc/passwd") == "___etc_passwd"
    assert sanitize("") == "peer"
    assert sanitize("   ") == "peer"
    assert sanitize("hi-there_42") == "hi-there_42"


def test_paste_peer_key_button_disables_during_action() -> None:
    from gui.connection_view import ConnectionView

    state = AppState(page=_build_mock_page())
    view = ConnectionView(state)
    view.build()
    assert view._paste_peer_key_button.disabled is False  # type: ignore[attr-defined]

    view._set_in_progress(True)  # type: ignore[attr-defined]
    assert view._paste_peer_key_button.disabled is True  # type: ignore[attr-defined]

    view._set_in_progress(False)  # type: ignore[attr-defined]
    assert view._paste_peer_key_button.disabled is False  # type: ignore[attr-defined]


def test_register_shared_file_picker_uses_page_services_not_overlay() -> None:
    """Regression test for the "Unknown control: FilePicker" red banner.

    In Flet 0.84 ``FilePicker`` is a ``Service``, not a visual
    ``Control``. Putting one on ``page.overlay`` makes the front-end
    render it as a fallback red rectangle. The fix is to register the
    picker on ``page.services`` --- and this test pins that behaviour
    so an accidental revert to the overlay-based registration is
    caught locally rather than only at runtime on the macOS / Android
    bundles.
    """
    from gui.main import _register_shared_file_picker

    fake_page = _build_mock_page()
    picker = _register_shared_file_picker(fake_page)

    assert isinstance(picker, flet.FilePicker)
    # Picker must NOT have leaked into the overlay --- that is what
    # produced the "Unknown control" banner in the diploma demo.
    assert fake_page.overlay == []
    # Picker MUST have been registered with the services registry.
    assert picker in fake_page.services._services  # type: ignore[attr-defined]
