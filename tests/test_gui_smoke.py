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
    assert state.download_directory.parts[-2:] == ("DSTU-SecureChannel", "received")


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
