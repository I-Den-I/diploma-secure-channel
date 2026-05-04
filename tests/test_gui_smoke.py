# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Smoke tests for the Flet GUI shell.

These tests are intentionally lightweight: they construct each view
with a mocked :class:`flet.Page` and assert that the resulting control
tree is a non-``None`` :class:`flet.Control`. The goal is to catch
import-time errors and constructor-signature regressions across Flet
point releases without spinning up an actual desktop window.

Heavier visual integration tests (clicking buttons, completing a real
SIGMA handshake from the GUI, ...) are out of scope for Phase 6 and
will be covered by Phase 7 once the chat interface is in place.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

flet = pytest.importorskip("flet")

from gui.app_state import AppState  # noqa: E402  -- import after pytest.importorskip
from gui.chat_view import build_chat_view  # noqa: E402
from gui.connection_view import build_connection_view  # noqa: E402


def _build_mock_page() -> object:
    """Create a fake :class:`flet.Page` with the attributes the views use."""
    fake_page = MagicMock(spec=flet.Page)
    fake_page.controls = []
    fake_page.overlay = []
    fake_page.update = lambda: None
    return fake_page


def test_app_state_holds_the_page() -> None:
    fake_page = _build_mock_page()
    state = AppState(page=fake_page)
    assert state.page is fake_page
    assert state.secure_connection is None
    assert state.secure_server is None
    assert state.own_private_key_path is None
    assert state.peer_public_key_path is None


def test_connection_view_root_is_a_flet_control() -> None:
    state = AppState(page=_build_mock_page())
    root = build_connection_view(state)
    assert isinstance(root, flet.Control)


def test_chat_view_root_is_a_flet_control() -> None:
    state = AppState(page=_build_mock_page())
    root = build_chat_view(state)
    assert isinstance(root, flet.Control)


def test_render_view_calls_page_update_exactly_once() -> None:
    fake_page = _build_mock_page()
    update_calls: list[str] = []
    fake_page.update = lambda: update_calls.append("update")

    state = AppState(page=fake_page)
    state.render_view(build_connection_view)

    assert update_calls == ["update"]
    assert len(fake_page.controls) == 1


def test_connection_view_attaches_file_pickers_to_overlay() -> None:
    fake_page = _build_mock_page()
    state = AppState(page=fake_page)

    build_connection_view(state)
    # Two FilePicker controls land on the page overlay (one per slot).
    assert len(fake_page.overlay) == 2
