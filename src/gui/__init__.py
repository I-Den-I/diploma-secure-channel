# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Flet-based graphical user interface for the secure channel.

The :mod:`gui` package provides a desktop-style front-end built on top
of `Flet <https://flet.dev>`_. It does not implement any cryptographic
logic of its own; every operation goes through the existing
:mod:`secure_channel` modules.

Layout
------

* :mod:`gui.main` --- application entry point. Sets the page title,
  theme, and dispatches to the connection view first.
* :mod:`gui.app_state` --- mutable runtime state shared between views
  (active page, established :class:`SecureChannelConnection`, etc.).
* :mod:`gui.connection_view` --- pre-handshake screen: identity file
  pickers, mode toggle (server / client), host & port inputs, and the
  primary "Listen" / "Connect" button.
* :mod:`gui.chat_view` --- placeholder post-handshake screen.

Phase 6 covers the foundation only: app shell, connection view,
async handshake, and the placeholder chat. Phase 7 will replace the
placeholder with the full chat & file-transfer interface.
"""

from __future__ import annotations
