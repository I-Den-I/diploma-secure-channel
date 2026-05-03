# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Asynchronous TCP transport for the secure channel.

This package layers the cryptographic session machinery from
:mod:`secure_channel.session` on top of :mod:`asyncio` streams, exposing
a small, application-friendly API:

* :func:`secure_channel.network.client.connect_secure_channel` --- open a
  TCP connection, perform the SIGMA handshake, and return a fully
  initialised :class:`SecureChannelConnection`.
* :class:`secure_channel.network.server.SecureChannelServer` --- accept
  inbound TCP connections, perform the responder side of the SIGMA
  handshake, and dispatch each authenticated session to a user-supplied
  coroutine.
* :class:`secure_channel.network.connection.SecureChannelConnection`
  --- bidirectional message-oriented wrapper around an asyncio stream
  pair plus a :class:`SecureSession`.
* :mod:`secure_channel.network.file_transfer` --- chunked,
  incremental-on-disk file send/receive that never holds a full file
  in memory.

The transport is *transport-typed* over TCP because TCP delivers an
ordered, reliable byte stream that matches the in-order replay-window
expectations enforced by the session layer; for UDP-style deployments
the same connection class can be reused if a length-prefixed datagram
framing is plugged in.
"""

from __future__ import annotations
