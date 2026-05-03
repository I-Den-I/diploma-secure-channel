# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""TCP secure-channel server.

The server listens on a configurable host/port pair, performs the
responder side of the SIGMA handshake on every accepted connection,
and dispatches the resulting :class:`SecureChannelConnection` to a
user-provided coroutine. Each connection runs in its own asyncio task
so the server processes peers concurrently.

If the handshake fails (signature mismatch, malformed message, ...)
the offending socket is closed silently. Authenticated connections
that survive the handshake are guaranteed to come from a peer holding
the long-term DSTU 4145 private key associated with the responder's
``credentials.peer_long_term_public_key``.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Final

from secure_channel.network.connection import SecureChannelConnection
from secure_channel.network.framing import DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH
from secure_channel.network.handshake_io import (
    perform_responder_handshake_over_stream,
)
from secure_channel.session.clock import (
    MICROSECOND_WALL_CLOCK,
    MicrosecondClock,
)
from secure_channel.session.handshake import (
    HandshakeError,
    HandshakeIdentityCredentials,
)
from secure_channel.session.key_exchange import RandomBytesProvider
from secure_channel.session.records import FreshnessPolicy


SecureConnectionHandler = Callable[[SecureChannelConnection], Awaitable[None]]
"""Coroutine accepting one fully authenticated connection."""


class SecureChannelServer:
    """Asynchronous server that accepts authenticated secure connections.

    Instantiate the class, then call :meth:`start` (typically inside an
    ``async with`` block via :meth:`__aenter__`). The server begins
    listening as soon as :meth:`start` returns and stops when
    :meth:`close` is awaited.

    :param credentials: Long-term identity credentials of the
        responder. Must include the initiator's authentic long-term
        public key.
    :param connection_handler: User-supplied coroutine invoked with one
        ``SecureChannelConnection`` per authenticated peer. The handler
        is run inside its own task and is expected to close the
        connection when it returns.
    :param random_bytes: Source of cryptographic randomness.
    :param sending_clock: Wall-clock provider used to stamp outgoing
        records.
    :param freshness_policy: Receiver-side freshness and replay-window
        configuration applied to incoming records.
    :param maximum_record_byte_length: Hard cap on encrypted record
        sizes.
    """

    __slots__ = (
        "_credentials",
        "_connection_handler",
        "_random_bytes",
        "_sending_clock",
        "_freshness_policy",
        "_maximum_record_byte_length",
        "_asyncio_server",
    )

    def __init__(
        self,
        *,
        credentials: HandshakeIdentityCredentials,
        connection_handler: SecureConnectionHandler,
        random_bytes: RandomBytesProvider | None = None,
        sending_clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
        freshness_policy: FreshnessPolicy | None = None,
        maximum_record_byte_length: int = DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
    ) -> None:
        self._credentials: Final[HandshakeIdentityCredentials] = credentials
        self._connection_handler: Final[SecureConnectionHandler] = connection_handler
        self._random_bytes: Final[RandomBytesProvider | None] = random_bytes
        self._sending_clock: Final[MicrosecondClock] = sending_clock
        self._freshness_policy: Final[FreshnessPolicy | None] = freshness_policy
        self._maximum_record_byte_length: Final[int] = maximum_record_byte_length
        self._asyncio_server: asyncio.base_events.Server | None = None

    async def start(self, host: str, port: int) -> None:
        """Begin listening on the supplied (host, port) pair.

        :param host: Bind address. Use ``"127.0.0.1"`` for tests or
            ``"0.0.0.0"`` to expose on every interface.
        :param port: TCP port. Pass ``0`` to let the OS pick a free port,
            then read it back via :attr:`bound_port`.
        """
        if self._asyncio_server is not None:
            raise RuntimeError("Server has already been started.")
        self._asyncio_server = await asyncio.start_server(
            self._handle_incoming_connection, host=host, port=port
        )

    @property
    def bound_port(self) -> int:
        """Concrete TCP port the server is listening on."""
        if self._asyncio_server is None:
            raise RuntimeError("Server is not started.")
        sockets = self._asyncio_server.sockets
        if not sockets:
            raise RuntimeError("Server has no bound sockets.")
        return int(sockets[0].getsockname()[1])

    async def close(self) -> None:
        """Stop accepting new connections and wait for shutdown."""
        if self._asyncio_server is None:
            return
        self._asyncio_server.close()
        await self._asyncio_server.wait_closed()
        self._asyncio_server = None

    async def __aenter__(self) -> "SecureChannelServer":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Internal: per-connection handler
    # ------------------------------------------------------------------

    async def _handle_incoming_connection(
        self,
        stream_reader: asyncio.StreamReader,
        stream_writer: asyncio.StreamWriter,
    ) -> None:
        """asyncio callback executed for every accepted TCP connection."""
        secure_channel_connection: SecureChannelConnection | None = None
        try:
            secure_channel_connection = (
                await perform_responder_handshake_over_stream(
                    stream_reader=stream_reader,
                    stream_writer=stream_writer,
                    credentials=self._credentials,
                    random_bytes=self._random_bytes,
                    sending_clock=self._sending_clock,
                    freshness_policy=self._freshness_policy,
                    maximum_record_byte_length=self._maximum_record_byte_length,
                )
            )
        except (HandshakeError, ValueError, asyncio.IncompleteReadError):
            # Failed handshakes are silently dropped; production code
            # may wish to log the peer address for forensics.
            stream_writer.close()
            try:
                await stream_writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            return

        try:
            await self._connection_handler(secure_channel_connection)
        finally:
            await secure_channel_connection.close()


__all__: Final[list[str]] = [
    "SecureChannelServer",
    "SecureConnectionHandler",
]
