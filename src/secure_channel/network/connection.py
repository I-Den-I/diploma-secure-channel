# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Bidirectional message-oriented secure connection.

A :class:`SecureChannelConnection` ties together:

* an asyncio (:class:`asyncio.StreamReader`,
  :class:`asyncio.StreamWriter`) pair, which provides the underlying
  TCP transport;
* a :class:`secure_channel.session.SecureSession`, which provides
  authenticated encryption with strict freshness and replay
  protection;
* a small message multiplexer
  (:mod:`secure_channel.network.messages`), which stamps every
  encrypted record with a one-byte application tag so that text
  messages and file-transfer chunks can be distinguished by the
  receiver.

The class is intentionally low-level: it deals in
:class:`ApplicationMessage` instances rather than file-transfer
operations or chat-style higher-order primitives. The chunked file
transfer logic in :mod:`secure_channel.network.file_transfer` is
layered on top, and never accesses the underlying stream directly.
"""

from __future__ import annotations

import asyncio
from typing import Final

from secure_channel.crypto.kalyna_aead import AuthenticationFailed
from secure_channel.network.framing import (
    DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
    ConnectionClosedDuringRead,
    read_length_prefixed_frame,
    write_length_prefixed_frame,
)
from secure_channel.network.messages import (
    ApplicationMessage,
    decode_application_message,
)
from secure_channel.session.secure_session import SecureSession


class SecureChannelConnectionClosed(Exception):
    """Raised when an attempt is made to use a connection that has been closed.

    Also raised by :meth:`SecureChannelConnection.receive_message` when
    the peer closes the stream cleanly between two complete frames.
    Application code uses this exception to terminate read loops.
    """


class SecureChannelConnection:
    """Encrypted, message-oriented wrapper around an asyncio stream pair.

    :param secure_session: Fully initialised post-handshake session.
    :param stream_reader: Asyncio reader bound to the peer.
    :param stream_writer: Asyncio writer bound to the peer.
    :param maximum_frame_byte_length: Hard cap on the size of any single
        encrypted record (the ceiling protects the receiver from
        memory-exhaustion attacks).
    """

    __slots__ = (
        "_secure_session",
        "_stream_reader",
        "_stream_writer",
        "_maximum_frame_byte_length",
        "_is_closed",
        "_send_lock",
        "_receive_lock",
    )

    def __init__(
        self,
        secure_session: SecureSession,
        stream_reader: asyncio.StreamReader,
        stream_writer: asyncio.StreamWriter,
        *,
        maximum_frame_byte_length: int = DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
    ) -> None:
        self._secure_session: Final[SecureSession] = secure_session
        self._stream_reader: Final[asyncio.StreamReader] = stream_reader
        self._stream_writer: Final[asyncio.StreamWriter] = stream_writer
        self._maximum_frame_byte_length: Final[int] = maximum_frame_byte_length
        self._is_closed: bool = False
        self._send_lock: Final[asyncio.Lock] = asyncio.Lock()
        self._receive_lock: Final[asyncio.Lock] = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def is_closed(self) -> bool:
        """Whether the connection has been closed locally."""
        return self._is_closed

    @property
    def secure_session(self) -> SecureSession:
        """Read-only access to the underlying session for inspection in tests."""
        return self._secure_session

    @property
    def peer_address(self) -> object:
        """Best-effort socket-level peer address for diagnostics."""
        return self._stream_writer.get_extra_info("peername")

    async def close(self) -> None:
        """Close the underlying transport. Idempotent."""
        if self._is_closed:
            return
        self._is_closed = True
        try:
            self._stream_writer.close()
            await self._stream_writer.wait_closed()
        except (ConnectionError, OSError):
            # The peer might have torn down the socket already; silence
            # secondary errors so that close() remains best-effort.
            pass

    async def __aenter__(self) -> "SecureChannelConnection":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------

    async def send_message(self, message: ApplicationMessage) -> None:
        """Encrypt and transmit a single application-layer message.

        :raises SecureChannelConnectionClosed: If the connection has
            been closed locally.
        """
        if self._is_closed:
            raise SecureChannelConnectionClosed("Connection has already been closed.")
        plaintext_record: bytes = message.to_record_bytes()
        async with self._send_lock:
            sealed_record: bytes = self._secure_session.encrypt_outgoing_record(
                plaintext_record
            )
            await write_length_prefixed_frame(
                self._stream_writer,
                sealed_record,
                maximum_frame_byte_length=self._maximum_frame_byte_length,
            )

    # ------------------------------------------------------------------
    # Receiving
    # ------------------------------------------------------------------

    async def receive_message(self) -> ApplicationMessage:
        """Read, authenticate, decrypt and decode a single message.

        :raises SecureChannelConnectionClosed: If the peer has closed
            the stream cleanly between two complete frames, or if the
            connection has been closed locally.
        :raises AuthenticationFailed: If the AEAD verification fails
            (also raised for sequence-number / timestamp policy
            violations, since those derived classes inherit from
            :class:`AuthenticationFailed`).
        """
        if self._is_closed:
            raise SecureChannelConnectionClosed("Connection has already been closed.")
        async with self._receive_lock:
            try:
                sealed_record: bytes = await read_length_prefixed_frame(
                    self._stream_reader,
                    maximum_frame_byte_length=self._maximum_frame_byte_length,
                )
            except asyncio.IncompleteReadError as eof_error:
                # Peer closed the stream cleanly at a frame boundary;
                # surface it as a typed connection-closed signal.
                raise SecureChannelConnectionClosed(
                    "Peer closed the stream at a frame boundary."
                ) from eof_error
            except ConnectionClosedDuringRead:
                raise
        plaintext_record: bytes = self._secure_session.decrypt_incoming_record(
            sealed_record
        )
        return decode_application_message(plaintext_record)


__all__: Final[list[str]] = [
    "AuthenticationFailed",
    "SecureChannelConnection",
    "SecureChannelConnectionClosed",
]
