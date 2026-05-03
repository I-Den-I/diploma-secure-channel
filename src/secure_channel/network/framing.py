# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Length-prefix framing helpers for asyncio TCP streams.

TCP delivers an ordered byte stream with no inherent message boundaries;
to recover discrete protocol units we prepend each payload with an
unsigned 32-bit big-endian length prefix. The two helpers in this
module --- :func:`write_length_prefixed_frame` and
:func:`read_length_prefixed_frame` --- are the only routines in the
network package that touch raw bytes on the wire.

A configurable *maximum frame size* prevents a malicious or buggy peer
from forcing the receiver to allocate arbitrarily large buffers; the
default cap of 16 MiB comfortably accommodates the post-handshake
records and the per-chunk payloads of the file transfer module while
still being orders of magnitude smaller than any realistic memory
footprint.
"""

from __future__ import annotations

import asyncio
from typing import Final


_LENGTH_PREFIX_BYTE_LENGTH: Final[int] = 4
"""Width of the length prefix, in bytes (uint32 big-endian)."""

DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH: Final[int] = 16 * 1024 * 1024
"""Default ceiling on a single frame's payload size (16 MiB)."""


class FrameTooLarge(Exception):
    """Raised when an inbound frame exceeds the configured size cap.

    The exception is the network layer's primary defence against
    memory-exhaustion attacks. The protocol layer never legitimately
    sends frames close to the cap, so this signal can be treated as a
    fatal protocol violation.
    """


class ConnectionClosedDuringRead(Exception):
    """Raised when the peer closes the stream mid-frame.

    Distinct from a successful EOF at a frame boundary, this exception
    indicates that the wire was cut while a frame was still being
    received. Application code typically reacts by tearing down the
    associated session.
    """


async def write_length_prefixed_frame(
    writer: asyncio.StreamWriter,
    payload: bytes,
    *,
    maximum_frame_byte_length: int = DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
) -> None:
    """Write a single length-prefixed frame to ``writer`` and flush it.

    :param writer: An asyncio stream writer connected to the peer.
    :param payload: Raw bytes to transmit. Must not exceed
        ``maximum_frame_byte_length``.
    :param maximum_frame_byte_length: Sender-side hard cap, mirrors the
        receiver's :func:`read_length_prefixed_frame` argument.
    :raises FrameTooLarge: If ``payload`` exceeds the cap.
    """
    if len(payload) > maximum_frame_byte_length:
        raise FrameTooLarge(
            f"Outbound frame of {len(payload)} bytes exceeds the "
            f"{maximum_frame_byte_length}-byte limit."
        )
    length_prefix: bytes = len(payload).to_bytes(
        _LENGTH_PREFIX_BYTE_LENGTH, "big"
    )
    writer.write(length_prefix + payload)
    await writer.drain()


async def read_length_prefixed_frame(
    reader: asyncio.StreamReader,
    *,
    maximum_frame_byte_length: int = DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
) -> bytes:
    """Read exactly one length-prefixed frame from ``reader``.

    :param reader: An asyncio stream reader connected to the peer.
    :param maximum_frame_byte_length: Hard cap on the announced frame
        length. Frames larger than this trigger :class:`FrameTooLarge`
        before any payload bytes are read.
    :returns: The decoded payload bytes.
    :raises asyncio.IncompleteReadError: If the stream reaches EOF
        cleanly at the very start of a new frame (i.e., between frames).
        Callers are expected to treat this as the orderly end of the
        peer's message stream.
    :raises ConnectionClosedDuringRead: If EOF is reached *after* the
        length prefix has been received but before the payload is
        complete.
    :raises FrameTooLarge: If the announced frame exceeds the cap.
    """
    length_prefix_bytes: bytes = await reader.readexactly(
        _LENGTH_PREFIX_BYTE_LENGTH
    )
    announced_payload_byte_length: int = int.from_bytes(length_prefix_bytes, "big")
    if announced_payload_byte_length > maximum_frame_byte_length:
        raise FrameTooLarge(
            f"Inbound frame announces {announced_payload_byte_length} bytes; "
            f"cap is {maximum_frame_byte_length}."
        )
    if announced_payload_byte_length == 0:
        return b""
    try:
        return await reader.readexactly(announced_payload_byte_length)
    except asyncio.IncompleteReadError as incomplete_read_error:
        raise ConnectionClosedDuringRead(
            "Peer closed the stream while a framed payload was still "
            f"being received ({len(incomplete_read_error.partial)} of "
            f"{announced_payload_byte_length} bytes received)."
        ) from incomplete_read_error
