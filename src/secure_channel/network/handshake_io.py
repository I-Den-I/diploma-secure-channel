# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Run the SIGMA handshake over an asyncio TCP stream pair.

The handshake protocol implemented in
:mod:`secure_channel.session.handshake` is transport-agnostic: it
operates on byte strings and exposes pending-state objects whose
methods consume and produce the next message of the conversation. This
module wraps the three exchange steps in
:class:`asyncio.StreamReader` / :class:`asyncio.StreamWriter` calls and
returns a fully initialised :class:`SecureChannelConnection` at the end.

Both the *initiator* and the *responder* helpers cap the size of any
single inbound handshake frame to defend against memory-exhaustion
attacks.
"""

from __future__ import annotations

import asyncio
from typing import Final

from secure_channel.network.connection import SecureChannelConnection
from secure_channel.network.framing import (
    DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
    read_length_prefixed_frame,
    write_length_prefixed_frame,
)
from secure_channel.session.clock import (
    MICROSECOND_WALL_CLOCK,
    MicrosecondClock,
)
from secure_channel.session.handshake import (
    HandshakeIdentityCredentials,
    initiate_handshake,
    respond_to_handshake,
)
from secure_channel.session.key_exchange import RandomBytesProvider
from secure_channel.session.records import FreshnessPolicy


_MAXIMUM_HANDSHAKE_FRAME_BYTE_LENGTH: Final[int] = 64 * 1024
"""Per-message ceiling for the handshake (64 KiB is far above the 1 KiB needed)."""


async def perform_initiator_handshake_over_stream(
    *,
    stream_reader: asyncio.StreamReader,
    stream_writer: asyncio.StreamWriter,
    credentials: HandshakeIdentityCredentials,
    random_bytes: RandomBytesProvider | None = None,
    sending_clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
    freshness_policy: FreshnessPolicy | None = None,
    maximum_record_byte_length: int = DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
) -> SecureChannelConnection:
    """Run the three-message SIGMA handshake from the initiator side.

    :param stream_reader: Asyncio reader bound to the responder.
    :param stream_writer: Asyncio writer bound to the responder.
    :param credentials: Initiator's long-term identity credentials.
    :param random_bytes: Source of cryptographic randomness.
    :param sending_clock: Wall-clock provider used to stamp outgoing
        records of the resulting :class:`SecureChannelConnection`.
    :param freshness_policy: Receiver-side freshness and replay-window
        configuration for incoming records.
    :param maximum_record_byte_length: Hard cap on subsequent encrypted
        records. Does *not* affect the handshake messages themselves,
        which are bounded by a much smaller constant.
    :returns: A fully initialised :class:`SecureChannelConnection`.
    """
    pending_initiator = initiate_handshake(
        credentials,
        random_bytes=random_bytes,
        sending_clock=sending_clock,
        freshness_policy=freshness_policy,
    )
    await write_length_prefixed_frame(
        stream_writer,
        pending_initiator.message_one_bytes,
        maximum_frame_byte_length=_MAXIMUM_HANDSHAKE_FRAME_BYTE_LENGTH,
    )
    message_two_bytes: bytes = await read_length_prefixed_frame(
        stream_reader,
        maximum_frame_byte_length=_MAXIMUM_HANDSHAKE_FRAME_BYTE_LENGTH,
    )
    message_three_bytes, secure_session = pending_initiator.consume_message_two(
        message_two_bytes
    )
    await write_length_prefixed_frame(
        stream_writer,
        message_three_bytes,
        maximum_frame_byte_length=_MAXIMUM_HANDSHAKE_FRAME_BYTE_LENGTH,
    )
    return SecureChannelConnection(
        secure_session=secure_session,
        stream_reader=stream_reader,
        stream_writer=stream_writer,
        maximum_frame_byte_length=maximum_record_byte_length,
    )


async def perform_responder_handshake_over_stream(
    *,
    stream_reader: asyncio.StreamReader,
    stream_writer: asyncio.StreamWriter,
    credentials: HandshakeIdentityCredentials,
    random_bytes: RandomBytesProvider | None = None,
    sending_clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
    freshness_policy: FreshnessPolicy | None = None,
    maximum_record_byte_length: int = DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
) -> SecureChannelConnection:
    """Run the three-message SIGMA handshake from the responder side.

    :param stream_reader: Asyncio reader bound to the initiator.
    :param stream_writer: Asyncio writer bound to the initiator.
    :param credentials: Responder's long-term identity credentials.
    :param random_bytes: Source of cryptographic randomness.
    :param sending_clock: Wall-clock provider used to stamp outgoing
        records of the resulting :class:`SecureChannelConnection`.
    :param freshness_policy: Receiver-side freshness and replay-window
        configuration for incoming records.
    :param maximum_record_byte_length: Hard cap on subsequent encrypted
        records.
    :returns: A fully initialised :class:`SecureChannelConnection`.
    """
    message_one_bytes: bytes = await read_length_prefixed_frame(
        stream_reader,
        maximum_frame_byte_length=_MAXIMUM_HANDSHAKE_FRAME_BYTE_LENGTH,
    )
    pending_responder = respond_to_handshake(
        credentials,
        message_one_bytes,
        random_bytes=random_bytes,
        sending_clock=sending_clock,
        freshness_policy=freshness_policy,
    )
    await write_length_prefixed_frame(
        stream_writer,
        pending_responder.message_two_bytes,
        maximum_frame_byte_length=_MAXIMUM_HANDSHAKE_FRAME_BYTE_LENGTH,
    )
    message_three_bytes: bytes = await read_length_prefixed_frame(
        stream_reader,
        maximum_frame_byte_length=_MAXIMUM_HANDSHAKE_FRAME_BYTE_LENGTH,
    )
    secure_session = pending_responder.consume_message_three(message_three_bytes)
    return SecureChannelConnection(
        secure_session=secure_session,
        stream_reader=stream_reader,
        stream_writer=stream_writer,
        maximum_frame_byte_length=maximum_record_byte_length,
    )


__all__: Final[list[str]] = [
    "perform_initiator_handshake_over_stream",
    "perform_responder_handshake_over_stream",
]
