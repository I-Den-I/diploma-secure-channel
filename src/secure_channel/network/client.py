# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Client-side TCP entry point for the secure channel."""

from __future__ import annotations

from typing import Final

from secure_channel.network.connection import SecureChannelConnection
from secure_channel.network.framing import DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH
from secure_channel.network.handshake_io import (
    perform_initiator_handshake_over_stream,
)
from secure_channel.session.clock import (
    MICROSECOND_WALL_CLOCK,
    MicrosecondClock,
)
from secure_channel.session.handshake import HandshakeIdentityCredentials
from secure_channel.session.key_exchange import RandomBytesProvider
from secure_channel.session.records import FreshnessPolicy

import asyncio


async def connect_secure_channel(
    *,
    host: str,
    port: int,
    credentials: HandshakeIdentityCredentials,
    random_bytes: RandomBytesProvider | None = None,
    sending_clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
    freshness_policy: FreshnessPolicy | None = None,
    maximum_record_byte_length: int = DEFAULT_MAXIMUM_FRAME_BYTE_LENGTH,
) -> SecureChannelConnection:
    """Open a TCP connection and perform the SIGMA handshake as initiator.

    :param host: Hostname or IP address of the secure-channel server.
    :param port: TCP port on which the secure-channel server listens.
    :param credentials: Initiator's long-term identity credentials.
        Must include the responder's authentic long-term public key.
    :param random_bytes: Source of cryptographic randomness.
    :param sending_clock: Wall-clock provider used to stamp outgoing
        records of the resulting :class:`SecureChannelConnection`.
    :param freshness_policy: Receiver-side freshness and replay-window
        configuration for incoming records.
    :param maximum_record_byte_length: Hard cap on incoming and outgoing
        encrypted record sizes.
    :returns: A fully initialised :class:`SecureChannelConnection`.
    """
    stream_reader, stream_writer = await asyncio.open_connection(host, port)
    try:
        return await perform_initiator_handshake_over_stream(
            stream_reader=stream_reader,
            stream_writer=stream_writer,
            credentials=credentials,
            random_bytes=random_bytes,
            sending_clock=sending_clock,
            freshness_policy=freshness_policy,
            maximum_record_byte_length=maximum_record_byte_length,
        )
    except BaseException:
        # If the handshake fails for any reason, drop the underlying
        # socket immediately so that the OS resource is reclaimed.
        stream_writer.close()
        try:
            await stream_writer.wait_closed()
        except (ConnectionError, OSError):
            pass
        raise


__all__: Final[list[str]] = ["connect_secure_channel"]
