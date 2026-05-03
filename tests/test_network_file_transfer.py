# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Async tests of the chunked file transfer module.

The headline test transmits a freshly generated multi-megabyte random
file from a client to a server over a real loopback TCP connection,
through the full DSTU 7624 + DSTU 4145 secure channel, and verifies
that the SHA-256 of the received bytes matches the original. Smaller
correctness tests round out the suite.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path

import pytest

from secure_channel.crypto.dstu4145 import (
    Dstu4145PrivateKey,
    Dstu4145SignatureScheme,
)
from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB
from secure_channel.network.client import connect_secure_channel
from secure_channel.network.connection import SecureChannelConnection
from secure_channel.network.file_transfer import (
    DEFAULT_FILE_TRANSFER_CHUNK_BYTE_LENGTH,
    FileTransferProtocolError,
    receive_file_over_secure_channel,
    send_file_over_secure_channel,
)
from secure_channel.network.messages import (
    FileTransferBegin,
    FileTransferChunk,
    FileTransferEnd,
)
from secure_channel.network.server import SecureChannelServer
from secure_channel.session.handshake import HandshakeIdentityCredentials
from secure_channel.session.records import FreshnessPolicy

# Pure-Python Kalyna throughput is on the order of 60 KiB/s, so even a
# 1 MiB file takes roughly 30 s of wall time per direction to enc/dec
# under the AEAD. To keep these tests reproducible regardless of the
# host CPU we widen the freshness window well beyond the production
# default of 30 s. In production the cipher would normally be backed by
# a C extension and the default 30 s window would be ample.
_TEST_FRESHNESS_TOLERANCE_MICROSECONDS: int = 30 * 60 * 1_000_000  # 30 minutes


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_long_term_keys() -> tuple[Dstu4145PrivateKey, Dstu4145PrivateKey]:
    scheme = Dstu4145SignatureScheme(DSTU4145_M163_PB)
    initiator_private_key, _ = scheme.generate_key_pair()
    responder_private_key, _ = scheme.generate_key_pair()
    return initiator_private_key, responder_private_key


def _credentials_for(
    own_private_key: Dstu4145PrivateKey, peer_private_key: Dstu4145PrivateKey
) -> HandshakeIdentityCredentials:
    return HandshakeIdentityCredentials(
        domain=DSTU4145_M163_PB,
        own_long_term_private_key=own_private_key,
        peer_long_term_public_key=peer_private_key.derive_public_key(),
    )


def _stream_sha256(file_path: Path) -> bytes:
    """Compute the SHA-256 of a file by reading it in 64 KiB chunks."""
    streaming_digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        while True:
            chunk_data: bytes = handle.read(64 * 1024)
            if not chunk_data:
                break
            streaming_digest.update(chunk_data)
    return streaming_digest.digest()


# ---------------------------------------------------------------------------
# Headline test: multi-MB random file over loopback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_large_random_file_round_trip_via_loopback_and_secure_channel(
    tmp_path: Path,
) -> None:
    """End-to-end: send a multi-MiB random file, verify SHA-256 on receive."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    # 1. Materialise a multi-MB random file. 1 MiB is enough to exercise
    #    several hundred chunks and a non-trivial number of CTR blocks
    #    while keeping pure-Python Kalyna runtime tractable.
    source_file_path: Path = tmp_path / "source.bin"
    file_byte_length: int = 1 * 1024 * 1024
    with source_file_path.open("wb") as handle:
        bytes_remaining: int = file_byte_length
        while bytes_remaining > 0:
            block_byte_length: int = min(64 * 1024, bytes_remaining)
            handle.write(os.urandom(block_byte_length))
            bytes_remaining -= block_byte_length
    expected_digest: bytes = _stream_sha256(source_file_path)

    destination_directory: Path = tmp_path / "received"
    destination_directory.mkdir()

    received_file_path_holder: list[Path] = []
    server_side_done = asyncio.Event()
    test_freshness_policy = FreshnessPolicy(
        timestamp_tolerance_microseconds=_TEST_FRESHNESS_TOLERANCE_MICROSECONDS,
    )

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        try:
            destination_file_path = await receive_file_over_secure_channel(
                connection=connection,
                destination_directory=destination_directory,
            )
            received_file_path_holder.append(destination_file_path)
        finally:
            server_side_done.set()

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
        freshness_policy=test_freshness_policy,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        async with await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
            freshness_policy=test_freshness_policy,
        ) as client_connection:
            sender_reported_digest: bytes = await send_file_over_secure_channel(
                connection=client_connection,
                source_file_path=source_file_path,
            )
        assert sender_reported_digest == expected_digest

        await asyncio.wait_for(server_side_done.wait(), timeout=120.0)
    finally:
        await server.close()

    assert len(received_file_path_holder) == 1
    received_file_path: Path = received_file_path_holder[0]
    assert received_file_path.stat().st_size == file_byte_length
    assert _stream_sha256(received_file_path) == expected_digest


# ---------------------------------------------------------------------------
# Smaller correctness tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_transfer_uses_default_chunk_size(tmp_path: Path) -> None:
    """The sender must split files exactly along the configured chunk boundary."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    chunk_byte_length: int = 4096
    file_byte_length: int = chunk_byte_length * 3 + 17  # not a multiple
    source_file_path: Path = tmp_path / "small.bin"
    source_file_path.write_bytes(os.urandom(file_byte_length))

    destination_directory: Path = tmp_path / "dst"
    destination_directory.mkdir()

    chunk_indexes_seen: list[int] = []
    last_chunk_lengths: list[int] = []
    server_side_done = asyncio.Event()

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        try:
            begin_message = await connection.receive_message()
            assert isinstance(begin_message, FileTransferBegin)
            assert begin_message.chunk_byte_length == chunk_byte_length
            assert begin_message.total_byte_length == file_byte_length

            bytes_written_so_far: int = 0
            while bytes_written_so_far < begin_message.total_byte_length:
                chunk = await connection.receive_message()
                assert isinstance(chunk, FileTransferChunk)
                chunk_indexes_seen.append(chunk.chunk_index)
                last_chunk_lengths.append(len(chunk.data))
                bytes_written_so_far += len(chunk.data)
            end = await connection.receive_message()
            assert isinstance(end, FileTransferEnd)
        finally:
            server_side_done.set()

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        async with await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
        ) as client_connection:
            await send_file_over_secure_channel(
                connection=client_connection,
                source_file_path=source_file_path,
                chunk_byte_length=chunk_byte_length,
            )
        await asyncio.wait_for(server_side_done.wait(), timeout=10.0)
    finally:
        await server.close()

    # 4 chunks total: three full chunks of 4096 bytes plus a 17-byte tail.
    assert chunk_indexes_seen == [0, 1, 2, 3]
    assert last_chunk_lengths == [chunk_byte_length, chunk_byte_length, chunk_byte_length, 17]


@pytest.mark.asyncio
async def test_receive_refuses_directory_traversal_filename(tmp_path: Path) -> None:
    """Filenames containing path separators must be sanitised."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    source_file_path: Path = tmp_path / "innocent.bin"
    source_file_path.write_bytes(b"safe contents")
    destination_directory: Path = tmp_path / "dst"
    destination_directory.mkdir()

    received_file_path_holder: list[Path] = []
    server_side_done = asyncio.Event()

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        try:
            received_file_path_holder.append(
                await receive_file_over_secure_channel(
                    connection=connection,
                    destination_directory=destination_directory,
                )
            )
        finally:
            server_side_done.set()

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        async with await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
        ) as client_connection:
            await send_file_over_secure_channel(
                connection=client_connection,
                source_file_path=source_file_path,
                destination_filename="../escape.bin",
            )
        await asyncio.wait_for(server_side_done.wait(), timeout=10.0)
    finally:
        await server.close()

    assert len(received_file_path_holder) == 1
    written_path: Path = received_file_path_holder[0]
    # The receiver collapsed the path component to bare "escape.bin"
    # under the destination directory, never above it.
    assert written_path.parent == destination_directory
    assert written_path.name == "escape.bin"
    assert not (destination_directory.parent / "escape.bin").exists()


@pytest.mark.asyncio
async def test_receive_detects_corrupted_streaming_digest(tmp_path: Path) -> None:
    """If the closing FileTransferEnd carries a wrong digest, raise."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    source_file_path: Path = tmp_path / "data.bin"
    source_file_path.write_bytes(b"some bytes for the test")

    destination_directory: Path = tmp_path / "dst"
    destination_directory.mkdir()

    receiver_error_holder: list[BaseException] = []
    server_side_done = asyncio.Event()

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        try:
            try:
                await receive_file_over_secure_channel(
                    connection=connection,
                    destination_directory=destination_directory,
                )
            except FileTransferProtocolError as protocol_error:
                receiver_error_holder.append(protocol_error)
        finally:
            server_side_done.set()

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        async with await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
        ) as client_connection:
            # Hand-craft the message sequence with a deliberately wrong
            # SHA-256 in the closing FileTransferEnd.
            transfer_identifier: bytes = os.urandom(16)
            payload: bytes = source_file_path.read_bytes()
            await client_connection.send_message(
                FileTransferBegin(
                    transfer_identifier=transfer_identifier,
                    filename="data.bin",
                    total_byte_length=len(payload),
                    chunk_byte_length=DEFAULT_FILE_TRANSFER_CHUNK_BYTE_LENGTH,
                )
            )
            await client_connection.send_message(
                FileTransferChunk(
                    transfer_identifier=transfer_identifier,
                    chunk_index=0,
                    data=payload,
                )
            )
            await client_connection.send_message(
                FileTransferEnd(
                    transfer_identifier=transfer_identifier,
                    sha256_digest=b"\x00" * 32,
                )
            )
        await asyncio.wait_for(server_side_done.wait(), timeout=10.0)
    finally:
        await server.close()

    assert len(receiver_error_holder) == 1
    assert "Streaming SHA-256" in str(receiver_error_holder[0])
