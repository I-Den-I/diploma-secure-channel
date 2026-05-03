# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Chunked, streaming file transfer over the secure channel.

This module provides two coroutines:

* :func:`send_file_over_secure_channel` --- read a file from disk
  incrementally, hash it on the fly, encrypt each chunk through the
  underlying :class:`SecureChannelConnection` and transmit it.
* :func:`receive_file_over_secure_channel` --- read incoming
  :class:`FileTransferChunk` messages, write them to disk
  incrementally, recompute the streaming SHA-256, and verify the
  digest carried in the closing :class:`FileTransferEnd` message.

**Memory invariant:** at no point is more than one chunk's worth of
plaintext held in memory. The default chunk size of 64 KiB keeps the
peak working set comfortably under 1 MiB even for multi-GiB files.

The transfer protocol is single-shot --- one file per
``send_file_over_secure_channel`` call --- and is composable with
unrelated text messages on the same channel (the receiver dispatches by
the leading application tag in :func:`decode_application_message`).
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Final

from secure_channel.network.connection import SecureChannelConnection
from secure_channel.network.messages import (
    ApplicationMessage,
    FileTransferBegin,
    FileTransferChunk,
    FileTransferEnd,
)


DEFAULT_FILE_TRANSFER_CHUNK_BYTE_LENGTH: Final[int] = 64 * 1024
"""Default chunk payload size (64 KiB)."""

_TRANSFER_IDENTIFIER_BYTE_LENGTH: Final[int] = 16


class FileTransferProtocolError(Exception):
    """Raised on protocol-level violations during a file transfer.

    Examples include: receiving a chunk for an unknown transfer
    identifier, receiving an out-of-order chunk index, or finding that
    the streaming SHA-256 does not match the closing
    :class:`FileTransferEnd` digest.
    """


# ---------------------------------------------------------------------------
# Sender
# ---------------------------------------------------------------------------


async def send_file_over_secure_channel(
    *,
    connection: SecureChannelConnection,
    source_file_path: Path,
    chunk_byte_length: int = DEFAULT_FILE_TRANSFER_CHUNK_BYTE_LENGTH,
    transfer_identifier: bytes | None = None,
    destination_filename: str | None = None,
) -> bytes:
    """Stream-transfer ``source_file_path`` to the peer over ``connection``.

    The function emits a :class:`FileTransferBegin`, then one
    :class:`FileTransferChunk` per disk read, and finally a
    :class:`FileTransferEnd` carrying the total SHA-256.

    :param connection: An authenticated :class:`SecureChannelConnection`.
    :param source_file_path: Path to a regular file on the local
        filesystem.
    :param chunk_byte_length: Bytes per chunk. Must be positive.
    :param transfer_identifier: Optional caller-supplied 16-byte
        identifier. When ``None``, a random value is generated.
    :param destination_filename: Optional filename to advertise to the
        peer; defaults to the basename of ``source_file_path``.
    :returns: The 32-byte SHA-256 of the transmitted file (handy for
        unit tests that want to recompute it independently).
    :raises FileNotFoundError: If ``source_file_path`` does not exist.
    :raises ValueError: If the chunk size or supplied identifier is
        invalid.
    """
    if chunk_byte_length < 1:
        raise ValueError("chunk_byte_length must be a positive integer.")
    if transfer_identifier is None:
        transfer_identifier = os.urandom(_TRANSFER_IDENTIFIER_BYTE_LENGTH)
    elif len(transfer_identifier) != _TRANSFER_IDENTIFIER_BYTE_LENGTH:
        raise ValueError(
            f"transfer_identifier must be {_TRANSFER_IDENTIFIER_BYTE_LENGTH} bytes."
        )
    advertised_filename: str = destination_filename or source_file_path.name
    total_byte_length: int = source_file_path.stat().st_size

    await connection.send_message(
        FileTransferBegin(
            transfer_identifier=transfer_identifier,
            filename=advertised_filename,
            total_byte_length=total_byte_length,
            chunk_byte_length=chunk_byte_length,
        )
    )

    streaming_digest = hashlib.sha256()
    chunk_index: int = 0
    with source_file_path.open("rb") as input_file_handle:
        while True:
            chunk_data: bytes = input_file_handle.read(chunk_byte_length)
            if not chunk_data:
                break
            streaming_digest.update(chunk_data)
            await connection.send_message(
                FileTransferChunk(
                    transfer_identifier=transfer_identifier,
                    chunk_index=chunk_index,
                    data=chunk_data,
                )
            )
            chunk_index += 1

    final_digest_bytes: bytes = streaming_digest.digest()
    await connection.send_message(
        FileTransferEnd(
            transfer_identifier=transfer_identifier,
            sha256_digest=final_digest_bytes,
        )
    )
    return final_digest_bytes


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------


async def receive_file_over_secure_channel(
    *,
    connection: SecureChannelConnection,
    destination_directory: Path,
    file_transfer_begin: FileTransferBegin | None = None,
    overwrite_existing_file: bool = False,
) -> Path:
    """Receive a chunked file transfer and write it to disk.

    The receiver may either let this function read the
    :class:`FileTransferBegin` itself, or pass a previously-received
    instance via the ``file_transfer_begin`` parameter (useful when the
    application has already peeked at the first message of the
    conversation to learn what kind of payload is coming).

    :param connection: An authenticated :class:`SecureChannelConnection`.
    :param destination_directory: Directory under which the file will
        be written. Must exist.
    :param file_transfer_begin: Optional pre-consumed begin message.
        When ``None`` the function reads it from the connection.
    :param overwrite_existing_file: If ``False`` (the default) and the
        target path already exists, :class:`FileExistsError` is raised
        before any data is written.
    :returns: The :class:`Path` to the freshly written file.
    :raises FileTransferProtocolError: On any protocol-level
        inconsistency.
    :raises FileExistsError: If the destination file already exists and
        ``overwrite_existing_file`` is ``False``.
    """
    if not destination_directory.is_dir():
        raise NotADirectoryError(
            f"Destination directory {destination_directory!s} does not exist."
        )

    begin_message: FileTransferBegin
    if file_transfer_begin is None:
        first_message: ApplicationMessage = await connection.receive_message()
        if not isinstance(first_message, FileTransferBegin):
            raise FileTransferProtocolError(
                "Expected a FileTransferBegin as the first message, "
                f"got {type(first_message).__name__}."
            )
        begin_message = first_message
    else:
        begin_message = file_transfer_begin

    safe_filename: str = _sanitise_filename(begin_message.filename)
    destination_file_path: Path = destination_directory / safe_filename
    if destination_file_path.exists() and not overwrite_existing_file:
        raise FileExistsError(
            f"Destination file {destination_file_path!s} already exists."
        )

    streaming_digest = hashlib.sha256()
    bytes_written_so_far: int = 0
    expected_next_chunk_index: int = 0

    with destination_file_path.open("wb") as output_file_handle:
        while bytes_written_so_far < begin_message.total_byte_length:
            next_message: ApplicationMessage = await connection.receive_message()
            if not isinstance(next_message, FileTransferChunk):
                raise FileTransferProtocolError(
                    "Expected a FileTransferChunk during transfer, "
                    f"got {type(next_message).__name__}."
                )
            if next_message.transfer_identifier != begin_message.transfer_identifier:
                raise FileTransferProtocolError(
                    "Chunk transfer identifier does not match the announced one."
                )
            if next_message.chunk_index != expected_next_chunk_index:
                raise FileTransferProtocolError(
                    f"Chunk index {next_message.chunk_index} arrived out of "
                    f"order; expected {expected_next_chunk_index}."
                )
            if (
                bytes_written_so_far + len(next_message.data)
                > begin_message.total_byte_length
            ):
                raise FileTransferProtocolError(
                    "Chunk would overflow the announced total file size."
                )
            output_file_handle.write(next_message.data)
            streaming_digest.update(next_message.data)
            bytes_written_so_far += len(next_message.data)
            expected_next_chunk_index += 1

    closing_message: ApplicationMessage = await connection.receive_message()
    if not isinstance(closing_message, FileTransferEnd):
        raise FileTransferProtocolError(
            "Expected a FileTransferEnd to close the transfer, "
            f"got {type(closing_message).__name__}."
        )
    if closing_message.transfer_identifier != begin_message.transfer_identifier:
        raise FileTransferProtocolError(
            "FileTransferEnd identifier does not match the announced one."
        )
    if closing_message.sha256_digest != streaming_digest.digest():
        raise FileTransferProtocolError(
            "Streaming SHA-256 digest does not match the closing message."
        )

    return destination_file_path


def _sanitise_filename(advertised_filename: str) -> str:
    """Strip any path components from a peer-supplied filename.

    Defends against directory traversal attempts by collapsing the
    incoming filename to its bare component (no separators, no parent
    references). Refuses empty or pure-separator inputs.
    """
    bare_name: str = Path(advertised_filename).name
    if not bare_name or bare_name in (".", ".."):
        raise FileTransferProtocolError(
            f"Refusing to use unsafe filename {advertised_filename!r}."
        )
    return bare_name


__all__: Final[list[str]] = [
    "DEFAULT_FILE_TRANSFER_CHUNK_BYTE_LENGTH",
    "FileTransferProtocolError",
    "receive_file_over_secure_channel",
    "send_file_over_secure_channel",
]
