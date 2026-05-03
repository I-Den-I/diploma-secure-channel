# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Application-layer message types carried over the secure channel.

The session layer hides everything below the *encrypted record*; the
network layer adds a 1-byte *application tag* in front of every record's
plaintext so that several logical message kinds can be multiplexed over
the same secure session. Currently four kinds are supported:

============================  =====  ========================================
Kind                          Tag    Purpose
============================  =====  ========================================
:class:`TextMessage`          0x01   UTF-8 textual payload (chat message).
:class:`FileTransferBegin`    0x10   Announce a new file transfer.
:class:`FileTransferChunk`    0x11   One incremental chunk of a file.
:class:`FileTransferEnd`      0x12   Announce end-of-file + SHA-256.
============================  =====  ========================================

The four message classes share a common :class:`ApplicationMessage`
base. Encoding and decoding are reversible round-trips; the
:func:`decode_application_message` helper inspects the leading tag and
dispatches to the appropriate decoder.

Because the messages travel inside the encrypted record protocol of
:mod:`secure_channel.session`, every field below is implicitly
authenticated: an attacker cannot tamper with a tag, a transfer
identifier, or a chunk index without being detected by the AEAD layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Final


# Application tag byte values.
APPLICATION_TAG_TEXT_MESSAGE: Final[int] = 0x01
APPLICATION_TAG_FILE_TRANSFER_BEGIN: Final[int] = 0x10
APPLICATION_TAG_FILE_TRANSFER_CHUNK: Final[int] = 0x11
APPLICATION_TAG_FILE_TRANSFER_END: Final[int] = 0x12


# Encoded fixed-width fields.
_TRANSFER_IDENTIFIER_BYTE_LENGTH: Final[int] = 16
_FILENAME_LENGTH_FIELD_BYTES: Final[int] = 2
_TOTAL_FILE_SIZE_FIELD_BYTES: Final[int] = 8
_CHUNK_SIZE_FIELD_BYTES: Final[int] = 4
_CHUNK_INDEX_FIELD_BYTES: Final[int] = 8
_SHA256_DIGEST_BYTE_LENGTH: Final[int] = 32

MAXIMUM_FILE_NAME_BYTE_LENGTH: Final[int] = 1024
"""Cap on the encoded filename length (UTF-8 bytes)."""


class ApplicationMessage:
    """Base class shared by every multiplexed message kind.

    Subclasses implement :meth:`to_record_bytes` to serialise themselves
    into the plaintext that the session layer encrypts. The leading
    application tag is mandatory and is what :func:`decode_application_message`
    uses to dispatch on the receiving side.
    """

    APPLICATION_TAG: int = -1
    """Subclass-specific tag. Negative value means "do not instantiate the base class"."""

    def to_record_bytes(self) -> bytes:
        """Encode this message into the plaintext of one secure record."""
        raise NotImplementedError("Subclasses must implement to_record_bytes().")


# ---------------------------------------------------------------------------
# Text message
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TextMessage(ApplicationMessage):
    """A UTF-8 textual chat message.

    :param text: The message contents. Encoded as UTF-8 on the wire;
        any input :class:`str` is acceptable.
    """

    APPLICATION_TAG: int = APPLICATION_TAG_TEXT_MESSAGE  # type: ignore[misc]
    text: str = ""

    def to_record_bytes(self) -> bytes:
        return bytes([APPLICATION_TAG_TEXT_MESSAGE]) + self.text.encode("utf-8")

    @classmethod
    def from_record_bytes_after_tag(cls, payload: bytes) -> "TextMessage":
        return cls(text=payload.decode("utf-8"))


# ---------------------------------------------------------------------------
# File transfer messages
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FileTransferBegin(ApplicationMessage):
    """Announce the beginning of a chunked file transfer.

    :param transfer_identifier: 16-byte opaque identifier chosen by the
        sender; tags every subsequent chunk so that interleaved or
        repeated transfers cannot be confused.
    :param filename: Originator-side filename (without path components).
    :param total_byte_length: Total size of the file in bytes.
    :param chunk_byte_length: Maximum payload size per
        :class:`FileTransferChunk` message.
    """

    APPLICATION_TAG: int = APPLICATION_TAG_FILE_TRANSFER_BEGIN  # type: ignore[misc]
    transfer_identifier: bytes = b""
    filename: str = ""
    total_byte_length: int = 0
    chunk_byte_length: int = 0

    def __post_init__(self) -> None:
        if len(self.transfer_identifier) != _TRANSFER_IDENTIFIER_BYTE_LENGTH:
            raise ValueError(
                f"transfer_identifier must be {_TRANSFER_IDENTIFIER_BYTE_LENGTH} bytes."
            )
        encoded_filename: bytes = self.filename.encode("utf-8")
        if len(encoded_filename) > MAXIMUM_FILE_NAME_BYTE_LENGTH:
            raise ValueError(
                f"Filename exceeds {MAXIMUM_FILE_NAME_BYTE_LENGTH} UTF-8 bytes."
            )
        if self.total_byte_length < 0:
            raise ValueError("total_byte_length must be non-negative.")
        if self.chunk_byte_length < 1:
            raise ValueError("chunk_byte_length must be a positive integer.")

    def to_record_bytes(self) -> bytes:
        encoded_filename: bytes = self.filename.encode("utf-8")
        return (
            bytes([APPLICATION_TAG_FILE_TRANSFER_BEGIN])
            + self.transfer_identifier
            + len(encoded_filename).to_bytes(_FILENAME_LENGTH_FIELD_BYTES, "big")
            + encoded_filename
            + self.total_byte_length.to_bytes(_TOTAL_FILE_SIZE_FIELD_BYTES, "big")
            + self.chunk_byte_length.to_bytes(_CHUNK_SIZE_FIELD_BYTES, "big")
        )

    @classmethod
    def from_record_bytes_after_tag(cls, payload: bytes) -> "FileTransferBegin":
        offset: int = 0
        transfer_identifier: bytes = payload[
            offset : offset + _TRANSFER_IDENTIFIER_BYTE_LENGTH
        ]
        offset += _TRANSFER_IDENTIFIER_BYTE_LENGTH
        filename_byte_length: int = int.from_bytes(
            payload[offset : offset + _FILENAME_LENGTH_FIELD_BYTES], "big"
        )
        offset += _FILENAME_LENGTH_FIELD_BYTES
        if filename_byte_length > MAXIMUM_FILE_NAME_BYTE_LENGTH:
            raise ValueError("Encoded filename length exceeds the protocol limit.")
        filename_bytes: bytes = payload[offset : offset + filename_byte_length]
        offset += filename_byte_length
        total_byte_length: int = int.from_bytes(
            payload[offset : offset + _TOTAL_FILE_SIZE_FIELD_BYTES], "big"
        )
        offset += _TOTAL_FILE_SIZE_FIELD_BYTES
        chunk_byte_length: int = int.from_bytes(
            payload[offset : offset + _CHUNK_SIZE_FIELD_BYTES], "big"
        )
        offset += _CHUNK_SIZE_FIELD_BYTES
        if offset != len(payload):
            raise ValueError("Trailing bytes after FileTransferBegin payload.")
        return cls(
            transfer_identifier=transfer_identifier,
            filename=filename_bytes.decode("utf-8"),
            total_byte_length=total_byte_length,
            chunk_byte_length=chunk_byte_length,
        )


@dataclass(frozen=True, slots=True)
class FileTransferChunk(ApplicationMessage):
    """One incremental chunk of an in-progress file transfer.

    :param transfer_identifier: 16-byte identifier matching the
        preceding :class:`FileTransferBegin`.
    :param chunk_index: Zero-based monotonic index of this chunk.
    :param data: Raw chunk payload (1..``chunk_byte_length`` bytes).
    """

    APPLICATION_TAG: int = APPLICATION_TAG_FILE_TRANSFER_CHUNK  # type: ignore[misc]
    transfer_identifier: bytes = b""
    chunk_index: int = 0
    data: bytes = b""

    def __post_init__(self) -> None:
        if len(self.transfer_identifier) != _TRANSFER_IDENTIFIER_BYTE_LENGTH:
            raise ValueError(
                f"transfer_identifier must be {_TRANSFER_IDENTIFIER_BYTE_LENGTH} bytes."
            )
        if self.chunk_index < 0:
            raise ValueError("chunk_index must be non-negative.")

    def to_record_bytes(self) -> bytes:
        return (
            bytes([APPLICATION_TAG_FILE_TRANSFER_CHUNK])
            + self.transfer_identifier
            + self.chunk_index.to_bytes(_CHUNK_INDEX_FIELD_BYTES, "big")
            + self.data
        )

    @classmethod
    def from_record_bytes_after_tag(cls, payload: bytes) -> "FileTransferChunk":
        offset: int = 0
        transfer_identifier: bytes = payload[
            offset : offset + _TRANSFER_IDENTIFIER_BYTE_LENGTH
        ]
        offset += _TRANSFER_IDENTIFIER_BYTE_LENGTH
        chunk_index: int = int.from_bytes(
            payload[offset : offset + _CHUNK_INDEX_FIELD_BYTES], "big"
        )
        offset += _CHUNK_INDEX_FIELD_BYTES
        data: bytes = payload[offset:]
        return cls(
            transfer_identifier=transfer_identifier,
            chunk_index=chunk_index,
            data=data,
        )


@dataclass(frozen=True, slots=True)
class FileTransferEnd(ApplicationMessage):
    """End-of-file marker carrying the streaming SHA-256 of the payload.

    The receiver must recompute the SHA-256 of the data it wrote to
    disk and compare it with this field; a mismatch indicates either
    a transport-level corruption (which the AEAD should also have
    caught) or a bug in the chunk reassembly logic.

    :param transfer_identifier: 16-byte identifier matching the
        preceding :class:`FileTransferBegin`.
    :param sha256_digest: 32-byte SHA-256 of the original file contents.
    """

    APPLICATION_TAG: int = APPLICATION_TAG_FILE_TRANSFER_END  # type: ignore[misc]
    transfer_identifier: bytes = b""
    sha256_digest: bytes = b""

    def __post_init__(self) -> None:
        if len(self.transfer_identifier) != _TRANSFER_IDENTIFIER_BYTE_LENGTH:
            raise ValueError(
                f"transfer_identifier must be {_TRANSFER_IDENTIFIER_BYTE_LENGTH} bytes."
            )
        if len(self.sha256_digest) != _SHA256_DIGEST_BYTE_LENGTH:
            raise ValueError(
                f"sha256_digest must be {_SHA256_DIGEST_BYTE_LENGTH} bytes."
            )

    def to_record_bytes(self) -> bytes:
        return (
            bytes([APPLICATION_TAG_FILE_TRANSFER_END])
            + self.transfer_identifier
            + self.sha256_digest
        )

    @classmethod
    def from_record_bytes_after_tag(cls, payload: bytes) -> "FileTransferEnd":
        if len(payload) != _TRANSFER_IDENTIFIER_BYTE_LENGTH + _SHA256_DIGEST_BYTE_LENGTH:
            raise ValueError("FileTransferEnd payload has unexpected length.")
        return cls(
            transfer_identifier=payload[:_TRANSFER_IDENTIFIER_BYTE_LENGTH],
            sha256_digest=payload[_TRANSFER_IDENTIFIER_BYTE_LENGTH:],
        )


# ---------------------------------------------------------------------------
# Tag-based dispatch
# ---------------------------------------------------------------------------


_TAG_TO_DECODER: Final[dict[int, type[ApplicationMessage]]] = {
    APPLICATION_TAG_TEXT_MESSAGE: TextMessage,
    APPLICATION_TAG_FILE_TRANSFER_BEGIN: FileTransferBegin,
    APPLICATION_TAG_FILE_TRANSFER_CHUNK: FileTransferChunk,
    APPLICATION_TAG_FILE_TRANSFER_END: FileTransferEnd,
}


class UnknownApplicationTag(ValueError):
    """Raised when the leading byte of a record's plaintext is unrecognised."""


def decode_application_message(record_plaintext: bytes) -> ApplicationMessage:
    """Decode a record's plaintext into one of the typed message classes.

    :param record_plaintext: Plaintext bytes returned by
        :meth:`secure_channel.session.SecureSession.decrypt_incoming_record`.
    :returns: An instance of one of the :class:`ApplicationMessage`
        subclasses, depending on the leading tag byte.
    :raises ValueError: If the buffer is empty.
    :raises UnknownApplicationTag: If the leading tag is not assigned to
        any known message kind.
    """
    if len(record_plaintext) == 0:
        raise ValueError("Cannot decode an empty record plaintext.")
    leading_tag: int = record_plaintext[0]
    decoder_cls: type[ApplicationMessage] | None = _TAG_TO_DECODER.get(leading_tag)
    if decoder_cls is None:
        raise UnknownApplicationTag(
            f"Unknown application tag byte 0x{leading_tag:02x}."
        )
    decoder: Callable[[bytes], ApplicationMessage] = (
        decoder_cls.from_record_bytes_after_tag  # type: ignore[attr-defined]
    )
    return decoder(record_plaintext[1:])


__all__: Final[list[str]] = [
    "APPLICATION_TAG_FILE_TRANSFER_BEGIN",
    "APPLICATION_TAG_FILE_TRANSFER_CHUNK",
    "APPLICATION_TAG_FILE_TRANSFER_END",
    "APPLICATION_TAG_TEXT_MESSAGE",
    "ApplicationMessage",
    "FileTransferBegin",
    "FileTransferChunk",
    "FileTransferEnd",
    "MAXIMUM_FILE_NAME_BYTE_LENGTH",
    "TextMessage",
    "UnknownApplicationTag",
    "decode_application_message",
]
