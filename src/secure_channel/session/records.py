# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Authenticated record protocol used after the handshake completes.

Once the SIGMA-style handshake has produced four 32-byte keys (one
encryption key and one authentication key per direction), application
data is exchanged in self-contained *records*. A record encodes:

::

    sequence_number (8 B, big-endian)  ||
    payload_length  (4 B, big-endian)  ||
    encrypted_payload + 16-byte CMAC tag

where the AEAD nonce is derived deterministically from the sequence
number and a constant per-direction prefix. Because the nonce is
deterministic, two sender-side sequence numbers can never collide as long
as the sender increments the counter for every record it emits, which the
implementation enforces. Sequence numbers also serve as the basis for the
replay-protection logic implemented in
:mod:`secure_channel.session.replay_window` (Phase 3).

The record layer is intentionally *transport-agnostic*: the encrypt /
decrypt methods operate on byte strings, leaving the actual transmission
to :mod:`secure_channel.network`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from secure_channel.crypto.kalyna_aead import (
    AuthenticationFailed,
    KalynaAead,
    KalynaAeadKey,
)


_SEQUENCE_NUMBER_BYTE_LENGTH: Final[int] = 8
_PAYLOAD_LENGTH_FIELD_BYTES: Final[int] = 4
_RECORD_HEADER_BYTE_LENGTH: Final[int] = (
    _SEQUENCE_NUMBER_BYTE_LENGTH + _PAYLOAD_LENGTH_FIELD_BYTES
)


def _build_directional_nonce(direction_prefix: bytes, sequence_number: int) -> bytes:
    """Combine a 4-byte direction tag with the 8-byte sequence number.

    The resulting 12-byte nonce satisfies the AEAD's nonce-uniqueness
    requirement as long as the sequence number is not allowed to repeat,
    which the sender side enforces explicitly.
    """
    if len(direction_prefix) != 4:
        raise ValueError("Direction prefix must be exactly 4 bytes.")
    return direction_prefix + sequence_number.to_bytes(
        _SEQUENCE_NUMBER_BYTE_LENGTH, "big"
    )


def _build_record_header(sequence_number: int, payload_byte_length: int) -> bytes:
    """Pack ``(sequence_number, payload_length)`` into the wire header."""
    return sequence_number.to_bytes(
        _SEQUENCE_NUMBER_BYTE_LENGTH, "big"
    ) + payload_byte_length.to_bytes(_PAYLOAD_LENGTH_FIELD_BYTES, "big")


def _parse_record_header(header_bytes: bytes) -> tuple[int, int]:
    """Inverse of :func:`_build_record_header`."""
    if len(header_bytes) != _RECORD_HEADER_BYTE_LENGTH:
        raise ValueError(
            f"Header must be {_RECORD_HEADER_BYTE_LENGTH} bytes; got {len(header_bytes)}."
        )
    sequence_number: int = int.from_bytes(
        header_bytes[:_SEQUENCE_NUMBER_BYTE_LENGTH], "big"
    )
    payload_byte_length: int = int.from_bytes(
        header_bytes[_SEQUENCE_NUMBER_BYTE_LENGTH:], "big"
    )
    return sequence_number, payload_byte_length


@dataclass(frozen=True, slots=True)
class DirectionalKeySet:
    """Pair of (AEAD key, direction prefix) used in one direction."""

    aead_key: KalynaAeadKey
    direction_prefix: bytes


class SendingHalf:
    """Sender-side state for one direction of the record protocol.

    Maintains a strictly monotonically increasing sequence number and uses
    it both as the AEAD nonce and as authenticated header data.
    """

    __slots__ = ("_aead", "_direction_prefix", "_next_sequence_number")

    def __init__(self, key_set: DirectionalKeySet) -> None:
        self._aead: Final[KalynaAead] = KalynaAead(key_set.aead_key)
        self._direction_prefix: Final[bytes] = key_set.direction_prefix
        self._next_sequence_number: int = 0

    @property
    def next_sequence_number(self) -> int:
        return self._next_sequence_number

    def encrypt_record(self, plaintext: bytes) -> bytes:
        """Wrap ``plaintext`` into a fully-formed encrypted record.

        :returns: ``header || nonce || ciphertext || tag`` ready for
            transmission. The header (sequence number + length) is also
            included in the AEAD's associated-data input so that any in
            transit modification fails verification.
        :raises OverflowError: If the 64-bit sequence number is exhausted
            (a 64 EiB session, in practice impossible).
        """
        if self._next_sequence_number >= (1 << 63):
            raise OverflowError(
                "Sequence number exhausted for this session direction."
            )
        nonce: bytes = _build_directional_nonce(
            self._direction_prefix, self._next_sequence_number
        )
        header: bytes = _build_record_header(
            self._next_sequence_number, len(plaintext)
        )
        sealed_with_nonce: bytes = self._aead.encrypt(
            nonce=nonce, plaintext=plaintext, associated_data=header
        )
        # The nonce embedded inside ``sealed_with_nonce`` is deterministic
        # given the header, but we keep it on the wire to match the AEAD's
        # self-describing encoding and simplify decoding on the receiver.
        self._next_sequence_number += 1
        return header + sealed_with_nonce


class ReceivingHalf:
    """Receiver-side state for one direction of the record protocol.

    The simple in-order policy implemented here rejects any record whose
    sequence number is not strictly greater than the most recent
    successful one. The full sliding-window replay protection logic
    needed for unreliable transports is implemented in Phase 3.
    """

    __slots__ = ("_aead", "_direction_prefix", "_highest_accepted_sequence_number")

    def __init__(self, key_set: DirectionalKeySet) -> None:
        self._aead: Final[KalynaAead] = KalynaAead(key_set.aead_key)
        self._direction_prefix: Final[bytes] = key_set.direction_prefix
        self._highest_accepted_sequence_number: int = -1

    @property
    def highest_accepted_sequence_number(self) -> int:
        return self._highest_accepted_sequence_number

    def decrypt_record(self, wire_bytes: bytes) -> bytes:
        """Verify, decrypt and return the plaintext of a received record.

        :raises AuthenticationFailed: If the AEAD tag does not verify, if
            the embedded nonce does not match the one derived from the
            header, or if the sequence number replays a previously
            accepted value.
        """
        if len(wire_bytes) < _RECORD_HEADER_BYTE_LENGTH:
            raise AuthenticationFailed("Record is shorter than its header.")
        header: bytes = wire_bytes[:_RECORD_HEADER_BYTE_LENGTH]
        sealed_record: bytes = wire_bytes[_RECORD_HEADER_BYTE_LENGTH:]
        sequence_number, payload_byte_length = _parse_record_header(header)

        if sequence_number <= self._highest_accepted_sequence_number:
            raise AuthenticationFailed(
                "Sequence number is not strictly greater than the previous one."
            )

        expected_nonce: bytes = _build_directional_nonce(
            self._direction_prefix, sequence_number
        )
        if not sealed_record.startswith(expected_nonce):
            raise AuthenticationFailed(
                "Record nonce does not match the value derived from the header."
            )
        plaintext: bytes = self._aead.decrypt(sealed_record, associated_data=header)
        if len(plaintext) != payload_byte_length:
            raise AuthenticationFailed(
                "Decrypted payload length does not match the header field."
            )

        self._highest_accepted_sequence_number = sequence_number
        return plaintext


__all__: Final[list[str]] = [
    "DirectionalKeySet",
    "SendingHalf",
    "ReceivingHalf",
]
