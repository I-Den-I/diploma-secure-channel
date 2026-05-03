# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Authenticated record protocol used after the handshake completes.

Once the SIGMA-style handshake has produced four 32-byte keys (one
encryption key and one authentication key per direction), application
data is exchanged in self-contained *records*. A record encodes:

::

    sequence_number      (8 B, big-endian)  ||
    timestamp_microseconds (8 B, big-endian) ||
    payload_length       (4 B, big-endian)  ||
    encrypted_payload + 16-byte CMAC tag

where the AEAD nonce is derived deterministically from the sequence
number and a constant per-direction prefix. Because the nonce is
deterministic, two sender-side sequence numbers can never collide as long
as the sender increments the counter for every record it emits, which the
implementation enforces.

The 8-byte microsecond timestamp is included in the header (and therefore
in the AEAD's associated data) for two purposes:

* It defends against *delay attacks*: the receiver compares the embedded
  timestamp against its local clock and rejects records whose
  timestamps fall outside a configurable freshness window.
* It binds each record to a specific time of issuance, which makes
  forensic analysis of recorded traffic straightforward.

Anti-replay is enforced by a sliding bitmap window
(:class:`secure_channel.session.replay_window.SlidingReplayWindow`) so
that out-of-order delivery on an unreliable transport (UDP, raw IP, ...)
is supported without weakening the protection against duplicate
delivery.

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
from secure_channel.session.clock import (
    MICROSECOND_WALL_CLOCK,
    MicrosecondClock,
)
from secure_channel.session.replay_window import (
    ReplayDetected,
    SlidingReplayWindow,
)


_SEQUENCE_NUMBER_BYTE_LENGTH: Final[int] = 8
_TIMESTAMP_BYTE_LENGTH: Final[int] = 8
_PAYLOAD_LENGTH_FIELD_BYTES: Final[int] = 4
_RECORD_HEADER_BYTE_LENGTH: Final[int] = (
    _SEQUENCE_NUMBER_BYTE_LENGTH
    + _TIMESTAMP_BYTE_LENGTH
    + _PAYLOAD_LENGTH_FIELD_BYTES
)

DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS: Final[int] = 30 * 1_000_000
"""Default freshness window: ±30 seconds.

Allows for modest clock skew between peers (NTP-synchronised hosts are
typically within tens of milliseconds, but corporate VPNs and mobile
networks can introduce noticeably larger drift).
"""


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


def _build_record_header(
    sequence_number: int,
    timestamp_microseconds: int,
    payload_byte_length: int,
) -> bytes:
    """Pack ``(sequence, timestamp, payload_length)`` into the wire header."""
    return (
        sequence_number.to_bytes(_SEQUENCE_NUMBER_BYTE_LENGTH, "big")
        + timestamp_microseconds.to_bytes(_TIMESTAMP_BYTE_LENGTH, "big")
        + payload_byte_length.to_bytes(_PAYLOAD_LENGTH_FIELD_BYTES, "big")
    )


def _parse_record_header(header_bytes: bytes) -> tuple[int, int, int]:
    """Inverse of :func:`_build_record_header`."""
    if len(header_bytes) != _RECORD_HEADER_BYTE_LENGTH:
        raise ValueError(
            f"Header must be {_RECORD_HEADER_BYTE_LENGTH} bytes; got {len(header_bytes)}."
        )
    sequence_number: int = int.from_bytes(
        header_bytes[:_SEQUENCE_NUMBER_BYTE_LENGTH], "big"
    )
    timestamp_microseconds: int = int.from_bytes(
        header_bytes[
            _SEQUENCE_NUMBER_BYTE_LENGTH : _SEQUENCE_NUMBER_BYTE_LENGTH
            + _TIMESTAMP_BYTE_LENGTH
        ],
        "big",
    )
    payload_byte_length: int = int.from_bytes(
        header_bytes[_SEQUENCE_NUMBER_BYTE_LENGTH + _TIMESTAMP_BYTE_LENGTH :], "big"
    )
    return sequence_number, timestamp_microseconds, payload_byte_length


@dataclass(frozen=True, slots=True)
class DirectionalKeySet:
    """Pair of (AEAD key, direction prefix) used in one direction."""

    aead_key: KalynaAeadKey
    direction_prefix: bytes


@dataclass(frozen=True, slots=True)
class FreshnessPolicy:
    """Configuration of the freshness checks applied on the receiver side.

    :param clock: Source of microsecond-precision wall-clock time. The
        default is :data:`MICROSECOND_WALL_CLOCK`; tests inject a
        deterministic generator to exercise edge cases.
    :param timestamp_tolerance_microseconds: Maximum absolute deviation
        between the embedded record timestamp and the local clock at the
        instant of decryption. Records outside the symmetric window are
        rejected (defends against delay attacks).
    :param replay_window_byte_size: Width of the sliding-window bitmap
        in bytes. Larger windows tolerate more aggressive packet
        reordering at a small memory cost.
    """

    clock: MicrosecondClock = MICROSECOND_WALL_CLOCK
    timestamp_tolerance_microseconds: int = DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS
    replay_window_byte_size: int = SlidingReplayWindow.DEFAULT_WINDOW_BYTE_SIZE

    def __post_init__(self) -> None:
        if self.timestamp_tolerance_microseconds < 0:
            raise ValueError(
                "Timestamp tolerance must be a non-negative integer."
            )
        if self.replay_window_byte_size < 1:
            raise ValueError("Replay window size must be at least 1 byte.")


class StaleRecordDetected(AuthenticationFailed):
    """Raised when a record's embedded timestamp falls outside the freshness window.

    Inherits from :class:`AuthenticationFailed` so that callers wishing
    to treat any policy violation uniformly can catch the parent class.
    Specific subclasses are still useful for targeted handling and for
    informative test assertions.
    """


class FutureRecordDetected(AuthenticationFailed):
    """Raised when a record's embedded timestamp is too far in the future."""


class SequenceNumberReplayed(AuthenticationFailed):
    """Raised when a sequence number replays a previously accepted value."""


class SequenceNumberOutOfWindow(AuthenticationFailed):
    """Raised when a sequence number falls outside the sliding window."""


class SendingHalf:
    """Sender-side state for one direction of the record protocol.

    Maintains a strictly monotonically increasing sequence number and uses
    it both as the AEAD nonce and as authenticated header data. Each
    outgoing record is stamped with the wall-clock time at the moment of
    encryption so that the peer can validate freshness.

    :param key_set: AEAD key + direction prefix used for this direction.
    :param clock: Source of microsecond-precision wall-clock time.
    """

    __slots__ = ("_aead", "_direction_prefix", "_next_sequence_number", "_clock")

    def __init__(
        self,
        key_set: DirectionalKeySet,
        *,
        clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
    ) -> None:
        self._aead: Final[KalynaAead] = KalynaAead(key_set.aead_key)
        self._direction_prefix: Final[bytes] = key_set.direction_prefix
        self._clock: Final[MicrosecondClock] = clock
        self._next_sequence_number: int = 0

    @property
    def next_sequence_number(self) -> int:
        return self._next_sequence_number

    def encrypt_record(self, plaintext: bytes) -> bytes:
        """Wrap ``plaintext`` into a fully-formed encrypted record.

        :returns: ``header || nonce || ciphertext || tag`` ready for
            transmission. The header (sequence number + timestamp +
            length) is also included in the AEAD's associated-data
            input, so any in-transit modification fails verification.
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
        timestamp_microseconds: int = self._clock()
        header: bytes = _build_record_header(
            self._next_sequence_number,
            timestamp_microseconds,
            len(plaintext),
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

    Performs three independent integrity / freshness checks on every
    incoming record:

    1. *AEAD authentication* via the underlying Kalyna-CMAC tag.
    2. *Freshness* via timestamp comparison with the local clock.
    3. *Anti-replay* via the sliding bitmap window.

    The checks are applied in the order: AEAD → timestamp → replay,
    because failing the AEAD check is the strongest indicator that the
    record was forged or corrupted in transit, and short-circuiting on
    that result avoids leaking secondary diagnostic signals to the
    network.

    :param key_set: AEAD key + direction prefix used for this direction.
    :param policy: Freshness and replay-window configuration.
    """

    __slots__ = (
        "_aead",
        "_direction_prefix",
        "_replay_window",
        "_clock",
        "_timestamp_tolerance_microseconds",
    )

    def __init__(
        self,
        key_set: DirectionalKeySet,
        *,
        policy: FreshnessPolicy | None = None,
    ) -> None:
        effective_policy: FreshnessPolicy = policy or FreshnessPolicy()
        self._aead: Final[KalynaAead] = KalynaAead(key_set.aead_key)
        self._direction_prefix: Final[bytes] = key_set.direction_prefix
        self._replay_window: Final[SlidingReplayWindow] = SlidingReplayWindow(
            window_byte_size=effective_policy.replay_window_byte_size
        )
        self._clock: Final[MicrosecondClock] = effective_policy.clock
        self._timestamp_tolerance_microseconds: Final[int] = (
            effective_policy.timestamp_tolerance_microseconds
        )

    @property
    def highest_accepted_sequence_number(self) -> int:
        """Largest sequence number successfully decrypted (-1 if none yet)."""
        return self._replay_window.highest_accepted_sequence_number

    @property
    def replay_window(self) -> SlidingReplayWindow:
        """Read-only access to the underlying sliding window for tests."""
        return self._replay_window

    def decrypt_record(self, wire_bytes: bytes) -> bytes:
        """Verify, decrypt and return the plaintext of a received record.

        :raises AuthenticationFailed: If the AEAD tag does not verify or
            if the embedded nonce does not match the one derived from
            the header.
        :raises StaleRecordDetected: If the record's timestamp is older
            than the freshness window allows.
        :raises FutureRecordDetected: If the record's timestamp lies
            further in the future than the freshness window allows.
        :raises SequenceNumberReplayed: If the record's sequence number
            has already been accepted within the sliding window.
        :raises SequenceNumberOutOfWindow: If the record's sequence
            number is older than the sliding window can track.
        """
        if len(wire_bytes) < _RECORD_HEADER_BYTE_LENGTH:
            raise AuthenticationFailed("Record is shorter than its header.")
        header: bytes = wire_bytes[:_RECORD_HEADER_BYTE_LENGTH]
        sealed_record: bytes = wire_bytes[_RECORD_HEADER_BYTE_LENGTH:]
        sequence_number, timestamp_microseconds, payload_byte_length = (
            _parse_record_header(header)
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

        self._enforce_freshness_window(timestamp_microseconds)
        self._enforce_anti_replay(sequence_number)
        return plaintext

    def _enforce_freshness_window(self, timestamp_microseconds: int) -> None:
        """Reject records whose timestamps fall outside the freshness window."""
        current_time_microseconds: int = self._clock()
        lower_bound: int = (
            current_time_microseconds - self._timestamp_tolerance_microseconds
        )
        upper_bound: int = (
            current_time_microseconds + self._timestamp_tolerance_microseconds
        )
        if timestamp_microseconds < lower_bound:
            raise StaleRecordDetected(
                "Record timestamp predates the freshness window "
                f"(record={timestamp_microseconds}, lower_bound={lower_bound})."
            )
        if timestamp_microseconds > upper_bound:
            raise FutureRecordDetected(
                "Record timestamp lies beyond the freshness window "
                f"(record={timestamp_microseconds}, upper_bound={upper_bound})."
            )

    def _enforce_anti_replay(self, sequence_number: int) -> None:
        """Run the sliding-window replay check for ``sequence_number``.

        Distinguishes the two kinds of replay outcome so the application
        layer can react differently to "duplicate inside window" versus
        "too old to track" (the former is far more common; the latter
        usually signals a long-delayed delivery or an attacker hoarding
        ancient packets).
        """
        try:
            self._replay_window.check_and_record(sequence_number)
        except ReplayDetected as replay_error:
            error_message: str = str(replay_error)
            if "older than the sliding replay window" in error_message:
                raise SequenceNumberOutOfWindow(error_message) from replay_error
            raise SequenceNumberReplayed(error_message) from replay_error


__all__: Final[list[str]] = [
    "DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS",
    "DirectionalKeySet",
    "FreshnessPolicy",
    "FutureRecordDetected",
    "ReceivingHalf",
    "SendingHalf",
    "SequenceNumberOutOfWindow",
    "SequenceNumberReplayed",
    "StaleRecordDetected",
]
