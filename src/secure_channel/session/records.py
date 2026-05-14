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

* It defends against *delay attacks*: the receiver rejects records whose
  timestamps fall outside a configurable freshness window. To stay
  usable when the two peers' wall clocks are not NTP-synchronised --- a
  routine situation when they sit in different countries or on mobile
  devices --- the freshness check is **anchored to the peer's clock**
  rather than to absolute local time. The first authentic record a
  receiver decrypts establishes a one-off ``peer_clock_offset`` (the
  signed difference ``peer_timestamp - local_now``); every subsequent
  record is then validated against ``local_now + peer_clock_offset``.
  A constant clock skew of *any* magnitude is therefore absorbed, while
  a record delayed (or replayed stale) *after* the anchor is still
  rejected because its timestamp lags the anchored "now". On the very
  first record a genuine skew and a delay attack are information-
  theoretically indistinguishable without an external time source, so
  the AEAD-authenticated peer is trusted to set the anchor.
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

Since :class:`ReceivingHalf` anchors the freshness check to the peer's
clock (see the module docstring), this tolerance no longer has to
absorb the *absolute* offset between two unsynchronised wall clocks ---
that is handled by the per-session ``peer_clock_offset``. What is left
for the ±30 s window to cover is the comparatively tiny *relative*
drift that accumulates between the two clocks during a single session
plus ordinary network jitter. ±30 s is therefore a generous margin,
not a tight one.
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
        """Sequence number that the next call to :meth:`encrypt_record` will use."""
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
    2. *Freshness* via timestamp comparison, **anchored to the peer's
       clock**: the first authentic record sets a one-off
       ``peer_clock_offset`` and every later record is checked against
       ``local_now + peer_clock_offset`` (see the module docstring for
       the full rationale).
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
        "_peer_clock_offset_microseconds",
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
        # Signed difference ``peer_timestamp - local_now`` learned from
        # the first authentic record; ``None`` until that record
        # arrives. Once set it is never changed again for the lifetime
        # of the session direction.
        self._peer_clock_offset_microseconds: int | None = None

    @property
    def highest_accepted_sequence_number(self) -> int:
        """Largest sequence number successfully decrypted (-1 if none yet)."""
        return self._replay_window.highest_accepted_sequence_number

    @property
    def replay_window(self) -> SlidingReplayWindow:
        """Read-only access to the underlying sliding window for tests."""
        return self._replay_window

    @property
    def peer_clock_offset_microseconds(self) -> int | None:
        """Clock offset (peer minus local) learned from the first record.

        ``None`` until the first authentic record has been decrypted.
        A positive value means the peer's wall clock runs ahead of the
        local one; a negative value means it runs behind. Exposed for
        diagnostics — the GUI surfaces it so the user can *see* the
        protocol absorbing a cross-country clock skew.
        """
        return self._peer_clock_offset_microseconds

    def decrypt_record(self, wire_bytes: bytes) -> bytes:
        """Verify, decrypt and return the plaintext of a received record.

        The very first authentic record only *bootstraps* the
        peer-clock anchor and is exempt from the freshness window;
        every record after it is freshness-checked relative to that
        anchor (see :meth:`_bootstrap_or_enforce_freshness_window`).

        :raises AuthenticationFailed: If the AEAD tag does not verify or
            if the embedded nonce does not match the one derived from
            the header.
        :raises StaleRecordDetected: If a *non-first* record's timestamp
            is older than the anchored freshness window allows.
        :raises FutureRecordDetected: If a *non-first* record's
            timestamp lies further in the future than the anchored
            freshness window allows.
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

        self._bootstrap_or_enforce_freshness_window(timestamp_microseconds)
        self._enforce_anti_replay(sequence_number)
        return plaintext

    def _bootstrap_or_enforce_freshness_window(
        self, timestamp_microseconds: int
    ) -> None:
        """Anchor to the peer's clock, then enforce the freshness window.

        On the **first** authentic record this learns the one-off
        ``peer_clock_offset`` and returns without rejecting anything ---
        the AEAD-authenticated peer is trusted to set the time anchor,
        and a constant skew of any magnitude (peers in different
        countries / devices not NTP-synced) is absorbed here.

        On **every subsequent** record the embedded timestamp is
        compared against ``local_now + peer_clock_offset``: a record
        that lags (stale / delayed replay) or races ahead (clock glitch)
        by more than ``timestamp_tolerance_microseconds`` is rejected.
        Because the comparison is relative to the anchor, the only thing
        the tolerance has to cover is intra-session relative drift plus
        network jitter --- not the absolute cross-peer offset.
        """
        current_time_microseconds: int = self._clock()
        if self._peer_clock_offset_microseconds is None:
            # First authentic record — adopt the peer's clock as the
            # trusted baseline. See the module docstring for why a
            # first-record delay attack is out of scope here.
            self._peer_clock_offset_microseconds = (
                timestamp_microseconds - current_time_microseconds
            )
            return
        anchored_now: int = (
            current_time_microseconds + self._peer_clock_offset_microseconds
        )
        lower_bound: int = anchored_now - self._timestamp_tolerance_microseconds
        upper_bound: int = anchored_now + self._timestamp_tolerance_microseconds
        if timestamp_microseconds < lower_bound:
            raise StaleRecordDetected(
                "Record timestamp predates the (peer-anchored) freshness "
                f"window (record={timestamp_microseconds}, "
                f"lower_bound={lower_bound}, "
                f"peer_clock_offset={self._peer_clock_offset_microseconds})."
            )
        if timestamp_microseconds > upper_bound:
            raise FutureRecordDetected(
                "Record timestamp lies beyond the (peer-anchored) freshness "
                f"window (record={timestamp_microseconds}, "
                f"upper_bound={upper_bound}, "
                f"peer_clock_offset={self._peer_clock_offset_microseconds})."
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
