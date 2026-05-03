# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Sliding-window replay protection for unreliable transport layers.

The Phase 2 record protocol enforces strictly monotonic sequence numbers
on the receiver, which is appropriate for a TCP-like reliable transport
but rejects the legitimate out-of-order delivery that occurs over UDP or
any datagram-style network. Phase 3 introduces this module, which
implements the standard *sliding bitmap* anti-replay algorithm specified
by RFC 6479 (and adopted virtually unchanged by IPsec ESP, DTLS 1.3 and
WireGuard).

Algorithm summary
-----------------

The receiver tracks the largest sequence number successfully decrypted
so far together with a fixed-width bitmap of the most recent
:math:`N` sequence numbers. The bit at position ``i`` of the bitmap
records whether sequence number ``highest - i`` has been seen.

A new sequence number :math:`s` is processed as follows:

* If :math:`s > \\text{highest}`: shift the bitmap left by
  :math:`s - \\text{highest}` positions, set bit 0, and update
  :math:`\\text{highest} \\leftarrow s`.
* If :math:`s = \\text{highest}` or :math:`s` lies inside the current
  bitmap window:
    * Compute the offset :math:`o = \\text{highest} - s`.
    * If bit :math:`o` is already set, the packet is a *replay* and is
      rejected.
    * Otherwise set bit :math:`o` and accept the packet.
* If :math:`s` falls outside the window
  (:math:`o \\ge N`), reject as *too old*.

This guarantees:

* Each sequence number can be accepted at most once.
* Out-of-order delivery is tolerated up to a configurable window depth.
* A packet whose sequence number is older than ``highest - N`` is always
  rejected, defeating long-delay replay attacks.

The data structure stores the bitmap as a single Python integer. Bit
shifts and OR / AND operations on Python ``int`` objects are written in
C inside CPython and remain O(N / 64) regardless of the chosen window
size.
"""

from __future__ import annotations

from typing import Final


class ReplayDetected(Exception):
    """Raised when an incoming sequence number is identified as a replay.

    The exception is split out from :class:`ValueError` so that callers
    (notably :class:`secure_channel.session.records.ReceivingHalf`) can
    distinguish a replay attack from a malformed input.
    """


class SlidingReplayWindow:
    """Anti-replay sliding window over unsigned sequence numbers.

    :param window_byte_size: Number of bytes of sliding-window history
        to maintain. The default of 8 matches RFC 6479 (a 64-bit window)
        and is sufficient for high-jitter datagram transports without
        burdening memory.
    """

    DEFAULT_WINDOW_BYTE_SIZE: Final[int] = 8

    __slots__ = ("_window_bit_size", "_highest_accepted_sequence_number", "_received_bitmap")

    def __init__(self, window_byte_size: int = DEFAULT_WINDOW_BYTE_SIZE) -> None:
        if window_byte_size < 1:
            raise ValueError("Sliding-window size must be at least one byte.")
        if window_byte_size > 1024:
            raise ValueError(
                "Sliding-window size must not exceed 8192 bits (1024 bytes)."
            )
        self._window_bit_size: Final[int] = window_byte_size * 8
        self._highest_accepted_sequence_number: int = -1
        self._received_bitmap: int = 0

    @property
    def window_bit_size(self) -> int:
        """Width of the sliding bitmap, in bits."""
        return self._window_bit_size

    @property
    def highest_accepted_sequence_number(self) -> int:
        """Largest sequence number successfully recorded so far (-1 initially)."""
        return self._highest_accepted_sequence_number

    @property
    def received_bitmap(self) -> int:
        """Snapshot of the receive bitmap, exposed for testing only."""
        return self._received_bitmap

    def check_and_record(self, sequence_number: int) -> None:
        """Validate a freshly-received sequence number and record acceptance.

        :param sequence_number: Non-negative integer carried in the
            authenticated header of an incoming record.
        :raises ValueError: If ``sequence_number`` is negative.
        :raises ReplayDetected: If the sequence number falls outside the
            sliding window or has already been accepted.
        """
        if sequence_number < 0:
            raise ValueError("Sequence number must be non-negative.")

        bitmap_mask: int = (1 << self._window_bit_size) - 1

        if sequence_number > self._highest_accepted_sequence_number:
            shift_distance: int = (
                sequence_number - self._highest_accepted_sequence_number
            )
            if shift_distance >= self._window_bit_size:
                # The new sequence number jumps past the entire window;
                # discard all prior history and start with only this bit.
                self._received_bitmap = 1
            else:
                self._received_bitmap = (
                    (self._received_bitmap << shift_distance) | 1
                ) & bitmap_mask
            self._highest_accepted_sequence_number = sequence_number
            return

        offset_from_highest: int = (
            self._highest_accepted_sequence_number - sequence_number
        )
        if offset_from_highest >= self._window_bit_size:
            raise ReplayDetected(
                "Sequence number is older than the sliding replay window allows."
            )
        bit_position_mask: int = 1 << offset_from_highest
        if self._received_bitmap & bit_position_mask:
            raise ReplayDetected(
                "Sequence number was already accepted within the window."
            )
        self._received_bitmap |= bit_position_mask


__all__: Final[list[str]] = [
    "ReplayDetected",
    "SlidingReplayWindow",
]
