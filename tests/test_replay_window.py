# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Unit tests for the sliding-window anti-replay primitive.

These tests exercise :class:`SlidingReplayWindow` in isolation, without
touching the rest of the session machinery. They validate the formal
invariants of the algorithm (RFC 6479): linear acceptance,
out-of-order acceptance within the window, replay detection inside the
window, and rejection of sequence numbers older than the window depth.
"""

from __future__ import annotations

import pytest

from secure_channel.session.replay_window import ReplayDetected, SlidingReplayWindow


def test_strictly_increasing_sequence_is_always_accepted() -> None:
    window = SlidingReplayWindow(window_byte_size=4)
    for sequence_number in range(64):
        window.check_and_record(sequence_number)
    assert window.highest_accepted_sequence_number == 63


def test_out_of_order_inside_window_is_accepted() -> None:
    window = SlidingReplayWindow(window_byte_size=4)  # 32-bit window
    window.check_and_record(20)
    # Out-of-order delivery within the window must be accepted.
    window.check_and_record(15)
    window.check_and_record(5)
    window.check_and_record(18)


def test_replay_inside_window_is_rejected() -> None:
    window = SlidingReplayWindow(window_byte_size=4)
    window.check_and_record(10)
    with pytest.raises(ReplayDetected):
        window.check_and_record(10)


def test_replay_of_older_sequence_inside_window_is_rejected() -> None:
    window = SlidingReplayWindow(window_byte_size=8)
    window.check_and_record(50)
    window.check_and_record(45)
    with pytest.raises(ReplayDetected):
        window.check_and_record(45)


def test_sequence_outside_window_is_rejected() -> None:
    window = SlidingReplayWindow(window_byte_size=4)  # 32-bit window
    window.check_and_record(100)
    # 100 - 32 = 68: anything below 68 is outside the window.
    with pytest.raises(ReplayDetected):
        window.check_and_record(67)
    with pytest.raises(ReplayDetected):
        window.check_and_record(0)


def test_sequence_jumping_past_window_resets_history() -> None:
    """A jump greater than the window width zeros the bitmap."""
    window = SlidingReplayWindow(window_byte_size=4)  # 32-bit window
    window.check_and_record(0)
    window.check_and_record(10)
    window.check_and_record(15)
    window.check_and_record(1_000_000)
    # All previous bits should now be outside the window.
    with pytest.raises(ReplayDetected):
        window.check_and_record(15)
    # And the freshly accepted high value cannot be replayed either.
    with pytest.raises(ReplayDetected):
        window.check_and_record(1_000_000)


def test_negative_sequence_number_is_rejected() -> None:
    window = SlidingReplayWindow()
    with pytest.raises(ValueError):
        window.check_and_record(-1)


def test_sequence_at_exact_window_edge_is_accepted() -> None:
    """Sequence number ``highest - (N - 1)`` lies inside the window."""
    window = SlidingReplayWindow(window_byte_size=1)  # 8-bit window
    window.check_and_record(10)
    window.check_and_record(3)  # 10 - 7 = 3, just inside the 8-bit window.


def test_sequence_just_outside_window_edge_is_rejected() -> None:
    window = SlidingReplayWindow(window_byte_size=1)  # 8-bit window
    window.check_and_record(10)
    with pytest.raises(ReplayDetected):
        window.check_and_record(2)  # 10 - 8 = 2, outside the window.


def test_disordered_then_strictly_higher_progresses_window() -> None:
    window = SlidingReplayWindow(window_byte_size=2)  # 16-bit window
    window.check_and_record(5)
    window.check_and_record(3)
    window.check_and_record(10)
    window.check_and_record(8)
    assert window.highest_accepted_sequence_number == 10
    with pytest.raises(ReplayDetected):
        window.check_and_record(8)


def test_window_size_validation() -> None:
    with pytest.raises(ValueError):
        SlidingReplayWindow(window_byte_size=0)
    with pytest.raises(ValueError):
        SlidingReplayWindow(window_byte_size=2048)
