# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Sophisticated attack scenarios against the Phase 3 secure channel.

This module simulates an active attacker on the wire who can:

* duplicate a valid record and re-inject it later (in-window or
  out-of-window replay);
* delay a valid record's delivery so the receiver only sees it long
  after issuance (stale-timestamp replay);
* fabricate a header carrying a timestamp from the future (clock-skew
  spoofing);
* freely reorder records sent over a UDP-style transport.

Each test asserts both the negative case (the attacker's manipulation
must be rejected with the correct typed exception) and the positive
case (legitimate variations of the same scenario must succeed). The
sender's and the receiver's clocks are driven by deterministic in-test
generators that allow time to advance one tick at a time, so race
conditions are eliminated.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from secure_channel.crypto.dstu4145 import (
    Dstu4145PrivateKey,
    Dstu4145SignatureScheme,
)
from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB
from secure_channel.session.handshake import (
    HandshakeIdentityCredentials,
    initiate_handshake,
    respond_to_handshake,
)
from secure_channel.session.records import (
    DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS,
    FreshnessPolicy,
    FutureRecordDetected,
    SequenceNumberOutOfWindow,
    SequenceNumberReplayed,
    StaleRecordDetected,
)
from secure_channel.session.secure_session import SecureSession


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@dataclass
class _ManualMicrosecondClock:
    """Deterministic clock returning whatever the test sets ``current`` to."""

    current_microseconds: int

    def __call__(self) -> int:
        return self.current_microseconds

    def advance_by(self, microseconds: int) -> None:
        self.current_microseconds += microseconds


def _generate_long_term_credentials() -> tuple[Dstu4145PrivateKey, Dstu4145PrivateKey]:
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


@dataclass
class _ChannelEndpoints:
    initiator_clock: _ManualMicrosecondClock
    responder_clock: _ManualMicrosecondClock
    initiator_session: SecureSession
    responder_session: SecureSession


def _open_channel_with_clocks(
    *,
    initial_initiator_microseconds: int = 1_700_000_000_000_000,
    initial_responder_microseconds: int = 1_700_000_000_000_000,
    timestamp_tolerance_microseconds: int = DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS,
    replay_window_byte_size: int = 8,
) -> _ChannelEndpoints:
    """Run the full handshake with deterministic clocks on both sides."""
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    initiator_clock = _ManualMicrosecondClock(initial_initiator_microseconds)
    responder_clock = _ManualMicrosecondClock(initial_responder_microseconds)

    initiator_freshness_policy = FreshnessPolicy(
        clock=responder_clock,  # the initiator's *receiving* clock matches the responder's send clock for symmetry of the test
        timestamp_tolerance_microseconds=timestamp_tolerance_microseconds,
        replay_window_byte_size=replay_window_byte_size,
    )
    responder_freshness_policy = FreshnessPolicy(
        clock=initiator_clock,  # responder *receives* using the initiator's clock to keep the two virtual clocks in lockstep for test reproducibility
        timestamp_tolerance_microseconds=timestamp_tolerance_microseconds,
        replay_window_byte_size=replay_window_byte_size,
    )

    pending_initiator = initiate_handshake(
        initiator_credentials,
        sending_clock=initiator_clock,
        freshness_policy=initiator_freshness_policy,
    )
    pending_responder = respond_to_handshake(
        responder_credentials,
        pending_initiator.message_one_bytes,
        sending_clock=responder_clock,
        freshness_policy=responder_freshness_policy,
    )
    message_three_bytes, initiator_session = pending_initiator.consume_message_two(
        pending_responder.message_two_bytes
    )
    responder_session = pending_responder.consume_message_three(message_three_bytes)
    return _ChannelEndpoints(
        initiator_clock=initiator_clock,
        responder_clock=responder_clock,
        initiator_session=initiator_session,
        responder_session=responder_session,
    )


# ---------------------------------------------------------------------------
# Replay-window scenarios
# ---------------------------------------------------------------------------


def test_attacker_replay_within_window_is_rejected() -> None:
    """A valid record captured and re-injected later must be rejected."""
    endpoints = _open_channel_with_clocks()
    sealed_first: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"first")
    sealed_second: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"second")
    assert endpoints.responder_session.decrypt_incoming_record(sealed_first) == b"first"
    assert endpoints.responder_session.decrypt_incoming_record(sealed_second) == b"second"

    # The attacker re-injects ``sealed_first`` later in the session.
    with pytest.raises(SequenceNumberReplayed):
        endpoints.responder_session.decrypt_incoming_record(sealed_first)


def test_attacker_replay_outside_window_is_rejected_with_specific_error() -> None:
    """Replays older than the sliding window must surface as out-of-window."""
    # Use an 8-bit window so we don't have to send hundreds of records.
    endpoints = _open_channel_with_clocks(replay_window_byte_size=1)
    captured_first_record: bytes = (
        endpoints.initiator_session.encrypt_outgoing_record(b"captured")
    )

    # Send enough additional records to push the captured one out of the
    # 8-bit window (need at least 8 more records).
    for record_index in range(1, 12):
        sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(
            f"r{record_index}".encode()
        )
        endpoints.responder_session.decrypt_incoming_record(sealed)

    # Skipping the first record entirely, the attacker now tries to
    # inject it into the past, well outside the window.
    with pytest.raises(SequenceNumberOutOfWindow):
        endpoints.responder_session.decrypt_incoming_record(captured_first_record)


def test_out_of_order_inside_window_is_accepted() -> None:
    """A record delivered out of order but still inside the window must succeed."""
    endpoints = _open_channel_with_clocks()
    sealed_records: list[bytes] = [
        endpoints.initiator_session.encrypt_outgoing_record(
            f"record-{record_index}".encode()
        )
        for record_index in range(5)
    ]

    # Deliver in the order [2, 0, 4, 1, 3].
    delivery_indexes: list[int] = [2, 0, 4, 1, 3]
    for index in delivery_indexes:
        plaintext: bytes = endpoints.responder_session.decrypt_incoming_record(
            sealed_records[index]
        )
        assert plaintext == f"record-{index}".encode()


def test_replay_of_out_of_order_accepted_record_is_rejected() -> None:
    """Once an out-of-order record is accepted, replaying it must fail."""
    endpoints = _open_channel_with_clocks()
    first_sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"first")
    second_sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"second")
    third_sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"third")

    # Deliver out of order: third, then first.
    endpoints.responder_session.decrypt_incoming_record(third_sealed)
    endpoints.responder_session.decrypt_incoming_record(first_sealed)
    # Now the attacker tries to replay the (already-accepted) first record.
    with pytest.raises(SequenceNumberReplayed):
        endpoints.responder_session.decrypt_incoming_record(first_sealed)
    # The legitimate second record must still be accepted.
    endpoints.responder_session.decrypt_incoming_record(second_sealed)


# ---------------------------------------------------------------------------
# Timestamp scenarios
# ---------------------------------------------------------------------------


def test_record_with_expired_timestamp_is_rejected() -> None:
    """A record stored by the attacker for hours and replayed must be rejected."""
    endpoints = _open_channel_with_clocks(
        timestamp_tolerance_microseconds=5 * 1_000_000  # ±5 seconds tolerance
    )
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"old")

    # Attacker delays delivery by 1 hour --- well past the freshness window.
    endpoints.initiator_clock.advance_by(60 * 60 * 1_000_000)

    with pytest.raises(StaleRecordDetected):
        endpoints.responder_session.decrypt_incoming_record(sealed)


def test_record_with_future_timestamp_is_rejected() -> None:
    """A record whose timestamp lies far in the future must be rejected.

    This simulates either a malicious sender or a desynchronised peer
    whose clock is grossly ahead.
    """
    endpoints = _open_channel_with_clocks(
        timestamp_tolerance_microseconds=5 * 1_000_000
    )
    # The initiator side advances its sending clock by 1 hour before
    # encrypting; the receiver's clock stays at the original time.
    endpoints.initiator_clock.advance_by(60 * 60 * 1_000_000)
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"future")

    # Roll the initiator's clock back so the receiving side (which
    # consults the initiator clock per test setup) sees an old "now"
    # but a far-future record timestamp.
    endpoints.initiator_clock.advance_by(-60 * 60 * 1_000_000)

    with pytest.raises(FutureRecordDetected):
        endpoints.responder_session.decrypt_incoming_record(sealed)


def test_record_at_exact_freshness_boundary_is_accepted() -> None:
    """A record whose age equals the tolerance limit must still be accepted."""
    tolerance: int = 5 * 1_000_000
    endpoints = _open_channel_with_clocks(
        timestamp_tolerance_microseconds=tolerance
    )
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"on-the-edge")

    # Advance by exactly the tolerance --- still inside the closed window.
    endpoints.initiator_clock.advance_by(tolerance)
    plaintext: bytes = endpoints.responder_session.decrypt_incoming_record(sealed)
    assert plaintext == b"on-the-edge"


def test_record_just_outside_freshness_boundary_is_rejected() -> None:
    """A record one microsecond past the freshness limit must be rejected."""
    tolerance: int = 5 * 1_000_000
    endpoints = _open_channel_with_clocks(
        timestamp_tolerance_microseconds=tolerance
    )
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"just-too-old")
    endpoints.initiator_clock.advance_by(tolerance + 1)
    with pytest.raises(StaleRecordDetected):
        endpoints.responder_session.decrypt_incoming_record(sealed)


def test_modest_clock_skew_is_tolerated() -> None:
    """A small clock skew within tolerance must not break the channel."""
    endpoints = _open_channel_with_clocks(
        timestamp_tolerance_microseconds=10 * 1_000_000
    )
    # Sender clock is 2 seconds ahead of receiver clock.
    endpoints.initiator_clock.advance_by(2 * 1_000_000)
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"skew-ok")
    plaintext: bytes = endpoints.responder_session.decrypt_incoming_record(sealed)
    assert plaintext == b"skew-ok"


# ---------------------------------------------------------------------------
# Combined scenarios: replay + timestamp interplay
# ---------------------------------------------------------------------------


def test_freshness_check_runs_independently_of_replay_window() -> None:
    """A fresh-but-replayed record must surface the replay error.

    Order of checks: AEAD → timestamp → replay window. So if the
    timestamp is acceptable, we rely on the replay window to catch
    duplicates.
    """
    endpoints = _open_channel_with_clocks()
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"fresh")
    endpoints.responder_session.decrypt_incoming_record(sealed)
    with pytest.raises(SequenceNumberReplayed):
        endpoints.responder_session.decrypt_incoming_record(sealed)


def test_stale_replay_surfaces_timestamp_error_first() -> None:
    """A replayed record that is also stale must be flagged as stale.

    Order of checks: timestamp comes before the replay window, so a
    record that violates *both* policies is rejected for the timestamp
    reason.
    """
    endpoints = _open_channel_with_clocks(
        timestamp_tolerance_microseconds=5 * 1_000_000
    )
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"stale-replay")
    endpoints.responder_session.decrypt_incoming_record(sealed)
    endpoints.initiator_clock.advance_by(60 * 1_000_000)
    with pytest.raises(StaleRecordDetected):
        endpoints.responder_session.decrypt_incoming_record(sealed)


def test_attacker_cannot_modify_timestamp_field() -> None:
    """Tampering with the timestamp bytes invalidates the AEAD tag."""
    endpoints = _open_channel_with_clocks()
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"signed-time")
    # The timestamp lives in bytes 8..16 of the record header. Flip a
    # bit there; the AEAD authentication must fail (the timestamp is
    # part of the AAD covered by the CMAC tag).
    tampered: bytes = bytearray(sealed)
    tampered[8] ^= 0x01
    from secure_channel.crypto.kalyna_aead import AuthenticationFailed

    with pytest.raises(AuthenticationFailed):
        endpoints.responder_session.decrypt_incoming_record(bytes(tampered))


def test_attacker_cannot_advance_sequence_to_skip_window() -> None:
    """Forging the sequence number invalidates the deterministic nonce."""
    endpoints = _open_channel_with_clocks()
    sealed: bytes = endpoints.initiator_session.encrypt_outgoing_record(b"forge-seq")
    tampered: bytes = bytearray(sealed)
    # Flip a bit inside the sequence-number field (bytes 0..8).
    tampered[7] ^= 0x01
    from secure_channel.crypto.kalyna_aead import AuthenticationFailed

    with pytest.raises(AuthenticationFailed):
        endpoints.responder_session.decrypt_incoming_record(bytes(tampered))
