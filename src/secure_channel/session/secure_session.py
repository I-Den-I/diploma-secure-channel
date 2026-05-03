# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""High-level :class:`SecureSession` exposed to applications.

A :class:`SecureSession` is the post-handshake handle that ties together a
sending and a receiving record-protocol half. It is created by the
handshake module and used by the application layer to encrypt and decrypt
arbitrary payloads.

Two byte-string entry points are provided:

* :meth:`SecureSession.encrypt_outgoing_record` --- wrap an outgoing
  plaintext record into the on-the-wire encrypted form.
* :meth:`SecureSession.decrypt_incoming_record` --- unwrap an incoming
  encrypted record and return the plaintext, raising
  :class:`secure_channel.crypto.kalyna_aead.AuthenticationFailed` (or
  one of its subclasses) when authentication, freshness or replay
  invariants are violated.

The freshness and replay parameters are configurable through a
:class:`secure_channel.session.records.FreshnessPolicy` instance. The
sender's clock is exposed separately so test code can keep the two
clocks in lockstep.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from secure_channel.session.clock import (
    MICROSECOND_WALL_CLOCK,
    MicrosecondClock,
)
from secure_channel.session.records import (
    DirectionalKeySet,
    FreshnessPolicy,
    ReceivingHalf,
    SendingHalf,
)


@dataclass(frozen=True, slots=True)
class SessionRole:
    """Symbolic constants for the two sides of the SIGMA handshake."""

    name: str
    direction_label_outgoing: bytes
    direction_label_incoming: bytes


SESSION_ROLE_INITIATOR: Final[SessionRole] = SessionRole(
    name="initiator",
    direction_label_outgoing=b"i->r",
    direction_label_incoming=b"r->i",
)
"""Role used by the party that sent the first handshake message."""

SESSION_ROLE_RESPONDER: Final[SessionRole] = SessionRole(
    name="responder",
    direction_label_outgoing=b"r->i",
    direction_label_incoming=b"i->r",
)
"""Role used by the party that sent the second handshake message."""


class SecureSession:
    """Post-handshake bidirectional encrypted channel.

    :param outgoing_key_set: Per-record AEAD key + direction prefix used
        to encrypt records the local peer transmits.
    :param incoming_key_set: Per-record AEAD key + direction prefix used
        to verify records the remote peer transmits.
    :param role: Whether this peer played the SIGMA initiator or
        responder role during the handshake.
    :param sending_clock: Wall-clock provider used to stamp outgoing
        records.
    :param freshness_policy: Receiver-side freshness and replay
        configuration.
    """

    __slots__ = ("_sending_half", "_receiving_half", "_role")

    def __init__(
        self,
        outgoing_key_set: DirectionalKeySet,
        incoming_key_set: DirectionalKeySet,
        role: SessionRole,
        *,
        sending_clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
        freshness_policy: FreshnessPolicy | None = None,
    ) -> None:
        self._sending_half: Final[SendingHalf] = SendingHalf(
            outgoing_key_set, clock=sending_clock
        )
        self._receiving_half: Final[ReceivingHalf] = ReceivingHalf(
            incoming_key_set, policy=freshness_policy
        )
        self._role: Final[SessionRole] = role

    @property
    def role(self) -> SessionRole:
        """Local peer's role in the underlying handshake."""
        return self._role

    @property
    def next_outgoing_sequence_number(self) -> int:
        """Sequence number the next outgoing record will use."""
        return self._sending_half.next_sequence_number

    @property
    def highest_accepted_incoming_sequence_number(self) -> int:
        """Largest sequence number successfully decrypted so far (-1 if none)."""
        return self._receiving_half.highest_accepted_sequence_number

    def encrypt_outgoing_record(self, plaintext: bytes) -> bytes:
        """Wrap an application record into its encrypted on-wire form."""
        return self._sending_half.encrypt_record(plaintext)

    def decrypt_incoming_record(self, wire_bytes: bytes) -> bytes:
        """Return the plaintext of an authenticated incoming record."""
        return self._receiving_half.decrypt_record(wire_bytes)


__all__: Final[list[str]] = [
    "SESSION_ROLE_INITIATOR",
    "SESSION_ROLE_RESPONDER",
    "SecureSession",
    "SessionRole",
]
