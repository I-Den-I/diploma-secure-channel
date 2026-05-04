# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""SIGMA-style mutually authenticated handshake protocol.

The handshake binds two ephemeral Diffie--Hellman public keys to the
participants' long-term DSTU 4145-2002 identities and produces a shared
:class:`SecureSession`. The protocol consists of three messages:

::

    Initiator                                                    Responder
    ---------                                                    ---------
    msg1 = "DSTU-CH/1.0" || nonce_I || E_I_pub
                       --------------------------->
                                                   msg2 = nonce_R || E_R_pub
                                                          || sig_R(transcript_1||2)
                       <---------------------------
    msg3 = sig_I(transcript_1||2||sig_R)
                       --------------------------->

After the third message both parties:

1. Verify the peer's signature against its known long-term public key.
2. Compute the shared secret :math:`S = e_{\\text{self}} \\cdot E_{\\text{peer}}`.
3. Run :func:`derive_keys_from_shared_secret` over
   ``shared_secret || transcript`` to obtain four 32-byte keys (two
   encryption keys and two authentication keys, one per direction).
4. Wrap the keys in a :class:`SecureSession`.

Because the long-term signature covers the full transcript including
both ephemeral public keys and the handshake nonces, an in-the-middle
attacker cannot substitute its own ephemeral keys without invalidating
either signature: this delivers mutual authentication and protects the
agreed shared secret from tampering, the cornerstone defence against the
*man-in-the-middle attack* required by Phase 3.

Out-of-scope concerns:
    Long-term identity binding (PKI, certificate validation, ...) is
    explicitly out of scope: the application layer must obtain the
    counterparty's long-term DSTU 4145 public key through some trusted
    side-channel before invoking the handshake.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Final

from secure_channel.crypto.binary_curve import BinaryCurvePoint
from secure_channel.crypto.dstu4145 import (
    Dstu4145PrivateKey,
    Dstu4145PublicKey,
    Dstu4145SignatureScheme,
)
from secure_channel.crypto.dstu4145_curves import Dstu4145DomainParameters
from secure_channel.crypto.kalyna_aead import KalynaAeadKey
from secure_channel.crypto.kdf import derive_keys_from_shared_secret
from secure_channel.session.clock import (
    MICROSECOND_WALL_CLOCK,
    MicrosecondClock,
)
from secure_channel.session.key_exchange import (
    EphemeralKeyAgreementKeyPair,
    RandomBytesProvider,
    compute_shared_secret_x_bytes,
    decode_ephemeral_public_key,
    encode_ephemeral_public_key,
    generate_ephemeral_key_pair,
)
from secure_channel.session.records import DirectionalKeySet, FreshnessPolicy
from secure_channel.session.secure_session import (
    SESSION_ROLE_INITIATOR,
    SESSION_ROLE_RESPONDER,
    SecureSession,
)


PROTOCOL_VERSION_LABEL: Final[bytes] = b"DSTU-CH/1.0"
"""Wire-level protocol version identifier."""

HANDSHAKE_NONCE_BYTE_LENGTH: Final[int] = 16
"""Length of the random handshake nonces ``nonce_I`` and ``nonce_R``."""

_KEY_DERIVATION_INFO_LABEL: Final[bytes] = b"DSTU-CH/1.0/session-keys"
"""Application-specific KDF context label."""

_TOTAL_DERIVED_KEY_BYTE_LENGTH: Final[int] = 4 * 32
"""Two AEAD keys per direction at 32 bytes each (encrypt + MAC)."""


# ---------------------------------------------------------------------------
# Wire-format helpers
# ---------------------------------------------------------------------------


def _length_prefixed(byte_string: bytes) -> bytes:
    """Encode a byte string with a 4-byte big-endian length prefix."""
    return len(byte_string).to_bytes(4, "big") + byte_string


def _consume_length_prefixed(buffer: bytes, offset: int) -> tuple[bytes, int]:
    """Inverse of :func:`_length_prefixed`; returns ``(value, new_offset)``."""
    if len(buffer) < offset + 4:
        raise ValueError("Truncated handshake message: missing length prefix.")
    field_byte_length: int = int.from_bytes(buffer[offset : offset + 4], "big")
    consumed_offset: int = offset + 4 + field_byte_length
    if len(buffer) < consumed_offset:
        raise ValueError("Truncated handshake message: incomplete field.")
    return buffer[offset + 4 : consumed_offset], consumed_offset


def _hash_transcript(transcript: bytes) -> bytes:
    """Hash the transcript with SHA-256 for use as a signature digest.

    Although the secure channel is built around DSTU 7624 and DSTU 4145,
    the diploma project does not implement DSTU 7564 (Kupyna) for time
    reasons. SHA-256 is well understood and its 256-bit output is then
    truncated to the field size by the DSTU 4145 signature primitive.
    The choice of hash function does not affect the security analysis as
    long as it is collision resistant. A future revision may swap in
    Kupyna without changing the protocol on the wire.
    """
    return hashlib.sha256(transcript).digest()


def _derive_session_keys(
    shared_secret: bytes,
    handshake_transcript: bytes,
) -> tuple[KalynaAeadKey, KalynaAeadKey]:
    """Derive the two directional AEAD keys from the shared secret.

    :returns: ``(initiator_to_responder_key, responder_to_initiator_key)``.
    """
    derived_key_material: bytes = derive_keys_from_shared_secret(
        shared_secret,
        info=_KEY_DERIVATION_INFO_LABEL,
        salt=handshake_transcript,
        output_byte_length=_TOTAL_DERIVED_KEY_BYTE_LENGTH,
    )
    initiator_to_responder_key = KalynaAeadKey.from_concatenated(
        derived_key_material[:64]
    )
    responder_to_initiator_key = KalynaAeadKey.from_concatenated(
        derived_key_material[64:128]
    )
    return initiator_to_responder_key, responder_to_initiator_key


# ---------------------------------------------------------------------------
# Message encoding / decoding
# ---------------------------------------------------------------------------


def _encode_handshake_message_one(
    nonce: bytes, ephemeral_public_key_bytes: bytes
) -> bytes:
    """Serialise the initiator's ``ClientHello``."""
    return (
        _length_prefixed(PROTOCOL_VERSION_LABEL)
        + _length_prefixed(nonce)
        + _length_prefixed(ephemeral_public_key_bytes)
    )


def _decode_handshake_message_one(message_bytes: bytes) -> tuple[bytes, bytes]:
    """Parse a ``ClientHello`` returning ``(nonce, encoded_ephemeral_key)``."""
    protocol_version_label, offset = _consume_length_prefixed(message_bytes, 0)
    if protocol_version_label != PROTOCOL_VERSION_LABEL:
        raise ValueError(
            f"Unsupported protocol version: {protocol_version_label!r}."
        )
    nonce, offset = _consume_length_prefixed(message_bytes, offset)
    if len(nonce) != HANDSHAKE_NONCE_BYTE_LENGTH:
        raise ValueError("ClientHello nonce has unexpected length.")
    ephemeral_public_key_bytes, offset = _consume_length_prefixed(
        message_bytes, offset
    )
    if offset != len(message_bytes):
        raise ValueError("Trailing bytes after ClientHello.")
    return nonce, ephemeral_public_key_bytes


def _encode_handshake_message_two(
    responder_nonce: bytes,
    responder_ephemeral_public_key_bytes: bytes,
    responder_signature: bytes,
) -> bytes:
    return (
        _length_prefixed(responder_nonce)
        + _length_prefixed(responder_ephemeral_public_key_bytes)
        + _length_prefixed(responder_signature)
    )


def _decode_handshake_message_two(
    message_bytes: bytes,
) -> tuple[bytes, bytes, bytes]:
    responder_nonce, offset = _consume_length_prefixed(message_bytes, 0)
    if len(responder_nonce) != HANDSHAKE_NONCE_BYTE_LENGTH:
        raise ValueError("ServerHello nonce has unexpected length.")
    responder_ephemeral_public_key_bytes, offset = _consume_length_prefixed(
        message_bytes, offset
    )
    responder_signature, offset = _consume_length_prefixed(message_bytes, offset)
    if offset != len(message_bytes):
        raise ValueError("Trailing bytes after ServerHello.")
    return responder_nonce, responder_ephemeral_public_key_bytes, responder_signature


def _encode_handshake_message_three(initiator_signature: bytes) -> bytes:
    return _length_prefixed(initiator_signature)


def _decode_handshake_message_three(message_bytes: bytes) -> bytes:
    initiator_signature, offset = _consume_length_prefixed(message_bytes, 0)
    if offset != len(message_bytes):
        raise ValueError("Trailing bytes after ClientFinished.")
    return initiator_signature


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HandshakeIdentityCredentials:
    """Long-term identity credentials of one handshake participant.

    :param domain: Curve, base point and subgroup order. Must match the
        peer's domain.
    :param own_long_term_private_key: Local DSTU 4145 long-term private
        key used to sign the transcript.
    :param peer_long_term_public_key: Authentic copy of the remote
        peer's long-term DSTU 4145 public key. The application is
        responsible for obtaining it through a trusted channel; this
        module performs no certificate validation.
    """

    domain: Dstu4145DomainParameters
    own_long_term_private_key: Dstu4145PrivateKey
    peer_long_term_public_key: Dstu4145PublicKey

    def __post_init__(self) -> None:
        if self.own_long_term_private_key.domain != self.domain:
            raise ValueError("Own private key domain does not match handshake domain.")
        if self.peer_long_term_public_key.domain != self.domain:
            raise ValueError("Peer public key domain does not match handshake domain.")


class HandshakeError(Exception):
    """Raised when the handshake transcript or signature is invalid."""


# ---------------------------------------------------------------------------
# Initiator
# ---------------------------------------------------------------------------


class PendingInitiatorHandshake:
    """Initiator-side state held between sending msg1 and receiving msg2."""

    __slots__ = (
        "_credentials",
        "_ephemeral_key_pair",
        "_initiator_nonce",
        "_message_one_bytes",
        "_signature_scheme",
        "_random_bytes",
        "_sending_clock",
        "_freshness_policy",
    )

    def __init__(
        self,
        credentials: HandshakeIdentityCredentials,
        ephemeral_key_pair: EphemeralKeyAgreementKeyPair,
        initiator_nonce: bytes,
        message_one_bytes: bytes,
        random_bytes: RandomBytesProvider,
        sending_clock: MicrosecondClock,
        freshness_policy: FreshnessPolicy | None,
    ) -> None:
        self._credentials: Final[HandshakeIdentityCredentials] = credentials
        self._ephemeral_key_pair: Final[EphemeralKeyAgreementKeyPair] = (
            ephemeral_key_pair
        )
        self._initiator_nonce: Final[bytes] = initiator_nonce
        self._message_one_bytes: Final[bytes] = message_one_bytes
        self._signature_scheme: Final[Dstu4145SignatureScheme] = (
            Dstu4145SignatureScheme(credentials.domain)
        )
        self._random_bytes: Final[RandomBytesProvider] = random_bytes
        self._sending_clock: Final[MicrosecondClock] = sending_clock
        self._freshness_policy: Final[FreshnessPolicy | None] = freshness_policy

    @property
    def message_one_bytes(self) -> bytes:
        """Encoded ``ClientHello`` to transmit to the responder."""
        return self._message_one_bytes

    def consume_message_two(
        self, message_two_bytes: bytes
    ) -> tuple[bytes, SecureSession]:
        """Verify the responder's reply and produce ``(msg3, session)``."""
        (
            responder_nonce,
            responder_ephemeral_public_key_bytes,
            responder_signature,
        ) = _decode_handshake_message_two(message_two_bytes)

        responder_ephemeral_public_point = decode_ephemeral_public_key(
            self._credentials.domain, responder_ephemeral_public_key_bytes
        )

        # Independent self-consistency check: peer's ephemeral key must
        # lie in the prime-order subgroup, otherwise the shared secret
        # may leak into a small subgroup.
        if not responder_ephemeral_public_point.scalar_multiply(
            self._credentials.domain.subgroup_order
        ).is_infinity:
            raise HandshakeError(
                "Responder ephemeral key is not in the prime-order subgroup."
            )

        signed_transcript: bytes = (
            self._message_one_bytes
            + _length_prefixed(responder_nonce)
            + _length_prefixed(responder_ephemeral_public_key_bytes)
        )
        if not self._signature_scheme.verify(
            self._credentials.peer_long_term_public_key,
            _hash_transcript(signed_transcript),
            responder_signature,
        ):
            raise HandshakeError("Responder transcript signature is invalid.")

        full_transcript_so_far: bytes = signed_transcript + _length_prefixed(
            responder_signature
        )
        initiator_signature: bytes = self._signature_scheme.sign(
            self._credentials.own_long_term_private_key,
            _hash_transcript(full_transcript_so_far),
        )
        message_three_bytes: bytes = _encode_handshake_message_three(
            initiator_signature
        )
        complete_transcript: bytes = (
            full_transcript_so_far + _length_prefixed(initiator_signature)
        )

        shared_secret: bytes = compute_shared_secret_x_bytes(
            self._ephemeral_key_pair, responder_ephemeral_public_point
        )
        initiator_to_responder_key, responder_to_initiator_key = (
            _derive_session_keys(shared_secret, complete_transcript)
        )

        outgoing_key_set = DirectionalKeySet(
            aead_key=initiator_to_responder_key,
            direction_prefix=SESSION_ROLE_INITIATOR.direction_label_outgoing.ljust(
                4, b"\x00"
            ),
        )
        incoming_key_set = DirectionalKeySet(
            aead_key=responder_to_initiator_key,
            direction_prefix=SESSION_ROLE_INITIATOR.direction_label_incoming.ljust(
                4, b"\x00"
            ),
        )
        secure_session = SecureSession(
            outgoing_key_set=outgoing_key_set,
            incoming_key_set=incoming_key_set,
            role=SESSION_ROLE_INITIATOR,
            sending_clock=self._sending_clock,
            freshness_policy=self._freshness_policy,
        )
        return message_three_bytes, secure_session


def initiate_handshake(
    credentials: HandshakeIdentityCredentials,
    *,
    random_bytes: RandomBytesProvider | None = None,
    sending_clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
    freshness_policy: FreshnessPolicy | None = None,
) -> PendingInitiatorHandshake:
    """Begin a handshake from the initiator side.

    :param credentials: Long-term identity credentials of the initiator.
    :param random_bytes: Source of cryptographic randomness.
    :param sending_clock: Wall-clock provider used to stamp outgoing
        records of the resulting :class:`SecureSession`.
    :param freshness_policy: Receiver-side freshness and replay-window
        configuration applied to incoming records.
    :returns: A pending state object whose
        :attr:`PendingInitiatorHandshake.message_one_bytes` attribute
        carries the bytes to transmit to the responder.
    """
    random_source: RandomBytesProvider = random_bytes or os.urandom
    ephemeral_key_pair = generate_ephemeral_key_pair(
        credentials.domain, random_source
    )
    initiator_nonce: bytes = random_source(HANDSHAKE_NONCE_BYTE_LENGTH)
    encoded_ephemeral_public_key: bytes = encode_ephemeral_public_key(
        ephemeral_key_pair.public_point
    )
    message_one_bytes: bytes = _encode_handshake_message_one(
        initiator_nonce, encoded_ephemeral_public_key
    )
    return PendingInitiatorHandshake(
        credentials=credentials,
        ephemeral_key_pair=ephemeral_key_pair,
        initiator_nonce=initiator_nonce,
        message_one_bytes=message_one_bytes,
        random_bytes=random_source,
        sending_clock=sending_clock,
        freshness_policy=freshness_policy,
    )


# ---------------------------------------------------------------------------
# Responder
# ---------------------------------------------------------------------------


class PendingResponderHandshake:
    """Responder-side state held between sending msg2 and receiving msg3."""

    __slots__ = (
        "_credentials",
        "_ephemeral_key_pair",
        "_message_one_bytes",
        "_message_two_bytes",
        "_initiator_ephemeral_public_point",
        "_responder_signature",
        "_signature_scheme",
        "_sending_clock",
        "_freshness_policy",
    )

    def __init__(
        self,
        credentials: HandshakeIdentityCredentials,
        ephemeral_key_pair: EphemeralKeyAgreementKeyPair,
        message_one_bytes: bytes,
        message_two_bytes: bytes,
        initiator_ephemeral_public_point: BinaryCurvePoint,
        responder_signature: bytes,
        sending_clock: MicrosecondClock,
        freshness_policy: FreshnessPolicy | None,
    ) -> None:
        self._credentials: Final[HandshakeIdentityCredentials] = credentials
        self._ephemeral_key_pair: Final[EphemeralKeyAgreementKeyPair] = (
            ephemeral_key_pair
        )
        self._message_one_bytes: Final[bytes] = message_one_bytes
        self._message_two_bytes: Final[bytes] = message_two_bytes
        self._initiator_ephemeral_public_point = initiator_ephemeral_public_point
        self._responder_signature: Final[bytes] = responder_signature
        self._signature_scheme: Final[Dstu4145SignatureScheme] = (
            Dstu4145SignatureScheme(credentials.domain)
        )
        self._sending_clock: Final[MicrosecondClock] = sending_clock
        self._freshness_policy: Final[FreshnessPolicy | None] = freshness_policy

    @property
    def message_two_bytes(self) -> bytes:
        """Encoded ``ServerHello`` to transmit back to the initiator."""
        return self._message_two_bytes

    def consume_message_three(self, message_three_bytes: bytes) -> SecureSession:
        """Verify the initiator's signature and produce the active session."""
        initiator_signature: bytes = _decode_handshake_message_three(
            message_three_bytes
        )

        signed_transcript: bytes = (
            self._message_one_bytes
            + self._message_two_bytes
        )
        # Note: msg2 already includes the responder's signature with its
        # length prefix, so the transcript signed by the initiator is
        # just the concatenation of msg1 and msg2.
        if not self._signature_scheme.verify(
            self._credentials.peer_long_term_public_key,
            _hash_transcript(signed_transcript),
            initiator_signature,
        ):
            raise HandshakeError("Initiator transcript signature is invalid.")

        complete_transcript: bytes = signed_transcript + _length_prefixed(
            initiator_signature
        )
        shared_secret: bytes = compute_shared_secret_x_bytes(
            self._ephemeral_key_pair, self._initiator_ephemeral_public_point
        )
        initiator_to_responder_key, responder_to_initiator_key = (
            _derive_session_keys(shared_secret, complete_transcript)
        )

        outgoing_key_set = DirectionalKeySet(
            aead_key=responder_to_initiator_key,
            direction_prefix=SESSION_ROLE_RESPONDER.direction_label_outgoing.ljust(
                4, b"\x00"
            ),
        )
        incoming_key_set = DirectionalKeySet(
            aead_key=initiator_to_responder_key,
            direction_prefix=SESSION_ROLE_RESPONDER.direction_label_incoming.ljust(
                4, b"\x00"
            ),
        )
        return SecureSession(
            outgoing_key_set=outgoing_key_set,
            incoming_key_set=incoming_key_set,
            role=SESSION_ROLE_RESPONDER,
            sending_clock=self._sending_clock,
            freshness_policy=self._freshness_policy,
        )


def respond_to_handshake(
    credentials: HandshakeIdentityCredentials,
    message_one_bytes: bytes,
    *,
    random_bytes: RandomBytesProvider | None = None,
    sending_clock: MicrosecondClock = MICROSECOND_WALL_CLOCK,
    freshness_policy: FreshnessPolicy | None = None,
) -> PendingResponderHandshake:
    """Process ``msg1`` and prepare ``msg2`` plus the responder's pending state.

    :param credentials: Long-term identity credentials of the responder.
    :param message_one_bytes: ``ClientHello`` message received from the
        initiator over the wire.
    :param random_bytes: Source of cryptographic randomness.
    :param sending_clock: Wall-clock provider used to stamp outgoing
        records of the resulting :class:`SecureSession`.
    :param freshness_policy: Receiver-side freshness and replay-window
        configuration applied to incoming records.
    """
    random_source: RandomBytesProvider = random_bytes or os.urandom
    initiator_nonce, encoded_initiator_ephemeral_public_key = (
        _decode_handshake_message_one(message_one_bytes)
    )
    initiator_ephemeral_public_point = decode_ephemeral_public_key(
        credentials.domain, encoded_initiator_ephemeral_public_key
    )
    if not initiator_ephemeral_public_point.scalar_multiply(
        credentials.domain.subgroup_order
    ).is_infinity:
        raise HandshakeError(
            "Initiator ephemeral key is not in the prime-order subgroup."
        )

    ephemeral_key_pair = generate_ephemeral_key_pair(credentials.domain, random_source)
    responder_nonce: bytes = random_source(HANDSHAKE_NONCE_BYTE_LENGTH)
    encoded_responder_ephemeral_public_key: bytes = encode_ephemeral_public_key(
        ephemeral_key_pair.public_point
    )

    signature_scheme = Dstu4145SignatureScheme(credentials.domain)
    transcript_to_be_signed: bytes = (
        message_one_bytes
        + _length_prefixed(responder_nonce)
        + _length_prefixed(encoded_responder_ephemeral_public_key)
    )
    responder_signature: bytes = signature_scheme.sign(
        credentials.own_long_term_private_key,
        _hash_transcript(transcript_to_be_signed),
    )

    message_two_bytes: bytes = _encode_handshake_message_two(
        responder_nonce,
        encoded_responder_ephemeral_public_key,
        responder_signature,
    )

    return PendingResponderHandshake(
        credentials=credentials,
        ephemeral_key_pair=ephemeral_key_pair,
        message_one_bytes=message_one_bytes,
        message_two_bytes=message_two_bytes,
        initiator_ephemeral_public_point=initiator_ephemeral_public_point,
        responder_signature=responder_signature,
        sending_clock=sending_clock,
        freshness_policy=freshness_policy,
    )


__all__: Final[list[str]] = [
    "HANDSHAKE_NONCE_BYTE_LENGTH",
    "HandshakeError",
    "HandshakeIdentityCredentials",
    "PendingInitiatorHandshake",
    "PendingResponderHandshake",
    "PROTOCOL_VERSION_LABEL",
    "initiate_handshake",
    "respond_to_handshake",
]
