# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""End-to-end tests for the SIGMA-style handshake and the post-handshake
record protocol.

The tests run the initiator and the responder in the same process,
exchanging byte-string handshake messages directly. This isolates the
cryptographic protocol from any networking dependency and matches the
transport-agnostic design of :mod:`secure_channel.session`.
"""

from __future__ import annotations

import os

import pytest

from secure_channel.crypto.dstu4145 import (
    Dstu4145PrivateKey,
    Dstu4145SignatureScheme,
)
from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB
from secure_channel.crypto.kalyna_aead import AuthenticationFailed
from secure_channel.session.handshake import (
    HandshakeError,
    HandshakeIdentityCredentials,
    initiate_handshake,
    respond_to_handshake,
)


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


def test_full_handshake_produces_matching_session_keys() -> None:
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    pending_initiator = initiate_handshake(initiator_credentials)
    pending_responder = respond_to_handshake(
        responder_credentials, pending_initiator.message_one_bytes
    )
    message_three_bytes, initiator_session = pending_initiator.consume_message_two(
        pending_responder.message_two_bytes
    )
    responder_session = pending_responder.consume_message_three(
        message_three_bytes
    )

    payload_initiator_to_responder: bytes = b"hello from initiator"
    sealed_to_responder: bytes = initiator_session.encrypt_outgoing_record(
        payload_initiator_to_responder
    )
    decoded_by_responder: bytes = responder_session.decrypt_incoming_record(
        sealed_to_responder
    )
    assert decoded_by_responder == payload_initiator_to_responder

    payload_responder_to_initiator: bytes = b"reply from responder"
    sealed_to_initiator: bytes = responder_session.encrypt_outgoing_record(
        payload_responder_to_initiator
    )
    decoded_by_initiator: bytes = initiator_session.decrypt_incoming_record(
        sealed_to_initiator
    )
    assert decoded_by_initiator == payload_responder_to_initiator


def test_handshake_records_increment_sequence_numbers() -> None:
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )
    pending_initiator = initiate_handshake(initiator_credentials)
    pending_responder = respond_to_handshake(
        responder_credentials, pending_initiator.message_one_bytes
    )
    message_three_bytes, initiator_session = pending_initiator.consume_message_two(
        pending_responder.message_two_bytes
    )
    responder_session = pending_responder.consume_message_three(message_three_bytes)

    for record_index in range(5):
        payload: bytes = f"record number {record_index}".encode()
        sealed: bytes = initiator_session.encrypt_outgoing_record(payload)
        assert responder_session.decrypt_incoming_record(sealed) == payload
        assert (
            responder_session.highest_accepted_incoming_sequence_number == record_index
        )


def test_replayed_record_is_rejected() -> None:
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )
    pending_initiator = initiate_handshake(initiator_credentials)
    pending_responder = respond_to_handshake(
        responder_credentials, pending_initiator.message_one_bytes
    )
    message_three_bytes, initiator_session = pending_initiator.consume_message_two(
        pending_responder.message_two_bytes
    )
    responder_session = pending_responder.consume_message_three(message_three_bytes)

    sealed: bytes = initiator_session.encrypt_outgoing_record(b"payload")
    assert responder_session.decrypt_incoming_record(sealed) == b"payload"
    with pytest.raises(AuthenticationFailed):
        responder_session.decrypt_incoming_record(sealed)


def test_man_in_the_middle_substituted_ephemeral_key_is_detected() -> None:
    """Tampering with the responder's ephemeral key invalidates msg2."""
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )
    pending_initiator = initiate_handshake(initiator_credentials)
    pending_responder = respond_to_handshake(
        responder_credentials, pending_initiator.message_one_bytes
    )
    # Flip one byte inside msg2 (somewhere in the second length-prefixed
    # field, which is the responder's ephemeral key encoding).
    tampered_message_two_bytes: bytes = bytearray(pending_responder.message_two_bytes)
    tampered_message_two_bytes[20] ^= 0x01
    with pytest.raises((HandshakeError, ValueError)):
        pending_initiator.consume_message_two(bytes(tampered_message_two_bytes))


def test_initiator_signature_with_wrong_long_term_key_is_rejected() -> None:
    """The responder must reject msg3 if it was signed by a stranger."""
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    impostor_private_key, _ = _generate_long_term_credentials()

    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    # Responder believes the *impostor* key is the initiator's long-term key.
    responder_credentials = _credentials_for(
        responder_private_key, impostor_private_key
    )

    pending_initiator = initiate_handshake(initiator_credentials)
    pending_responder = respond_to_handshake(
        responder_credentials, pending_initiator.message_one_bytes
    )
    message_three_bytes, _ = pending_initiator.consume_message_two(
        pending_responder.message_two_bytes
    )
    with pytest.raises(HandshakeError):
        pending_responder.consume_message_three(message_three_bytes)


def test_responder_with_wrong_long_term_key_is_rejected() -> None:
    """The initiator must reject msg2 if it was signed by a stranger."""
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    impostor_private_key, _ = _generate_long_term_credentials()

    initiator_credentials = _credentials_for(
        initiator_private_key, impostor_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    pending_initiator = initiate_handshake(initiator_credentials)
    pending_responder = respond_to_handshake(
        responder_credentials, pending_initiator.message_one_bytes
    )
    with pytest.raises(HandshakeError):
        pending_initiator.consume_message_two(pending_responder.message_two_bytes)


def test_random_garbage_is_not_a_valid_handshake_message() -> None:
    initiator_private_key, responder_private_key = _generate_long_term_credentials()
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )
    with pytest.raises(ValueError):
        respond_to_handshake(responder_credentials, os.urandom(64))
