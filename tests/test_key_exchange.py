# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Tests for the ephemeral ECDH module of the session layer."""

from __future__ import annotations

import pytest

from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB
from secure_channel.session.key_exchange import (
    compute_shared_secret_x_bytes,
    decode_ephemeral_public_key,
    encode_ephemeral_public_key,
    generate_ephemeral_key_pair,
)


def test_two_parties_derive_identical_shared_secret() -> None:
    domain = DSTU4145_M163_PB
    initiator_key_pair = generate_ephemeral_key_pair(domain)
    responder_key_pair = generate_ephemeral_key_pair(domain)
    shared_for_initiator: bytes = compute_shared_secret_x_bytes(
        initiator_key_pair, responder_key_pair.public_point
    )
    shared_for_responder: bytes = compute_shared_secret_x_bytes(
        responder_key_pair, initiator_key_pair.public_point
    )
    assert shared_for_initiator == shared_for_responder


def test_public_key_encoding_round_trip() -> None:
    domain = DSTU4145_M163_PB
    key_pair = generate_ephemeral_key_pair(domain)
    encoded: bytes = encode_ephemeral_public_key(key_pair.public_point)
    decoded = decode_ephemeral_public_key(domain, encoded)
    assert decoded == key_pair.public_point


def test_decoding_rejects_off_curve_point() -> None:
    domain = DSTU4145_M163_PB
    coordinate_byte_length: int = (domain.curve.field.degree + 7) // 8
    bogus_encoded: bytes = (1).to_bytes(coordinate_byte_length, "big") + (
        1
    ).to_bytes(coordinate_byte_length, "big")
    with pytest.raises(ValueError):
        decode_ephemeral_public_key(domain, bogus_encoded)


def test_decoding_rejects_truncated_encoding() -> None:
    domain = DSTU4145_M163_PB
    with pytest.raises(ValueError):
        decode_ephemeral_public_key(domain, b"\x00" * 5)


def test_distinct_key_pairs_yield_distinct_shared_secrets() -> None:
    domain = DSTU4145_M163_PB
    initiator_key_pair = generate_ephemeral_key_pair(domain)
    first_responder = generate_ephemeral_key_pair(domain)
    second_responder = generate_ephemeral_key_pair(domain)
    first_secret: bytes = compute_shared_secret_x_bytes(
        initiator_key_pair, first_responder.public_point
    )
    second_secret: bytes = compute_shared_secret_x_bytes(
        initiator_key_pair, second_responder.public_point
    )
    assert first_secret != second_secret
