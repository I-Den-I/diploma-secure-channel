# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Tests for the Kalyna encrypt-then-MAC AEAD wrapper."""

from __future__ import annotations

import os

import pytest

from secure_channel.crypto.kalyna_aead import (
    AuthenticationFailed,
    KalynaAead,
    KalynaAeadKey,
)


def _fresh_aead() -> tuple[KalynaAead, bytes]:
    key = KalynaAeadKey(
        encryption_key=os.urandom(32),
        authentication_key=os.urandom(32),
    )
    return KalynaAead(key), os.urandom(KalynaAead.NONCE_BYTE_LENGTH)


def test_aead_round_trip_random_lengths() -> None:
    aead, nonce = _fresh_aead()
    for length in (0, 1, 16, 17, 64, 1024):
        plaintext: bytes = os.urandom(length)
        sealed: bytes = aead.encrypt(nonce, plaintext, associated_data=b"context")
        recovered: bytes = aead.decrypt(sealed, associated_data=b"context")
        assert recovered == plaintext


def test_aead_authentication_failure_on_modified_ciphertext() -> None:
    aead, nonce = _fresh_aead()
    plaintext: bytes = b"diploma payload"
    sealed: bytes = aead.encrypt(nonce, plaintext)
    # Flip a bit somewhere in the encrypted payload (after the nonce).
    tampered: bytes = (
        sealed[: KalynaAead.NONCE_BYTE_LENGTH]
        + bytes([sealed[KalynaAead.NONCE_BYTE_LENGTH] ^ 0x01])
        + sealed[KalynaAead.NONCE_BYTE_LENGTH + 1 :]
    )
    with pytest.raises(AuthenticationFailed):
        aead.decrypt(tampered)


def test_aead_authentication_failure_on_modified_aad() -> None:
    aead, nonce = _fresh_aead()
    sealed: bytes = aead.encrypt(nonce, b"plain", associated_data=b"context")
    with pytest.raises(AuthenticationFailed):
        aead.decrypt(sealed, associated_data=b"context-tampered")


def test_aead_truncated_record_is_rejected() -> None:
    aead, _ = _fresh_aead()
    with pytest.raises(AuthenticationFailed):
        aead.decrypt(b"\x00" * 5)


def test_aead_keys_must_have_correct_length() -> None:
    with pytest.raises(ValueError):
        KalynaAeadKey(encryption_key=b"\x00" * 31, authentication_key=b"\x00" * 32)
    with pytest.raises(ValueError):
        KalynaAeadKey(encryption_key=b"\x00" * 32, authentication_key=b"\x00" * 33)


def test_aead_key_from_concatenated_splits_correctly() -> None:
    raw: bytes = bytes(range(64))
    key = KalynaAeadKey.from_concatenated(raw)
    assert key.encryption_key == raw[:32]
    assert key.authentication_key == raw[32:]


def test_aead_key_from_concatenated_rejects_wrong_length() -> None:
    with pytest.raises(ValueError):
        KalynaAeadKey.from_concatenated(b"\x00" * 63)


def test_aead_aad_substitution_attack_blocked() -> None:
    """Length-prefixed AAD prevents trivial AAD/ciphertext shifting attacks."""
    aead, nonce = _fresh_aead()
    plaintext: bytes = b"AB"
    sealed_with_long_aad: bytes = aead.encrypt(nonce, plaintext, associated_data=b"XX")
    # Cannot simply swap a byte between AAD and ciphertext because the
    # AAD is length-prefixed inside the MAC input.
    with pytest.raises(AuthenticationFailed):
        aead.decrypt(sealed_with_long_aad, associated_data=b"XXX")
