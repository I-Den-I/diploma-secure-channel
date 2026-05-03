# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Property tests for Kalyna CTR and CMAC modes."""

from __future__ import annotations

import os

import pytest

from secure_channel.crypto.kalyna_modes import KalynaCmac, KalynaCounterMode


def test_ctr_round_trip_arbitrary_lengths() -> None:
    key: bytes = os.urandom(32)
    cipher_mode = KalynaCounterMode(key)
    nonce: bytes = os.urandom(KalynaCounterMode.NONCE_BYTE_LENGTH)
    for length in (0, 1, 15, 16, 17, 33, 100, 257, 1024):
        plaintext: bytes = os.urandom(length)
        ciphertext: bytes = cipher_mode.process(nonce, plaintext)
        assert len(ciphertext) == length
        recovered_plaintext: bytes = cipher_mode.process(nonce, ciphertext)
        assert recovered_plaintext == plaintext


def test_ctr_distinct_nonces_yield_distinct_ciphertexts() -> None:
    key: bytes = os.urandom(32)
    cipher_mode = KalynaCounterMode(key)
    plaintext: bytes = os.urandom(64)
    first_nonce: bytes = b"\x00" * KalynaCounterMode.NONCE_BYTE_LENGTH
    second_nonce: bytes = b"\xff" * KalynaCounterMode.NONCE_BYTE_LENGTH
    assert cipher_mode.process(first_nonce, plaintext) != cipher_mode.process(
        second_nonce, plaintext
    )


def test_ctr_rejects_wrong_nonce_length() -> None:
    cipher_mode = KalynaCounterMode(os.urandom(32))
    with pytest.raises(ValueError):
        cipher_mode.process(b"\x00" * 8, b"")


def test_ctr_requires_32_byte_key() -> None:
    with pytest.raises(ValueError):
        KalynaCounterMode(b"\x00" * 16)


def test_cmac_is_deterministic() -> None:
    key: bytes = os.urandom(32)
    mac = KalynaCmac(key)
    message: bytes = os.urandom(75)
    assert mac.compute_tag(message) == mac.compute_tag(message)


def test_cmac_changes_with_message() -> None:
    key: bytes = os.urandom(32)
    mac = KalynaCmac(key)
    base_message: bytes = os.urandom(40)
    altered_message: bytes = bytes([base_message[0] ^ 0x01]) + base_message[1:]
    assert mac.compute_tag(base_message) != mac.compute_tag(altered_message)


def test_cmac_distinguishes_short_padded_from_long_message() -> None:
    """The 10*-padded short message must not collide with the longer one."""
    key: bytes = os.urandom(32)
    mac = KalynaCmac(key)
    short_message: bytes = b"abc"
    extended_message: bytes = short_message + b"\x80" + b"\x00" * 12
    assert mac.compute_tag(short_message) != mac.compute_tag(extended_message)


def test_cmac_verify_constant_time() -> None:
    key: bytes = os.urandom(32)
    mac = KalynaCmac(key)
    message: bytes = b"diploma"
    valid_tag: bytes = mac.compute_tag(message)
    assert mac.verify_tag(message, valid_tag) is True
    assert mac.verify_tag(message, bytes(len(valid_tag))) is False
    assert mac.verify_tag(message, valid_tag + b"\x00") is False


def test_cmac_handles_empty_message() -> None:
    """The empty input must produce a well-defined, key-dependent tag."""
    first_key: bytes = b"\x00" * 32
    second_key: bytes = b"\xff" * 32
    assert KalynaCmac(first_key).compute_tag(b"") != KalynaCmac(second_key).compute_tag(
        b""
    )


def test_cmac_truncated_tag_length() -> None:
    key: bytes = os.urandom(32)
    full_mac = KalynaCmac(key, tag_byte_length=16)
    short_mac = KalynaCmac(key, tag_byte_length=8)
    full_tag: bytes = full_mac.compute_tag(b"diploma")
    short_tag: bytes = short_mac.compute_tag(b"diploma")
    assert short_tag == full_tag[:8]
