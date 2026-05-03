# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Tests for the Kalyna-CMAC-based HKDF analogue."""

from __future__ import annotations

import os

import pytest

from secure_channel.crypto.kdf import derive_keys_from_shared_secret


def test_kdf_is_deterministic_for_identical_inputs() -> None:
    shared_secret: bytes = os.urandom(32)
    info: bytes = b"diploma-test"
    salt: bytes = os.urandom(16)
    first_run: bytes = derive_keys_from_shared_secret(
        shared_secret, info=info, salt=salt, output_byte_length=64
    )
    second_run: bytes = derive_keys_from_shared_secret(
        shared_secret, info=info, salt=salt, output_byte_length=64
    )
    assert first_run == second_run


def test_kdf_changes_with_info_label() -> None:
    shared_secret: bytes = os.urandom(32)
    salt: bytes = b""
    first_label: bytes = derive_keys_from_shared_secret(
        shared_secret, info=b"alpha", salt=salt, output_byte_length=32
    )
    second_label: bytes = derive_keys_from_shared_secret(
        shared_secret, info=b"beta", salt=salt, output_byte_length=32
    )
    assert first_label != second_label


def test_kdf_changes_with_salt() -> None:
    shared_secret: bytes = os.urandom(32)
    info: bytes = b"label"
    first_salt: bytes = derive_keys_from_shared_secret(
        shared_secret, info=info, salt=b"\x01", output_byte_length=32
    )
    second_salt: bytes = derive_keys_from_shared_secret(
        shared_secret, info=info, salt=b"\x02", output_byte_length=32
    )
    assert first_salt != second_salt


def test_kdf_extends_correctly_when_more_blocks_requested() -> None:
    """The first 16 bytes of an N-byte expansion must equal a 16-byte expansion."""
    shared_secret: bytes = os.urandom(32)
    info: bytes = b"prefix"
    salt: bytes = b"salt"
    short_output: bytes = derive_keys_from_shared_secret(
        shared_secret, info=info, salt=salt, output_byte_length=16
    )
    long_output: bytes = derive_keys_from_shared_secret(
        shared_secret, info=info, salt=salt, output_byte_length=64
    )
    assert long_output.startswith(short_output)


def test_kdf_rejects_zero_output_length() -> None:
    with pytest.raises(ValueError):
        derive_keys_from_shared_secret(
            b"k", info=b"i", salt=b"", output_byte_length=0
        )
