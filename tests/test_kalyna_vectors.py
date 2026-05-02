# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Verification of the Kalyna (DSTU 7624:2014) implementation against the
official test vectors published in Annex A of the standard.

Every parameter combination defined by DSTU 7624:2014 is exercised in both
the enciphering and the deciphering directions:

* ``Kalyna(128, 128)``
* ``Kalyna(128, 256)``
* ``Kalyna(256, 256)``
* ``Kalyna(256, 512)``
* ``Kalyna(512, 512)``

In addition, a property test verifies that for arbitrary deterministic
plaintexts ``decrypt(encrypt(p)) == p`` for every variant.

The expected values are stored as tuples of 64-bit little-endian words
(matching the natural representation of the cipher state in the standard).
A small helper converts them to byte strings before comparison so the
canonical word values from Annex A remain copy-paste verifiable against
the source standard.

Reference: DSTU 7624:2014, Annex A. The byte-level vectors below were
produced by the authors of the standard and re-published in the Kalyna
reference implementation by Roman Oliynykov et al.:
https://github.com/Roman-Oliynykov/Kalyna-reference (file ``main.c``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Sequence

import pytest

from secure_channel.crypto.kalyna import KalynaCipher, KalynaParameters


def _words_to_le_bytes(words: Sequence[int]) -> bytes:
    """Concatenate ``words`` as little-endian 64-bit unsigned integers."""
    return b"".join(int(w).to_bytes(8, "little") for w in words)


@dataclass(frozen=True)
class _KalynaVector:
    """A single Annex-A test vector expressed via 64-bit words."""

    label: str
    block_bits: int
    key_bits: int
    key_words: tuple[int, ...]
    plaintext_words: tuple[int, ...]
    ciphertext_words: tuple[int, ...]

    @property
    def parameters(self) -> KalynaParameters:
        return KalynaParameters(
            block_bit_length=self.block_bits, key_bit_length=self.key_bits
        )

    @property
    def key(self) -> bytes:
        return _words_to_le_bytes(self.key_words)

    @property
    def plaintext(self) -> bytes:
        return _words_to_le_bytes(self.plaintext_words)

    @property
    def ciphertext(self) -> bytes:
        return _words_to_le_bytes(self.ciphertext_words)


# ---------------------------------------------------------------------------
# Encipherment vectors (Annex A.1 of DSTU 7624:2014)
# ---------------------------------------------------------------------------
ENCIPHER_VECTORS: tuple[_KalynaVector, ...] = (
    _KalynaVector(
        label="Kalyna(128, 128) encrypt",
        block_bits=128,
        key_bits=128,
        key_words=(0x0706050403020100, 0x0F0E0D0C0B0A0908),
        plaintext_words=(0x1716151413121110, 0x1F1E1D1C1B1A1918),
        ciphertext_words=(0x20AC9B777D1CBF81, 0x06ADD2B439EAC9E1),
    ),
    _KalynaVector(
        label="Kalyna(128, 256) encrypt",
        block_bits=128,
        key_bits=256,
        key_words=(
            0x0706050403020100,
            0x0F0E0D0C0B0A0908,
            0x1716151413121110,
            0x1F1E1D1C1B1A1918,
        ),
        plaintext_words=(0x2726252423222120, 0x2F2E2D2C2B2A2928),
        ciphertext_words=(0x8A150010093EEC58, 0x144F336F16F74811),
    ),
    _KalynaVector(
        label="Kalyna(256, 256) encrypt",
        block_bits=256,
        key_bits=256,
        key_words=(
            0x0706050403020100,
            0x0F0E0D0C0B0A0908,
            0x1716151413121110,
            0x1F1E1D1C1B1A1918,
        ),
        plaintext_words=(
            0x2726252423222120,
            0x2F2E2D2C2B2A2928,
            0x3736353433323130,
            0x3F3E3D3C3B3A3938,
        ),
        ciphertext_words=(
            0x3521C90E573D6EF6,
            0x8C2ABDDC23E3DAAE,
            0x5A0D6A20EC6339A0,
            0x2CD97F61245C3888,
        ),
    ),
    _KalynaVector(
        label="Kalyna(256, 512) encrypt",
        block_bits=256,
        key_bits=512,
        key_words=(
            0x0706050403020100,
            0x0F0E0D0C0B0A0908,
            0x1716151413121110,
            0x1F1E1D1C1B1A1918,
            0x2726252423222120,
            0x2F2E2D2C2B2A2928,
            0x3736353433323130,
            0x3F3E3D3C3B3A3938,
        ),
        plaintext_words=(
            0x4746454443424140,
            0x4F4E4D4C4B4A4948,
            0x5756555453525150,
            0x5F5E5D5C5B5A5958,
        ),
        ciphertext_words=(
            0x7AB6B7E6E9906960,
            0xB76822D793D8D64B,
            0x02E1D73C3CC8028E,
            0xD95DFEFDA8742EFD,
        ),
    ),
    _KalynaVector(
        label="Kalyna(512, 512) encrypt",
        block_bits=512,
        key_bits=512,
        key_words=(
            0x0706050403020100,
            0x0F0E0D0C0B0A0908,
            0x1716151413121110,
            0x1F1E1D1C1B1A1918,
            0x2726252423222120,
            0x2F2E2D2C2B2A2928,
            0x3736353433323130,
            0x3F3E3D3C3B3A3938,
        ),
        plaintext_words=(
            0x4746454443424140,
            0x4F4E4D4C4B4A4948,
            0x5756555453525150,
            0x5F5E5D5C5B5A5958,
            0x6766656463626160,
            0x6F6E6D6C6B6A6968,
            0x7776757473727170,
            0x7F7E7D7C7B7A7978,
        ),
        ciphertext_words=(
            0x6A351C811BE3264A,
            0x1A239605CAD61DA6,
            0xA1F347AA5483BA67,
            0xB856EB20C3EE1D3E,
            0x66AB5B1717F4D095,
            0x6CC815BB34F1D62F,
            0xB7FE6E85266A90CB,
            0xD9D90D947264BCC5,
        ),
    ),
)


# ---------------------------------------------------------------------------
# Decipherment vectors (Annex A.2 of DSTU 7624:2014)
# ---------------------------------------------------------------------------
DECIPHER_VECTORS: tuple[_KalynaVector, ...] = (
    _KalynaVector(
        label="Kalyna(128, 128) decrypt",
        block_bits=128,
        key_bits=128,
        key_words=(0x08090A0B0C0D0E0F, 0x0001020304050607),
        ciphertext_words=(0x18191A1B1C1D1E1F, 0x1011121314151617),
        plaintext_words=(0x84C70C472BEF9172, 0xD7DA733930C2096F),
    ),
    _KalynaVector(
        label="Kalyna(128, 256) decrypt",
        block_bits=128,
        key_bits=256,
        key_words=(
            0x18191A1B1C1D1E1F,
            0x1011121314151617,
            0x08090A0B0C0D0E0F,
            0x0001020304050607,
        ),
        ciphertext_words=(0x28292A2B2C2D2E2F, 0x2021222324252627),
        plaintext_words=(0xE1DFFDCE56B46DF3, 0x96D9CA30705F5BB4),
    ),
    _KalynaVector(
        label="Kalyna(256, 256) decrypt",
        block_bits=256,
        key_bits=256,
        key_words=(
            0x18191A1B1C1D1E1F,
            0x1011121314151617,
            0x08090A0B0C0D0E0F,
            0x0001020304050607,
        ),
        ciphertext_words=(
            0x38393A3B3C3D3E3F,
            0x3031323334353637,
            0x28292A2B2C2D2E2F,
            0x2021222324252627,
        ),
        plaintext_words=(
            0x864E67967823C57F,
            0xA34B8B3FB0E9C103,
            0xD3C33F2C597C5BAB,
            0xE30FB28625D1ED61,
        ),
    ),
    _KalynaVector(
        label="Kalyna(256, 512) decrypt",
        block_bits=256,
        key_bits=512,
        key_words=(
            0x38393A3B3C3D3E3F,
            0x3031323334353637,
            0x28292A2B2C2D2E2F,
            0x2021222324252627,
            0x18191A1B1C1D1E1F,
            0x1011121314151617,
            0x08090A0B0C0D0E0F,
            0x0001020304050607,
        ),
        ciphertext_words=(
            0x58595A5B5C5D5E5F,
            0x5051525354555657,
            0x48494A4B4C4D4E4F,
            0x4041424344454647,
        ),
        plaintext_words=(
            0x82D4DA67277A3118,
            0x078D78A1B907CDBC,
            0x97845F9E1898705E,
            0xE06ABA796D910B2D,
        ),
    ),
    _KalynaVector(
        label="Kalyna(512, 512) decrypt",
        block_bits=512,
        key_bits=512,
        key_words=(
            0x38393A3B3C3D3E3F,
            0x3031323334353637,
            0x28292A2B2C2D2E2F,
            0x2021222324252627,
            0x18191A1B1C1D1E1F,
            0x1011121314151617,
            0x08090A0B0C0D0E0F,
            0x0001020304050607,
        ),
        ciphertext_words=(
            0x78797A7B7C7D7E7F,
            0x7071727374757677,
            0x68696A6B6C6D6E6F,
            0x6061626364656667,
            0x58595A5B5C5D5E5F,
            0x5051525354555657,
            0x48494A4B4C4D4E4F,
            0x4041424344454647,
        ),
        plaintext_words=(
            0x5252A025338480CE,
            0x29D8A9E614D7EA1B,
            0xBD45A8E90E1E38FD,
            0xA346FAD954450492,
            0xF2B13B85DBEF7F75,
            0x6AE6753B839DFF97,
            0xDC1B29B5AB5741AF,
            0x22FF5AAA13BB94F0,
        ),
    ),
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("vector", ENCIPHER_VECTORS, ids=lambda v: v.label)
def test_encipher_matches_dstu_annex_a_vector(vector: _KalynaVector) -> None:
    """The encipherment of every Annex A vector must match exactly."""
    cipher = KalynaCipher(vector.parameters, vector.key)
    produced_ciphertext: bytes = cipher.encrypt_block(vector.plaintext)
    assert produced_ciphertext == vector.ciphertext, (
        f"Ciphertext mismatch for {vector.label}:\n"
        f"  expected: {vector.ciphertext.hex()}\n"
        f"  produced: {produced_ciphertext.hex()}"
    )


@pytest.mark.parametrize("vector", DECIPHER_VECTORS, ids=lambda v: v.label)
def test_decipher_matches_dstu_annex_a_vector(vector: _KalynaVector) -> None:
    """The decipherment of every Annex A vector must match exactly."""
    cipher = KalynaCipher(vector.parameters, vector.key)
    produced_plaintext: bytes = cipher.decrypt_block(vector.ciphertext)
    assert produced_plaintext == vector.plaintext, (
        f"Plaintext mismatch for {vector.label}:\n"
        f"  expected: {vector.plaintext.hex()}\n"
        f"  produced: {produced_plaintext.hex()}"
    )


@pytest.mark.parametrize(
    ("block_bits", "key_bits"),
    [(128, 128), (128, 256), (256, 256), (256, 512), (512, 512)],
)
def test_decrypt_inverts_encrypt_for_all_variants(block_bits: int, key_bits: int) -> None:
    """For random inputs ``decrypt(encrypt(p)) == p`` must always hold."""
    parameters = KalynaParameters(block_bit_length=block_bits, key_bit_length=key_bits)
    key: bytes = os.urandom(parameters.key_byte_length)
    plaintext: bytes = os.urandom(parameters.block_byte_length)

    cipher = KalynaCipher(parameters, key)
    ciphertext: bytes = cipher.encrypt_block(plaintext)
    recovered_plaintext: bytes = cipher.decrypt_block(ciphertext)

    assert recovered_plaintext == plaintext


def test_invalid_block_size_is_rejected() -> None:
    with pytest.raises(ValueError):
        KalynaParameters(block_bit_length=64, key_bit_length=128)


def test_invalid_key_size_is_rejected() -> None:
    with pytest.raises(ValueError):
        KalynaParameters(block_bit_length=128, key_bit_length=512)


def test_wrong_key_length_raises() -> None:
    parameters = KalynaParameters(block_bit_length=128, key_bit_length=128)
    with pytest.raises(ValueError):
        KalynaCipher(parameters, b"\x00" * 15)


def test_wrong_block_length_raises() -> None:
    parameters = KalynaParameters(block_bit_length=128, key_bit_length=128)
    cipher = KalynaCipher(parameters, b"\x00" * 16)
    with pytest.raises(ValueError):
        cipher.encrypt_block(b"\x00" * 15)
