# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Key derivation function based on Kalyna-CMAC.

The construction follows the *HKDF* paradigm (Krawczyk, RFC 5869) but
substitutes the underlying HMAC-SHA-256 PRF with the Ukrainian-standard
:class:`KalynaCmac` PRF. The resulting KDF is therefore built exclusively
out of DSTU 7624:2014 primitives.

HKDF proceeds in two stages:

1. **Extract** a fixed-size pseudo-random key from possibly biased input
   keying material:

   .. math::
       PRK = \\text{CMAC}(\\textit{salt}, IKM)

2. **Expand** ``PRK`` into the requested number of output bytes by
   chaining the PRF in counter mode:

   .. math::
       T_{i} = \\text{CMAC}(PRK, T_{i-1} \\,\\|\\, \\textit{info} \\,\\|\\, i)

   where :math:`T_0` is the empty string and ``i`` is a single counter
   byte starting at 1.
"""

from __future__ import annotations

from typing import Final

from secure_channel.crypto.kalyna_modes import KalynaCmac

_PSEUDORANDOM_KEY_BYTE_LENGTH: Final[int] = 32
"""Width of the intermediate PRK; doubled CMAC tag (32 bytes)."""

_DEFAULT_SALT: Final[bytes] = b"\x00" * _PSEUDORANDOM_KEY_BYTE_LENGTH
"""Fall-back salt used when the caller does not supply one."""


def _extract(salt: bytes, input_key_material: bytes) -> bytes:
    """HKDF-Extract step using two parallel Kalyna-CMACs to fill 32 bytes.

    A single Kalyna-CMAC tag is 16 bytes wide. To match the 32-byte width
    of the keys consumed by :class:`secure_channel.crypto.kalyna_aead.KalynaAeadKey`,
    we run the extract step twice with one-byte domain separators and
    concatenate the two halves. The construction remains a secure PRF as
    long as the underlying CMAC is a secure PRF, since the extra byte
    enforces input-domain disjointness.
    """
    if len(salt) < 32:
        padded_salt: bytes = salt + bytes(32 - len(salt))
    else:
        padded_salt = salt[:32]
    extractor = KalynaCmac(padded_salt, tag_byte_length=16)
    upper_half: bytes = extractor.compute_tag(b"\x01" + input_key_material)
    lower_half: bytes = extractor.compute_tag(b"\x02" + input_key_material)
    return upper_half + lower_half


def _expand(pseudo_random_key: bytes, info: bytes, output_byte_length: int) -> bytes:
    """HKDF-Expand step with one-byte counter, capped at 255 blocks (4080 B)."""
    expander = KalynaCmac(pseudo_random_key, tag_byte_length=16)
    if output_byte_length > 255 * 16:
        raise ValueError("Cannot derive more than 4080 bytes per invocation.")
    accumulated_output = bytearray()
    previous_block: bytes = b""
    counter_byte: int = 1
    while len(accumulated_output) < output_byte_length:
        previous_block = expander.compute_tag(
            previous_block + info + bytes([counter_byte])
        )
        accumulated_output.extend(previous_block)
        counter_byte += 1
    return bytes(accumulated_output[:output_byte_length])


def derive_keys_from_shared_secret(
    shared_secret: bytes,
    *,
    info: bytes,
    salt: bytes | None = None,
    output_byte_length: int,
) -> bytes:
    """Derive cryptographically independent key bytes from ``shared_secret``.

    :param shared_secret: Raw shared key material, e.g. the x-coordinate
        of the ECDH shared point produced during handshake.
    :param info: Application-specific context label (e.g. the literal
        string ``b"client-to-server-encryption"``).
    :param salt: Optional public salt; defaults to a deterministic
        zero-filled buffer when ``None``.
    :param output_byte_length: Number of output bytes to derive.
    :returns: ``output_byte_length`` pseudo-random bytes deterministically
        derived from the inputs.
    """
    if output_byte_length < 1:
        raise ValueError("output_byte_length must be a positive integer.")
    pseudo_random_key: bytes = _extract(salt or _DEFAULT_SALT, shared_secret)
    return _expand(pseudo_random_key, info, output_byte_length)


__all__: Final[list[str]] = ["derive_keys_from_shared_secret"]
