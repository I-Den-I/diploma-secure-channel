# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Modes of operation for the Kalyna block cipher (DSTU 7624:2014).

This module provides two of the modes specified in DSTU 7624:2014:

* :class:`KalynaCounterMode` --- a Counter (CTR) mode implementation that
  turns Kalyna into an additive stream cipher. The keystream is generated
  by enciphering successive values of an input counter and is XORed with
  the plaintext to produce the ciphertext.
* :class:`KalynaCmac` --- the OMAC1 / CMAC message authentication code
  built on top of Kalyna. CMAC is specified in DSTU 7624:2014 (clauses on
  modes of authenticated transformation) and provides a deterministic
  variable-length pseudo-random function.

Both implementations are deliberately scoped to the 128-bit block variant
of Kalyna. This is the variant most commonly deployed in Ukrainian secure
messaging products and the only one needed for the secure channel of this
diploma project.

Together with the encrypt-then-MAC composition implemented in
:mod:`secure_channel.crypto.kalyna_aead`, these modes form a complete
authenticated-encryption suite based exclusively on the Ukrainian national
symmetric cipher standard.
"""

from __future__ import annotations

from typing import Final

from secure_channel.crypto.kalyna import KalynaCipher, KalynaParameters

_BLOCK_SIZE_BITS: Final[int] = 128
_BLOCK_SIZE_BYTES: Final[int] = _BLOCK_SIZE_BITS // 8


# ---------------------------------------------------------------------------
# CTR mode
# ---------------------------------------------------------------------------


class KalynaCounterMode:
    """Kalyna in Counter (CTR) mode of operation.

    The CTR mode turns the underlying block cipher into a synchronous
    stream cipher. For each counter value :math:`T` the cipher emits the
    keystream block :math:`E_K(T)`, which the caller XORs with the
    plaintext to produce the ciphertext (or with the ciphertext to recover
    the plaintext).

    The 128-bit counter input :math:`T` is laid out as the concatenation
    of a 96-bit *nonce* (selected by the caller) and a big-endian 32-bit
    block counter. This layout matches the AES-GCM convention and bounds
    the maximum amount of data per nonce to :math:`2^{32}` blocks =
    :math:`64\\,{\\rm GiB}`, which is more than enough for an interactive
    secure messaging session.

    :param key: Secret key for the underlying Kalyna(128, 256) cipher.
    """

    NONCE_BYTE_LENGTH: Final[int] = 12
    """Length of the per-message nonce, in bytes (96 bits)."""

    BLOCK_BYTE_LENGTH: Final[int] = _BLOCK_SIZE_BYTES
    """Length of one Kalyna block, in bytes."""

    _COUNTER_BYTE_LENGTH: Final[int] = _BLOCK_SIZE_BYTES - NONCE_BYTE_LENGTH
    """Width of the in-block counter (bytes)."""

    __slots__ = ("_cipher",)

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError(
                "KalynaCounterMode uses Kalyna(128, 256); key must be exactly 32 bytes."
            )
        parameters = KalynaParameters(block_bit_length=128, key_bit_length=256)
        self._cipher: Final[KalynaCipher] = KalynaCipher(parameters, key)

    def process(self, nonce: bytes, data: bytes) -> bytes:
        """Encrypt or decrypt ``data`` using the CTR keystream for ``nonce``.

        Encryption and decryption are identical in CTR mode, hence a
        single :meth:`process` method serves both directions.

        :param nonce: 12-byte nonce. Must be unique for every message
            encrypted under the same key.
        :param data: Arbitrary-length byte string to transform.
        :returns: The ciphertext (or recovered plaintext) of the same
            length as ``data``.
        :raises ValueError: If ``nonce`` does not have the required size,
            or if ``data`` would exhaust the 32-bit counter range.
        """
        if len(nonce) != self.NONCE_BYTE_LENGTH:
            raise ValueError(
                f"Nonce must be exactly {self.NONCE_BYTE_LENGTH} bytes."
            )
        block_count_required: int = (len(data) + self.BLOCK_BYTE_LENGTH - 1) // self.BLOCK_BYTE_LENGTH
        if block_count_required > (1 << (8 * self._COUNTER_BYTE_LENGTH)):
            raise ValueError(
                "Plaintext would exhaust the 32-bit counter for this nonce."
            )

        output = bytearray(len(data))
        for block_index in range(block_count_required):
            counter_block: bytes = nonce + block_index.to_bytes(
                self._COUNTER_BYTE_LENGTH, "big"
            )
            keystream_block: bytes = self._cipher.encrypt_block(counter_block)
            start: int = block_index * self.BLOCK_BYTE_LENGTH
            stop: int = min(start + self.BLOCK_BYTE_LENGTH, len(data))
            for byte_offset in range(stop - start):
                output[start + byte_offset] = (
                    data[start + byte_offset] ^ keystream_block[byte_offset]
                )
        return bytes(output)


# ---------------------------------------------------------------------------
# CMAC (OMAC1) mode
# ---------------------------------------------------------------------------


def _double_in_gcm_field(block: bytes) -> bytes:
    """Multiply a 128-bit block by :math:`x` in :math:`GF(2^{128})`.

    The polynomial :math:`p(x) = x^{128} + x^7 + x^2 + x + 1` is used as
    the field's irreducible polynomial. This is the same polynomial used
    by NIST SP 800-38B for AES-CMAC subkey derivation; reusing it for
    Kalyna-CMAC is the convention adopted in DSTU 7624:2014.

    :param block: 16-byte input.
    :returns: ``2 * block`` reduced modulo :math:`p(x)`.
    """
    if len(block) != _BLOCK_SIZE_BYTES:
        raise ValueError("Doubling is only defined for one full Kalyna block.")
    block_integer: int = int.from_bytes(block, "big")
    high_bit_set: bool = bool(block_integer & (1 << 127))
    block_integer = (block_integer << 1) & ((1 << 128) - 1)
    if high_bit_set:
        block_integer ^= 0x87  # = x^7 + x^2 + x + 1
    return block_integer.to_bytes(_BLOCK_SIZE_BYTES, "big")


def _xor_blocks(left: bytes, right: bytes) -> bytes:
    """Bitwise XOR of two equal-length byte strings."""
    return bytes(left_byte ^ right_byte for left_byte, right_byte in zip(left, right, strict=True))


class KalynaCmac:
    """Cipher-based MAC (CMAC / OMAC1) built on Kalyna(128, 256).

    CMAC is a secure pseudo-random function that maps an arbitrary-length
    byte string to a fixed-size tag. It is used both as the authentication
    primitive for the encrypt-then-MAC AEAD construction in
    :mod:`secure_channel.crypto.kalyna_aead` and as the underlying PRF
    for the HKDF-style key derivation function in
    :mod:`secure_channel.crypto.kdf`.

    The tag length defaults to the full block size (16 bytes); shorter
    truncated tags can be requested via :paramref:`tag_byte_length`.

    :param key: 32-byte secret key for the Kalyna(128, 256) primitive.
    :param tag_byte_length: Length of the produced tag in bytes; must be
        between 1 and the full block size (16).
    """

    BLOCK_BYTE_LENGTH: Final[int] = _BLOCK_SIZE_BYTES

    __slots__ = ("_cipher", "_subkey_complete", "_subkey_padded", "_tag_byte_length")

    def __init__(self, key: bytes, *, tag_byte_length: int = _BLOCK_SIZE_BYTES) -> None:
        if len(key) != 32:
            raise ValueError("KalynaCmac uses Kalyna(128, 256); key must be 32 bytes.")
        if not (1 <= tag_byte_length <= _BLOCK_SIZE_BYTES):
            raise ValueError(
                f"Tag length must be in 1..{_BLOCK_SIZE_BYTES}; got {tag_byte_length}."
            )
        parameters = KalynaParameters(block_bit_length=128, key_bit_length=256)
        self._cipher: Final[KalynaCipher] = KalynaCipher(parameters, key)
        zero_block: bytes = bytes(_BLOCK_SIZE_BYTES)
        l_value: bytes = self._cipher.encrypt_block(zero_block)
        self._subkey_complete: Final[bytes] = _double_in_gcm_field(l_value)
        self._subkey_padded: Final[bytes] = _double_in_gcm_field(self._subkey_complete)
        self._tag_byte_length: Final[int] = tag_byte_length

    def compute_tag(self, message: bytes) -> bytes:
        """Compute the CMAC tag of ``message``.

        :param message: Arbitrary-length byte string.
        :returns: A fixed-size tag (length controlled by the constructor's
            ``tag_byte_length``).
        """
        if len(message) == 0:
            last_block_padded: bytes = b"\x80" + bytes(_BLOCK_SIZE_BYTES - 1)
            last_block: bytes = _xor_blocks(last_block_padded, self._subkey_padded)
            full_blocks: list[bytes] = []
        else:
            full_block_count: int = (len(message) - 1) // _BLOCK_SIZE_BYTES
            tail_byte_count: int = len(message) - full_block_count * _BLOCK_SIZE_BYTES
            full_blocks = [
                message[i * _BLOCK_SIZE_BYTES : (i + 1) * _BLOCK_SIZE_BYTES]
                for i in range(full_block_count)
            ]
            tail: bytes = message[full_block_count * _BLOCK_SIZE_BYTES :]
            if tail_byte_count == _BLOCK_SIZE_BYTES:
                last_block = _xor_blocks(tail, self._subkey_complete)
            else:
                padded_tail: bytes = (
                    tail + b"\x80" + bytes(_BLOCK_SIZE_BYTES - tail_byte_count - 1)
                )
                last_block = _xor_blocks(padded_tail, self._subkey_padded)

        cipher_state: bytes = bytes(_BLOCK_SIZE_BYTES)
        for full_block in full_blocks:
            cipher_state = self._cipher.encrypt_block(_xor_blocks(cipher_state, full_block))
        final_input: bytes = _xor_blocks(cipher_state, last_block)
        full_tag: bytes = self._cipher.encrypt_block(final_input)
        return full_tag[: self._tag_byte_length]

    def verify_tag(self, message: bytes, expected_tag: bytes) -> bool:
        """Constant-time verification of a CMAC tag.

        :returns: ``True`` iff ``expected_tag`` matches the tag computed
            for ``message``.
        """
        actual_tag: bytes = self.compute_tag(message)
        if len(actual_tag) != len(expected_tag):
            return False
        difference: int = 0
        for actual_byte, expected_byte in zip(actual_tag, expected_tag, strict=True):
            difference |= actual_byte ^ expected_byte
        return difference == 0


__all__: Final[list[str]] = [
    "KalynaCounterMode",
    "KalynaCmac",
]
