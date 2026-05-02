# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Pure-Python implementation of the Kalyna block cipher (DSTU 7624:2014).

Kalyna is the Ukrainian national symmetric block cipher standard. It is
parameterised by the block bit-length :math:`l \\in \\{128, 256, 512\\}` and the
secret key bit-length :math:`k \\in \\{l, 2l\\}`. The number of enciphering
rounds :math:`t` is determined exclusively by :math:`k` according to:

.. math:: t = \\begin{cases} 10 & k = 128 \\\\
                              14 & k = 256 \\\\
                              18 & k = 512 \\end{cases}

The internal state is treated as a byte matrix with eight rows and
:math:`c = l / 64` columns, where each column is interpreted as a little
endian 64-bit word for the modular addition operations of the cipher.

This module implements **all five** standard parameter combinations:

==================== ============= ============ ===========
Variant              Block (bits)  Key (bits)   Rounds
==================== ============= ============ ===========
``Kalyna(128, 128)`` 128           128          10
``Kalyna(128, 256)`` 128           256          14
``Kalyna(256, 256)`` 256           256          14
``Kalyna(256, 512)`` 256           512          18
``Kalyna(512, 512)`` 512           512          18
==================== ============= ============ ===========

The implementation focuses on academic clarity; nevertheless a 256x256
GF(2^8) multiplication lookup table is precomputed at import time so that
the linear ψ transformation runs in pure-Python with acceptable speed.

.. note::
   This module is a **block-cipher primitive**. For confidentiality of
   variable-length messages, build an authenticated mode of operation on
   top of it. See :mod:`secure_channel.crypto.kalyna_modes`.

:see: DSTU 7624:2014 sections 5--6 (cipher specification, key schedule)
      and Annex A (test vectors).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from secure_channel.crypto._kalyna_tables import (
    KALYNA_FORWARD_SBOXES,
    KALYNA_INVERSE_SBOXES,
    KALYNA_MDS_FORWARD,
    KALYNA_MDS_INVERSE,
    KALYNA_REDUCTION_POLYNOMIAL,
)

# ---------------------------------------------------------------------------
# Field arithmetic helpers
# ---------------------------------------------------------------------------


def _multiply_in_gf_2_8(left_factor: int, right_factor: int) -> int:
    """Multiply two elements of :math:`GF(2^8)` modulo the Kalyna polynomial.

    Implements the bit-by-bit Russian peasant multiplication. The reduction
    is performed against the irreducible polynomial
    :math:`x^{8} + x^{4} + x^{3} + x^{2} + 1` (numeric value
    ``0x011D``) defined in section 5.4 of DSTU 7624:2014.

    :param left_factor: First operand, in the range 0..255.
    :param right_factor: Second operand, in the range 0..255.
    :returns: The product :math:`a \\cdot b \\bmod p(x)` as an integer in
        the range 0..255.
    """
    accumulator: int = 0
    for _ in range(8):
        if right_factor & 1:
            accumulator ^= left_factor
        high_bit_set: bool = bool(left_factor & 0x80)
        left_factor = (left_factor << 1) & 0xFF
        if high_bit_set:
            left_factor ^= KALYNA_REDUCTION_POLYNOMIAL & 0xFF
        right_factor >>= 1
    return accumulator


def _build_gf_multiplication_table() -> tuple[tuple[int, ...], ...]:
    """Construct the 256x256 multiplication lookup table over :math:`GF(2^8)`.

    A precomputed table replaces the inner :func:`_multiply_in_gf_2_8` call
    in the linear ψ transformation, which is the hottest code path of the
    cipher. Building the table costs roughly 65 000 byte multiplications and
    runs once when the module is first imported.

    :returns: A tuple of 256 tuples; ``table[a][b]`` equals
        :math:`a \\cdot b \\bmod p(x)`.
    """
    return tuple(
        tuple(_multiply_in_gf_2_8(left, right) for right in range(256))
        for left in range(256)
    )


_GF_MULTIPLICATION_TABLE: Final[tuple[tuple[int, ...], ...]] = (
    _build_gf_multiplication_table()
)


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_BYTES_PER_WORD: Final[int] = 8
"""Width of a single Kalyna 64-bit word, in bytes."""

_SUPPORTED_BLOCK_BIT_SIZES: Final[frozenset[int]] = frozenset({128, 256, 512})
"""Block sizes accepted by :class:`KalynaCipher` (in bits)."""

_SUPPORTED_KEY_BIT_SIZES: Final[frozenset[int]] = frozenset({128, 256, 512})
"""Key sizes accepted by :class:`KalynaCipher` (in bits)."""

_ROUNDS_FOR_KEY_BITS: Final[dict[int, int]] = {128: 10, 256: 14, 512: 18}
"""Number of enciphering rounds :math:`t` for each key bit-length."""


# ---------------------------------------------------------------------------
# Public dataclass for cipher parameters
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KalynaParameters:
    """Immutable description of a single Kalyna cipher variant.

    :param block_bit_length: Block length :math:`l` in bits, one of
        128, 256, or 512.
    :param key_bit_length: Secret key length :math:`k` in bits; must equal
        either :attr:`block_bit_length` or :math:`2 \\cdot` it.
    :raises ValueError: If the chosen :math:`(l, k)` tuple is not one of
        the five combinations defined by DSTU 7624:2014.
    """

    block_bit_length: int
    key_bit_length: int

    def __post_init__(self) -> None:
        if self.block_bit_length not in _SUPPORTED_BLOCK_BIT_SIZES:
            raise ValueError(
                f"Unsupported block size {self.block_bit_length} (must be 128, 256 or 512)."
            )
        if self.key_bit_length not in _SUPPORTED_KEY_BIT_SIZES:
            raise ValueError(
                f"Unsupported key size {self.key_bit_length} (must be 128, 256 or 512)."
            )
        if self.key_bit_length not in (
            self.block_bit_length,
            2 * self.block_bit_length,
        ):
            raise ValueError(
                "DSTU 7624:2014 only allows key bit-length equal to or double "
                f"the block bit-length; got block={self.block_bit_length}, "
                f"key={self.key_bit_length}."
            )

    @property
    def block_byte_length(self) -> int:
        """Block length :math:`l/8` in bytes."""
        return self.block_bit_length // 8

    @property
    def key_byte_length(self) -> int:
        """Key length :math:`k/8` in bytes."""
        return self.key_bit_length // 8

    @property
    def block_word_count(self) -> int:
        """Number of 64-bit columns :math:`N_b` per state."""
        return self.block_bit_length // (_BYTES_PER_WORD * 8)

    @property
    def key_word_count(self) -> int:
        """Number of 64-bit words :math:`N_k` in the key."""
        return self.key_bit_length // (_BYTES_PER_WORD * 8)

    @property
    def rounds(self) -> int:
        """Number of enciphering rounds :math:`t` for this variant."""
        return _ROUNDS_FOR_KEY_BITS[self.key_bit_length]


# ---------------------------------------------------------------------------
# Internal byte/word helpers
# ---------------------------------------------------------------------------


def _bytes_to_words_little_endian(data: bytes) -> list[int]:
    """Decode a byte string into a list of little-endian 64-bit words.

    :param data: Input buffer whose length must be a positive multiple of 8.
    :returns: A list of integers, each in :math:`[0, 2^{64})`.
    """
    if len(data) % _BYTES_PER_WORD != 0:
        raise ValueError(
            "Buffer length must be a multiple of 8 bytes to decode as 64-bit words."
        )
    return [
        int.from_bytes(data[i : i + _BYTES_PER_WORD], "little")
        for i in range(0, len(data), _BYTES_PER_WORD)
    ]


def _words_to_bytes_little_endian(words: list[int]) -> bytes:
    """Encode a list of 64-bit words to a contiguous little-endian byte string.

    :param words: Sequence of unsigned 64-bit integers.
    :returns: A :class:`bytes` object of length ``8 * len(words)``.
    """
    return b"".join(word.to_bytes(_BYTES_PER_WORD, "little") for word in words)


# ---------------------------------------------------------------------------
# Cipher class
# ---------------------------------------------------------------------------


class KalynaCipher:
    """Stateful Kalyna block cipher object with precomputed round keys.

    The instance is initialised with a fully expanded round-key schedule.
    Every subsequent call to :meth:`encrypt_block` and :meth:`decrypt_block`
    operates on a single block-sized input and is independent of any
    previous calls (the object is therefore thread-safe for read-only use).

    :param parameters: The :class:`KalynaParameters` descriptor specifying
        the block and key bit lengths.
    :param key: Secret key of exact length ``parameters.key_byte_length``.

    :raises ValueError: If ``key`` has a length that does not match
        ``parameters.key_byte_length``.
    """

    __slots__ = ("_parameters", "_round_keys")

    def __init__(self, parameters: KalynaParameters, key: bytes) -> None:
        if len(key) != parameters.key_byte_length:
            raise ValueError(
                f"Key length must be exactly {parameters.key_byte_length} bytes "
                f"for Kalyna({parameters.block_bit_length},"
                f" {parameters.key_bit_length}); got {len(key)}."
            )
        self._parameters: Final[KalynaParameters] = parameters
        self._round_keys: Final[tuple[tuple[int, ...], ...]] = self._derive_round_keys(key)

    # ------------------------------------------------------------------
    # Public properties
    # ------------------------------------------------------------------

    @property
    def parameters(self) -> KalynaParameters:
        """Cipher parameters this instance was initialised with."""
        return self._parameters

    @property
    def block_byte_length(self) -> int:
        """Convenience accessor for :attr:`KalynaParameters.block_byte_length`."""
        return self._parameters.block_byte_length

    # ------------------------------------------------------------------
    # Public block API
    # ------------------------------------------------------------------

    def encrypt_block(self, plaintext_block: bytes) -> bytes:
        """Encipher a single plaintext block.

        Implements the iterated structure
        :math:`(\\eta^{+}_{K_t} \\circ \\psi \\circ \\sigma_l \\circ \\tau_{\\pi'})
        \\circ \\prod_{r=t-1}^{1} (\\kappa^{\\oplus}_{K_r} \\circ
        \\psi \\circ \\sigma_l \\circ \\tau_{\\pi'}) \\circ
        \\eta^{+}_{K_0}` from section 5.1 of DSTU 7624:2014.

        :param plaintext_block: Exactly :attr:`block_byte_length` bytes
            of plaintext.
        :returns: Exactly :attr:`block_byte_length` bytes of ciphertext.
        :raises ValueError: If the input length is incorrect.
        """
        self._check_block_length(plaintext_block, label="plaintext")
        state_words: list[int] = _bytes_to_words_little_endian(plaintext_block)

        self._add_round_key_modular(state_words, round_index=0)
        for round_index in range(1, self._parameters.rounds):
            self._encipher_round(state_words)
            self._xor_round_key(state_words, round_index=round_index)
        self._encipher_round(state_words)
        self._add_round_key_modular(state_words, round_index=self._parameters.rounds)

        return _words_to_bytes_little_endian(state_words)

    def decrypt_block(self, ciphertext_block: bytes) -> bytes:
        """Decipher a single ciphertext block.

        Inverts :meth:`encrypt_block` by reversing the order of the round
        operations and substituting each transformation with its inverse.

        :param ciphertext_block: Exactly :attr:`block_byte_length` bytes
            of ciphertext.
        :returns: Exactly :attr:`block_byte_length` bytes of plaintext.
        :raises ValueError: If the input length is incorrect.
        """
        self._check_block_length(ciphertext_block, label="ciphertext")
        state_words: list[int] = _bytes_to_words_little_endian(ciphertext_block)

        self._subtract_round_key_modular(state_words, round_index=self._parameters.rounds)
        for round_index in range(self._parameters.rounds - 1, 0, -1):
            self._decipher_round(state_words)
            self._xor_round_key(state_words, round_index=round_index)
        self._decipher_round(state_words)
        self._subtract_round_key_modular(state_words, round_index=0)

        return _words_to_bytes_little_endian(state_words)

    # ------------------------------------------------------------------
    # Internal: invariants
    # ------------------------------------------------------------------

    def _check_block_length(self, block: bytes, *, label: str) -> None:
        if len(block) != self.block_byte_length:
            raise ValueError(
                f"{label.capitalize()} block must be exactly "
                f"{self.block_byte_length} bytes; got {len(block)}."
            )

    # ------------------------------------------------------------------
    # Internal: forward and inverse round transformations
    # ------------------------------------------------------------------

    def _encipher_round(self, state_words: list[int]) -> None:
        """Apply ``ψ ∘ σ_l ∘ τ_π'`` in-place on ``state_words``.

        :param state_words: The 64-bit word vector representing the current
            cipher state. Mutated in place.
        """
        self._sub_bytes(state_words)
        self._shift_rows_forward(state_words)
        self._mix_columns(state_words, KALYNA_MDS_FORWARD)

    def _decipher_round(self, state_words: list[int]) -> None:
        """Apply ``τ⁻¹_π' ∘ σ⁻¹_l ∘ ψ⁻¹`` in-place on ``state_words``."""
        self._mix_columns(state_words, KALYNA_MDS_INVERSE)
        self._shift_rows_inverse(state_words)
        self._inverse_sub_bytes(state_words)

    # ------------------------------------------------------------------
    # Internal: τ_π' (SubBytes) and its inverse
    # ------------------------------------------------------------------

    def _sub_bytes(self, state_words: list[int]) -> None:
        """Substitute every byte of the state using the four forward S-boxes.

        Each 64-bit word holds eight bytes; the substitution selects S-box
        ``b mod 4`` for the byte at index ``b`` (0..7) inside the word, as
        prescribed by section 6.2.1 of DSTU 7624:2014.
        """
        sbox_0, sbox_1, sbox_2, sbox_3 = KALYNA_FORWARD_SBOXES
        for column_index in range(self._parameters.block_word_count):
            word: int = state_words[column_index]
            state_words[column_index] = (
                sbox_0[word & 0xFF]
                | (sbox_1[(word >> 8) & 0xFF] << 8)
                | (sbox_2[(word >> 16) & 0xFF] << 16)
                | (sbox_3[(word >> 24) & 0xFF] << 24)
                | (sbox_0[(word >> 32) & 0xFF] << 32)
                | (sbox_1[(word >> 40) & 0xFF] << 40)
                | (sbox_2[(word >> 48) & 0xFF] << 48)
                | (sbox_3[(word >> 56) & 0xFF] << 56)
            )

    def _inverse_sub_bytes(self, state_words: list[int]) -> None:
        """Inverse of :meth:`_sub_bytes` using the four inverse S-boxes."""
        inv_sbox_0, inv_sbox_1, inv_sbox_2, inv_sbox_3 = KALYNA_INVERSE_SBOXES
        for column_index in range(self._parameters.block_word_count):
            word: int = state_words[column_index]
            state_words[column_index] = (
                inv_sbox_0[word & 0xFF]
                | (inv_sbox_1[(word >> 8) & 0xFF] << 8)
                | (inv_sbox_2[(word >> 16) & 0xFF] << 16)
                | (inv_sbox_3[(word >> 24) & 0xFF] << 24)
                | (inv_sbox_0[(word >> 32) & 0xFF] << 32)
                | (inv_sbox_1[(word >> 40) & 0xFF] << 40)
                | (inv_sbox_2[(word >> 48) & 0xFF] << 48)
                | (inv_sbox_3[(word >> 56) & 0xFF] << 56)
            )

    # ------------------------------------------------------------------
    # Internal: σ_l (ShiftRows) and its inverse
    # ------------------------------------------------------------------

    def _shift_rows_forward(self, state_words: list[int]) -> None:
        """Cyclically shift each row of the cipher state to the right.

        DSTU 7624:2014 section 6.2.2 specifies that row :math:`r` is shifted
        by :math:`\\lfloor r \\cdot N_b / 8 \\rfloor` positions to the
        right, where :math:`N_b` is the number of columns.

        Internally, the state is stored as a vector of 64-bit words, one
        per column, with byte ``r`` of word ``c`` being the byte at row
        ``r`` and column ``c`` of the matrix view.
        """
        block_word_count: int = self._parameters.block_word_count
        flat_state: bytearray = bytearray(_words_to_bytes_little_endian(state_words))
        permuted: bytearray = bytearray(len(flat_state))
        for row in range(8):
            shift: int = (row * block_word_count) // 8
            for col in range(block_word_count):
                permuted[row + ((col + shift) % block_word_count) * 8] = flat_state[
                    row + col * 8
                ]
        state_words[:] = _bytes_to_words_little_endian(bytes(permuted))

    def _shift_rows_inverse(self, state_words: list[int]) -> None:
        """Inverse of :meth:`_shift_rows_forward` (cyclic left rotations)."""
        block_word_count: int = self._parameters.block_word_count
        flat_state: bytearray = bytearray(_words_to_bytes_little_endian(state_words))
        permuted: bytearray = bytearray(len(flat_state))
        for row in range(8):
            shift: int = (row * block_word_count) // 8
            for col in range(block_word_count):
                permuted[row + col * 8] = flat_state[
                    row + ((col + shift) % block_word_count) * 8
                ]
        state_words[:] = _bytes_to_words_little_endian(bytes(permuted))

    # ------------------------------------------------------------------
    # Internal: ψ (MixColumns) and its inverse
    # ------------------------------------------------------------------

    def _mix_columns(
        self,
        state_words: list[int],
        mds_matrix: tuple[tuple[int, ...], ...],
    ) -> None:
        """Multiply each column of the state by ``mds_matrix`` over GF(2^8).

        The byte at output row :math:`r` and column :math:`c` is
        :math:`\\bigoplus_{b=0}^{7} S_{b,c} \\cdot M_{r,b}` where :math:`S`
        is the input state and :math:`M` is ``mds_matrix``.

        :param state_words: Cipher state (mutated in place).
        :param mds_matrix: Either :data:`KALYNA_MDS_FORWARD` or
            :data:`KALYNA_MDS_INVERSE`.
        """
        gf_table = _GF_MULTIPLICATION_TABLE
        for column_index in range(self._parameters.block_word_count):
            column_word: int = state_words[column_index]
            column_bytes: list[int] = [
                (column_word >> (byte_offset * 8)) & 0xFF for byte_offset in range(8)
            ]
            new_column_word: int = 0
            for row in range(8):
                matrix_row = mds_matrix[row]
                product_byte: int = 0
                for byte_offset in range(8):
                    product_byte ^= gf_table[column_bytes[byte_offset]][matrix_row[byte_offset]]
                new_column_word |= product_byte << (row * 8)
            state_words[column_index] = new_column_word

    # ------------------------------------------------------------------
    # Internal: round-key injection
    # ------------------------------------------------------------------

    def _add_round_key_modular(self, state_words: list[int], round_index: int) -> None:
        """Add the round key element-wise modulo :math:`2^{64}`."""
        round_key = self._round_keys[round_index]
        for column_index in range(self._parameters.block_word_count):
            state_words[column_index] = (
                state_words[column_index] + round_key[column_index]
            ) & 0xFFFFFFFFFFFFFFFF

    def _subtract_round_key_modular(
        self, state_words: list[int], round_index: int
    ) -> None:
        """Subtract the round key element-wise modulo :math:`2^{64}`."""
        round_key = self._round_keys[round_index]
        for column_index in range(self._parameters.block_word_count):
            state_words[column_index] = (
                state_words[column_index] - round_key[column_index]
            ) & 0xFFFFFFFFFFFFFFFF

    def _xor_round_key(self, state_words: list[int], round_index: int) -> None:
        """XOR the round key element-wise into the state."""
        round_key = self._round_keys[round_index]
        for column_index in range(self._parameters.block_word_count):
            state_words[column_index] ^= round_key[column_index]

    # ------------------------------------------------------------------
    # Key schedule (DSTU 7624:2014 section 5.2)
    # ------------------------------------------------------------------

    def _derive_round_keys(self, key: bytes) -> tuple[tuple[int, ...], ...]:
        """Derive the full round-key schedule from a master key.

        Implements the three-stage construction of section 5.2:

        1. Compute the auxiliary key :math:`K_\\sigma = K_t` from ``key``.
        2. Generate the even-indexed round keys
           :math:`K_0, K_2, ..., K_t` deterministically from
           ``key`` and :math:`K_\\sigma`.
        3. Derive each odd-indexed round key :math:`K_{2i+1}` by rotating
           :math:`K_{2i}` cyclically to the left by :math:`(2 N_b + 3)`
           bytes, in accordance with section 5.2.4.

        :param key: Raw secret key, ``parameters.key_byte_length`` bytes.
        :returns: Tuple of :math:`t + 1` round keys, each consisting of
            :math:`N_b` 64-bit words.
        """
        key_words: list[int] = _bytes_to_words_little_endian(key)
        auxiliary_key_words: list[int] = self._derive_auxiliary_key(key_words)

        even_round_keys: list[list[int]] = self._derive_even_round_keys(
            key_words, auxiliary_key_words
        )

        round_keys: list[list[int]] = [list(rk) for rk in even_round_keys]
        for odd_round_index in range(1, self._parameters.rounds, 2):
            previous_even_round_key: list[int] = list(round_keys[odd_round_index - 1])
            self._rotate_round_key_left(previous_even_round_key)
            round_keys.insert(odd_round_index, previous_even_round_key)

        return tuple(tuple(rk) for rk in round_keys)

    def _derive_auxiliary_key(self, key_words: list[int]) -> list[int]:
        """Compute :math:`K_\\sigma` (the *Kt* auxiliary value).

        Defined by Algorithm 6 of DSTU 7624:2014 (section 5.2.2):

        1. Initialise the state as a single column ``[N_b + N_k + 1, 0, ..., 0]``.
        2. ``state ← state ⊞ K^{(0)}``        (modular addition)
        3. ``state ← ψ ∘ σ_l ∘ τ_π'(state)``
        4. ``state ← state ⊕ K^{(1)}``        (XOR)
        5. ``state ← ψ ∘ σ_l ∘ τ_π'(state)``
        6. ``state ← state ⊞ K^{(0)}``        (modular addition)
        7. ``state ← ψ ∘ σ_l ∘ τ_π'(state)``

        Where :math:`K^{(0)}, K^{(1)}` are the lower and upper halves of the
        master key (or both equal the key when :math:`N_k = N_b`).

        :param key_words: Master key as :math:`N_k` 64-bit words.
        :returns: :math:`K_\\sigma` as a list of :math:`N_b` words.
        """
        block_word_count: int = self._parameters.block_word_count
        key_word_count: int = self._parameters.key_word_count

        if key_word_count == block_word_count:
            key_part_lower: list[int] = list(key_words)
            key_part_upper: list[int] = list(key_words)
        else:
            key_part_lower = list(key_words[:block_word_count])
            key_part_upper = list(key_words[block_word_count:])

        state_words: list[int] = [0] * block_word_count
        state_words[0] = (block_word_count + key_word_count + 1) & 0xFFFFFFFFFFFFFFFF

        self._add_value_modular(state_words, key_part_lower)
        self._encipher_round(state_words)
        self._xor_value(state_words, key_part_upper)
        self._encipher_round(state_words)
        self._add_value_modular(state_words, key_part_lower)
        self._encipher_round(state_words)
        return state_words

    def _derive_even_round_keys(
        self, key_words: list[int], auxiliary_key_words: list[int]
    ) -> list[list[int]]:
        """Generate :math:`K_0, K_2, ..., K_t` (Algorithm 7 of section 5.2.3).

        :param key_words: Master key as :math:`N_k` 64-bit words.
        :param auxiliary_key_words: :math:`K_\\sigma` produced by
            :meth:`_derive_auxiliary_key`.
        :returns: A list ``[K_0, K_2, ..., K_t]``; the slot for an odd
            index is reserved (filled later by the caller) by storing the
            even key one index apart.
        """
        block_word_count: int = self._parameters.block_word_count
        key_word_count: int = self._parameters.key_word_count
        rounds: int = self._parameters.rounds

        round_keys_by_index: dict[int, list[int]] = {}

        rolling_key_words: list[int] = list(key_words)
        round_constant_words: list[int] = [0x0001000100010001] * block_word_count

        round_index: int = 0
        while True:
            round_keys_by_index[round_index] = self._compute_single_round_key(
                rolling_key_words[:block_word_count],
                auxiliary_key_words,
                round_constant_words,
            )
            if round_index == rounds:
                break

            if key_word_count != block_word_count:
                round_index += 2
                self._shift_left_in_place(round_constant_words)
                round_keys_by_index[round_index] = self._compute_single_round_key(
                    rolling_key_words[block_word_count : 2 * block_word_count],
                    auxiliary_key_words,
                    round_constant_words,
                )
                if round_index == rounds:
                    break

            round_index += 2
            self._shift_left_in_place(round_constant_words)
            rolling_key_words = rolling_key_words[1:] + rolling_key_words[:1]

        return [round_keys_by_index[i] for i in range(0, rounds + 1, 2)]

    def _compute_single_round_key(
        self,
        seed_words: list[int],
        auxiliary_key_words: list[int],
        round_constant_words: list[int],
    ) -> list[int]:
        """Compute one even-indexed round key.

        Realises the inner three-step structure shared by every even
        round key in Algorithm 7:

        1. ``round_specific = K_σ ⊞ TMV``
        2. ``state = seed ⊞ round_specific``
        3. ``state ← ψ ∘ σ_l ∘ τ_π'(state)``
        4. ``state ← state ⊕ round_specific``
        5. ``state ← ψ ∘ σ_l ∘ τ_π'(state)``
        6. ``state ← state ⊞ round_specific``

        :param seed_words: The :math:`N_b`-word slice of the master key
            that seeds this round key.
        :param auxiliary_key_words: :math:`K_\\sigma`.
        :param round_constant_words: Current value of the *TMV* round
            constant vector.
        :returns: The freshly computed even-indexed round key.
        """
        round_specific_value: list[int] = list(auxiliary_key_words)
        self._add_value_modular(round_specific_value, round_constant_words)

        state_words: list[int] = list(seed_words)
        self._add_value_modular(state_words, round_specific_value)
        self._encipher_round(state_words)
        self._xor_value(state_words, round_specific_value)
        self._encipher_round(state_words)
        self._add_value_modular(state_words, round_specific_value)
        return state_words

    @staticmethod
    def _shift_left_in_place(state_words: list[int]) -> None:
        """Left-shift every 64-bit word of ``state_words`` by one bit."""
        for index in range(len(state_words)):
            state_words[index] = (state_words[index] << 1) & 0xFFFFFFFFFFFFFFFF

    def _rotate_round_key_left(self, round_key_words: list[int]) -> None:
        """Cyclically rotate ``round_key_words`` left by :math:`2 N_b + 3` bytes.

        This rotation derives the odd-indexed round keys from the even ones
        (DSTU 7624:2014 section 5.2.4). The state is treated as a flat
        little-endian byte string ``8 N_b`` bytes long; the rotation is
        performed on that byte string and the result is re-encoded into
        64-bit words.

        :param round_key_words: Round key to rotate, modified in place.
        """
        block_word_count: int = self._parameters.block_word_count
        rotate_byte_count: int = 2 * block_word_count + 3
        flat_round_key: bytearray = bytearray(_words_to_bytes_little_endian(round_key_words))
        rotated: bytes = bytes(
            flat_round_key[rotate_byte_count:] + flat_round_key[:rotate_byte_count]
        )
        round_key_words[:] = _bytes_to_words_little_endian(rotated)

    # ------------------------------------------------------------------
    # Internal helpers used during key expansion
    # ------------------------------------------------------------------

    @staticmethod
    def _add_value_modular(state_words: list[int], value_words: list[int]) -> None:
        """Add ``value_words`` to ``state_words`` element-wise mod :math:`2^{64}`."""
        for index in range(len(state_words)):
            state_words[index] = (state_words[index] + value_words[index]) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _xor_value(state_words: list[int], value_words: list[int]) -> None:
        """XOR ``value_words`` into ``state_words`` element-wise."""
        for index in range(len(state_words)):
            state_words[index] ^= value_words[index]
