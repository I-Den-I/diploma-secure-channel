# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Authenticated encryption with associated data based on Kalyna.

This module assembles two of the modes from
:mod:`secure_channel.crypto.kalyna_modes` --- :class:`KalynaCounterMode`
for confidentiality and :class:`KalynaCmac` for integrity --- into a
single authenticated-encryption-with-associated-data (AEAD) primitive.

The composition follows the *Encrypt-then-MAC* pattern, which is provably
indistinguishable from a random function under the assumption that the
underlying block cipher is a strong PRP and the MAC is a secure PRF
(Bellare & Namprempre, 2000). Two independent keys are used: one for the
CTR keystream and one for the CMAC tag, derived through a single
key-derivation step inside :class:`KalynaAead`.

Wire format
-----------

A single AEAD record encodes as

::

    nonce  || ciphertext || tag
    12 B      n B            16 B

where ``nonce`` is supplied by the caller, ``ciphertext`` has the same
length as the plaintext, and ``tag`` is the CMAC of the byte string
``length-prefixed associated data || nonce || ciphertext``.

Length prefixing of the associated data prevents trivial collision
attacks where an attacker could shift bytes between the AAD and the
ciphertext while keeping the concatenation identical.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Final

from secure_channel.crypto.kalyna_modes import KalynaCmac, KalynaCounterMode


class AuthenticationFailed(Exception):
    """Raised when a record's authentication tag does not verify.

    The exception carries no diagnostic information about which byte of
    the ciphertext failed to authenticate; this avoids leaking timing /
    structural information that would aid an attacker.
    """


@dataclass(frozen=True, slots=True)
class KalynaAeadKey:
    """Pair of independent keys for the Kalyna AEAD construction.

    :param encryption_key: 32-byte key for the CTR keystream cipher.
    :param authentication_key: 32-byte key for the CMAC tag.
    """

    encryption_key: bytes
    authentication_key: bytes

    KEY_BYTE_LENGTH: ClassVar[int] = 32

    def __post_init__(self) -> None:
        if len(self.encryption_key) != self.KEY_BYTE_LENGTH:
            raise ValueError(
                f"Encryption key must be {self.KEY_BYTE_LENGTH} bytes."
            )
        if len(self.authentication_key) != self.KEY_BYTE_LENGTH:
            raise ValueError(
                f"Authentication key must be {self.KEY_BYTE_LENGTH} bytes."
            )

    @classmethod
    def total_byte_length(cls) -> int:
        """Number of bytes of key material required to construct an instance."""
        return 2 * cls.KEY_BYTE_LENGTH

    @classmethod
    def from_concatenated(cls, concatenated_key_material: bytes) -> "KalynaAeadKey":
        """Split 64 bytes into two 32-byte halves used as the AEAD keys."""
        if len(concatenated_key_material) != cls.total_byte_length():
            raise ValueError(
                f"Need {cls.total_byte_length()} bytes; got {len(concatenated_key_material)}."
            )
        return cls(
            encryption_key=concatenated_key_material[: cls.KEY_BYTE_LENGTH],
            authentication_key=concatenated_key_material[cls.KEY_BYTE_LENGTH :],
        )


class KalynaAead:
    """Encrypt-then-MAC AEAD wrapper around Kalyna(128, 256).

    :param key: Pair of independent keys for confidentiality and integrity.
    :param tag_byte_length: Size of the authentication tag (default 16).
    """

    NONCE_BYTE_LENGTH: Final[int] = KalynaCounterMode.NONCE_BYTE_LENGTH
    DEFAULT_TAG_BYTE_LENGTH: Final[int] = 16

    __slots__ = ("_cipher_mode", "_mac", "_tag_byte_length")

    def __init__(self, key: KalynaAeadKey, *, tag_byte_length: int = DEFAULT_TAG_BYTE_LENGTH) -> None:
        self._cipher_mode: Final[KalynaCounterMode] = KalynaCounterMode(key.encryption_key)
        self._mac: Final[KalynaCmac] = KalynaCmac(
            key.authentication_key, tag_byte_length=tag_byte_length
        )
        self._tag_byte_length: Final[int] = tag_byte_length

    @property
    def tag_byte_length(self) -> int:
        """Length of the authentication tag emitted by :meth:`encrypt`, in bytes."""
        return self._tag_byte_length

    def encrypt(
        self,
        nonce: bytes,
        plaintext: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        """Encrypt and authenticate ``plaintext`` along with ``associated_data``.

        :param nonce: 12-byte unique nonce for this record.
        :param plaintext: The data to be kept confidential.
        :param associated_data: Public-but-authenticated header bytes.
        :returns: ``nonce || ciphertext || tag``.
        """
        if len(nonce) != self.NONCE_BYTE_LENGTH:
            raise ValueError(f"Nonce must be {self.NONCE_BYTE_LENGTH} bytes.")
        ciphertext: bytes = self._cipher_mode.process(nonce, plaintext)
        tag: bytes = self._mac.compute_tag(
            self._build_mac_input(associated_data, nonce, ciphertext)
        )
        return nonce + ciphertext + tag

    def decrypt(self, sealed_record: bytes, associated_data: bytes = b"") -> bytes:
        """Authenticate and decrypt a sealed record.

        :param sealed_record: ``nonce || ciphertext || tag`` (as produced
            by :meth:`encrypt`).
        :param associated_data: Same public-but-authenticated bytes used
            during encryption.
        :returns: The recovered plaintext.
        :raises AuthenticationFailed: If the tag does not verify.
        """
        if len(sealed_record) < self.NONCE_BYTE_LENGTH + self._tag_byte_length:
            raise AuthenticationFailed("Record is shorter than the AEAD overhead.")
        nonce: bytes = sealed_record[: self.NONCE_BYTE_LENGTH]
        ciphertext_with_tag: bytes = sealed_record[self.NONCE_BYTE_LENGTH :]
        ciphertext: bytes = ciphertext_with_tag[: -self._tag_byte_length]
        tag: bytes = ciphertext_with_tag[-self._tag_byte_length :]

        if not self._mac.verify_tag(
            self._build_mac_input(associated_data, nonce, ciphertext), tag
        ):
            raise AuthenticationFailed("Authentication tag mismatch.")
        return self._cipher_mode.process(nonce, ciphertext)

    @staticmethod
    def _build_mac_input(
        associated_data: bytes, nonce: bytes, ciphertext: bytes
    ) -> bytes:
        """Length-prefix the AAD before concatenating with nonce and ciphertext.

        The 8-byte big-endian length prefix prevents an attacker from
        moving bytes between the AAD and the ciphertext while keeping the
        MAC input identical.
        """
        return (
            len(associated_data).to_bytes(8, "big")
            + associated_data
            + nonce
            + ciphertext
        )


__all__: Final[list[str]] = [
    "AuthenticationFailed",
    "KalynaAead",
    "KalynaAeadKey",
]
