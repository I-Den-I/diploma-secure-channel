# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Ephemeral Diffie--Hellman key exchange over a DSTU 4145-2002 curve.

The key exchange follows the standard "ECDH" template adapted to the
binary curve setting. Both parties:

1. Sample an ephemeral private scalar :math:`e \\in [1, n - 1]` uniformly
   at random.
2. Compute the corresponding ephemeral public key
   :math:`E = e \\cdot P`, where :math:`P` is the curve's base point.
3. Exchange the public keys :math:`E_A` and :math:`E_B`.
4. Each derives the shared secret as
   :math:`S = e_{\\text{self}} \\cdot E_{\\text{peer}}`. The
   x-coordinate of :math:`S` is the canonical shared key material that
   feeds the KDF in :mod:`secure_channel.crypto.kdf`.

Ephemeral keys provide *forward secrecy*: even if a long-term DSTU 4145
private key is later compromised, recordings of past sessions cannot be
decrypted as long as the corresponding ephemeral keys were destroyed.

The functions exposed by this module never accept the peer's long-term
key; the binding between the long-term identity and the ephemeral key is
performed in the handshake module by signing the ephemeral public key
with the long-term DSTU 4145 private key.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Final

from secure_channel.crypto.binary_curve import BinaryCurvePoint
from secure_channel.crypto.dstu4145_curves import Dstu4145DomainParameters

RandomBytesProvider = Callable[[int], bytes]
"""A function returning ``n`` cryptographically random bytes."""


def _sample_scalar_in_subgroup_range(
    subgroup_order: int, random_bytes: RandomBytesProvider
) -> int:
    """Uniformly sample a scalar in :math:`[1, n - 1]` (rejection sampling)."""
    upper_bound_byte_length: int = (subgroup_order.bit_length() + 7) // 8
    while True:
        candidate: int = int.from_bytes(random_bytes(upper_bound_byte_length), "big")
        candidate &= (1 << subgroup_order.bit_length()) - 1
        if 1 <= candidate < subgroup_order:
            return candidate


@dataclass(frozen=True, slots=True)
class EphemeralKeyAgreementKeyPair:
    """A short-lived ECDH key pair for a single handshake.

    :param domain: Curve and base-point parameters.
    :param private_scalar: Secret ephemeral scalar :math:`e`.
    :param public_point: Public ephemeral point :math:`E = e \\cdot P`.
    """

    domain: Dstu4145DomainParameters
    private_scalar: int
    public_point: BinaryCurvePoint


def generate_ephemeral_key_pair(
    domain: Dstu4145DomainParameters,
    random_bytes: RandomBytesProvider | None = None,
) -> EphemeralKeyAgreementKeyPair:
    """Generate a fresh ephemeral key pair on the supplied curve.

    :param domain: Curve, base point and subgroup order.
    :param random_bytes: Source of cryptographic randomness; defaults to
        :func:`os.urandom`.
    :returns: A new :class:`EphemeralKeyAgreementKeyPair` instance.
    """
    random_source: RandomBytesProvider = random_bytes or os.urandom
    private_scalar: int = _sample_scalar_in_subgroup_range(
        domain.subgroup_order, random_source
    )
    public_point: BinaryCurvePoint = domain.base_point.scalar_multiply(private_scalar)
    return EphemeralKeyAgreementKeyPair(
        domain=domain,
        private_scalar=private_scalar,
        public_point=public_point,
    )


def encode_ephemeral_public_key(public_point: BinaryCurvePoint) -> bytes:
    """Serialise an ephemeral public key as ``x_bytes || y_bytes``.

    The encoding is "uncompressed affine": both coordinates are stored
    big-endian, padded to :math:`\\lceil m / 8 \\rceil` bytes each. This
    avoids the ambiguity of x-only encoding and is sufficient for the
    purposes of this protocol (the verifier always re-checks curve
    membership of any deserialised point).
    """
    if public_point.is_infinity:
        raise ValueError("Cannot serialise the point at infinity.")
    coordinate_byte_length: int = (public_point.curve.field.degree + 7) // 8
    return public_point.x_coordinate.to_bytes(
        coordinate_byte_length, "big"
    ) + public_point.y_coordinate.to_bytes(coordinate_byte_length, "big")


def decode_ephemeral_public_key(
    domain: Dstu4145DomainParameters, encoded_point: bytes
) -> BinaryCurvePoint:
    """Deserialise and re-validate an encoded ephemeral public key.

    :raises ValueError: If the bytes are malformed, the resulting point is
        not on the curve, or it is the point at infinity.
    """
    coordinate_byte_length: int = (domain.curve.field.degree + 7) // 8
    if len(encoded_point) != 2 * coordinate_byte_length:
        raise ValueError(
            f"Encoded public key must be {2 * coordinate_byte_length} bytes."
        )
    x_coordinate: int = int.from_bytes(encoded_point[:coordinate_byte_length], "big")
    y_coordinate: int = int.from_bytes(encoded_point[coordinate_byte_length:], "big")
    return domain.curve.point(x_coordinate=x_coordinate, y_coordinate=y_coordinate)


def compute_shared_secret_x_bytes(
    own_key_pair: EphemeralKeyAgreementKeyPair,
    peer_public_point: BinaryCurvePoint,
) -> bytes:
    """Derive the canonical shared secret bytes from an ECDH exchange.

    The shared point is :math:`e_{\\text{self}} \\cdot E_{\\text{peer}}`.
    Its x-coordinate is encoded as a fixed-length big-endian byte string
    of length :math:`\\lceil m / 8 \\rceil`.

    :raises ValueError: If the shared point degenerates to infinity (a
        cryptographically negligible event indicating either a bug or a
        deliberately malicious peer key).
    """
    shared_point: BinaryCurvePoint = peer_public_point.scalar_multiply(
        own_key_pair.private_scalar
    )
    if shared_point.is_infinity:
        raise ValueError(
            "ECDH degenerated to the point at infinity; peer public key likely invalid."
        )
    coordinate_byte_length: int = (own_key_pair.domain.field.degree + 7) // 8
    return shared_point.x_coordinate.to_bytes(coordinate_byte_length, "big")


__all__: Final[list[str]] = [
    "EphemeralKeyAgreementKeyPair",
    "RandomBytesProvider",
    "compute_shared_secret_x_bytes",
    "decode_ephemeral_public_key",
    "encode_ephemeral_public_key",
    "generate_ephemeral_key_pair",
]
