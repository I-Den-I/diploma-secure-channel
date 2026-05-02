# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""DSTU 4145-2002 elliptic-curve digital signature algorithm.

The Ukrainian national digital signature standard *DSTU 4145-2002* is a
DSA-like construction defined over a binary extension field
:math:`GF(2^m)`. It uses the discrete logarithm problem on a
characteristic-two short-Weierstrass elliptic curve as the underlying hard
problem and is structurally similar to (but distinct from) ECDSA.

Algorithmic summary
-------------------

Let :math:`E(GF(2^m))` be the curve, :math:`P` a point of prime order
:math:`n`, :math:`d \\in [1, n-1]` the signer's private key and
:math:`Q = -d \\cdot P` the corresponding public key. Let :math:`H` be the
binary representation of a message digest.

Signing :math:`H`:

1. Choose a uniformly random :math:`e \\in [1, n-1]`.
2. Compute the curve point :math:`R = e \\cdot P` and let
   :math:`f_e = R_x` (an element of the field).
3. Convert :math:`H` to a field element :math:`h` (truncating extra bits).
4. Compute :math:`y = h \\cdot f_e` in :math:`GF(2^m)`.
5. Let :math:`r` be the integer interpretation of :math:`y` reduced
   modulo :math:`n`. If :math:`r = 0`, restart at step 1.
6. Compute :math:`s = (e + d \\cdot r) \\bmod n`. If :math:`s = 0`,
   restart at step 1.
7. The signature is the pair :math:`(s, r)`, each encoded big-endian and
   zero-padded to :math:`\\lceil \\log_2 n / 8 \\rceil` bytes.

Verification of :math:`(s, r)` against :math:`Q` and :math:`H`:

1. Reject if :math:`r \\notin [1, n-1]` or :math:`s \\notin [1, n-1]`.
2. Convert :math:`H` to a field element :math:`h` exactly as in signing.
3. Compute :math:`R' = s \\cdot P + r \\cdot Q`.
4. If :math:`R'` is the point at infinity, reject.
5. Compute :math:`y' = h \\cdot R'_x`.
6. Accept if and only if the integer interpretation of :math:`y'` mod
   :math:`n` equals :math:`r`.

The inputs to the API are byte strings. The :class:`Dstu4145PrivateKey`
and :class:`Dstu4145PublicKey` types wrap the underlying integers and
points respectively.

:see: DSTU 4145-2002, sections 7 (signing) and 8 (verification).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Final

from secure_channel.crypto.binary_curve import BinaryCurvePoint
from secure_channel.crypto.dstu4145_curves import Dstu4145DomainParameters

RandomBytesProvider = Callable[[int], bytes]
"""A function returning ``n`` cryptographically random bytes."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _signature_component_byte_length(domain: Dstu4145DomainParameters) -> int:
    """Number of bytes used to encode one of the two signature components.

    DSTU 4145-2002 fixes the signature byte width as
    :math:`\\lceil \\log_2(n) / 8 \\rceil` per component. Both components
    are then concatenated into the final signature.
    """
    return (domain.subgroup_order.bit_length() + 7) // 8


def _convert_digest_to_field_element(
    domain: Dstu4145DomainParameters, message_digest: bytes
) -> int:
    """Convert a message digest into a field element of :math:`GF(2^m)`.

    The digest is interpreted as a big-endian integer. Bits beyond the
    field's degree :math:`m` are silently discarded; if the resulting
    element is the field zero, the value :math:`1` is substituted (the
    standard's signing algorithm cannot proceed when ``h * f_e = 0``).
    """
    integer_form: int = int.from_bytes(message_digest, "big")
    field_element: int = integer_form & domain.field.field_mask
    if field_element == 0:
        field_element = 1
    return field_element


def _sample_scalar_in_subgroup_range(
    subgroup_order: int, random_bytes: RandomBytesProvider
) -> int:
    """Uniformly sample an integer in :math:`[1, n - 1]`.

    Uses rejection sampling on a buffer of the appropriate width to avoid
    the modulo bias that a naive ``int(...) % n`` reduction would exhibit.
    """
    upper_bound_byte_length: int = (subgroup_order.bit_length() + 7) // 8
    while True:
        candidate: int = int.from_bytes(random_bytes(upper_bound_byte_length), "big")
        candidate &= (1 << subgroup_order.bit_length()) - 1
        if 1 <= candidate < subgroup_order:
            return candidate


def _encode_signature_component(value: int, byte_length: int) -> bytes:
    """Encode a non-negative integer as a big-endian, zero-padded byte string."""
    return value.to_bytes(byte_length, "big")


def _decode_signature_components(
    domain: Dstu4145DomainParameters, signature: bytes
) -> tuple[int, int]:
    """Split ``signature`` into integer ``(s, r)`` components.

    DSTU 4145-2002 stipulates that the signature is the concatenation of
    ``s`` followed by ``r``, each component encoded in
    :math:`\\lceil \\log_2(n) / 8 \\rceil` bytes (or any equal multiple
    thereof, padded with leading zeros).
    """
    if len(signature) % 2 != 0:
        raise ValueError("Signature byte length must be even.")
    half_length: int = len(signature) // 2
    s_value: int = int.from_bytes(signature[:half_length], "big")
    r_value: int = int.from_bytes(signature[half_length:], "big")
    return s_value, r_value


# ---------------------------------------------------------------------------
# Key types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Dstu4145PrivateKey:
    """A DSTU 4145-2002 private key, wrapping the integer scalar :math:`d`."""

    domain: Dstu4145DomainParameters
    secret_scalar: int

    def __post_init__(self) -> None:
        if not (1 <= self.secret_scalar < self.domain.subgroup_order):
            raise ValueError("Private key scalar d must lie in [1, n - 1].")

    def derive_public_key(self) -> "Dstu4145PublicKey":
        """Compute the matching public key :math:`Q = -d P`."""
        public_point: BinaryCurvePoint = (
            self.domain.base_point.scalar_multiply(self.secret_scalar).negate()
        )
        return Dstu4145PublicKey(domain=self.domain, point=public_point)


@dataclass(frozen=True, slots=True)
class Dstu4145PublicKey:
    """A DSTU 4145-2002 public key, wrapping the curve point :math:`Q`."""

    domain: Dstu4145DomainParameters
    point: BinaryCurvePoint

    def __post_init__(self) -> None:
        if self.point.is_infinity:
            raise ValueError("Public key cannot be the point at infinity.")
        if not self.domain.curve.contains(self.point):
            raise ValueError("Public key point does not lie on the curve.")
        # The point must lie in the prime-order subgroup of order n.
        if not self.point.scalar_multiply(self.domain.subgroup_order).is_infinity:
            raise ValueError("Public key point is not in the prime-order subgroup.")


# ---------------------------------------------------------------------------
# Signature scheme
# ---------------------------------------------------------------------------


class Dstu4145SignatureScheme:
    """Stateless signing/verification engine for a DSTU 4145-2002 curve.

    The class is constructed once for a given set of domain parameters and
    can subsequently be reused to sign or verify many messages with the
    same curve. All inputs are byte strings; the caller is responsible for
    hashing the message before invoking :meth:`sign` or :meth:`verify`.

    :param domain: Curve, base point and subgroup order.
    :param random_bytes: Callable returning ``n`` cryptographically random
        bytes; defaults to :func:`os.urandom` and should only be replaced
        for deterministic tests.
    """

    __slots__ = ("_domain", "_random_bytes", "_component_length")

    def __init__(
        self,
        domain: Dstu4145DomainParameters,
        random_bytes: RandomBytesProvider | None = None,
    ) -> None:
        self._domain: Final[Dstu4145DomainParameters] = domain
        self._random_bytes: Final[RandomBytesProvider] = random_bytes or os.urandom
        self._component_length: Final[int] = _signature_component_byte_length(domain)

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_key_pair(self) -> tuple[Dstu4145PrivateKey, Dstu4145PublicKey]:
        """Generate a fresh ``(private_key, public_key)`` pair."""
        secret_scalar: int = _sample_scalar_in_subgroup_range(
            self._domain.subgroup_order, self._random_bytes
        )
        private_key = Dstu4145PrivateKey(self._domain, secret_scalar)
        return private_key, private_key.derive_public_key()

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, private_key: Dstu4145PrivateKey, message_digest: bytes) -> bytes:
        """Produce a DSTU 4145-2002 signature over ``message_digest``.

        :param private_key: The signer's private key. Its domain must
            match this engine's domain.
        :param message_digest: Pre-computed message digest (typically the
            output of a cryptographic hash such as SHA-256 or Kupyna).
        :returns: The signature as ``s || r`` (concatenated big-endian
            byte strings, each :math:`\\lceil \\log_2 n / 8 \\rceil`
            bytes).
        :raises ValueError: If ``private_key`` belongs to a different
            domain than this engine.
        """
        if private_key.domain != self._domain:
            raise ValueError("Private key was created for a different domain.")

        field_digest: int = _convert_digest_to_field_element(
            self._domain, message_digest
        )
        while True:
            ephemeral_scalar, intermediate_field_value = (
                self._compute_presignature(field_digest)
            )
            integer_view: int = intermediate_field_value
            r_component: int = integer_view % self._domain.subgroup_order
            if r_component == 0:
                continue
            s_component: int = (
                ephemeral_scalar
                + private_key.secret_scalar * r_component
            ) % self._domain.subgroup_order
            if s_component == 0:
                continue
            return (
                _encode_signature_component(s_component, self._component_length)
                + _encode_signature_component(r_component, self._component_length)
            )

    def sign_with_explicit_nonce(
        self,
        private_key: Dstu4145PrivateKey,
        message_digest: bytes,
        ephemeral_scalar: int,
    ) -> bytes:
        """Produce a signature using a caller-supplied nonce.

        This entry point exists *exclusively* for verifying the cipher
        against the published test vectors of DSTU 4145-2002, where the
        nonce :math:`e` is fixed for reproducibility. **Do not use it in
        production**: a leaked or repeated nonce immediately reveals the
        private key.

        :param private_key: Signer's private key.
        :param message_digest: Pre-computed message digest.
        :param ephemeral_scalar: Deterministic value of :math:`e`.
        :raises ValueError: If the nonce or any derived value violates the
            standard's preconditions.
        """
        if private_key.domain != self._domain:
            raise ValueError("Private key was created for a different domain.")
        if not (1 <= ephemeral_scalar < self._domain.subgroup_order):
            raise ValueError("Ephemeral scalar e must lie in [1, n - 1].")

        field_digest: int = _convert_digest_to_field_element(
            self._domain, message_digest
        )
        intermediate_field_value: int = (
            self._domain.base_point.scalar_multiply(ephemeral_scalar).x_coordinate
        )
        if intermediate_field_value == 0:
            raise ValueError("Test nonce produced a zero x-coordinate.")
        product_field_value: int = self._domain.field.multiply(
            field_digest, intermediate_field_value
        )
        r_component: int = product_field_value % self._domain.subgroup_order
        if r_component == 0:
            raise ValueError("Test nonce produced r = 0.")
        s_component: int = (
            ephemeral_scalar + private_key.secret_scalar * r_component
        ) % self._domain.subgroup_order
        if s_component == 0:
            raise ValueError("Test nonce produced s = 0.")

        return (
            _encode_signature_component(s_component, self._component_length)
            + _encode_signature_component(r_component, self._component_length)
        )

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify(
        self,
        public_key: Dstu4145PublicKey,
        message_digest: bytes,
        signature: bytes,
    ) -> bool:
        """Verify a DSTU 4145-2002 signature.

        :param public_key: The signer's public key.
        :param message_digest: The same message digest the signer used.
        :param signature: The signature ``s || r`` to verify.
        :returns: ``True`` iff the signature is valid for the digest and
            the public key, ``False`` otherwise.
        """
        if public_key.domain != self._domain:
            return False

        try:
            s_component, r_component = _decode_signature_components(
                self._domain, signature
            )
        except ValueError:
            return False

        if not (1 <= r_component < self._domain.subgroup_order):
            return False
        if not (1 <= s_component < self._domain.subgroup_order):
            return False

        recovered_point: BinaryCurvePoint = self._domain.base_point.scalar_multiply(
            s_component
        ).add(public_key.point.scalar_multiply(r_component))
        if recovered_point.is_infinity:
            return False

        field_digest: int = _convert_digest_to_field_element(
            self._domain, message_digest
        )
        product_field_value: int = self._domain.field.multiply(
            field_digest, recovered_point.x_coordinate
        )
        return (product_field_value % self._domain.subgroup_order) == r_component

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_presignature(self, field_digest: int) -> tuple[int, int]:
        """Compute :math:`(e, h \\cdot (eP)_x)` for a fresh random nonce.

        Loops until the resulting field value is non-zero so that the
        outer signing loop always sees a well-defined ``r`` candidate.
        """
        while True:
            ephemeral_scalar: int = _sample_scalar_in_subgroup_range(
                self._domain.subgroup_order, self._random_bytes
            )
            intermediate_field_value: int = (
                self._domain.base_point.scalar_multiply(ephemeral_scalar).x_coordinate
            )
            if intermediate_field_value == 0:
                continue
            product_field_value: int = self._domain.field.multiply(
                field_digest, intermediate_field_value
            )
            if product_field_value == 0:
                continue
            return ephemeral_scalar, product_field_value


__all__: Final[list[str]] = [
    "Dstu4145SignatureScheme",
    "Dstu4145PrivateKey",
    "Dstu4145PublicKey",
    "RandomBytesProvider",
]
