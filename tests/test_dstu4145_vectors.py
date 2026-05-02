# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Verification of the DSTU 4145-2002 implementation against the worked
example documented in Annex B of the standard.

The test vector chosen here is the only fully-specified end-to-end example
that is universally reproduced in independent third-party DSTU 4145
implementations (notably the :mod:`dstu4145` C++ library by Anton Shamray,
https://github.com/shamray/dstu4145, file ``test/dstu.cpp``). Inputs:

* Curve over :math:`GF(2^{163})` with pentanomial reduction polynomial,
  :math:`a = 1`,
  :math:`b = \\mathtt{0x5FF6108462A2DC8210AB403925E638A19C1455D21}`.
* Subgroup order :math:`n = \\mathtt{0x400000000000000000002BEC12BE2262D39BCF14D}`.
* Base point :math:`P` as in Annex B.
* Private key :math:`d = \\mathtt{0x183F60FDF7951FF47D67193F8D073790C1C9B5A3E}`.
* Random nonce :math:`e = \\mathtt{0x1025E40BD97DB012B7A1D79DE8E12932D247F61C6}`
  (fixed to make the test reproducible).
* Hash to be signed :math:`H` =
  ``0x09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF``.

Expected outputs:

* :math:`s = \\mathtt{0x02100D86957331832B8E8C230F5BD6A332B3615ACA}`
* :math:`r = \\mathtt{0x0274EA2C0CAA014A0D80A424F59ADE7A93068D08A7}`

A second test then verifies that :meth:`verify` returns ``True`` for the
freshly generated signature, and that flipping any bit of either the
digest or the signature flips the verifier's verdict to ``False``.
"""

from __future__ import annotations

import os

import pytest

from secure_channel.crypto.dstu4145 import (
    Dstu4145PrivateKey,
    Dstu4145PublicKey,
    Dstu4145SignatureScheme,
)
from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB


_TEST_VECTOR_PRIVATE_KEY: int = 0x183F60FDF7951FF47D67193F8D073790C1C9B5A3E
_TEST_VECTOR_NONCE_E: int = 0x1025E40BD97DB012B7A1D79DE8E12932D247F61C6
_TEST_VECTOR_HASH_HEX: str = (
    "09C9C44277910C9AAEE486883A2EB95B7180166DDF73532EEB76EDAEF52247FF"
)
_TEST_VECTOR_EXPECTED_S: int = 0x02100D86957331832B8E8C230F5BD6A332B3615ACA
_TEST_VECTOR_EXPECTED_R: int = 0x0274EA2C0CAA014A0D80A424F59ADE7A93068D08A7


def test_signing_with_fixed_nonce_matches_dstu4145_annex_b() -> None:
    """The published example must be reproduced bit-for-bit."""
    domain = DSTU4145_M163_PB
    private_key = Dstu4145PrivateKey(domain, _TEST_VECTOR_PRIVATE_KEY)
    scheme = Dstu4145SignatureScheme(domain)

    digest_bytes: bytes = bytes.fromhex(_TEST_VECTOR_HASH_HEX)
    signature: bytes = scheme.sign_with_explicit_nonce(
        private_key=private_key,
        message_digest=digest_bytes,
        ephemeral_scalar=_TEST_VECTOR_NONCE_E,
    )

    component_byte_length: int = (domain.subgroup_order.bit_length() + 7) // 8
    expected_signature: bytes = (
        _TEST_VECTOR_EXPECTED_S.to_bytes(component_byte_length, "big")
        + _TEST_VECTOR_EXPECTED_R.to_bytes(component_byte_length, "big")
    )
    assert signature == expected_signature, (
        "Signature for the Annex B vector does not match the expected value."
        f"\n  expected: {expected_signature.hex()}"
        f"\n  produced: {signature.hex()}"
    )


def test_verifier_accepts_fixed_nonce_signature() -> None:
    """The verifier must accept the canonical signature."""
    domain = DSTU4145_M163_PB
    private_key = Dstu4145PrivateKey(domain, _TEST_VECTOR_PRIVATE_KEY)
    public_key: Dstu4145PublicKey = private_key.derive_public_key()
    scheme = Dstu4145SignatureScheme(domain)

    digest_bytes: bytes = bytes.fromhex(_TEST_VECTOR_HASH_HEX)
    component_byte_length: int = (domain.subgroup_order.bit_length() + 7) // 8
    signature: bytes = (
        _TEST_VECTOR_EXPECTED_S.to_bytes(component_byte_length, "big")
        + _TEST_VECTOR_EXPECTED_R.to_bytes(component_byte_length, "big")
    )

    assert scheme.verify(public_key, digest_bytes, signature) is True


def test_verifier_rejects_tampered_signature() -> None:
    """Flipping a single bit of the signature must invalidate it."""
    domain = DSTU4145_M163_PB
    private_key = Dstu4145PrivateKey(domain, _TEST_VECTOR_PRIVATE_KEY)
    public_key: Dstu4145PublicKey = private_key.derive_public_key()
    scheme = Dstu4145SignatureScheme(domain)

    digest_bytes: bytes = bytes.fromhex(_TEST_VECTOR_HASH_HEX)
    component_byte_length: int = (domain.subgroup_order.bit_length() + 7) // 8
    valid_signature: bytes = (
        _TEST_VECTOR_EXPECTED_S.to_bytes(component_byte_length, "big")
        + _TEST_VECTOR_EXPECTED_R.to_bytes(component_byte_length, "big")
    )
    tampered_signature: bytes = bytes(
        valid_signature[:0] + bytes([valid_signature[0] ^ 0x01]) + valid_signature[1:]
    )
    assert scheme.verify(public_key, digest_bytes, tampered_signature) is False


def test_verifier_rejects_tampered_digest() -> None:
    """A different message digest must produce a verification failure."""
    domain = DSTU4145_M163_PB
    private_key = Dstu4145PrivateKey(domain, _TEST_VECTOR_PRIVATE_KEY)
    public_key: Dstu4145PublicKey = private_key.derive_public_key()
    scheme = Dstu4145SignatureScheme(domain)

    digest_bytes: bytes = bytes.fromhex(_TEST_VECTOR_HASH_HEX)
    component_byte_length: int = (domain.subgroup_order.bit_length() + 7) // 8
    valid_signature: bytes = (
        _TEST_VECTOR_EXPECTED_S.to_bytes(component_byte_length, "big")
        + _TEST_VECTOR_EXPECTED_R.to_bytes(component_byte_length, "big")
    )
    # Flip a bit in the *last* byte of the digest. Since the field
    # truncation discards the most-significant 256 - 163 = 93 bits, we
    # must alter a low-order bit (i.e., a byte near the end of the
    # big-endian buffer) for the change to survive the field reduction.
    altered_digest: bytes = digest_bytes[:-1] + bytes([digest_bytes[-1] ^ 0x01])
    assert scheme.verify(public_key, altered_digest, valid_signature) is False


def test_round_trip_with_random_keys() -> None:
    """For a fresh key pair, ``verify(sign(m)) == True`` for many messages."""
    domain = DSTU4145_M163_PB
    scheme = Dstu4145SignatureScheme(domain, random_bytes=os.urandom)
    private_key, public_key = scheme.generate_key_pair()

    for _ in range(8):
        message_digest: bytes = os.urandom(32)
        signature: bytes = scheme.sign(private_key, message_digest)
        assert scheme.verify(public_key, message_digest, signature) is True


def test_signature_with_wrong_key_is_rejected() -> None:
    """Verification with an unrelated public key must fail."""
    domain = DSTU4145_M163_PB
    scheme = Dstu4145SignatureScheme(domain)
    signing_private_key, _signing_public_key = scheme.generate_key_pair()
    _other_private_key, other_public_key = scheme.generate_key_pair()

    message_digest: bytes = os.urandom(32)
    signature: bytes = scheme.sign(signing_private_key, message_digest)
    assert scheme.verify(other_public_key, message_digest, signature) is False


def test_invalid_private_key_scalar_is_rejected() -> None:
    with pytest.raises(ValueError):
        Dstu4145PrivateKey(DSTU4145_M163_PB, 0)
    with pytest.raises(ValueError):
        Dstu4145PrivateKey(DSTU4145_M163_PB, DSTU4145_M163_PB.subgroup_order)


def test_public_key_must_be_on_curve() -> None:
    """A point not on the curve must not be accepted as a public key."""
    domain = DSTU4145_M163_PB
    rogue_point = domain.base_point.__class__(
        domain.curve, x_coordinate=0xDEAD, y_coordinate=0xBEEF
    )
    with pytest.raises(ValueError):
        Dstu4145PublicKey(domain, rogue_point)
