# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Algebraic property tests for :class:`BinaryExtensionField`.

These tests exercise the basic axioms of a finite field --- additive and
multiplicative identities, the inverse relation
:math:`a \\cdot a^{-1} = 1`, the relation between squaring and
multiplication, and the trace/half-trace specialisation
:math:`(HTr(a))^{2} + HTr(a) = a` for trace-zero inputs --- against the
two reduction polynomials used by the standard curves of the project.
"""

from __future__ import annotations

import os

import pytest

from secure_channel.crypto.binary_field import BinaryExtensionField

# Pentanomial reduction polynomial of the DSTU 4145 m = 163 curve.
_FIELD_M163: BinaryExtensionField = BinaryExtensionField(
    degree=163,
    reduction_polynomial=(1 << 163) | (1 << 7) | (1 << 6) | (1 << 3) | 1,
)


@pytest.fixture
def sample_field() -> BinaryExtensionField:
    return _FIELD_M163


def _random_field_element(field: BinaryExtensionField) -> int:
    raw_byte_count: int = (field.degree + 7) // 8
    return int.from_bytes(os.urandom(raw_byte_count), "big") & field.field_mask


def test_zero_is_additive_identity(sample_field: BinaryExtensionField) -> None:
    a: int = _random_field_element(sample_field)
    assert sample_field.add(a, 0) == a


def test_one_is_multiplicative_identity(sample_field: BinaryExtensionField) -> None:
    a: int = _random_field_element(sample_field)
    assert sample_field.multiply(a, 1) == a


def test_zero_absorbs_multiplication(sample_field: BinaryExtensionField) -> None:
    a: int = _random_field_element(sample_field)
    assert sample_field.multiply(a, 0) == 0


def test_squaring_equals_self_multiplication(sample_field: BinaryExtensionField) -> None:
    a: int = _random_field_element(sample_field)
    assert sample_field.square(a) == sample_field.multiply(a, a)


def test_inverse_yields_unity(sample_field: BinaryExtensionField) -> None:
    for _ in range(8):
        candidate: int = _random_field_element(sample_field)
        if candidate == 0:
            continue
        assert sample_field.multiply(candidate, sample_field.inverse(candidate)) == 1


def test_inverse_of_zero_raises(sample_field: BinaryExtensionField) -> None:
    with pytest.raises(ZeroDivisionError):
        sample_field.inverse(0)


def test_half_trace_solves_quadratic(sample_field: BinaryExtensionField) -> None:
    """For elements with zero trace, ``HTr(a)`` satisfies ``z^2 + z = a``."""
    for _ in range(8):
        candidate: int = _random_field_element(sample_field)
        if sample_field.trace(candidate) == 1:
            # Square it once to project onto the trace-zero subspace.
            candidate = sample_field.square(candidate) ^ candidate
        if sample_field.trace(candidate) != 0:
            continue
        z: int = sample_field.half_trace(candidate)
        assert sample_field.add(sample_field.square(z), z) == candidate


def test_invalid_polynomial_is_rejected() -> None:
    with pytest.raises(ValueError):
        BinaryExtensionField(degree=4, reduction_polynomial=0b11000)
    with pytest.raises(ValueError):
        BinaryExtensionField(degree=4, reduction_polynomial=0b11110)
