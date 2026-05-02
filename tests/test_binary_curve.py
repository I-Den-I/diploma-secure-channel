# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Group-law tests for :class:`BinaryEllipticCurve` arithmetic.

The tests use the DSTU 4145 :math:`GF(2^{163})` curve as the worked
example. They check the elementary group axioms that an ECC
implementation must satisfy:

* The point at infinity is the identity.
* Adding a point to its own negation yields the identity.
* Scalar multiplication agrees with iterated addition.
* The advertised subgroup order :math:`n` annihilates the base point
  (i.e., :math:`nP = O`).
"""

from __future__ import annotations

from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB


def test_infinity_is_additive_identity() -> None:
    base_point = DSTU4145_M163_PB.base_point
    assert (base_point + DSTU4145_M163_PB.curve.infinity()) == base_point
    assert (DSTU4145_M163_PB.curve.infinity() + base_point) == base_point


def test_point_plus_negation_is_infinity() -> None:
    base_point = DSTU4145_M163_PB.base_point
    assert (base_point + base_point.negate()).is_infinity


def test_scalar_zero_yields_infinity() -> None:
    assert DSTU4145_M163_PB.base_point.scalar_multiply(0).is_infinity


def test_scalar_one_is_identity() -> None:
    base_point = DSTU4145_M163_PB.base_point
    assert base_point.scalar_multiply(1) == base_point


def test_doubling_matches_self_addition() -> None:
    base_point = DSTU4145_M163_PB.base_point
    doubled_via_addition = base_point + base_point
    doubled_via_scalar = base_point.scalar_multiply(2)
    assert doubled_via_addition == doubled_via_scalar


def test_iterated_addition_matches_scalar_multiply() -> None:
    base_point = DSTU4145_M163_PB.base_point
    accumulator = DSTU4145_M163_PB.curve.infinity()
    for _ in range(7):
        accumulator = accumulator + base_point
    assert accumulator == base_point.scalar_multiply(7)


def test_subgroup_order_annihilates_base_point() -> None:
    assert DSTU4145_M163_PB.base_point.scalar_multiply(
        DSTU4145_M163_PB.subgroup_order
    ).is_infinity


def test_distributivity_of_scalar_multiplication() -> None:
    base_point = DSTU4145_M163_PB.base_point
    scalar_first: int = 1234567
    scalar_second: int = 9876543
    sum_then_multiply = base_point.scalar_multiply(scalar_first + scalar_second)
    multiply_then_add = base_point.scalar_multiply(
        scalar_first
    ) + base_point.scalar_multiply(scalar_second)
    assert sum_then_multiply == multiply_then_add
