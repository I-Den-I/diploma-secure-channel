# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Affine arithmetic on the elliptic curves of DSTU 4145-2002.

DSTU 4145-2002 specifies elliptic curves of the short Koblitz form

.. math::
    E: y^{2} + xy = x^{3} + a x^{2} + b

over a binary extension field :math:`GF(2^m)`, where :math:`a \\in \\{0, 1\\}`
and :math:`b \\in GF(2^m)^{*}`. This module provides immutable
representations of points on such a curve together with point addition,
point doubling, point negation and scalar multiplication.

Affine coordinates are used throughout. Although Jacobian or López-Dahab
projective coordinates would yield better speed in production code, affine
arithmetic is mathematically the most direct presentation of the standard
and is fast enough for the modest signature throughput required by the
secure channel of this diploma project.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from secure_channel.crypto.binary_field import BinaryExtensionField


@dataclass(frozen=True, slots=True)
class BinaryEllipticCurve:
    """A short Weierstrass elliptic curve in characteristic two.

    :param field: The underlying binary extension field.
    :param coefficient_a: The :math:`a` coefficient (an element of
        :math:`GF(2^m)`; for DSTU 4145 it is always 0 or 1).
    :param coefficient_b: The :math:`b` coefficient (a non-zero element of
        :math:`GF(2^m)`).
    """

    field: BinaryExtensionField
    coefficient_a: int
    coefficient_b: int

    def __post_init__(self) -> None:
        if self.coefficient_b == 0:
            raise ValueError("DSTU 4145-2002 forbids b = 0.")
        if (self.coefficient_a >> self.field.degree) != 0:
            raise ValueError("Coefficient a does not fit inside the field.")
        if (self.coefficient_b >> self.field.degree) != 0:
            raise ValueError("Coefficient b does not fit inside the field.")

    def contains(self, point: "BinaryCurvePoint") -> bool:
        """Return whether ``point`` lies on the curve.

        The infinity point trivially satisfies the equation. For a finite
        point the standard short-Weierstrass relation
        :math:`y^2 + xy = x^3 + a x^2 + b` is checked literally.
        """
        if point.is_infinity:
            return True
        x_value: int = point.x_coordinate
        y_value: int = point.y_coordinate
        f = self.field
        left_hand_side: int = f.add(f.square(y_value), f.multiply(x_value, y_value))
        right_hand_side: int = f.add(
            f.add(
                f.multiply(f.square(x_value), x_value),
                f.multiply(self.coefficient_a, f.square(x_value)),
            ),
            self.coefficient_b,
        )
        return left_hand_side == right_hand_side

    def infinity(self) -> "BinaryCurvePoint":
        """Return the point at infinity on this curve."""
        return BinaryCurvePoint(self, _is_infinity_point=True)

    def point(self, x_coordinate: int, y_coordinate: int) -> "BinaryCurvePoint":
        """Construct an affine point and verify that it lies on the curve.

        :raises ValueError: If the supplied :math:`(x, y)` pair does not
            satisfy the curve equation.
        """
        candidate = BinaryCurvePoint(
            self,
            x_coordinate=x_coordinate,
            y_coordinate=y_coordinate,
            _is_infinity_point=False,
        )
        if not self.contains(candidate):
            raise ValueError(
                "Point (x, y) does not lie on the elliptic curve."
            )
        return candidate


@dataclass(frozen=True, slots=True)
class BinaryCurvePoint:
    """An affine point on a :class:`BinaryEllipticCurve`.

    Use :meth:`BinaryEllipticCurve.point` rather than constructing this
    class directly to receive automatic membership validation.

    :param curve: The owning curve.
    :param x_coordinate: Affine :math:`x`. Ignored for the infinity point.
    :param y_coordinate: Affine :math:`y`. Ignored for the infinity point.
    :param _is_infinity_point: Internal flag distinguishing the identity.
    """

    curve: BinaryEllipticCurve
    x_coordinate: int = 0
    y_coordinate: int = 0
    _is_infinity_point: bool = False

    @property
    def is_infinity(self) -> bool:
        """Whether this point is the additive identity (point at infinity)."""
        return self._is_infinity_point

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BinaryCurvePoint):
            return NotImplemented
        if self.curve != other.curve:
            return False
        if self.is_infinity or other.is_infinity:
            return self.is_infinity == other.is_infinity
        return (
            self.x_coordinate == other.x_coordinate
            and self.y_coordinate == other.y_coordinate
        )

    def __hash__(self) -> int:
        if self.is_infinity:
            return hash(("BinaryCurvePoint", "infinity", id(self.curve)))
        return hash(
            ("BinaryCurvePoint", id(self.curve), self.x_coordinate, self.y_coordinate)
        )

    def negate(self) -> "BinaryCurvePoint":
        """Return :math:`-P`.

        On characteristic-two curves :math:`-(x, y) = (x, x + y)`.
        """
        if self.is_infinity:
            return self
        return BinaryCurvePoint(
            self.curve,
            x_coordinate=self.x_coordinate,
            y_coordinate=self.curve.field.add(self.x_coordinate, self.y_coordinate),
            _is_infinity_point=False,
        )

    def add(self, other: "BinaryCurvePoint") -> "BinaryCurvePoint":
        """Return :math:`P + Q` using the affine addition formulas.

        Three branches are taken depending on the relationship between the
        two operands:

        * If either operand is the point at infinity, the sum is the other
          operand.
        * If :math:`P = -Q` the sum is the point at infinity.
        * If :math:`P = Q` (point doubling), the formula

          .. math::
              \\lambda = y_P / x_P + x_P, \\quad
              x_R = \\lambda^2 + \\lambda + a, \\quad
              y_R = x_P^2 + (\\lambda + 1) \\cdot x_R

          is applied.
        * Otherwise the slope is
          :math:`\\lambda = (y_P + y_Q) / (x_P + x_Q)` and

          .. math::
              x_R = \\lambda^2 + \\lambda + x_P + x_Q + a, \\quad
              y_R = \\lambda (x_P + x_R) + x_R + y_P
        """
        if self.curve != other.curve:
            raise ValueError("Cannot add points belonging to different curves.")
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        if self == other.negate():
            return self.curve.infinity()

        f = self.curve.field
        a_coefficient: int = self.curve.coefficient_a
        if self == other:
            if self.x_coordinate == 0:
                return self.curve.infinity()
            slope_lambda: int = f.add(
                f.divide(self.y_coordinate, self.x_coordinate),
                self.x_coordinate,
            )
            x_result: int = f.add(
                f.add(f.square(slope_lambda), slope_lambda),
                a_coefficient,
            )
            y_result: int = f.add(
                f.square(self.x_coordinate),
                f.multiply(f.add(slope_lambda, 1), x_result),
            )
        else:
            slope_lambda = f.divide(
                f.add(self.y_coordinate, other.y_coordinate),
                f.add(self.x_coordinate, other.x_coordinate),
            )
            x_result = f.add(
                f.add(
                    f.add(f.square(slope_lambda), slope_lambda),
                    f.add(self.x_coordinate, other.x_coordinate),
                ),
                a_coefficient,
            )
            y_result = f.add(
                f.add(
                    f.multiply(slope_lambda, f.add(self.x_coordinate, x_result)),
                    x_result,
                ),
                self.y_coordinate,
            )
        return BinaryCurvePoint(
            self.curve,
            x_coordinate=x_result,
            y_coordinate=y_result,
            _is_infinity_point=False,
        )

    def scalar_multiply(self, scalar: int) -> "BinaryCurvePoint":
        """Compute :math:`k \\cdot P` using the constant-iterations
        double-and-add ladder.

        For ``scalar`` equal to zero the result is the point at infinity;
        for negative scalars the result is :math:`(-k) \\cdot (-P)`.

        :param scalar: Multiplier.
        :returns: The scalar multiple as a curve point.
        """
        if scalar == 0:
            return self.curve.infinity()
        if scalar < 0:
            return self.negate().scalar_multiply(-scalar)

        accumulator: BinaryCurvePoint = self.curve.infinity()
        running_double: BinaryCurvePoint = self
        remaining_scalar: int = scalar
        while remaining_scalar:
            if remaining_scalar & 1:
                accumulator = accumulator.add(running_double)
            running_double = running_double.add(running_double)
            remaining_scalar >>= 1
        return accumulator

    # Operator overloads for ergonomic call sites.
    __add__ = add

    def __neg__(self) -> "BinaryCurvePoint":
        return self.negate()

    def __mul__(self, scalar: int) -> "BinaryCurvePoint":
        return self.scalar_multiply(scalar)

    __rmul__ = __mul__


# Re-exports kept compact and explicit for downstream modules.
__all__: Final[list[str]] = [
    "BinaryEllipticCurve",
    "BinaryCurvePoint",
]
