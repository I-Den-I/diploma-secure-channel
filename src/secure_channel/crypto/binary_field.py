# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Polynomial-basis arithmetic over the binary extension field :math:`GF(2^m)`.

DSTU 4145-2002 specifies its elliptic curves over :math:`GF(2^m)` represented
in *polynomial basis*. A field element is therefore an unsigned integer
whose binary expansion encodes the coefficients of a polynomial of degree
at most :math:`m - 1` over :math:`GF(2)`. The least significant bit of the
integer stores the constant coefficient.

The reduction (irreducible) polynomial :math:`f(x)` is itself encoded in the
same way; for the curves of DSTU 4145-2002 it is always either a trinomial
:math:`x^m + x^{k} + 1` or a pentanomial
:math:`x^m + x^{k_1} + x^{k_2} + x^{k_3} + 1`.

This module deliberately uses ``int``-based arithmetic rather than a custom
"polynomial" class. Python integers offer arbitrary precision, are
immutable, and admit very fast XOR and shift operations implemented in
optimised C code, which is exactly what binary-field arithmetic needs.

:see: DSTU 4145-2002 sections 5 and 6.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BinaryExtensionField:
    """Immutable description of a binary extension field :math:`GF(2^m)`.

    :param degree: Field degree :math:`m`.
    :param reduction_polynomial: Polynomial coefficient bit-mask of
        :math:`f(x)`; the bit at position ``i`` represents the
        coefficient of :math:`x^i`. The polynomial *must* be irreducible
        of degree exactly :math:`m`.
    """

    degree: int
    reduction_polynomial: int

    def __post_init__(self) -> None:
        if self.degree < 1:
            raise ValueError("Field degree m must be a positive integer.")
        if (self.reduction_polynomial >> self.degree) != 1:
            raise ValueError(
                "Reduction polynomial must have degree exactly m "
                f"(top bit at position {self.degree})."
            )
        if (self.reduction_polynomial & 1) == 0:
            raise ValueError(
                "Reduction polynomial of an extension field must have a "
                "non-zero constant term, otherwise it is reducible by x."
            )

    @property
    def field_mask(self) -> int:
        """Bit-mask :math:`2^m - 1` selecting valid coefficient positions."""
        return (1 << self.degree) - 1

    # ------------------------------------------------------------------
    # Reduction
    # ------------------------------------------------------------------

    def reduce(self, polynomial: int) -> int:
        """Reduce ``polynomial`` modulo the field's irreducible polynomial.

        Implements long division in :math:`GF(2)[x]` by repeatedly
        subtracting (XOR) a left-shifted copy of the reduction polynomial
        until the operand has degree strictly less than :math:`m`.

        :param polynomial: Arbitrary-precision integer encoding the
            polynomial to reduce. The value is assumed to be non-negative.
        :returns: A field element in canonical reduced form (an integer
            whose bit-length is at most :math:`m`).
        """
        reduced: int = polynomial
        while reduced.bit_length() > self.degree:
            shift: int = reduced.bit_length() - 1 - self.degree
            reduced ^= self.reduction_polynomial << shift
        return reduced

    # ------------------------------------------------------------------
    # Field operations
    # ------------------------------------------------------------------

    @staticmethod
    def add(left_element: int, right_element: int) -> int:
        """Compute :math:`a + b` in :math:`GF(2^m)` (polynomial XOR)."""
        return left_element ^ right_element

    def multiply(self, left_element: int, right_element: int) -> int:
        """Compute :math:`a \\cdot b \\bmod f(x)` in :math:`GF(2^m)`.

        Uses a textbook bit-level "Russian peasant" routine: for every set
        bit ``i`` of ``right_element``, XOR ``left_element`` shifted left by
        ``i`` into the running accumulator, then reduce.

        :param left_element: First field element (already reduced).
        :param right_element: Second field element (already reduced).
        :returns: Their product as a reduced field element.
        """
        accumulator: int = 0
        scanned_factor: int = right_element
        shifted_factor: int = left_element
        while scanned_factor:
            if scanned_factor & 1:
                accumulator ^= shifted_factor
            scanned_factor >>= 1
            shifted_factor <<= 1
        return self.reduce(accumulator)

    def square(self, element: int) -> int:
        """Compute :math:`a^2 \\bmod f(x)` in :math:`GF(2^m)`.

        Squaring in characteristic two is the bit-spreading map
        :math:`(b_{m-1}, ..., b_0) \\mapsto (b_{m-1}, 0, ..., b_1, 0, b_0)`,
        which is implemented here in O(m) Python integer operations.

        :param element: Field element to square (already reduced).
        :returns: :math:`a^2` as a reduced field element.
        """
        spread: int = 0
        bit_position: int = 0
        residual: int = element
        while residual:
            if residual & 1:
                spread |= 1 << (2 * bit_position)
            residual >>= 1
            bit_position += 1
        return self.reduce(spread)

    def inverse(self, element: int) -> int:
        """Compute the multiplicative inverse :math:`a^{-1}` in :math:`GF(2^m)`.

        Uses the extended Euclidean algorithm on polynomials in
        :math:`GF(2)[x]`. The recurrence

        .. math:: u \\cdot g_1 + v \\cdot g_2 = a \\cdot g_1 \\bmod f

        is maintained until ``v`` reaches zero; the desired inverse is then
        ``g1`` (taken modulo the field).

        :param element: Element to invert. Must be non-zero.
        :returns: The multiplicative inverse in reduced canonical form.
        :raises ZeroDivisionError: If ``element`` is the field zero.
        """
        if element == 0:
            raise ZeroDivisionError("Zero is not invertible in GF(2^m).")

        residue_high: int = element
        residue_low: int = self.reduction_polynomial
        coefficient_high: int = 1
        coefficient_low: int = 0

        while residue_low != 0:
            degree_high: int = residue_high.bit_length() - 1
            degree_low: int = residue_low.bit_length() - 1
            if degree_high < degree_low:
                residue_high, residue_low = residue_low, residue_high
                coefficient_high, coefficient_low = coefficient_low, coefficient_high
                degree_high, degree_low = degree_low, degree_high
            shift: int = degree_high - degree_low
            residue_high ^= residue_low << shift
            coefficient_high ^= coefficient_low << shift

        return self.reduce(coefficient_high)

    def divide(self, dividend: int, divisor: int) -> int:
        """Compute :math:`a / b = a \\cdot b^{-1}` in :math:`GF(2^m)`."""
        return self.multiply(dividend, self.inverse(divisor))

    # ------------------------------------------------------------------
    # Trace and half-trace (used by EC point compression / decompression)
    # ------------------------------------------------------------------

    def trace(self, element: int) -> int:
        """Absolute trace :math:`Tr(a) = \\sum_{i=0}^{m-1} a^{2^i}`.

        The trace is a linear function with values in :math:`\\{0, 1\\}`.

        :param element: Field element.
        :returns: Either 0 or 1.
        """
        accumulator: int = element
        squared_term: int = element
        for _ in range(1, self.degree):
            squared_term = self.square(squared_term)
            accumulator ^= squared_term
        return accumulator

    def half_trace(self, element: int) -> int:
        """Half-trace :math:`HTr(a) = \\sum_{i=0}^{(m-1)/2} a^{2^{2i}}`.

        Defined for odd :math:`m`. For an element ``a`` whose absolute trace
        is zero, ``HTr(a)`` is a solution of the quadratic equation
        :math:`z^2 + z = a`.

        :param element: Field element.
        :returns: A field element :math:`z` satisfying
            :math:`z^2 + z = a` (only meaningful when :math:`Tr(a) = 0`).
        :raises ValueError: If the field degree is even.
        """
        if self.degree % 2 == 0:
            raise ValueError(
                "The half-trace is only defined for odd field degrees m; "
                f"got m = {self.degree}."
            )
        accumulator: int = element
        for _ in range((self.degree - 1) // 2):
            accumulator = self.square(self.square(accumulator))
            accumulator ^= element
        return accumulator

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def from_bytes_truncating(self, data: bytes) -> int:
        """Decode a byte string as a field element, truncating extra bits.

        Bytes are interpreted in big-endian order, mirroring the convention
        used throughout DSTU 4145-2002 for representing integers and field
        elements. Any input bits beyond position :math:`m - 1` are simply
        discarded; this matches the behaviour required when reducing the
        output of a hash function whose digest length exceeds :math:`m`.

        :param data: Byte string, big-endian.
        :returns: A reduced-form field element.
        """
        return int.from_bytes(data, "big") & self.field_mask

    def to_bytes(self, element: int) -> bytes:
        """Encode a field element as a fixed-length big-endian byte string.

        The returned buffer has length :math:`\\lceil m/8 \\rceil` bytes.

        :param element: Field element to encode.
        :returns: Big-endian byte representation.
        :raises ValueError: If ``element`` exceeds the field size.
        """
        if element < 0 or element > self.field_mask:
            raise ValueError("Element is outside the canonical field range.")
        byte_length: int = (self.degree + 7) // 8
        return int(element).to_bytes(byte_length, "big")
