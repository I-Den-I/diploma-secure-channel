# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Cryptographic primitives implementing the Ukrainian DSTU standards.

The submodules contained in this package implement, from first principles,
the symmetric block cipher *Kalyna* (DSTU 7624:2014) and the elliptic curve
digital signature algorithm DSTU 4145-2002 together with the supporting
binary-field arithmetic.

All algorithms were verified against the official test vectors published in
the appendices of the corresponding DSTU standards. The exposed public API
is intentionally minimal --- callers should rely on the high-level
:mod:`secure_channel.session` module rather than wiring primitives manually.
"""

from __future__ import annotations
