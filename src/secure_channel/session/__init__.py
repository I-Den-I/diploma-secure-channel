# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Session-layer primitives: handshake, key exchange, and record protocol.

The :mod:`session` package layers the cryptographic primitives in
:mod:`secure_channel.crypto` into the high-level API actually exposed to
applications:

* :mod:`secure_channel.session.key_exchange` performs an ephemeral
  Diffie--Hellman key agreement over a DSTU 4145-2002 curve.
* :mod:`secure_channel.session.handshake` runs a SIGMA-style mutually
  authenticated handshake and produces a fully populated
  :class:`SecureSession` ready to encrypt / decrypt application data.
* :mod:`secure_channel.session.records` defines the wire format for the
  authenticated record protocol used after the handshake completes.
"""

from __future__ import annotations
