# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Secure data exchange channel based on Ukrainian national crypto standards.

This package provides a from-scratch, audited implementation of the
cryptographic primitives standardised in Ukraine and a secure messaging
protocol layered on top of them:

* :mod:`secure_channel.crypto.kalyna` --- the Kalyna block cipher
  (DSTU 7624:2014) for symmetric confidentiality.
* :mod:`secure_channel.crypto.dstu4145` --- the DSTU 4145-2002 elliptic
  curve digital signature scheme over binary extension fields :math:`GF(2^m)`
  for asymmetric authentication.
* :mod:`secure_channel.session` --- mutual-authentication handshake,
  authenticated-encryption session establishment and replay protection.
* :mod:`secure_channel.network` --- asyncio framing layer and chunked
  encrypted file transfer.

The implementation follows the academic standards required by the
bachelor diploma project at Lviv Polytechnic National University.

:Version: 0.1.0
"""

from __future__ import annotations

__version__: str = "0.1.0"
__author__: str = "Denys Nazarenko"
__institution__: str = "Lviv Polytechnic National University"
