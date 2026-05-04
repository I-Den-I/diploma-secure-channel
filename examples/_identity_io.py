# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""On-disk persistence helpers for DSTU 4145-2002 identity key pairs.

The demo scripts under :mod:`examples` use a tiny JSON-on-disk format to
persist long-term identities. The format is intentionally human-readable
so a student can inspect a file with ``cat`` or open it in a text
editor to verify what is stored.

The identity directory layout produced by
:func:`save_private_key_to_file` and :func:`save_public_key_to_file`
mirrors the *PKI of small projects*: each user holds two files, one of
which (``public.json``) is shareable and one (``private.json``) is
local-only.

This module is *not* part of the public ``secure_channel`` API. It
exists solely to keep the demo scripts terse.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Final

from secure_channel.crypto.binary_curve import BinaryCurvePoint
from secure_channel.crypto.dstu4145 import (
    Dstu4145PrivateKey,
    Dstu4145PublicKey,
)
from secure_channel.crypto.dstu4145_curves import (
    DSTU4145_M163_PB,
    Dstu4145DomainParameters,
)
from secure_channel.session.handshake import HandshakeIdentityCredentials


SUPPORTED_DOMAIN_LABEL: Final[str] = "DSTU4145_M163_PB"
"""Label used in the JSON header to identify the curve domain."""

PRIVATE_KEY_FILE_NAME: Final[str] = "private.json"
"""Filename for the local-only private key inside an identity directory."""

PUBLIC_KEY_FILE_NAME: Final[str] = "public.json"
"""Filename for the shareable public key inside an identity directory."""


def _resolve_domain(label: str) -> Dstu4145DomainParameters:
    """Look up a :class:`Dstu4145DomainParameters` instance by its label."""
    if label != SUPPORTED_DOMAIN_LABEL:
        raise ValueError(
            f"Unsupported curve domain label: {label!r}; "
            f"only {SUPPORTED_DOMAIN_LABEL!r} is wired in to the demo scripts."
        )
    return DSTU4145_M163_PB


def save_private_key_to_file(private_key: Dstu4145PrivateKey, file_path: Path) -> None:
    """Serialise ``private_key`` to ``file_path`` and lock it down to ``0o600``.

    :param private_key: The DSTU 4145 private key to persist.
    :param file_path: Filesystem path of the JSON file to write.
    """
    payload: dict[str, object] = {
        "version": 1,
        "curve": SUPPORTED_DOMAIN_LABEL,
        "private_scalar_hex": format(private_key.secret_scalar, "x"),
    }
    file_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(file_path, 0o600)
    except OSError:
        # Read-only filesystems (e.g., CI) tolerate the failure.
        pass


def load_private_key_from_file(file_path: Path) -> Dstu4145PrivateKey:
    """Reverse :func:`save_private_key_to_file`."""
    payload: dict[str, object] = json.loads(file_path.read_text(encoding="utf-8"))
    domain = _resolve_domain(str(payload["curve"]))
    secret_scalar = int(str(payload["private_scalar_hex"]), 16)
    return Dstu4145PrivateKey(domain, secret_scalar)


def save_public_key_to_file(public_key: Dstu4145PublicKey, file_path: Path) -> None:
    """Serialise ``public_key`` to ``file_path`` (uncompressed affine).

    :param public_key: The DSTU 4145 public key to persist.
    :param file_path: Filesystem path of the JSON file to write.
    """
    payload: dict[str, object] = {
        "version": 1,
        "curve": SUPPORTED_DOMAIN_LABEL,
        "x_coordinate_hex": format(public_key.point.x_coordinate, "x"),
        "y_coordinate_hex": format(public_key.point.y_coordinate, "x"),
    }
    file_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_public_key_from_file(file_path: Path) -> Dstu4145PublicKey:
    """Reverse :func:`save_public_key_to_file`, re-validating the point on the curve."""
    payload: dict[str, object] = json.loads(file_path.read_text(encoding="utf-8"))
    domain = _resolve_domain(str(payload["curve"]))
    x_coordinate: int = int(str(payload["x_coordinate_hex"]), 16)
    y_coordinate: int = int(str(payload["y_coordinate_hex"]), 16)
    public_point: BinaryCurvePoint = domain.curve.point(
        x_coordinate=x_coordinate, y_coordinate=y_coordinate
    )
    return Dstu4145PublicKey(domain=domain, point=public_point)


def load_credentials_for_demo(
    own_identity_directory: Path, peer_identity_directory: Path
) -> HandshakeIdentityCredentials:
    """Assemble the :class:`HandshakeIdentityCredentials` used by the demo scripts.

    :param own_identity_directory: Directory holding the local user's
        ``private.json`` (and, irrelevantly, their own public key).
    :param peer_identity_directory: Directory holding *only* the
        counterparty's ``public.json`` (the private key is theirs and
        must remain on their machine).
    :returns: A populated :class:`HandshakeIdentityCredentials` ready to
        be passed to :func:`secure_channel.network.client.connect_secure_channel`
        or :class:`secure_channel.network.server.SecureChannelServer`.
    """
    own_private_key: Dstu4145PrivateKey = load_private_key_from_file(
        own_identity_directory / PRIVATE_KEY_FILE_NAME
    )
    peer_public_key: Dstu4145PublicKey = load_public_key_from_file(
        peer_identity_directory / PUBLIC_KEY_FILE_NAME
    )
    return HandshakeIdentityCredentials(
        domain=own_private_key.domain,
        own_long_term_private_key=own_private_key,
        peer_long_term_public_key=peer_public_key,
    )


__all__: Final[list[str]] = [
    "PRIVATE_KEY_FILE_NAME",
    "PUBLIC_KEY_FILE_NAME",
    "SUPPORTED_DOMAIN_LABEL",
    "load_credentials_for_demo",
    "load_private_key_from_file",
    "load_public_key_from_file",
    "save_private_key_to_file",
    "save_public_key_to_file",
]
