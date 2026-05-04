# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""On-disk persistence helpers for DSTU 4145-2002 identity key pairs.

The diploma project keeps identities in a tiny JSON-on-disk format so
that students can verify the contents with ``cat`` or any text editor.
The format is application-specific and not part of any DSTU standard;
its sole purpose is to make the demo scripts and the Flet GUI
reproducible.

Each user owns a directory holding two files:

* ``private.json`` --- the secret scalar :math:`d`. Mode ``0600``,
  must never leave the owning machine.
* ``public.json`` --- the public point :math:`Q = -dP` in
  uncompressed affine encoding (``x`` and ``y`` coordinates as
  big-endian hex). Shareable through any trusted out-of-band channel.

The module is consumed both by the runnable demo scripts under
``examples/`` and by the Flet GUI under :mod:`gui`.
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


def resolve_supported_domain(domain_label: str) -> Dstu4145DomainParameters:
    """Look up a :class:`Dstu4145DomainParameters` instance by its label.

    :param domain_label: The ``curve`` field as stored on disk.
    :returns: The matching domain parameter object.
    :raises ValueError: If ``domain_label`` is not known to this build.
    """
    if domain_label != SUPPORTED_DOMAIN_LABEL:
        raise ValueError(
            f"Unsupported curve domain label: {domain_label!r}; "
            f"only {SUPPORTED_DOMAIN_LABEL!r} is wired in to this build."
        )
    return DSTU4145_M163_PB


def save_private_key_to_file(
    private_key: Dstu4145PrivateKey, file_path: Path
) -> None:
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
        # Read-only filesystems (e.g. CI) tolerate the failure.
        pass


def load_private_key_from_file(file_path: Path) -> Dstu4145PrivateKey:
    """Reverse :func:`save_private_key_to_file`.

    :param file_path: Filesystem path of the ``private.json``.
    :returns: A :class:`Dstu4145PrivateKey` reconstructed from disk.
    :raises ValueError: If the JSON header references an unsupported curve.
    """
    payload: dict[str, object] = json.loads(file_path.read_text(encoding="utf-8"))
    domain = resolve_supported_domain(str(payload["curve"]))
    secret_scalar: int = int(str(payload["private_scalar_hex"]), 16)
    return Dstu4145PrivateKey(domain, secret_scalar)


def save_public_key_to_file(
    public_key: Dstu4145PublicKey, file_path: Path
) -> None:
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
    """Reverse :func:`save_public_key_to_file`.

    Re-validates that the deserialised :math:`(x, y)` pair lies on the
    advertised curve and that it lives in the prime-order subgroup. The
    :class:`Dstu4145PublicKey` constructor performs both checks
    internally; this function adds a friendlier error trace by
    surfacing them explicitly.

    :param file_path: Filesystem path of the ``public.json``.
    :returns: A validated :class:`Dstu4145PublicKey`.
    """
    payload: dict[str, object] = json.loads(file_path.read_text(encoding="utf-8"))
    domain = resolve_supported_domain(str(payload["curve"]))
    x_coordinate: int = int(str(payload["x_coordinate_hex"]), 16)
    y_coordinate: int = int(str(payload["y_coordinate_hex"]), 16)
    public_point: BinaryCurvePoint = domain.curve.point(
        x_coordinate=x_coordinate, y_coordinate=y_coordinate
    )
    return Dstu4145PublicKey(domain=domain, point=public_point)


def assemble_handshake_credentials(
    own_private_key_path: Path,
    peer_public_key_path: Path,
) -> HandshakeIdentityCredentials:
    """Load the credentials object expected by the handshake module.

    Glues :func:`load_private_key_from_file` and
    :func:`load_public_key_from_file` together and verifies that both
    keys live on the same curve domain.

    :param own_private_key_path: Path to the local user's
        ``private.json``.
    :param peer_public_key_path: Path to the peer's ``public.json``
        (obtained out-of-band, treated as authentic).
    :returns: A populated :class:`HandshakeIdentityCredentials` ready
        for :func:`secure_channel.network.client.connect_secure_channel`
        or :class:`secure_channel.network.server.SecureChannelServer`.
    :raises ValueError: If the two files reference different curves or
        if either file is malformed.
    """
    own_private_key: Dstu4145PrivateKey = load_private_key_from_file(
        own_private_key_path
    )
    peer_public_key: Dstu4145PublicKey = load_public_key_from_file(
        peer_public_key_path
    )
    if own_private_key.domain != peer_public_key.domain:
        raise ValueError(
            "Own private key and peer public key reference different curves."
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
    "assemble_handshake_credentials",
    "load_private_key_from_file",
    "load_public_key_from_file",
    "resolve_supported_domain",
    "save_private_key_to_file",
    "save_public_key_to_file",
]
