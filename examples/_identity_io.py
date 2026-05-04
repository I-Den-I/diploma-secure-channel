# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Backwards-compatibility shim around :mod:`secure_channel.identity_io`.

The original implementation of the identity-on-disk helpers used to live
inside the :mod:`examples` package. From Phase 6 onwards the same logic
is exposed as a first-class module of the importable ``secure_channel``
package so that the Flet GUI under :mod:`gui` can reuse it without
duplicating code.

This file re-exports the canonical names under their historical
module path so that the existing demo scripts
(``generate_identity.py``, ``run_server.py``, ``run_client.py``)
continue to work unchanged.
"""

from __future__ import annotations

from pathlib import Path

from secure_channel.identity_io import (
    PRIVATE_KEY_FILE_NAME,
    PUBLIC_KEY_FILE_NAME,
    SUPPORTED_DOMAIN_LABEL,
    assemble_handshake_credentials,
    load_private_key_from_file,
    load_public_key_from_file,
    save_private_key_to_file,
    save_public_key_to_file,
)
from secure_channel.session.handshake import HandshakeIdentityCredentials


def load_credentials_for_demo(
    own_identity_directory: Path, peer_identity_directory: Path
) -> HandshakeIdentityCredentials:
    """Compatibility wrapper: accepts identity *directories* (legacy API).

    Forwards to :func:`secure_channel.identity_io.assemble_handshake_credentials`,
    which now operates on the explicit file paths inside the directories.
    """
    return assemble_handshake_credentials(
        own_private_key_path=own_identity_directory / PRIVATE_KEY_FILE_NAME,
        peer_public_key_path=peer_identity_directory / PUBLIC_KEY_FILE_NAME,
    )


__all__ = [
    "PRIVATE_KEY_FILE_NAME",
    "PUBLIC_KEY_FILE_NAME",
    "SUPPORTED_DOMAIN_LABEL",
    "load_credentials_for_demo",
    "load_private_key_from_file",
    "load_public_key_from_file",
    "save_private_key_to_file",
    "save_public_key_to_file",
]
