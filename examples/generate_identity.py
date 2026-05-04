#!/usr/bin/env python3
# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Generate a long-term DSTU 4145-2002 identity for the demo scripts.

Each user of the secure channel needs exactly one long-term key pair.
Run this utility once per user, then share *only* the resulting
``public.json`` file (never the ``private.json``) with peers through a
trusted out-of-band channel (in-person, signed email, ...).

Usage::

    python examples/generate_identity.py alice
    python examples/generate_identity.py bob --output-dir /tmp/dstu

After both invocations the ``examples/identities/`` directory will
contain two sub-directories ``alice/`` and ``bob/``, each with a
``private.json`` (mode 0600) and a ``public.json``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Resolve sibling helper module without requiring an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from _identity_io import (  # noqa: E402  (sys.path tweak above)
    PRIVATE_KEY_FILE_NAME,
    PUBLIC_KEY_FILE_NAME,
    save_private_key_to_file,
    save_public_key_to_file,
)
from secure_channel.crypto.dstu4145 import Dstu4145SignatureScheme  # noqa: E402
from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB  # noqa: E402


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "identity_name",
        help="Short identifier for this user (e.g. 'alice', 'bob'). "
        "Used as the directory name inside --output-dir.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "identities",
        help="Parent directory under which the per-user folder is created. "
        "Defaults to ./examples/identities.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the script."""
    args = _build_argument_parser().parse_args(argv)
    identity_directory: Path = args.output_dir / args.identity_name
    identity_directory.mkdir(parents=True, exist_ok=True)

    signature_scheme = Dstu4145SignatureScheme(DSTU4145_M163_PB)
    private_key, public_key = signature_scheme.generate_key_pair()

    private_key_path: Path = identity_directory / PRIVATE_KEY_FILE_NAME
    public_key_path: Path = identity_directory / PUBLIC_KEY_FILE_NAME

    save_private_key_to_file(private_key, private_key_path)
    save_public_key_to_file(public_key, public_key_path)

    print(f"Identity '{args.identity_name}' generated:")
    print(f"  private key (KEEP SECRET, mode 0600): {private_key_path}")
    print(f"  public key  (share with peers):       {public_key_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
