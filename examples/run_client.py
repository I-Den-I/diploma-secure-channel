#!/usr/bin/env python3
# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Run the initiator side of the secure channel.

The script connects to a TCP host/port pair, performs the SIGMA-style
mutually authenticated handshake with the responder running
:mod:`run_server`, then enters an interactive prompt accepting:

* a free-form text line (transmitted as
  :class:`secure_channel.network.messages.TextMessage`);
* the special command ``/sendfile <path>`` (streams the file at
  ``<path>`` over the secure channel using the chunked file-transfer
  module);
* the special command ``/quit`` (closes the connection cleanly).

Usage::

    python examples/run_client.py \\
        --identity examples/identities/bob \\
        --peer     examples/identities/alice \\
        --host alice.example.com --port 9000 \\
        --save-files-to ./incoming
"""

from __future__ import annotations

import argparse
import asyncio
import shlex
import sys
from pathlib import Path

# Resolve sibling helper module without requiring an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from _identity_io import load_credentials_for_demo  # noqa: E402

from secure_channel.crypto.kalyna_aead import AuthenticationFailed  # noqa: E402
from secure_channel.network.client import connect_secure_channel  # noqa: E402
from secure_channel.network.connection import (  # noqa: E402
    SecureChannelConnection,
    SecureChannelConnectionClosed,
)
from secure_channel.network.file_transfer import (  # noqa: E402
    DEFAULT_FILE_TRANSFER_CHUNK_BYTE_LENGTH,
    receive_file_over_secure_channel,
    send_file_over_secure_channel,
)
from secure_channel.network.messages import (  # noqa: E402
    FileTransferBegin,
    TextMessage,
)
from secure_channel.session.records import (  # noqa: E402
    DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS,
    FreshnessPolicy,
)


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--identity", required=True, type=Path,
                        help="Directory holding our private.json + public.json.")
    parser.add_argument("--peer", required=True, type=Path,
                        help="Directory holding the peer's public.json.")
    parser.add_argument("--host", required=True,
                        help="Hostname / IP / ngrok / Tailscale address of the server.")
    parser.add_argument("--port", required=True, type=int,
                        help="TCP port the server is listening on.")
    parser.add_argument("--save-files-to", type=Path,
                        default=Path.cwd() / "received_files",
                        help="Directory where files received from the server are written.")
    parser.add_argument(
        "--chunk-size-bytes",
        type=int,
        default=DEFAULT_FILE_TRANSFER_CHUNK_BYTE_LENGTH,
        help="Per-chunk payload size for outgoing /sendfile transfers.",
    )
    parser.add_argument(
        "--freshness-tolerance-seconds",
        type=int,
        default=DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS // 1_000_000,
        help="Symmetric freshness window for record timestamps (default 30 s).",
    )
    return parser


async def _read_line_from_stdin() -> str:
    """Read one line from stdin in a worker thread."""
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)


async def _interactive_send_loop(
    connection: SecureChannelConnection, chunk_byte_length: int
) -> None:
    """Read user input and dispatch text messages or file sends.

    Reads commands from stdin until ``/quit`` is typed (interactive
    mode) or until stdin reaches EOF (scripted / piped mode). In both
    cases the function returns normally; the calling task tree then
    closes the connection.
    """
    print(
        "Type a message, '/sendfile <path>' to transfer a file, "
        "or '/quit' to disconnect:"
    )
    while True:
        try:
            line: str = await _read_line_from_stdin()
        except (KeyboardInterrupt, EOFError):
            break
        if not line:
            break
        line = line.rstrip("\r\n")
        if not line:
            continue
        if line == "/quit":
            break
        if line.startswith("/sendfile"):
            try:
                _, raw_path = shlex.split(line, posix=True)
            except ValueError:
                print("Usage: /sendfile <path>")
                continue
            file_path = Path(raw_path).expanduser()
            if not file_path.is_file():
                print(f"[error] {file_path} is not a regular file.")
                continue
            print(
                f"[client]> uploading {file_path} "
                f"({file_path.stat().st_size} bytes)..."
            )
            try:
                digest_bytes = await send_file_over_secure_channel(
                    connection=connection,
                    source_file_path=file_path,
                    chunk_byte_length=chunk_byte_length,
                )
            except SecureChannelConnectionClosed:
                print("[client]> peer disconnected during file transfer.")
                break
            print(f"[client]> upload complete; SHA-256 = {digest_bytes.hex()}")
            continue

        try:
            await connection.send_message(TextMessage(text=line))
        except SecureChannelConnectionClosed:
            print("[client]> peer disconnected.")
            break


async def _receive_loop(
    connection: SecureChannelConnection, save_files_to: Path
) -> None:
    """Print incoming text messages and save incoming files."""
    save_files_to.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            message = await connection.receive_message()
        except SecureChannelConnectionClosed:
            print("[client]> server closed the connection.")
            return
        except AuthenticationFailed as authentication_error:
            print(f"[client]> record rejected: {authentication_error}")
            continue

        if isinstance(message, TextMessage):
            print(f"[peer]> {message.text}")
        elif isinstance(message, FileTransferBegin):
            print(
                f"[peer]> sending file '{message.filename}' "
                f"({message.total_byte_length} bytes)..."
            )
            try:
                destination_file_path = await receive_file_over_secure_channel(
                    connection=connection,
                    destination_directory=save_files_to,
                    file_transfer_begin=message,
                    overwrite_existing_file=True,
                )
            except Exception as transfer_error:
                print(f"[peer]> file transfer failed: {transfer_error}")
                continue
            print(f"[peer]> file saved to {destination_file_path}")
        else:
            print(f"[peer]> unsupported message type: {type(message).__name__}")


async def _connect_and_chat(args: argparse.Namespace) -> None:
    credentials = load_credentials_for_demo(args.identity, args.peer)
    freshness_policy = FreshnessPolicy(
        timestamp_tolerance_microseconds=args.freshness_tolerance_seconds * 1_000_000,
    )
    print(f"[client]> connecting to {args.host}:{args.port} ...")
    connection = await connect_secure_channel(
        host=args.host,
        port=args.port,
        credentials=credentials,
        freshness_policy=freshness_policy,
    )
    print("[client]> handshake complete.")
    try:
        send_task = asyncio.create_task(
            _interactive_send_loop(connection, args.chunk_size_bytes)
        )
        receive_task = asyncio.create_task(
            _receive_loop(connection, args.save_files_to)
        )
        done, pending = await asyncio.wait(
            {send_task, receive_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
    finally:
        await connection.close()


def main(argv: list[str] | None = None) -> int:
    """Entry point for the script."""
    args = _build_argument_parser().parse_args(argv)
    try:
        asyncio.run(_connect_and_chat(args))
    except KeyboardInterrupt:
        print("\n[client]> interrupted by user.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
