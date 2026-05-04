#!/usr/bin/env python3
# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Run the responder side of the secure channel.

The script listens on a TCP host/port pair, performs the SIGMA-style
mutually authenticated handshake with one connecting peer, then enters
an interactive chat loop:

* incoming :class:`secure_channel.network.messages.TextMessage` records
  are printed to stdout;
* incoming :class:`secure_channel.network.messages.FileTransferBegin`
  messages trigger a chunked file reception that writes to disk
  incrementally (``--save-files-to`` directory);
* lines typed on stdin are sent to the peer as text messages;
* the line ``/quit`` terminates the session.

Usage::

    python examples/run_server.py \\
        --identity examples/identities/alice \\
        --peer     examples/identities/bob \\
        --host 0.0.0.0 --port 9000 \\
        --save-files-to ./incoming

Once the script prints "listening on ..." it is ready to accept the
matching :mod:`run_client` invocation from the peer.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

# Resolve sibling helper module without requiring an installed package.
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from _identity_io import load_credentials_for_demo  # noqa: E402

from secure_channel.crypto.kalyna_aead import AuthenticationFailed  # noqa: E402
from secure_channel.network.connection import (  # noqa: E402
    SecureChannelConnection,
    SecureChannelConnectionClosed,
)
from secure_channel.network.file_transfer import (  # noqa: E402
    receive_file_over_secure_channel,
)
from secure_channel.network.messages import (  # noqa: E402
    FileTransferBegin,
    TextMessage,
)
from secure_channel.network.server import SecureChannelServer  # noqa: E402
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
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind address (default 0.0.0.0).")
    parser.add_argument("--port", type=int, required=True,
                        help="TCP port to listen on.")
    parser.add_argument("--save-files-to", type=Path,
                        default=Path.cwd() / "received_files",
                        help="Directory where received files are written.")
    parser.add_argument(
        "--freshness-tolerance-seconds",
        type=int,
        default=DEFAULT_TIMESTAMP_TOLERANCE_MICROSECONDS // 1_000_000,
        help="Symmetric freshness window for record timestamps (default 30 s). "
             "Pure-Python Kalyna is slow; a larger value (e.g. 1800) helps "
             "during multi-MB file transfers.",
    )
    return parser


async def _read_lines_from_stdin() -> str:
    """Read one line from stdin in a thread, since stdin is not asyncio-aware."""
    return await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)


async def _send_loop(connection: SecureChannelConnection) -> None:
    """Read user input and forward each line as a :class:`TextMessage`.

    If stdin is not a TTY (e.g. when the script is launched from a
    scripted test harness, ``nohup``, or backgrounded with no
    controlling terminal) the loop disables interactive input and
    simply waits indefinitely so that EOF on a non-existent input does
    not prematurely cancel the receive side of the connection.
    """
    if not sys.stdin.isatty():
        await asyncio.Event().wait()  # never fires; cancelled on shutdown
        return

    print("Type a message and press Enter (or '/quit' to disconnect):")
    while True:
        try:
            line: str = await _read_lines_from_stdin()
        except (KeyboardInterrupt, EOFError):
            break
        if not line:
            break
        text: str = line.rstrip("\r\n")
        if text == "/quit":
            break
        if not text:
            continue
        try:
            await connection.send_message(TextMessage(text=text))
        except SecureChannelConnectionClosed:
            print("[peer disconnected; cannot send further messages]")
            break


async def _receive_loop(
    connection: SecureChannelConnection, save_files_to: Path
) -> None:
    """Print incoming text messages, save incoming files."""
    save_files_to.mkdir(parents=True, exist_ok=True)
    while True:
        try:
            message = await connection.receive_message()
        except SecureChannelConnectionClosed:
            print("[peer closed the connection]")
            return
        except AuthenticationFailed as authentication_error:
            print(f"[record rejected: {authentication_error}]")
            continue

        if isinstance(message, TextMessage):
            print(f"[peer]> {message.text}")
        elif isinstance(message, FileTransferBegin):
            print(
                f"[peer]> sending file '{message.filename}' "
                f"({message.total_byte_length} bytes, "
                f"chunk size {message.chunk_byte_length})..."
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


async def _serve(args: argparse.Namespace) -> None:
    credentials = load_credentials_for_demo(args.identity, args.peer)
    freshness_policy = FreshnessPolicy(
        timestamp_tolerance_microseconds=args.freshness_tolerance_seconds * 1_000_000,
    )

    handler_done_event = asyncio.Event()

    async def connection_handler(connection: SecureChannelConnection) -> None:
        print(f"[handshake]> peer authenticated: {connection.peer_address}")
        send_task = asyncio.create_task(_send_loop(connection))
        receive_task = asyncio.create_task(
            _receive_loop(connection, args.save_files_to)
        )
        try:
            done, pending = await asyncio.wait(
                {send_task, receive_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
        finally:
            handler_done_event.set()

    server = SecureChannelServer(
        credentials=credentials,
        connection_handler=connection_handler,
        freshness_policy=freshness_policy,
    )
    await server.start(host=args.host, port=args.port)
    print(f"[server]> listening on {args.host}:{server.bound_port}")
    print(f"[server]> received files will be written under {args.save_files_to}")
    try:
        await handler_done_event.wait()
    finally:
        await server.close()


def main(argv: list[str] | None = None) -> int:
    """Entry point for the script."""
    args = _build_argument_parser().parse_args(argv)
    try:
        asyncio.run(_serve(args))
    except KeyboardInterrupt:
        print("\n[server]> interrupted by user.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
