# Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.
"""Async integration tests of the asyncio TCP transport layer.

These tests verify that the SIGMA handshake completes successfully over
a real loopback TCP connection and that the resulting
:class:`SecureChannelConnection` correctly transports
:class:`TextMessage` payloads in both directions.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from secure_channel.crypto.dstu4145 import (
    Dstu4145PrivateKey,
    Dstu4145SignatureScheme,
)
from secure_channel.crypto.dstu4145_curves import DSTU4145_M163_PB
from secure_channel.crypto.kalyna_aead import AuthenticationFailed
from secure_channel.network.client import connect_secure_channel
from secure_channel.network.connection import (
    MessageMetrics,
    SecureChannelConnection,
    SecureChannelConnectionClosed,
)
from secure_channel.network.messages import TextMessage
from secure_channel.network.server import SecureChannelServer
from secure_channel.session.handshake import HandshakeIdentityCredentials


def _generate_long_term_keys() -> tuple[Dstu4145PrivateKey, Dstu4145PrivateKey]:
    scheme = Dstu4145SignatureScheme(DSTU4145_M163_PB)
    initiator_private_key, _ = scheme.generate_key_pair()
    responder_private_key, _ = scheme.generate_key_pair()
    return initiator_private_key, responder_private_key


def _credentials_for(
    own_private_key: Dstu4145PrivateKey, peer_private_key: Dstu4145PrivateKey
) -> HandshakeIdentityCredentials:
    return HandshakeIdentityCredentials(
        domain=DSTU4145_M163_PB,
        own_long_term_private_key=own_private_key,
        peer_long_term_public_key=peer_private_key.derive_public_key(),
    )


@pytest.mark.asyncio
async def test_loopback_handshake_and_text_round_trip() -> None:
    """A client and server complete the handshake and exchange text."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )

    received_messages: list[str] = []
    server_side_done = asyncio.Event()

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        try:
            while True:
                message = await connection.receive_message()
                assert isinstance(message, TextMessage)
                received_messages.append(message.text)
                await connection.send_message(
                    TextMessage(text=f"echo:{message.text}")
                )
        except SecureChannelConnectionClosed:
            pass
        finally:
            server_side_done.set()

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        async with await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
        ) as client_connection:
            for sent_index in range(4):
                await client_connection.send_message(
                    TextMessage(text=f"hello-{sent_index}")
                )
                response = await client_connection.receive_message()
                assert isinstance(response, TextMessage)
                assert response.text == f"echo:hello-{sent_index}"
        await asyncio.wait_for(server_side_done.wait(), timeout=5.0)
    finally:
        await server.close()

    assert received_messages == ["hello-0", "hello-1", "hello-2", "hello-3"]


@pytest.mark.asyncio
async def test_handshake_fails_when_server_uses_wrong_initiator_key() -> None:
    """Server rejects a client whose long-term key it does not trust."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    impostor_private_key, _ = _generate_long_term_keys()

    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    # Server expects the *impostor* as its peer; the real client will
    # therefore fail signature verification on msg3.
    responder_credentials = _credentials_for(
        responder_private_key, impostor_private_key
    )

    handler_invocation_count: int = 0

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        nonlocal handler_invocation_count
        handler_invocation_count += 1

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        # The client side completes msg1+msg2 successfully (responder
        # signature still verifies because the responder uses its true
        # private key), then sends msg3. The server rejects msg3 and
        # closes the socket. The client's connection_secure_channel
        # call returns successfully because its own state was
        # consistent; the failure is observed when the next read times
        # out or returns EOF.
        client_connection = await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
        )
        try:
            with pytest.raises(SecureChannelConnectionClosed):
                # Server has dropped the socket; no further messages
                # will arrive.
                await asyncio.wait_for(client_connection.receive_message(), timeout=2.0)
        finally:
            await client_connection.close()
    finally:
        await server.close()

    # The server-side handler is never invoked because the handshake
    # failed before authentication completed.
    assert handler_invocation_count == 0


@pytest.mark.asyncio
async def test_send_and_receive_with_metrics_returns_message_metrics() -> None:
    """send_message_with_metrics / receive_message_with_metrics report stats."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )
    server_done = asyncio.Event()
    server_metrics: list[MessageMetrics] = []

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        try:
            message, metrics = await connection.receive_message_with_metrics()
            assert isinstance(message, TextMessage)
            server_metrics.append(metrics)
            send_metrics = await connection.send_message_with_metrics(
                TextMessage(text=f"echo:{message.text}")
            )
            server_metrics.append(send_metrics)
        except SecureChannelConnectionClosed:
            pass
        finally:
            server_done.set()

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        async with await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
        ) as client_connection:
            client_send = await client_connection.send_message_with_metrics(
                TextMessage(text="hello-metrics")
            )
            response, client_recv = (
                await client_connection.receive_message_with_metrics()
            )
            assert isinstance(response, TextMessage)
            assert response.text == "echo:hello-metrics"
        await asyncio.wait_for(server_done.wait(), timeout=5.0)
    finally:
        await server.close()

    # Both endpoints saw two MessageMetrics — one for each direction.
    assert len(server_metrics) == 2
    for metrics in (client_send, client_recv, *server_metrics):
        assert isinstance(metrics, MessageMetrics)
        # Sealed records carry the AEAD tag, so they're always longer
        # than the plaintext record they wrap.
        assert metrics.sealed_byte_length > metrics.plaintext_byte_length
        # Crypto duration is non-negative; relax to >= 0 since perf_counter
        # may legitimately measure 0 on very fast systems with low resolution.
        assert metrics.crypto_duration_seconds >= 0
        assert metrics.crypto_duration_milliseconds == (
            metrics.crypto_duration_seconds * 1000.0
        )


@pytest.mark.asyncio
async def test_tamper_next_incoming_record_triggers_authentication_failed() -> None:
    """Setting tamper_next_incoming_record corrupts one byte → MAC fails."""
    initiator_private_key, responder_private_key = _generate_long_term_keys()
    initiator_credentials = _credentials_for(
        initiator_private_key, responder_private_key
    )
    responder_credentials = _credentials_for(
        responder_private_key, initiator_private_key
    )
    server_done = asyncio.Event()

    async def server_side_handler(connection: SecureChannelConnection) -> None:
        try:
            await connection.send_message(TextMessage(text="payload"))
        finally:
            server_done.set()

    server = SecureChannelServer(
        credentials=responder_credentials,
        connection_handler=server_side_handler,
    )
    await server.start(host="127.0.0.1", port=0)
    try:
        async with await connect_secure_channel(
            host="127.0.0.1",
            port=server.bound_port,
            credentials=initiator_credentials,
        ) as client_connection:
            client_connection.tamper_next_incoming_record = True
            with pytest.raises(AuthenticationFailed):
                await asyncio.wait_for(
                    client_connection.receive_message(), timeout=5.0
                )
            # Flag should auto-reset after one use.
            assert client_connection.tamper_next_incoming_record is False
        await asyncio.wait_for(server_done.wait(), timeout=5.0)
    finally:
        await server.close()
