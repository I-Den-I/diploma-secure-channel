# diploma-secure-channel

A bachelor's diploma project (Lviv Polytechnic National University, 2026)
implementing a secure data exchange channel based on the Ukrainian national
cryptographic standards:

* **DSTU 7624:2014** &mdash; the *Kalyna* symmetric block cipher.
* **DSTU 4145-2002** &mdash; elliptic curve digital signature algorithm
  over binary extension fields.

The project is structured as five sequential phases. After every phase the
test suite is executed end-to-end and a dedicated Git commit is produced.

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Cryptographic primitives & verification against DSTU test vectors | ✅ done |
| 2 | Secure handshake protocol (mutual auth + key agreement) | ✅ done |
| 3 | Attack mitigation (sliding replay window, timestamp validation, MITM) | ✅ done |
| 4 | Async TCP transport, multiplexed messages, chunked file/photo transfer | ✅ done |
| 5 | Final polish — copyright headers, docstrings, type hints, demo scripts, [`TESTING_GUIDE.md`](TESTING_GUIDE.md) | ✅ done |

## Quick start

```bash
# 1. Create and activate a virtual environment.
python3 -m venv .venv
source .venv/bin/activate

# 2. Install runtime + test dependencies.
pip install -r requirements.txt

# 3. Run the full test suite (Annex A vectors + property tests).
python -m pytest -q
```

## Real-world testing between two computers

The runnable demo scripts under [`examples/`](examples/) let two human
users (Alice and Bob, on different machines) exchange end-to-end
encrypted text and files over the secure channel. A complete
walkthrough — covering local-LAN, Tailscale and ngrok deployments —
lives in **[`TESTING_GUIDE.md`](TESTING_GUIDE.md)**. The 30-second
TL;DR:

```bash
# Once per user, on each laptop:
python examples/generate_identity.py alice          # Alice's machine
python examples/generate_identity.py bob            # Bob's machine
# then exchange the public.json files out-of-band.

# On Alice's machine:
python examples/run_server.py \
    --identity examples/identities/alice \
    --peer     examples/identities/bob \
    --host 0.0.0.0 --port 9000

# On Bob's machine:
python examples/run_client.py \
    --identity examples/identities/bob \
    --peer     examples/identities/alice \
    --host <alice-ip-or-tailnet-or-ngrok> --port 9000
# At the prompt: type chat lines, /sendfile <path>, /quit.
```

The package itself lives under [src/secure_channel](src/secure_channel) and is
arranged as follows:

```
src/secure_channel/
  crypto/
    kalyna.py             # DSTU 7624:2014 Kalyna block cipher
    kalyna_modes.py       # Kalyna-CTR and Kalyna-CMAC modes of operation
    kalyna_aead.py        # Encrypt-then-MAC AEAD wrapper around Kalyna
    kdf.py                # HKDF-style KDF using Kalyna-CMAC as PRF
    binary_field.py       # GF(2^m) polynomial-basis arithmetic
    binary_curve.py       # Elliptic curves y^2 + xy = x^3 + a x^2 + b
    dstu4145.py           # DSTU 4145-2002 signature scheme
    dstu4145_curves.py    # Recommended curve domain parameters
  session/
    key_exchange.py       # Ephemeral ECDH over a DSTU 4145 curve
    records.py            # Authenticated record protocol with timestamp + replay window
    secure_session.py     # Bidirectional post-handshake channel
    handshake.py          # SIGMA-style mutual-auth handshake
    clock.py              # Microsecond wall-clock provider abstraction
    replay_window.py      # RFC 6479-style sliding replay-window bitmap
  network/
    framing.py            # Length-prefix wire framing on asyncio streams
    messages.py           # Application multiplex (text vs file-transfer messages)
    handshake_io.py       # Run the SIGMA handshake over an asyncio stream pair
    connection.py         # SecureChannelConnection wrapping reader/writer + session
    server.py             # Async TCP secure-channel server
    client.py             # Async TCP secure-channel client
    file_transfer.py      # Chunked, streaming file send / receive
  utils/                  # Reserved namespace for cross-cutting helpers
```

The runnable demo lives outside the importable package:

```
examples/
  generate_identity.py    # One-shot DSTU 4145 key-pair generator
  run_server.py           # Interactive responder (chat + file receive)
  run_client.py           # Interactive initiator (chat + /sendfile)
  _identity_io.py         # JSON persistence helpers shared by the scripts
```

## Cryptographic protocol

The secure channel layered on top of the Phase 1 primitives uses:

* **Kalyna(128, 256)** in **CTR mode** for confidentiality.
* **Kalyna-CMAC** for integrity, composed with CTR via *Encrypt-then-MAC*.
* **Ephemeral Diffie-Hellman** over the DSTU 4145 m=163 standard curve
  for forward-secret key agreement.
* **DSTU 4145-2002** long-term signatures binding each side's identity
  to the handshake transcript (mutual authentication, MITM defence).
* **HKDF**-style key derivation built from Kalyna-CMAC as the PRF.

The handshake is a three-message SIGMA-style exchange. Records exchanged
afterwards include monotonic sequence numbers, a deterministic
per-direction nonce, and an 8-byte microsecond timestamp. The receiver:

* runs an RFC 6479-style **sliding replay-window** bitmap (default
  64 packets) over the sequence numbers, so out-of-order delivery on
  unreliable transports is supported without losing replay protection;
* validates the embedded **timestamp** against its local wall clock
  with a configurable symmetric tolerance (default ±30 s), defending
  against delay attacks and stale-record replays.

The Phase 3 attack-scenario test suite covers in-window replay,
out-of-window replay, expired timestamps, future timestamps, header
tampering of both the timestamp and the sequence number, and a number
of boundary conditions at the freshness window edges.

## Network layer (Phase 4)

The Phase 4 transport package layers `asyncio` TCP streams on top of
the secure session:

```python
from secure_channel.network.client import connect_secure_channel
from secure_channel.network.server import SecureChannelServer
from secure_channel.network.file_transfer import (
    send_file_over_secure_channel,
    receive_file_over_secure_channel,
)
from secure_channel.network.messages import TextMessage

# Server side
async def handle(connection):
    while True:
        message = await connection.receive_message()
        ...

server = SecureChannelServer(credentials=responder_credentials,
                             connection_handler=handle)
await server.start(host="0.0.0.0", port=12345)

# Client side
connection = await connect_secure_channel(
    host="server.example.com", port=12345,
    credentials=initiator_credentials,
)
await connection.send_message(TextMessage(text="hello"))
await send_file_over_secure_channel(
    connection=connection,
    source_file_path=Path("/path/to/photo.jpg"),
)
```

Multiplexed messages share the encrypted channel through a leading
1-byte tag (`TextMessage`, `FileTransferBegin`, `FileTransferChunk`,
`FileTransferEnd`). File transfers are **fully streaming** &mdash; no
matter the file size, the sender reads a chunk, encrypts it through
the AEAD, transmits, and moves on; the receiver decrypts and writes
each chunk to disk before reading the next. The streaming SHA-256 is
computed on the fly and verified against a digest sent in the closing
`FileTransferEnd` message.

## Verified test vectors

* All five Kalyna parameter combinations from
  *DSTU 7624:2014, Annex A*: `Kalyna(128, 128)`, `Kalyna(128, 256)`,
  `Kalyna(256, 256)`, `Kalyna(256, 512)`, `Kalyna(512, 512)`, both
  enciphering and deciphering.
* The DSTU 4145-2002 worked example over the standard curve over
  $GF(2^{163})$ with the deterministic nonce listed in Annex B.

## Coding standards

Every Python file under [`src/secure_channel`](src/secure_channel) and
[`tests`](tests):

* opens with the standard copyright header
  `Copyright (c) 2026 Denys Nazarenko, Lviv Polytechnic National University.`;
* carries a Sphinx-style module docstring describing its
  cryptographic role and (where relevant) the section of DSTU 7624 or
  DSTU 4145 it implements;
* uses strict type hints on every public function and method;
* documents every public class with parameter / return-value / raised
  exception sections in a Sphinx-style docstring.

## License

Academic-use software released for the purposes of a bachelor diploma at
Lviv Polytechnic National University.

Copyright &copy; 2026 Denys Nazarenko, Lviv Polytechnic National University.
