# Testing the secure channel between two real machines

This document is a step-by-step tutorial for putting the diploma
project to the test in a realistic, distributed setting: two
**different computers**, communicating either over the same local
network or across the public internet. By the end of this walkthrough
two human users (we will call them **Alice** and **Bob**) will be able
to exchange end-to-end encrypted text messages and transfer files
through the secure channel implemented by this repository.

The tutorial uses the runnable demo scripts shipped under
[`examples/`](examples/):

| Script | Purpose |
|--------|---------|
| `examples/generate_identity.py` | One-shot key-pair generation per user |
| `examples/run_server.py`        | Responder: listens, accepts a peer, runs an interactive chat / file receiver |
| `examples/run_client.py`        | Initiator: connects, sends text messages, transfers files |

---

## 1. Prerequisites

Both machines need:

* **Python 3.10+** (the project is developed on 3.13 but works on any
  modern Python).
* **`git`** for cloning the repository.
* The Python dependencies from `requirements.txt`
  (`pip install -r requirements.txt` inside a virtual environment).
* No additional packages are required: the cryptography is implemented
  in pure Python.

---

## 2. Generate a long-term identity on each machine

Each user must own a **DSTU 4145-2002 long-term key pair** before they
can talk to anyone else. Run **once per user, on that user's
machine**:

```bash
# On Alice's laptop
python examples/generate_identity.py alice
```

```bash
# On Bob's laptop
python examples/generate_identity.py bob
```

The command creates two files under `examples/identities/<name>/`:

* `private.json` — secret key, mode `0600`, must **never leave the
  laptop**.
* `public.json` — shareable, must reach the peer through a trusted
  out-of-band channel before the chat is started (see Section 3).

The contents are JSON, so a quick `cat` is enough to confirm the file
format:

```json
{
  "version": 1,
  "curve": "DSTU4145_M163_PB",
  "x_coordinate_hex": "...",
  "y_coordinate_hex": "..."
}
```

---

## 3. Exchange public keys (out of band)

The protocol implemented by this project assumes that both peers
already hold an authentic copy of the other's public key. **PKI and
certificate validation are deliberately out of scope.** Some practical
ways to perform the exchange:

* **In-person USB transfer**: copy `alice/public.json` onto a USB
  stick, hand it to Bob, and the same in the other direction.
* **Signed e-mail / Signal / Keybase**: paste the JSON contents into a
  message; the receiver saves them to disk and verifies the digest
  with the sender over a different channel.
* **`scp` over a pre-existing SSH session** between the two machines
  (the SSH host key fingerprint provides the trust anchor).

After the exchange each user should hold:

```
examples/identities/alice/private.json   (only on Alice's laptop)
examples/identities/alice/public.json    (on both laptops)
examples/identities/bob/private.json     (only on Bob's laptop)
examples/identities/bob/public.json      (on both laptops)
```

> **Why does it matter?** Without an authentic copy of the peer's
> public key, the SIGMA-style handshake cannot detect a man-in-the-
> middle. The handshake itself binds both ephemeral Diffie-Hellman
> keys to the long-term DSTU 4145-2002 identity through transcript
> signatures, but it can only catch an attacker if the verifier knows
> the *real* public key in advance.

---

## 4. Same-LAN test

This is the simplest possible scenario: both laptops are connected to
the same Wi-Fi or wired network.

### 4.1 Find Alice's LAN IP

```bash
# On Alice's laptop (macOS / Linux)
ipconfig getifaddr en0   # macOS
hostname -I              # Linux
```

Suppose Alice's laptop is reachable at `192.168.1.42`.

### 4.2 Start the responder on Alice's laptop

```bash
python examples/run_server.py \
    --identity examples/identities/alice \
    --peer     examples/identities/bob \
    --host 0.0.0.0 \
    --port 9000 \
    --save-files-to ./incoming_from_bob
```

The script prints `[server]> listening on 0.0.0.0:9000` and is now
ready.

### 4.3 Start the initiator on Bob's laptop

```bash
python examples/run_client.py \
    --identity examples/identities/bob \
    --peer     examples/identities/alice \
    --host 192.168.1.42 \
    --port 9000 \
    --save-files-to ./incoming_from_alice
```

After the handshake completes you can:

* type a free-form line and press Enter to send a chat message;
* type `/sendfile /path/to/photo.jpg` to send a file (chunked,
  authenticated, integrity-checked end-to-end);
* type `/quit` to terminate the session.

Files received by Alice land in `./incoming_from_bob/`; files sent by
Alice would land on Bob's machine inside `./incoming_from_alice/` (the
server side can also send through `/sendfile` if the user types it on
Alice's terminal).

### 4.4 Firewall reminder

If `run_client.py` cannot reach the server, allow inbound TCP on
port 9000 in the local firewall (`ufw allow 9000/tcp` on Linux,
"Internet Sharing → Firewall" on macOS).

---

## 5. Across the public internet via Tailscale

[Tailscale](https://tailscale.com/) provides a zero-config WireGuard
mesh between two laptops without any port forwarding or NAT traversal
gymnastics. Recommended option for cross-internet testing.

### 5.1 Install Tailscale on both laptops

Follow the official instructions for your OS at
<https://tailscale.com/download>. Sign in with the same identity on
both devices so they end up in the same tailnet.

### 5.2 Find Alice's tailnet IP

```bash
# On Alice's laptop
tailscale ip -4
# 100.101.102.103
```

### 5.3 Run the demo

The commands are identical to Section 4, except that Bob now connects
to the *tailnet* IP rather than the LAN IP:

```bash
# Alice
python examples/run_server.py \
    --identity examples/identities/alice \
    --peer     examples/identities/bob \
    --host 0.0.0.0 \
    --port 9000

# Bob
python examples/run_client.py \
    --identity examples/identities/bob \
    --peer     examples/identities/alice \
    --host 100.101.102.103 \
    --port 9000
```

Tailscale handles encryption *of the carrier link*; the secure-channel
implementation in this repository provides a second, **end-to-end**
layer with Ukrainian-standard cryptography. The two are independent —
even if a Tailscale relay node were compromised, the DSTU 7624 + DSTU
4145 ciphertext would remain unreadable.

---

## 6. Across the public internet via ngrok (one-sided exposure)

Use [ngrok](https://ngrok.com/) when one user is behind a NAT they
cannot reconfigure (corporate Wi-Fi, mobile hotspot, ...) and only
*one* side needs to be reachable.

### 6.1 Start ngrok on Alice's laptop

```bash
# Alice runs the responder as before, on the loopback interface
python examples/run_server.py \
    --identity examples/identities/alice \
    --peer     examples/identities/bob \
    --host 127.0.0.1 \
    --port 9000

# In a second terminal on the same laptop:
ngrok tcp 9000
```

`ngrok` prints a forwarding line such as:

```
Forwarding  tcp://0.tcp.eu.ngrok.io:14123 -> localhost:9000
```

### 6.2 Start the initiator on Bob's laptop

```bash
python examples/run_client.py \
    --identity examples/identities/bob \
    --peer     examples/identities/alice \
    --host 0.tcp.eu.ngrok.io \
    --port 14123
```

> **Note on freshness windows.** ngrok adds a noticeable round-trip
> latency. Combined with pure-Python Kalyna throughput (~60 KiB/s) the
> default ±30 s timestamp-validation window may need to be enlarged
> for multi-MB transfers. Both demo scripts accept a
> `--freshness-tolerance-seconds` flag for that purpose:
>
> ```bash
> python examples/run_client.py ... --freshness-tolerance-seconds 1800
> ```

---

## 7. Verifying the file integrity

After a `/sendfile` operation completes, the diagnostic line printed
by `run_client.py` looks like:

```
[client]> upload complete; SHA-256 = b1d3...c2a4
```

On the receiving side `run_server.py` prints:

```
[peer]> file saved to incoming_from_bob/photo.jpg
```

The file's SHA-256 is verified inside the protocol against the
streaming digest carried in the closing `FileTransferEnd` message, so
mismatches are detected and reported automatically. To independently
double-check from the shell:

```bash
shasum -a 256 incoming_from_bob/photo.jpg
```

The two digests must be identical. Any mismatch indicates either a
bug in the implementation or a successful in-flight tampering attempt
that the AEAD failed to catch (extremely unlikely under DSTU 7624 +
Kalyna-CMAC).

---

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
|--------|---------------|-----|
| `connection refused` on the client | Server not started, or port blocked | Start `run_server.py`; allow inbound TCP on the chosen port |
| `[record rejected: Record timestamp predates the freshness window …]` | Wall clocks of the two laptops differ by more than ±30 s | Sync via NTP, or pass `--freshness-tolerance-seconds 1800` on both sides |
| `HandshakeError: ... signature is invalid` | The two `public.json` files do not match the actual peer | Re-exchange `public.json` over a trusted channel |
| `[record rejected: Sequence number was already accepted]` | Network duplicated a record (rare on TCP, common on lossy NAT) | Diagnostic only — the duplicate is correctly dropped |
| Throughput feels slow | Pure-Python Kalyna runs at ~60 KiB/s | Documented limitation; a future C extension would solve this |

---

## 9. What is *not* tested by this guide

* **Forward secrecy** (the Phase 2 ECDH ephemeral keys deliver it; the
  *test* is performed in `tests/test_handshake.py`).
* **Replay & timestamp attacks** (Phase 3 unit tests in
  `tests/test_anti_replay_attacks.py`).
* **Test-vector conformance** (`tests/test_kalyna_vectors.py` and
  `tests/test_dstu4145_vectors.py`).

For those properties run `python -m pytest -v` from the repository
root.
