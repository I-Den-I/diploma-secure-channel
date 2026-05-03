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
| 1 | Cryptographic primitives & verification against DSTU test vectors | implemented |
| 2 | Secure handshake protocol (mutual auth + key agreement) | implemented |
| 3 | Attack mitigation (sliding replay window, timestamp validation, MITM) | implemented |
| 4 | Chunked encrypted file and photo transfer | pending |
| 5 | Final polish, documentation, type hints, copyright headers | pending |

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
  network/                # (Phase 4) async framing & file transfer
  utils/                  # Byte / RNG helpers
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

## Verified test vectors

* All five Kalyna parameter combinations from
  *DSTU 7624:2014, Annex A*: `Kalyna(128, 128)`, `Kalyna(128, 256)`,
  `Kalyna(256, 256)`, `Kalyna(256, 512)`, `Kalyna(512, 512)`, both
  enciphering and deciphering.
* The DSTU 4145-2002 worked example over the standard curve over
  $GF(2^{163})$ with the deterministic nonce listed in Annex B.

## License

Academic-use software released for the purposes of a bachelor diploma at
Lviv Polytechnic National University.

Copyright &copy; 2026 Denys Nazarenko, Lviv Polytechnic National University.
