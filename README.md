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
| 2 | Secure handshake protocol (mutual auth + key agreement) | pending |
| 3 | Attack mitigation (replay, MITM) | pending |
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
    binary_field.py       # GF(2^m) polynomial-basis arithmetic
    binary_curve.py       # Elliptic curves y^2 + xy = x^3 + a x^2 + b
    dstu4145.py           # DSTU 4145-2002 signature scheme
    dstu4145_curves.py    # Recommended curve domain parameters
  session/                # (Phase 2+) handshake & session keys
  network/                # (Phase 4) async framing & file transfer
  utils/                  # Byte / RNG helpers
```

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
