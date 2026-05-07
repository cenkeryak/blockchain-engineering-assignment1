# Blockchain Engineering Assignment 1

IPv8 client for Lab 1: Proof of Work over IPv8.

## Setup

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
brew install libsodium
```

The client stores your IPv8 identity in `lab1_identity.pem`. This file is gitignored on purpose. Keep it safe, because it is the private key for later labs.

## Run

```bash
.venv/bin/python lab1_client.py
```

Defaults are already set to:

- email: `cyakisir@tudelft.nl`
- GitHub URL: `https://github.com/cenkeryak/blockchain-engineering-assignment1`
- difficulty: `28`

The client mines a nonce, saves progress in `pow_progress.json`, discovers the verified server peer by public key, submits the signed IPv8 message, and prints the server response.

Useful variants:

```bash
# Mine only, without contacting IPv8
.venv/bin/python lab1_client.py --mine-only

# Reuse a known nonce
.venv/bin/python lab1_client.py --nonce 123456789

# Use more or fewer worker processes
.venv/bin/python lab1_client.py --workers 8
```

## Test

```bash
.venv/bin/python -m unittest discover -s tests
```
