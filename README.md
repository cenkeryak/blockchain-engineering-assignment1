# Blockchain Engineering Assignment 1

IPv8 client for Lab 1: Proof of Work over IPv8.

## Setup

```bash
brew install uv libsodium
uv sync
```

The client stores IPv8 identity in `lab1_key.pem`.

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

## Store Your Public Key Once

If you already have `lab1_key.pem` and want to store the matching public key once,
run:

```bash
.venv/bin/python ensure_public_key.py
```

This writes the derived public key (hex) to `lab1_public_key.txt` only when the file
does not exist yet. If the file already exists, the script verifies it matches
private key and leaves it unchanged.

You can also provide custom paths:

```bash
.venv/bin/python ensure_public_key.py --private-key lab1_key.pem --public-key my_public_key.txt
```

## Test

```bash
.venv/bin/python -m unittest discover -s tests
```
