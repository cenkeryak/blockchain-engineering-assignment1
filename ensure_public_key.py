from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ipv8.keyvault.crypto import default_eccrypto


def derive_public_key_hex(private_key_file: Path) -> str:
    private_bin = private_key_file.read_bytes()
    if not default_eccrypto.is_valid_private_bin(private_bin):
        raise ValueError(f"{private_key_file} does not contain a valid IPv8 private key")
    key = default_eccrypto.key_from_private_bin(private_bin)
    return key.pub().key_to_bin().hex()


def ensure_public_key(private_key_file: Path, public_key_file: Path) -> tuple[str, bool]:
    if not private_key_file.exists():
        raise FileNotFoundError(f"Private key file not found: {private_key_file}")

    public_key_hex = derive_public_key_hex(private_key_file)

    if public_key_file.exists():
        stored = public_key_file.read_text(encoding="utf-8").strip().lower()
        if not stored:
            raise ValueError(f"{public_key_file} exists but is empty")
        if stored != public_key_hex:
            raise ValueError(
                f"Stored public key in {public_key_file} does not match the private key from {private_key_file}"
            )
        return public_key_hex, False

    public_key_file.parent.mkdir(parents=True, exist_ok=True)
    public_key_file.write_text(public_key_hex + "\n", encoding="utf-8")
    return public_key_hex, True


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Derive and store an IPv8 public key from an existing private key file"
    )
    parser.add_argument(
        "--private-key",
        type=Path,
        default=Path("lab1_key.pem"),
        help="path to the IPv8 private key file",
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=Path("lab1_public_key.txt"),
        help="path to store the derived IPv8 public key (hex)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        public_key_hex, created = ensure_public_key(args.private_key, args.public_key)
        if created:
            print(f"Stored IPv8 public key in {args.public_key}")
        else:
            print(f"Public key already stored in {args.public_key}")
        print(public_key_hex)
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
