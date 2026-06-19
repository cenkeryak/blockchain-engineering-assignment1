from pathlib import Path
from ipv8.keyvault.crypto import default_eccrypto
priv = Path("lab1_key.pem").read_bytes()
key = default_eccrypto.key_from_private_bin(priv)
pub = key.pub().key_to_bin()
# print(pub)
print(pub.hex())          # full public key in hex (includes LibNaCLPK prefix)
# print(pub[:10], pub[10:]) # optional: show prefix/data split