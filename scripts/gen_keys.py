#!/usr/bin/env python3
"""Run ONCE on your own computer:  pip install cryptography  &&  python scripts/gen_keys.py
Prints (1) the PRIVATE key -> save as the GitHub secret SIGNING_KEY_PEM (never commit it),
       (2) the PUBLIC key (base64 X.509) -> goes into the app so it only accepts lists signed by you."""
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
k = ec.generate_private_key(ec.SECP256R1())
print(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())
print("PUBLIC_KEY_B64=" + base64.b64encode(k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode())
