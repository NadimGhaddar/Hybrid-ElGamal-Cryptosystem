# Hybrid ElGamal Cryptosystem

An educational hybrid public-key encryption implementation developed for EECE 455 (Network Cryptography) at the American University of Beirut (AUB). Work in progress.

## Overview

The project combines finite-field ElGamal-style ephemeral-static Diffie–Hellman key establishment, HKDF-SHA-256, and AES-256-GCM authenticated encryption. Rather than encrypting the message directly as a group element, the implementation derives a symmetric key and encrypts UTF-8 text with AES-GCM.

## Architecture

1. **Key generation:** Generate a random private exponent and its corresponding public key in the RFC 7919 ffdhe3072 group.
2. **Encryption:** Generate a fresh ephemeral exponent, compute `c1 = g^k mod p` and the shared secret `s = y^k mod p`.
3. **Key derivation:** Derive a 32-byte AES key using HKDF-SHA-256, binding the derivation to a protocol label, `c1`, and the recipient public value.
4. **Authenticated encryption:** Encrypt UTF-8 bytes using AES-256-GCM with a random 12-byte nonce and the same context as associated data.
5. **Decryption:** Validate parameters, keys and subgroup membership; reconstruct the shared secret, derive the same AES key, and verify the authentication tag before decoding the plaintext.

The returned packet contains `c1`, a hexadecimal nonce, and hexadecimal ciphertext with its authentication tag.

## Why hybrid encryption?

- Supports variable-length text without mapping plaintext into group elements.
- Uses efficient symmetric encryption for the message payload.
- Adds ciphertext integrity and tamper detection through AES-GCM.
- Uses HKDF to derive a fixed-length, context-bound symmetric key.

AES-256 does not imply 256-bit security for the whole construction. The overall security depends on the public-key component, implementation, and operational assumptions.

## Quick start

Requires Python 3 and the `cryptography` package.

```bash
python3 -m pip install -r requirements.txt
python3 key_generation.py
python3 encryption.py
python3 decryption.py
```

Example:

```python
from key_generation import generate_keys
from encryption import encrypt_text
from decryption import decrypt_text

public_key, private_key = generate_keys()
packet = encrypt_text("Hello! مرحبا", public_key)
assert decrypt_text(packet, private_key, public_key) == "Hello! مرحبا"
```

## Repository structure

| File | Purpose |
| --- | --- |
| `key_generation.py` | Group parameters and key generation |
| `encryption.py` | Shared-secret calculation, HKDF and AES-GCM encryption |
| `decryption.py` | Key validation, shared-secret reconstruction and authenticated decryption |
| `requirements.txt` | Python dependency |
| `.gitignore` | Generated file exclusions |

## Scope and limitations

This is a collaborative academic prototype, not a standardized or audited encryption protocol. It uses a standardized finite-field group but the hybrid construction itself has not been independently validated. It does not authenticate the sender, establish trust in recipient public keys, provide replay protection, or implement secure key storage. The Python modular arithmetic has not been assessed for side-channel resistance. This implementation should not be used to protect production or sensitive data.

Original implementation supplied by the project team; repository documentation was prepared with AI assistance. Individual contributions and publication permissions should be confirmed before public release.

## References

- [RFC 7919 — Negotiated Finite Field Diffie-Hellman Ephemeral Parameters](https://www.rfc-editor.org/rfc/rfc7919)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869)
- [NIST SP 800-38D — GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)

## Project status — Work in progress

The project is currently under development. We are working on implementing additional security checks and validation procedures to assess the security of the hybrid encryption construction, identify potential vulnerabilities, and evaluate its resistance to tampering and invalid inputs. A complete security assessment has not yet been performed, and the implementation should not be considered production-ready.
