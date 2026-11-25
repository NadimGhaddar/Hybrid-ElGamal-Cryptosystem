
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from key_generation import generate_keys, p as STANDARD_P, g as STANDARD_G, q


def encrypt_text(message, public_key):
    p, g, y = public_key

    # checks that the public key uses our expected values
    if p != STANDARD_P or g != STANDARD_G:
        raise ValueError("Invalid group parameters")

    # checks that y belongs to the correct subgroup
    if not (1 < y < p - 1) or pow(y, q, p) != 1:
        raise ValueError("Invalid public key")

    # generates a fresh random secret k
    k = secrets.randbelow(q - 2) + 2

    # El-Gamal calculations
    c1 = pow(g, k, p)
    s = pow(y, k, p)

    # converts the shared secret into bytes. why? hkdf expects bytes, not an integer
    size = (p.bit_length() + 7) // 8
    shared_bytes = s.to_bytes(size, "big") #"big" means big-endian order i.e. the most significant byte comes first.

    # Bind the derived key to this specific encryption
    context = (
        b"ElGamal-FFDHE3072-AES256GCM-v1"
        + c1.to_bytes(size, "big")
        + y.to_bytes(size, "big")
    )

    # derives a 256-bit AES key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context
    ).derive(shared_bytes)

    # encrypts the text using AES-256-GCM
    nonce = secrets.token_bytes(12)
    message_bytes = message.encode("utf-8")

    aes = AESGCM(aes_key)
    ciphertext = aes.encrypt(nonce, message_bytes, context)

    # returns what is needed for decryption. 
    return {
        "c1": c1,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex()
    }


if __name__ == "__main__":
    public_key, private_key = generate_keys()

    message = "Hello"

    encrypted = encrypt_text(message, public_key)

    print("Original message:", message)
    print("Encrypted successfully!")
    print("c1:", str(encrypted["c1"])[:50] + "...")
    print("Nonce:", encrypted["nonce"])
    print("Ciphertext and authentication tag:", encrypted["ciphertext"])
