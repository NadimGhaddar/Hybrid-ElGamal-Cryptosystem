
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from key_generation import generate_keys, p, g, q
from encryption import encrypt_text


def decrypt_text(encrypted, private_key, public_key):
    # gets the encrypted information
    c1 = encrypted["c1"]
    nonce = bytes.fromhex(encrypted["nonce"])
    ciphertext = bytes.fromhex(encrypted["ciphertext"])


    key_p, key_g, y = public_key
    # verifies the public key and private key
    if key_p != p or key_g != g:
        raise ValueError("Invalid group parameters")

    if not (2 <= private_key < q):
        raise ValueError("Invalid private key")

    if not (1 < y < p - 1) or pow(y, q, p) != 1:
        raise ValueError("Invalid public key")

    if pow(g, private_key, p) != y:
        raise ValueError("Public and private keys do not match")

    if not isinstance(c1, int) or not (1 < c1 < p - 1):
        raise ValueError("Invalid c1")

    if pow(c1, q, p) != 1:
        raise ValueError("c1 is not in the correct subgroup")

    if len(nonce) != 12 or len(ciphertext) < 16:
        raise ValueError("Invalid encrypted data")

    # shared secret
    s = pow(c1, private_key, p)

    # converts to bytes
    size = (p.bit_length() + 7) // 8
    shared_bytes = s.to_bytes(size, "big")

    # this is the context. note: it must be exactly the same context as encryption!!
    context = (
        b"ElGamal-FFDHE3072-AES256GCM-v1"
        + c1.to_bytes(size, "big")
        + y.to_bytes(size, "big")
    )

    # this is the same AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context
    ).derive(shared_bytes)

    # decrypt using aes and checks authentication
    aes = AESGCM(aes_key)

    #here, if verification fails, the cryptography library raises InvalidTag.
    try:
        decrypted_bytes = aes.decrypt(nonce, ciphertext, context)
    except InvalidTag:
        raise ValueError("Decryption failed: invalid authentication tag")    
    

    # converts UTF-8 bytes back into text
    return decrypted_bytes.decode("utf-8")


if __name__ == "__main__":
   
    public_key, private_key = generate_keys()

    
    message = "Hello Samir! مرحبا 🔥"
    #notice, we also tested arabic and emojis! they work bcz utf 8 can handle them
    encrypted = encrypt_text(message, public_key)

  
    decrypted = decrypt_text(encrypted, private_key, public_key)

    print("Original message:", message)
    print("Decrypted message:", decrypted)
    print("Messages match:", message == decrypted)
