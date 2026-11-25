
import secrets

# this is the standardized 3072-bit prime we got from RFC 7919 (ffdhe3072) [IETF]. 

P_HEX = """
FFFFFFFF FFFFFFFF ADF85458 A2BB4A9A AFDC5620 273D3CF1
D8B9C583 CE2D3695 A9E13641 146433FB CC939DCE 249B3EF9
7D2FE363 630C75D8 F681B202 AEC4617A D3DF1ED5 D5FD6561
2433F51F 5F066ED0 85636555 3DED1AF3 B557135E 7F57C935
984F0C70 E0E68B77 E2A689DA F3EFE872 1DF158A1 36ADE735
30ACCA4F 483A797A BC0AB182 B324FB61 D108A94B B2C8E3FB
B96ADAB7 60D7F468 1D4F42A3 DE394DF4 AE56EDE7 6372BB19
0B07A7C8 EE0A6D70 9E02FCE1 CDF7E2EC C03404CD 28342F61
9172FE9C E98583FF 8E4F1232 EEF28183 C3FE3B1B 4C6FAD73
3BB5FCBC 2EC22005 C58EF183 7D1683B2 C6F34A26 C1B2EFFA
886B4238 611FCFDC DE355B3B 6519035B BC34F4DE F99C0238
61B46FC9 D6E6C907 7AD91D26 91F7F7EE 598CB0FA C186D91C
AEFE1309 85139270 B4130C93 BC437944 F4FD4452 E2D74DD3
64F2E21E 71F54BFF 5CAE82AB 9C9DF69E E86D2BC5 22363A0D
ABC52197 9B0DEADA 1DBF9A42 D5C4484E 0ABCD06B FA53DDEF
3C1B20EE 3FD59D7C 25E41D2B 66C62E37 FFFFFFFF FFFFFFFF
"""

# converts the hexadecimal number into an integer
p = int(P_HEX.replace(" ", "").replace("\n", ""), 16)

g = 2
q = (p - 1) // 2 # subgrp size

#these are from rfc 7919

# generates El-Gamal public and private keys
def generate_keys():
    # random private key
    x = secrets.randbelow(q - 2) + 2

    # calculates the public value
    y = pow(g, x, p)

    return (p, g, y), x


if __name__ == "__main__":
    public_key, private_key = generate_keys()

    print("===== EL-GAMAL KEY GENERATION =====")
    print("Prime size:", p.bit_length(), "bits")
    print("Generator:", g)
    print("Private key generated:", 2 <= private_key < q)
    print("Public key generated:", 1 < public_key[2] < p)
    print("Key relationship correct:",
          pow(g, private_key, p) == public_key[2])
