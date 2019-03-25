from ecdsa import SigningKey
from ecdsa import VerifyingKey
from ecdsa.numbertheory import inverse_mod
import hashlib
import binascii
import base64

# get order from given priv key
private_key_pem = '''
-----BEGIN EC PRIVATE KEY-----
MF8CAQEEGKyFd/8lBEkufLbV+HFtTBk3KNhZK29CJaAKBggqhkjOPQMBAaE0AzIA
BB1ZB2byaoiLjGw46KCr2hYJtAlV0ZlmIIvRH4fo+HrgYH9Yv2gyffLlGG19l/LD
9w==
-----END EC PRIVATE KEY-----
'''
private_key = SigningKey.from_pem(private_key_pem.strip())
curve_order = private_key.curve.order


def string_to_number(tstr):
    return int(binascii.hexlify(tstr), 16)

def sha1(content):
    sha1_hash = hashlib.sha1()
    sha1_hash.update(content)
    hash = sha1_hash.digest()
    return hash

def recover_key(c1, sig1, c2, sig2):

    n = curve_order
    # cut up the strings before we convert to number!
    s1 = string_to_number(sig1[-24:])
    s2 = string_to_number(sig2[-24:])
    r = string_to_number(sig1[-48:-24])

    z1 = string_to_number(sha1(c1.encode('utf-8')))
    z2 = string_to_number(sha1(c2.encode('utf-8')))

    # solve
    sdelta_inv = inverse_mod(((s1-s2)%n),n)
    k = ( ((z1-z2)%n) * sdelta_inv) % n
    inverse_r = inverse_mod(r,n)
    da = (((((s1*k) %n) -z1) %n) * inverse_r) % n

    recovered_private_key = SigningKey.from_secret_exponent(da)
    return recovered_private_key.to_pem()

if __name__ == "__main__":

    challenge1 = "iSsuZJOq1FNKMuK4wm88UEkr21wgsypW"
    sig1 = '''
BRXVEpTGwCo1HsaTNmhJ5NynvUsdhFzvc1ilypdV4aDLRLIlVaCCkHsuN6EAet0+
    '''.strip()

    challenge2 = "x3wqOnaetBPO66TrBaMyr3NQIDbhvK0w"
    sig2 = '''
BRXVEpTGwCo1HsaTNmhJ5NynvUsdhFzvSvNuLoc421+3BZMMFukNTOztlpj9kf4e
    '''.strip()

    key = recover_key(challenge1,base64.b64decode(sig1),challenge2,base64.b64decode(sig2))
    print(key)

    #create the signature
    sk = SigningKey.from_pem(key)
    challenge = "DkHV48UYq10wj8SuOYrGsp65S0BrBHdc"
    vk = sk.get_verifying_key()
    signature = sk.sign(challenge.encode('utf-8'))
    try:
        # because who trusts python
        vk.verify(signature, challenge)
        print("good signature")
    except:
        print("BAD SIGNATURE")
    encoded_signature = base64.b64encode(signature)
    print(signature)
    print(encoded_signature)