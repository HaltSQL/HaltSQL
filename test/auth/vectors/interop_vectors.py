#!/usr/bin/env python3
"""Interoperability vectors from an independent implementation (pyca/cryptography).

    python3 interop_vectors.py generate > interop_vectors.json
    python3 interop_vectors.py check rfc_vectors.json interop_vectors.json

`generate` creates one key and one signed JWT for each algorithm haltsql-server
accepts (RS256 RS384 RS512 PS256 ES256 ES384 EdDSA). Keys are fresh on every run,
so regenerating replaces the whole file.

`check` verifies every positive vector in both files with pyca/cryptography. It is
how the committed files were validated independently of lib/auth: the RFC examples
were extracted by extract_rfc_vectors.py and must verify here before the OCaml
tests are allowed to rely on them.

Requires: cryptography >= 42. No JOSE library is used; the compact serialization
is assembled by hand so that this file and lib/auth share no code.
"""
import base64
import json
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ISS = "https://interop.example.test"
AUD = "haltsql"
# 2100-01-01T00:00:00Z / 2026-01-01T00:00:00Z
EXP, IAT = 4102444800, 1767225600

HASH = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def uint(n, length=None):
    return n.to_bytes(length or (n.bit_length() + 7) // 8, "big")


def rsa_jwk(pub):
    n = pub.public_numbers()
    return {"kty": "RSA", "n": b64(uint(n.n)), "e": b64(uint(n.e))}


def ec_jwk(pub, crv, size):
    n = pub.public_numbers()
    return {"kty": "EC", "crv": crv, "x": b64(uint(n.x, size)), "y": b64(uint(n.y, size))}


def sign(alg, key, msg):
    h = HASH.get(alg[2:], hashes.SHA256)()
    if alg.startswith("RS"):
        return key.sign(msg, padding.PKCS1v15(), h)
    if alg.startswith("PS"):
        pss = padding.PSS(mgf=padding.MGF1(h), salt_length=h.digest_size)
        return key.sign(msg, pss, h)
    if alg.startswith("ES"):
        size = (key.curve.key_size + 7) // 8
        r, s = decode_dss_signature(key.sign(msg, ec.ECDSA(h)))
        return uint(r, size) + uint(s, size)
    return key.sign(msg)


def generate():
    rsa_key = lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    specs = []
    for alg in ("RS256", "RS384", "RS512", "PS256"):
        k = rsa_key()
        specs.append((alg, k, rsa_jwk(k.public_key())))
    k = ec.generate_private_key(ec.SECP256R1())
    specs.append(("ES256", k, ec_jwk(k.public_key(), "P-256", 32)))
    k = ec.generate_private_key(ec.SECP384R1())
    specs.append(("ES384", k, ec_jwk(k.public_key(), "P-384", 48)))
    k = ed25519.Ed25519PrivateKey.generate()
    specs.append(
        ("EdDSA", k, {"kty": "OKP", "crv": "Ed25519", "x": b64(k.public_key().public_bytes_raw())})
    )
    keys, tokens = [], []
    for alg, key, jwk in specs:
        kid = "interop-" + alg.lower()
        jwk.update({"kid": kid, "use": "sig", "alg": alg})
        keys.append(jwk)
        header = {"alg": alg, "typ": "JWT", "kid": kid}
        claims = {"iss": ISS, "aud": AUD, "sub": "interop-" + alg, "iat": IAT, "exp": EXP}
        signing_input = (
            b64(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64(json.dumps(claims, separators=(",", ":")).encode())
        )
        sig = sign(alg, key, signing_input.encode())
        tokens.append({"alg": alg, "kid": kid, "token": signing_input + "." + b64(sig)})
    out = {
        "generator": "pyca/cryptography via test/auth/vectors/interop_vectors.py",
        "issuer": ISS,
        "audience": AUD,
        "jwks": {"keys": keys},
        "tokens": tokens,
    }
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


def public_key(jwk):
    if jwk["kty"] == "RSA":
        n, e = (int.from_bytes(unb64(jwk[m]), "big") for m in ("n", "e"))
        return rsa.RSAPublicNumbers(e, n).public_key()
    if jwk["kty"] == "EC":
        crv = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
        x, y = (int.from_bytes(unb64(jwk[m]), "big") for m in ("x", "y"))
        return ec.EllipticCurvePublicNumbers(x, y, crv[jwk["crv"]]()).public_key()
    if jwk["kty"] == "OKP":
        return ed25519.Ed25519PublicKey.from_public_bytes(unb64(jwk["x"]))
    raise ValueError("no public key for kty " + jwk["kty"])


def verify(jwk, token):
    """Raises unless the compact JWS verifies under the JWK."""
    h, p, s = token.split(".")
    alg = json.loads(unb64(h))["alg"]
    msg, sig, key = (h + "." + p).encode(), unb64(s), public_key(jwk)
    hash_ = HASH.get(alg[2:], hashes.SHA256)()
    if alg.startswith("RS"):
        key.verify(sig, msg, padding.PKCS1v15(), hash_)
    elif alg.startswith("PS"):
        pss = padding.PSS(mgf=padding.MGF1(hash_), salt_length=hash_.digest_size)
        key.verify(sig, msg, pss, hash_)
    elif alg.startswith("ES"):
        half = len(sig) // 2
        r, s_ = int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big")
        key.verify(encode_dss_signature(r, s_), msg, ec.ECDSA(hash_))
    elif alg == "EdDSA":
        key.verify(sig, msg)
    else:
        raise ValueError("unsupported alg " + alg)
    return alg


def check(rfc_path, interop_path):
    with open(rfc_path) as f:
        rfc = json.load(f)
    with open(interop_path) as f:
        interop = json.load(f)
    n = 0
    for name, v in sorted(rfc.items()):
        if v.get("jwk", {}).get("kty") in ("RSA", "EC", "OKP"):
            print("ok", name, verify(v["jwk"], v["token"]))
            n += 1
        else:
            print("--", name, "(no asymmetric signature to check)")
    by_kid = {k["kid"]: k for k in interop["jwks"]["keys"]}
    for t in interop["tokens"]:
        print("ok", "interop", verify(by_kid[t["kid"]], t["token"]))
        n += 1
    print(n, "vectors verified with pyca/cryptography")


if __name__ == "__main__":
    if sys.argv[1:2] == ["generate"]:
        generate()
    elif sys.argv[1:2] == ["check"] and len(sys.argv) == 4:
        check(sys.argv[2], sys.argv[3])
    else:
        sys.exit(__doc__)
