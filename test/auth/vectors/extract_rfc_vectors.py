#!/usr/bin/env python3
"""Extracts the JWS/JWK examples used by test_jose_vectors.ml from the RFC texts.

    curl -O https://www.rfc-editor.org/rfc/rfc7515.txt   (also rfc7520.txt, rfc8037.txt)
    python3 extract_rfc_vectors.py DIR_WITH_RFC_TXT > rfc_vectors.json

Every example is copied mechanically: the lines of a figure are joined with the
display whitespace removed (the RFCs wrap values "for display purposes only").
Nothing is retyped by hand. Line numbers refer to the published .txt files.
"""
import json
import re
import sys

FURNITURE = re.compile(r"\[Page \d+\]\s*$|^RFC \d{4} ")


def block(lines, first, last):
    """Lines first..last (1-based, inclusive) with all whitespace removed."""
    out = []
    for ln in lines[first - 1 : last]:
        if "\f" in ln or FURNITURE.search(ln):
            continue
        out.append("".join(ln.split()))
    return "".join(out)


def load(d, n):
    with open(f"{d}/rfc{n}.txt", encoding="utf-8") as f:
        return f.read().split("\n")


def main(d):
    r7515, r7520, r8037 = load(d, 7515), load(d, 7520), load(d, 8037)

    def jwk(lines, a, b):
        return json.loads(block(lines, a, b))

    out = {
        "rfc7515_a1_hs256": {
            "jwk": jwk(r7515, 2121, 2124),
            "token": block(r7515, 2152, 2157),
        },
        "rfc7515_a2_rs256": {
            "jwk": jwk(r7515, 2251, 2280),
            "token": block(r7515, 2364, 2374),
        },
        "rfc7515_a3_es256": {
            "jwk": jwk(r7515, 2452, 2457),
            "token": block(r7515, 2499, 2505),
        },
        "rfc7515_a4_es512": {
            "jwk": jwk(r7515, 2587, 2595),
            "token": block(r7515, 2644, 2650),
        },
        "rfc7515_a5_none": {"token": block(r7515, 2700, 2704)},
        "rfc8037_a4_eddsa": {
            "jwk": jwk(r8037, 481, 482),
            "private_jwk": jwk(r8037, 462, 464),
            "token": block(r8037, 551, 553),
        },
        "rfc7520_4_1_rs256": {
            "jwk": jwk(r7520, 407, 419),
            "token": block(r7520, 737, 750),
        },
        "rfc7520_4_2_ps384": {
            "jwk": jwk(r7520, 407, 419),
            "token": block(r7520, 915, 928),
        },
        "rfc7520_4_3_es512": {
            "jwk": jwk(r7520, 314, 323),
            "token": block(r7520, 1106, 1116),
        },
        "rfc7520_4_4_hs256": {
            "jwk": jwk(r7520, 531, 537),
            "token": block(r7520, 1258, 1266),
        },
    }
    for name, v in out.items():
        assert v["token"].count(".") == 2, name
    json.dump(out, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
