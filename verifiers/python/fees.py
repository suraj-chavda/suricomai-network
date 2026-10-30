#!/usr/bin/env python3
# Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
"""Check vectors/fees-v1.txt with a second, independent implementation of the fee math.

The Rust crate suricomai-escrow wrote the expected values. This script recomputes every line
from the rules in the protocol specification ("Fee schedule") using Python's arbitrary precision integers, so a
rounding or overflow mistake in either language shows up as a disagreement.
"""

import sys

U64_MAX = 2**64 - 1
BPS = 10_000
MIN_PRICE = 10_000
MAX_PROTOCOL_BPS = 300
MAX_ATTESTATION_BPS = 300
MAX_RELAY_BPS = 300
MAX_ATTESTATION_MIN = 100_000


def ceil_div(numerator, denominator):
    return -(-numerator // denominator)


def quote(protocol_bps, attestation_bps, attestation_min, relay_bps, price):
    """Return five amounts, or the refusal code."""
    if (
        protocol_bps > MAX_PROTOCOL_BPS
        or attestation_bps > MAX_ATTESTATION_BPS
        or relay_bps > MAX_RELAY_BPS
        or attestation_min > MAX_ATTESTATION_MIN
    ):
        return "bad_fee_schedule"
    if price < MIN_PRICE:
        return "price_too_small"
    protocol = ceil_div(price * protocol_bps, BPS)
    attestation = max(ceil_div(price * attestation_bps, BPS), attestation_min)
    relay_max = ceil_div(price * relay_bps, BPS)
    total = price + protocol + attestation + relay_max
    if max(protocol, attestation, relay_max, total) > U64_MAX:
        return "fee_overflow"
    return [price, protocol, attestation, relay_max, total]


def main(path):
    checked = 0
    for number, line in enumerate(open(path), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        inputs, expected = line.split("|")
        params = [int(word) for word in inputs.split()]
        want = expected.split()
        got = quote(*params)
        got_words = [got] if isinstance(got, str) else [str(n) for n in got]
        if got_words != want:
            print(f"line {number}: {line}\n  python says {got_words}")
            return 1
        checked += 1
    if checked < 100:
        print(f"only {checked} vectors")
        return 1
    print(f"{checked} fee vectors agree")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "vectors/fees-v1.txt"))
