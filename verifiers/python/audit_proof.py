#!/usr/bin/env python3
# Copyright (c) 2026 SuriComAI. All rights reserved. Proprietary: see LICENSE.
"""Audit a SuriComAI proof bundle without decrypting it.

Second implementation of the audit check; must agree with Rust on vectors/audit-v1.json.
It accepts the lab quote only. A lab quote is not a vendor root.
"""

import json
import sys

from blake3 import blake3
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

LAB_MAGIC = b"suricomai-lab-quote-v1"
LAB_DOMAIN = b"suricomai.lab-quote.v1\0"
RECEIPT_DOMAIN = b"suricomai.receipt.v1\0"
HPKE_PUBLIC_LEN = 1216
HPKE_ENC_LEN = 1120
DIGEST = 32
SIGNATURE = 64


class AuditError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def derive(domain, parts):
    hasher = blake3(derive_key_context=domain)
    for part in parts:
        hasher.update(part)
    return hasher.digest()


def read_argument(data, index):
    if index >= len(data):
        raise AuditError("malformed")
    first = data[index]
    major = first >> 5
    info = first & 0x1F
    index += 1
    if info < 24:
        return major, info, index
    widths = {24: 1, 25: 2, 26: 4, 27: 8}
    if info not in widths:
        raise AuditError("malformed")
    width = widths[info]
    if index + width > len(data):
        raise AuditError("malformed")
    argument = int.from_bytes(data[index : index + width], "big")
    index += width
    shortest = {1: 24, 2: 256, 4: 65536, 8: 2**32}
    if argument < shortest[width]:
        raise AuditError("non_canonical")
    return major, argument, index


def decode_one(data, index, depth):
    if depth > 4:
        raise AuditError("malformed")
    major, argument, index = read_argument(data, index)
    if major == 0:
        return ("uint", argument), index
    if major == 2:
        end = index + argument
        if end > len(data):
            raise AuditError("malformed")
        return ("bytes", data[index:end]), end
    if major == 5:
        mapping = {}
        previous = None
        for _ in range(argument):
            key, index = decode_one(data, index, depth + 1)
            if key[0] != "uint":
                raise AuditError("malformed")
            if previous is not None and key[1] <= previous:
                raise AuditError("non_canonical")
            previous = key[1]
            value, index = decode_one(data, index, depth + 1)
            mapping[key[1]] = value
        return ("map", mapping), index
    raise AuditError("malformed")


def decode(data):
    if not data or len(data) > 8 * 1024 * 1024:
        raise AuditError("malformed")
    value, index = decode_one(data, 0, 0)
    if index != len(data):
        raise AuditError("malformed")
    return value


def encode_len(major, number):
    head = major << 5
    if number < 24:
        return bytes([head | number])
    if number <= 0xFF:
        return bytes([head | 24, number])
    if number <= 0xFFFF:
        return bytes([head | 25]) + number.to_bytes(2, "big")
    if number <= 0xFFFFFFFF:
        return bytes([head | 26]) + number.to_bytes(4, "big")
    return bytes([head | 27]) + number.to_bytes(8, "big")


def encode(value):
    kind, body = value
    if kind == "uint":
        return encode_len(0, body)
    if kind == "bytes":
        return encode_len(2, len(body)) + body
    if kind == "map":
        out = encode_len(5, len(body))
        for key in sorted(body):
            out += encode_len(0, key)
            out += encode(body[key])
        return out
    raise AuditError("malformed")


def need_map(value):
    if value[0] != "map":
        raise AuditError("malformed")
    return value[1]


def need_uint(mapping, key):
    value = mapping.get(key)
    if value is None or value[0] != "uint":
        raise AuditError("malformed")
    return value[1]


def need_bytes(mapping, key, length=None):
    value = mapping.get(key)
    if value is None or value[0] != "bytes":
        raise AuditError("malformed")
    if length is not None and len(value[1]) != length:
        raise AuditError("bad_length")
    return value[1]


def require_keys(mapping, required, optional):
    allowed = set(required) | set(optional)
    if any(key not in allowed for key in mapping):
        raise AuditError("unknown_field")
    if any(key not in mapping for key in required):
        raise AuditError("malformed")


def verify_ed25519(public, message, signature, code):
    if len(public) != DIGEST or len(signature) != SIGNATURE:
        raise AuditError(code)
    try:
        VerifyKey(public).verify(message, signature)
    except (BadSignatureError, ValueError):
        raise AuditError(code) from None


def verify_lab_quote(lab_public, executor_id, report, quote):
    if len(quote) != len(LAB_MAGIC) + DIGEST + DIGEST + SIGNATURE:
        raise AuditError("bad_quote")
    if not quote.startswith(LAB_MAGIC):
        raise AuditError("bad_quote")
    body = quote[len(LAB_MAGIC) :]
    if body[:DIGEST] != executor_id or body[DIGEST : DIGEST * 2] != report:
        raise AuditError("bad_quote")
    message = LAB_DOMAIN + executor_id + report
    verify_ed25519(lab_public, message, body[DIGEST * 2 :], "bad_quote")


TOKEN_BUCKETS = (0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)


def valid_size_class(size):
    if size in (4096, 16384, 65536, 262144):
        return True
    return 262144 < size <= 4194304 and size % 262144 == 0


def validate_contract(contract):
    """Same checks and error codes as the Rust envelope decoder and `validate_contract`.

    Every field is type and length checked, in key order, as `contract_from_map` does.
    """
    for key in (2, 5, 6, 12, 13):
        need_bytes(contract, key, DIGEST)
    for key in (3, 4, 7, 8, 9, 10, 11, 15, 16, 17, 18):
        need_uint(contract, key)
    need_bytes(contract, 19)
    need_bytes(contract, 14, HPKE_PUBLIC_LEN)
    size_class = need_uint(contract, 8)
    if not valid_size_class(size_class):
        raise AuditError("bad_size")
    max_output = need_uint(contract, 7)
    if max_output == 0 or max_output > size_class - 4:
        raise AuditError("plaintext_too_large")
    if need_uint(contract, 16) > 1000:
        raise AuditError("malformed")
    if len(need_bytes(contract, 19)) > 64:
        raise AuditError("bad_length")
    tier = need_uint(contract, 4)
    if tier not in (0, 1, 2):
        raise AuditError("bad_tier")
    gpu = need_uint(contract, 18)
    if gpu not in (0, 1):
        raise AuditError("malformed")
    if gpu == 1 and tier != 2:
        raise AuditError("unexpected_gpu_evidence")


def audit(
    contract_bytes, result_bytes, allow, mode, lab_public, audit_now, target_executor, target_receipt
):
    contract = need_map(decode(contract_bytes))
    result = need_map(decode(result_bytes))
    require_keys(contract, list(range(1, 21)), [])
    require_keys(result, [1, 2, 3, 4, 5], [])
    if need_uint(contract, 1) != 1 or need_uint(result, 1) != 1:
        raise AuditError("bad_version")
    if need_uint(contract, 20) != 1:
        raise AuditError("bad_suite")
    validate_contract(contract)
    proof_bytes = need_bytes(result, 5)
    proof = need_map(decode(proof_bytes))
    require_keys(
        proof,
        [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        [8],
    )
    if (
        need_bytes(proof, 7, DIGEST) != target_executor
        or need_bytes(proof, 19, DIGEST) != target_receipt
    ):
        raise AuditError("identity_mismatch")
    if need_bytes(proof, 20, DIGEST) != derive("suricomai.contract.v1", [contract_bytes]):
        raise AuditError("identity_mismatch")
    if encode(("map", proof)) != proof_bytes:
        raise AuditError("non_canonical")
    if need_uint(proof, 1) != 1:
        raise AuditError("bad_version")
    if need_uint(proof, 9) not in TOKEN_BUCKETS:
        raise AuditError("malformed")

    expiry = need_uint(contract, 11)
    if need_uint(contract, 18) == 1:
        raise AuditError("missing_gpu_evidence")
    if need_bytes(proof, 13, DIGEST) != b"\x00" * DIGEST:
        raise AuditError("bad_assignment_vrf")
    started = need_uint(proof, 15)
    finished = need_uint(proof, 16)
    if finished < started:
        raise AuditError("malformed")
    if started >= expiry or finished >= expiry:
        raise AuditError("proof_expired")
    if audit_now >= expiry:
        raise AuditError("proof_expired")
    if finished > audit_now or started > audit_now:
        raise AuditError("proof_expired")

    tier = need_uint(contract, 4)
    if tier != need_uint(proof, 3):
        raise AuditError("identity_mismatch")
    if tier not in (0, 1, 2):
        raise AuditError("bad_tier")
    for key, proof_key in ((2, 2), (6, 4), (5, 6)):
        if need_bytes(contract, key, DIGEST) != need_bytes(proof, proof_key, DIGEST):
            raise AuditError("identity_mismatch")
    if need_bytes(result, 2, DIGEST) != need_bytes(proof, 2, DIGEST):
        raise AuditError("identity_mismatch")

    executor_id = need_bytes(proof, 7, DIGEST)
    if tier == 2 and executor_id not in allow:
        raise AuditError("measurement_rejected")

    needs_gpu = need_uint(contract, 18) == 1
    gpu = proof.get(8)
    if tier == 2 and needs_gpu:
        if gpu is None or gpu[0] != "bytes" or len(gpu[1]) != DIGEST or gpu[1] == b"\x00" * DIGEST:
            raise AuditError("missing_gpu_evidence")
    elif gpu is not None:
        raise AuditError("unexpected_gpu_evidence")

    quote = need_bytes(proof, 10)
    if tier == 2 and not quote:
        raise AuditError("bad_quote")
    if tier != 2 and quote:
        raise AuditError("bad_quote")

    hpke = need_bytes(proof, 17, HPKE_PUBLIC_LEN)

    answer_hash = derive(
        "suricomai.answer_ct.v1",
        [need_bytes(result, 3, HPKE_ENC_LEN), need_bytes(result, 4)],
    )
    if answer_hash != need_bytes(proof, 5, DIGEST):
        raise AuditError("answer_hash_mismatch")

    flag = b"\x01" if gpu is not None else b"\x00"
    gpu_digest = gpu[1] if gpu is not None else b"\x00" * DIGEST
    report = derive(
        "suricomai.report_data.v1",
        [
            need_bytes(proof, 2, DIGEST),
            need_bytes(proof, 4, DIGEST),
            answer_hash,
            need_bytes(proof, 6, DIGEST),
            executor_id,
            need_bytes(proof, 19, DIGEST),
            hpke,
            need_bytes(proof, 18, DIGEST),
            flag,
            gpu_digest,
            need_bytes(proof, 20, DIGEST),
        ],
    )
    if report != need_bytes(proof, 11, DIGEST):
        raise AuditError("bad_report_data")

    unsigned = dict(proof)
    del unsigned[12]
    message = RECEIPT_DOMAIN + encode(("map", unsigned))
    verify_ed25519(
        need_bytes(proof, 19, DIGEST),
        message,
        need_bytes(proof, 12, SIGNATURE),
        "bad_signature",
    )

    if tier == 2 and mode == "quote":
        verify_lab_quote(lab_public, executor_id, report, quote)
    elif tier != 2 and mode == "signature":
        return
    else:
        raise AuditError("bad_quote")


def ping_vector():
    digest = derive("suricomai.prompt.v1", [b"ping"])
    expect = bytes.fromhex(
        "27c5460634c02f90cc5891a14aa4b179b09f704d16fe6d216324f9405782d1b1"
    )
    if digest != expect:
        raise SystemExit("prompt commitment vector mismatch")


def contract_checks(document, lab_public):
    """Mutate a good contract and require the same codes the Rust validator returns."""
    base = next(case for case in document["cases"] if case["name"] == "p1_ok")
    good = need_map(decode(bytes.fromhex(base["contract"])))
    cases = [
        ("bad_size", 8, ("uint", 5000)),
        ("plaintext_too_large", 7, ("uint", 2**64 - 1)),
        ("plaintext_too_large", 7, ("uint", 4093)),
        ("plaintext_too_large", 7, ("uint", 0)),
        ("malformed", 16, ("uint", 1001)),
        ("bad_length", 19, ("bytes", b"x" * 65)),
        ("bad_length", 14, ("bytes", b"x" * 10)),
        ("malformed", 18, ("uint", 2)),
        ("unexpected_gpu_evidence", 18, ("uint", 1)),
        ("bad_tier", 4, ("uint", 3)),
        ("bad_suite", 20, ("uint", 2)),
        ("bad_length", 2, ("bytes", b"x" * 31)),
        ("bad_length", 5, ("bytes", b"x" * 33)),
        ("bad_length", 6, ("bytes", b"")),
        ("bad_length", 12, ("bytes", b"x" * 31)),
        ("bad_length", 13, ("bytes", b"x" * 33)),
        ("malformed", 3, ("bytes", b"x")),
        ("malformed", 9, ("bytes", b"x")),
        ("malformed", 10, ("bytes", b"x")),
        ("malformed", 11, ("bytes", b"x")),
        ("malformed", 15, ("bytes", b"x")),
        ("malformed", 17, ("bytes", b"x")),
        ("malformed", 19, ("uint", 1)),
    ]
    for code, key, value in cases:
        mutated = dict(good)
        mutated[key] = value
        try:
            audit(
                encode(("map", mutated)),
                bytes.fromhex(base["result"]),
                [],
                "signature",
                lab_public,
                999,
                bytes.fromhex(base["target_executor_id"]),
                bytes.fromhex(base["target_receipt_public"]),
            )
            got = "ok"
        except AuditError as err:
            got = err.code
        if got != code:
            raise SystemExit(f"contract key {key}: {got} != {code}")
        print(f"contract_key_{key} {got}")


def main(path):
    ping_vector()
    document = json.load(open(path, encoding="utf-8"))
    lab_public = bytes.fromhex(document["lab_public"])
    for case in document["cases"]:
        allow = [bytes.fromhex(item) for item in case["allow"]]
        contract_bytes = bytes.fromhex(case["contract"])
        contract_map = need_map(decode(contract_bytes))
        audit_now = case.get("audit_now", need_uint(contract_map, 11) - 1)
        try:
            audit(
                contract_bytes,
                bytes.fromhex(case["result"]),
                allow,
                case["mode"],
                lab_public,
                audit_now,
                bytes.fromhex(case["target_executor_id"]),
                bytes.fromhex(case["target_receipt_public"]),
            )
            got = "ok"
        except AuditError as err:
            got = err.code
        if got != case["expect"]:
            raise SystemExit(f"{case['name']}: {got} != {case['expect']}")
        print(f"{case['name']} {got}")
    contract_checks(document, lab_public)


def one():
    """Audit one case read as JSON from stdin and print `ok` or the error code."""
    case = json.load(sys.stdin)
    lab = bytes.fromhex(case["lab_public"]) if case.get("lab_public") else b""
    try:
        audit(
            bytes.fromhex(case["contract"]),
            bytes.fromhex(case["result"]),
            [bytes.fromhex(item) for item in case["allow"]],
            case["mode"],
            lab,
            int(case["audit_now"]),
            bytes.fromhex(case["target_executor_id"]),
            bytes.fromhex(case["target_receipt_public"]),
        )
        print("ok")
    except AuditError as err:
        print(err.code)


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--one":
        one()
    elif len(sys.argv) == 2:
        main(sys.argv[1])
    else:
        raise SystemExit("usage: audit_proof.py vectors/audit-v1.json | --one < case.json")
