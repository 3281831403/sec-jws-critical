"""JWS 临界头校验器的 15 条验收测试。"""

import base64
import hashlib
import hmac
import json

import pytest

import jws

KEY = {
    "kid": "k1",
    "kty": "oct",
    "secret": b"correct-horse-battery-staple",
}

POLICY = {
    "algs": ["HS256"],
    "understood": ["b64"],
    "keys": {"k1": KEY},
}

RSA_KEY = {
    "kid": "k1",
    "kty": "rsa",
    "n": "sXchY2F0ZXJwaWxsb3ctcnNhLW1vZHVsdXM",
    "e": "AQAB",
}


def _json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _digest(alg):
    return {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }[alg]


def _sign(key, data, alg="HS256"):
    return hmac.new(key["secret"], data, _digest(alg)).digest()


def _make_token(payload, key=KEY, header=None, alg="HS256"):
    if header is None:
        header = {"alg": alg, "kid": key["kid"], "typ": "JWT"}
    header_segment = _b64u(_json_bytes(header))
    payload_segment = _b64u(payload)
    signing_bytes = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = _sign(key, signing_bytes, alg)
    return f"{header_segment}.{payload_segment}.{_b64u(signature)}"


def _make_unencoded_token(payload_text, key, header):
    header_segment = _b64u(_json_bytes(header))
    signature = _sign(key, header_segment.encode("ascii"), header["alg"])
    return f"{header_segment}.{payload_text}.{_b64u(signature)}"


def _replace_payload(token, payload):
    header_segment, _, signature_segment = token.split(".")
    return f"{header_segment}.{_b64u(payload)}.{signature_segment}"


def test_defect_01_b64_switch_only_accepts_boolean_false():
    header = {
        "alg": "HS256",
        "kid": "k1",
        "typ": "JWT",
        "b64": 0,
        "crit": ["b64"],
    }
    token = _make_unencoded_token("payload", KEY, header)
    assert jws.verify_one(token, KEY, POLICY) is False

    header_segment = _b64u(_json_bytes({"alg": "HS256", "b64": 0}))
    for bad_value in (0, "false", None, 1, []):
        with pytest.raises(ValueError):
            jws.signing_input(
                header_segment,
                "payload",
                {"alg": "HS256", "b64": bad_value},
            )


def test_defect_02_unencoded_payload_is_not_in_signing_input():
    header = {
        "alg": "HS256",
        "kid": "k1",
        "typ": "JWT",
        "b64": False,
        "crit": ["b64"],
    }
    header_segment = _b64u(_json_bytes(header))
    assert jws.signing_input(header_segment, "raw-payload", header) == (
        header_segment.encode("ascii")
    )

    token = _make_unencoded_token("raw-payload", KEY, header)
    assert jws.verify_one(token, KEY, POLICY) is False


def test_defect_03_unknown_critical_header_is_rejected():
    header = {
        "alg": "HS256",
        "kid": "k1",
        "typ": "JWT",
        "crit": ["exp"],
        "exp": 1770000000,
    }
    token = _make_token(b"payload", header=header)
    assert jws.check_critical(header, ["b64"]) is False
    assert jws.verify_one(token, KEY, POLICY) is False


def test_defect_04_critical_names_are_case_sensitive():
    header = {
        "alg": "HS256",
        "kid": "k1",
        "typ": "JWT",
        "crit": ["B64"],
        "B64": True,
    }
    token = _make_token(b"payload", header=header)
    assert jws.check_critical(header, ["b64"]) is False
    assert jws.verify_one(token, KEY, POLICY) is False


def test_defect_05_empty_algorithm_whitelist_rejects_everything():
    assert jws.check_alg({"alg": "HS256"}, KEY, {"algs": []}) is False

    token = _make_token(b"payload")
    empty_policy = {
        "algs": [],
        "understood": ["b64"],
        "keys": {"k1": KEY},
    }
    assert jws.verify_one(token, KEY, empty_policy) is False


def test_defect_06_algorithm_must_match_key_type():
    assert jws.check_alg({"alg": "HS256"}, RSA_KEY, {"algs": ["HS256"]}) is False
    assert jws.check_alg({"alg": "RS256"}, KEY, {"algs": ["RS256"]}) is False
    assert jws.check_alg({"alg": "ES256"}, KEY, {"algs": ["ES256"]}) is False

    token = _make_token(b"payload")
    mismatched_policy = {
        "algs": ["HS256"],
        "understood": ["b64"],
        "keys": {"k1": RSA_KEY},
    }
    assert jws.verify_one(token, RSA_KEY, mismatched_policy) is False


def test_defect_07_segment_decoding_is_strict():
    for bad_value in ("A", "AA=", "QQ===", "A A", "AA$A", "AAAA="):
        with pytest.raises(ValueError):
            jws.decode_segment(bad_value)

    assert jws.decode_segment("QQ") == b"A"


def test_defect_08_duplicate_header_keys_are_rejected():
    text = (
        '{"alg":"HS256","kid":"k1","crit":["b64"],'
        '"crit":["exp"],"b64":true}'
    )
    with pytest.raises(ValueError):
        jws.parse_header(text)

    assert jws.parse_header('{"alg":"HS256","kid":"k1"}') == {
        "alg": "HS256",
        "kid": "k1",
    }


def test_defect_09_payload_is_bound_to_its_signature():
    original = _make_token(b'{"sub":"alice","role":"user"}')
    replaced = _replace_payload(original, b'{"sub":"alice","role":"admin"}')
    assert jws.verify_one(original, KEY, POLICY) is True
    assert jws.verify_one(replaced, KEY, POLICY) is False


def test_defect_10_batch_does_not_reuse_signing_input():
    first = _make_token(b"first-payload")
    header_segment, _, signature_segment = first.split(".")
    second = (
        f"{header_segment}.{_b64u(b'second-payload')}.{signature_segment}"
    )

    result = jws.jws_batch([first, second], POLICY)
    assert result == {"ok": False, "results": [True, False]}


def test_standard_token_verifies():
    token = _make_token(b"standard-payload")
    assert jws.verify_one(token, KEY, POLICY) is True


def test_tampered_payload_fails():
    token = _make_token(b"amount=10")
    tampered = _replace_payload(token, b"amount=99")
    assert jws.verify_one(token, KEY, POLICY) is True
    assert jws.verify_one(tampered, KEY, POLICY) is False


def test_unrecognized_critical_header_is_rejected():
    header = {
        "alg": "HS256",
        "kid": "k1",
        "typ": "JWT",
        "crit": ["svc"],
        "svc": "payments",
    }
    token = _make_token(b"payload", header=header)
    assert jws.verify_one(token, KEY, POLICY) is False


def test_algorithm_not_in_whitelist_is_rejected():
    token = _make_token(b"payload")
    policy = {
        "algs": ["HS512"],
        "understood": ["b64"],
        "keys": {"k1": KEY},
    }
    assert jws.verify_one(token, KEY, policy) is False


def test_two_batch_runs_match_individual_verification():
    key_a = {
        "kid": "a",
        "kty": "oct",
        "secret": b"batch-key-a",
    }
    key_b = {
        "kid": "b",
        "kty": "oct",
        "secret": b"batch-key-b",
    }
    policy = {
        "algs": ["HS256"],
        "understood": ["b64"],
        "keys": {"a": key_a, "b": key_b},
    }

    good = _make_token(b"alpha", key=key_a)
    bad = _make_token(
        b"beta",
        key=key_a,
        header={"alg": "HS256", "kid": "b", "typ": "JWT"},
    )
    tokens = [good, bad]

    first = jws.jws_batch(tokens, policy)
    second = jws.jws_batch(tokens, policy)
    assert first == second
    assert first == {"ok": False, "results": [True, False]}
    assert first["results"][0] == jws.verify_one(good, key_a, policy)
    assert first["results"][1] == jws.verify_one(bad, key_b, policy)