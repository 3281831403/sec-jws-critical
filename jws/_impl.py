"""JWS 临界头校验器的唯一实现文件。

本文件当前只有 8 个桩。每个桩都必须保持签名不变，并在实现时去掉
NotImplementedError。不要在此文件之外新增实现。
"""


def split_compact(token: str) -> dict:
    raise NotImplementedError


def decode_segment(text: str) -> bytes:
    raise NotImplementedError


def parse_header(text: str) -> dict:
    raise NotImplementedError


def check_critical(header: dict, understood) -> bool:
    raise NotImplementedError


def check_alg(header: dict, key: dict, policy: dict) -> bool:
    raise NotImplementedError


def signing_input(header_segment: str, payload_segment: str, header: dict) -> bytes:
    raise NotImplementedError


def verify_one(token: str, key: dict, policy: dict) -> bool:
    raise NotImplementedError


def jws_batch(tokens, policy: dict) -> dict:
    raise NotImplementedError