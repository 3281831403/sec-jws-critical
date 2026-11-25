"""JWS 临界头校验器的唯一实现文件。

公开函数的名称与签名保持不变；所有辅助逻辑也只放在本文件内。
校验严格遵循 README 中“必须遵守的语义”，任何解析失败都表现为
``ValueError``（针对要求抛错的函数）或 ``False``（针对 ``verify_one``）。
"""

import base64
import hashlib
import hmac
import json


# 仅允许无填充 base64url 字母表。
_B64URL_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)

# JWS 算法名 -> 允许配对的密钥类型（kty）。
_ALG_KTY = {
    "HS256": "oct",
    "HS384": "oct",
    "HS512": "oct",
    "RS256": "rsa",
    "RS384": "rsa",
    "RS512": "rsa",
    "ES256": "ec",
    "ES384": "ec",
    "ES512": "ec",
}

# 本项目真正实现的验签算法只有 HMAC 系列，摘要由头部 alg 决定。
_HMAC_DIGESTS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def split_compact(token: str) -> dict:
    """拆分三段紧凑序列化，返回 header/payload/signature 三个原始段。"""
    if not isinstance(token, str):
        raise ValueError("token must be a string")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWS compact serialization must have exactly 3 segments")

    header, payload, signature = parts
    if not header:
        raise ValueError("header segment must not be empty")
    if not signature:
        raise ValueError("signature segment must not be empty")
    # 载荷段允许为空字符串。
    return {"header": header, "payload": payload, "signature": signature}


def decode_segment(text: str) -> bytes:
    """严格解码无填充 base64url，拒绝填充、非法字符与非法长度。"""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("segment contains non-ASCII bytes") from exc
    if not isinstance(text, str):
        raise ValueError("segment must be a string")

    # 任何位置出现等号都属于（被禁止的）填充。
    if "=" in text:
        raise ValueError("padding is not allowed in an unpadded base64url segment")

    # 长度模 4 为 1 在任何规范形式下都是非法的。
    if len(text) % 4 == 1:
        raise ValueError("invalid base64url segment length")

    for char in text:
        if char not in _B64URL_ALPHABET:
            raise ValueError("invalid character in base64url segment")

    padding = "=" * ((-len(text)) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except ValueError as exc:  # binascii.Error 也是 ValueError 的子类
        raise ValueError("invalid base64url segment") from exc


def _reject_duplicate_keys(pairs):
    """object_pairs_hook：任意层级出现重复键即抛 ValueError。"""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key: %r" % (key,))
        result[key] = value
    return result


def parse_header(text: str) -> dict:
    """解析已经 UTF-8 解码的 JSON 头部文本，拒绝非法 JSON、非对象与重复键。"""
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("header is not valid UTF-8 text") from exc
    if not isinstance(text, str):
        raise ValueError("header text must be a string")

    try:
        header = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValueError:
        # JSONDecodeError 以及重复键钩子抛出的 ValueError 直接向上传播。
        raise
    except TypeError as exc:
        raise ValueError("invalid header JSON text") from exc

    if not isinstance(header, dict):
        raise ValueError("JWS protected header must be a JSON object")
    return header


def check_critical(header: dict, understood) -> bool:
    """校验 crit：所有临界头都必须存在、唯一且被逐字符精确理解。"""
    if not isinstance(header, dict):
        return False

    if understood is None:
        understood_names = set()
    else:
        try:
            understood_names = set(understood)
        except TypeError:
            return False

    # 没有 crit 成员时默认通过（但仍受 b64 必须临界的约束）。
    if "crit" not in header:
        return "b64" not in header

    crit = header["crit"]
    # crit 必须是非空数组（JSON 解析后为 list；直接调用也容忍 tuple）；
    # 显式 null、字符串、集合等都不合法。
    if not isinstance(crit, (list, tuple)) or len(crit) == 0:
        return False

    seen = set()
    for name in crit:
        if not isinstance(name, str):
            return False
        # crit 自身不得列入 crit，且数组元素不得重复。
        if name == "crit" or name in seen:
            return False
        seen.add(name)

        # 每个临界名必须确实出现在头部。
        if name not in header:
            return False
        # 必须与 understood 中的名字逐字符（大小写敏感）完全一致。
        if name not in understood_names:
            return False

    # 头部一旦出现 b64，b64 就必须被声明为临界头。
    if "b64" in header and "b64" not in seen:
        return False

    return True


def check_alg(header: dict, key: dict, policy: dict) -> bool:
    """校验算法在非空白名单内，且与密钥 kty / secret 形态匹配。"""
    if not isinstance(header, dict) or not isinstance(policy, dict):
        return False

    algs = policy.get("algs")
    # 缺失、None、字符串（避免子串语义）或任何无长度/不可成员判定的策略，
    # 以及空白名单，都一律拒绝——绝不默认放行。
    if algs is None or isinstance(algs, (str, bytes, bytearray)):
        return False
    try:
        if len(algs) == 0:
            return False
        alg_whitelisted = header.get("alg") in algs
    except TypeError:
        return False

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg_whitelisted:
        return False

    if not isinstance(key, dict):
        return False

    expected_kty = _ALG_KTY.get(alg)
    if expected_kty is None:
        # none 或未知算法没有任何可匹配的密钥类型，直接拒绝。
        return False
    if key.get("kty") != expected_kty:
        return False

    if expected_kty == "oct":
        secret = key.get("secret")
        if not isinstance(secret, (bytes, bytearray)) or len(secret) == 0:
            return False

    return True


def _b64_is_encoded(header: dict) -> bool:
    """返回 b64 开关的语义。

    缺省或 JSON 布尔 true -> True（载荷参与 base64url 编码与签名拼接）；
    JSON 布尔 false -> False（载荷原样、不进入待签名数据）；
    0、null、字符串、数组等任何非布尔值 -> ValueError。
    """
    if not isinstance(header, dict) or "b64" not in header:
        return True
    value = header["b64"]
    if not isinstance(value, bool):
        raise ValueError("the 'b64' header parameter must be a JSON boolean")
    return value


def signing_input(header_segment: str, payload_segment: str, header: dict) -> bytes:
    """按 b64 开关构造 JWS 待签名 ASCII 字节串。"""
    if not isinstance(header_segment, str) or header_segment == "":
        raise ValueError("header segment must be non-empty ASCII text")
    try:
        header_segment.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("header segment must be ASCII text") from exc

    encoded = _b64_is_encoded(header)  # 非布尔 b64 在此抛 ValueError

    if encoded is False:
        # RFC 7797：b64=false 时待签名数据只有头部段，没有点号和载荷。
        return header_segment.encode("ascii")

    if not isinstance(payload_segment, str):
        raise ValueError("payload segment must be text")
    try:
        return (header_segment + "." + payload_segment).encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("encoded payload segment must be ASCII text") from exc


def verify_one(token: str, key: dict, policy: dict) -> bool:
    """校验单个紧凑序列化 JWS；任何错误都收敛为 False，不向外抛异常。"""
    try:
        if not isinstance(policy, dict):
            policy = {}

        # 1) 拆分三段。
        parts = split_compact(token)
        header_segment = parts["header"]
        payload_segment = parts["payload"]
        signature_segment = parts["signature"]

        # 2) 严格解码头部段；3) UTF-8 解码并解析 JSON 头部（拒绝重复键）。
        header_json = decode_segment(header_segment).decode("utf-8")
        header = parse_header(header_json)

        # 4) 临界头必须全部可理解。
        if not check_critical(header, policy.get("understood", [])):
            return False

        # 5a) b64 开关必须是合法 JSON 布尔（非法类型会抛 ValueError）。
        encoded = _b64_is_encoded(header)

        # 5b) 算法白名单及其与密钥类型的匹配。
        if not check_alg(header, key, policy):
            return False

        # b64=false 时载荷未被签名覆盖，其明文永远不能视为已认证内容，
        # 即便签名恰好等于“仅头部”的 HMAC 也一样拒绝。
        if encoded is False:
            return False

        # 6) 严格解码载荷段与签名段。载荷段必须是合法无填充 base64url。
        decode_segment(payload_segment)
        provided_signature = decode_segment(signature_segment)

        # 7) 摘要算法由头部 alg 决定，禁止固定为单一算法。
        alg = header.get("alg")
        digestmod = _HMAC_DIGESTS.get(alg)
        if digestmod is None:
            # RS/ES 在本项目中只做密钥类型拒绝，不实现其非对称验签。
            return False

        # 8) 必须使用“当前令牌自己的”头部段与载荷段重新计算待签名数据，
        #    从而把载荷绑定到签名上，且不存在跨令牌复用。
        message = signing_input(header_segment, payload_segment, header)
        secret = key["secret"]
        expected_signature = hmac.new(secret, message, digestmod).digest()

        # 9) 常量时间比较。
        return hmac.compare_digest(expected_signature, provided_signature)
    except Exception:
        # 拆分、解码、解析或计算中的任何错误都意味着校验不通过。
        return False


def jws_batch(tokens, policy: dict) -> dict:
    """按输入顺序独立校验一批令牌，任一无效则 ok 为 False。"""
    results = []

    keys = {}
    if isinstance(policy, dict) and isinstance(policy.get("keys"), dict):
        keys = policy["keys"]

    for token in tokens:
        try:
            # 仅为按 kid 选密钥而读取头部；每个令牌都独立解析，
            # 不保留也不复用前一个令牌的任何中间数据。
            parts = split_compact(token)
            header = parse_header(
                decode_segment(parts["header"]).decode("utf-8")
            )
            kid = header.get("kid") if isinstance(header, dict) else None
            key = keys.get(kid) if kid is not None else None
            if key is None:
                results.append(False)
                continue

            results.append(bool(verify_one(token, key, policy)))
        except Exception:
            # 单个令牌损坏不得中断整批。
            results.append(False)

    return {"ok": all(results), "results": results}
