对方把签名段改成不参与编码，验签方照样按旧规则算，签名内容被换掉也没发现：编码开关只在头部出现真值判断，非真值也被当作不参与编码；不参与编码时仍把载荷拼进待签名数据，签名与声明不符；临界头未识别时不拒绝，未知扩展被忽略；临界头比较区分大小写但与规范不符，大小写变体绕过；算法白名单为空时默认放行任意算法；算法与密钥类型不做匹配校验，换算法仍通过；段解码使用宽松模式，多余填充被接受；头部重复键后者覆盖，临界头可被追加覆盖；载荷未绑定，签名可跨令牌复用；批量校验复用待签名数据，第二个令牌沿用第一个令牌的签名输入。jws/_impl.py 是核心，tests/test_verify.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

JWS 临界头校验器
================

字段表
------

字段        值
难度        安全
方向        漏洞检测与攻防
类型        Bugfix
技术栈      Python 3, pytest
外部依赖    无外部依赖

运行方式
--------

在仓库根目录执行：

    python -m pytest tests -q

首次运行必须得到：

    15 failed

15 条失败必须全部由 NotImplementedError 引起。不允许 collection error，不允许 import error，不允许 fixture error，也不允许因为语法错误或测试自身异常而失败。

门面布局
--------

sec-jws-critical/
  README.md
  conftest.py
  jws/
    __init__.py
    _impl.py
    api.py
  tests/
    test_verify.py

jws/__init__.py 只从 jws.api 导出公开名称。jws/api.py 只把 jws._impl 的名称再导出。jws/_impl.py 是唯一实现文件，必须有且只有 8 个桩，当前每个桩的函数体只有 raise NotImplementedError。不得新建其他实现模块，不得把逻辑塞进 api、init 或测试。

tests/test_verify.py 是只读验收文件，不允许修改任何一行，不允许新增测试文件、插件、收集钩子或跳过标记。conftest.py 只做仓库根路径引导。

必须遵守的语义
--------------

令牌格式为三段紧凑序列化，段之间用 ASCII 点号连接。split_compact(token) 返回 dict，键固定为 header、payload、signature，值都是原始段字符串。段数不是 3、头部段为空或签名段为空时抛 ValueError。载荷段可以为空。

decode_segment(text) 只接受无填充 base64url。允许字符只有大写字母、小写字母、数字、连字符和下划线；任何等号都算填充错误；长度模 4 为 1 也算非法。非法字符、非法长度和任何填充都抛 ValueError。不得使用宽松解码后修补，不得接受多余填充。

parse_header(text) 的 text 是已经解码的 UTF-8 JSON 文本，不是 base64url 段。顶层必须是对象。任何层级出现重复键都必须抛 ValueError，不允许后键覆盖前键。非法 JSON 和非对象也抛 ValueError。

check_critical(header, understood) 返回 bool。没有 crit 时返回 True。crit 必须是非空数组，元素必须是不重复字符串，不能包含 crit。每个临界名必须在头部存在，并且必须与 understood 中的名字逐字符大小写一致；未识别、缺失、重复、空数组或大小写变体都返回 False。头部一旦出现 b64，b64 就必须在 crit 中。

编码开关只认 JSON 布尔值。b64 缺省或为 true 时，载荷段是无填充 base64url，待签名数据是头部段 ASCII、一个 ASCII 点号、载荷段 ASCII 的拼接。b64 为 false 时，载荷段是原样 UTF-8，待签名数据只有头部段 ASCII，不含点号，也不含载荷段。b64 为 0、null、字符串、数组等任何非布尔值都属于非法头部，signing_input 抛 ValueError，verify_one 返回 False。

当 b64 为 false 时，载荷没有进入签名，因此 verify_one 对该令牌一律返回 False。可读的未编码载荷不得被当作已认证内容，即使签名与只含头部的待签名数据匹配也不行。

check_alg(header, key, policy) 返回 bool。policy 的 algs 必须是非空序列，缺失或为空时拒绝全部算法，绝不能默认放行。头部 alg 必须与白名单元素精确匹配。alg 还必须与 key 的 kty 匹配：HS256、HS384、HS512 只能配 oct；RS256、RS384、RS512 只能配 rsa；ES256、ES384、ES512 只能配 ec。oct 密钥还必须提供非空 secret 字节。白名单允许但密钥类型不匹配时返回 False。

本项目实际验签覆盖 HS256、HS384、HS512，摘要必须由头部 alg 决定，禁止固定为某一种算法。RS 与 ES 只用于拒绝错误密钥类型，不得因为密钥对象可读就放行。

signing_input(header_segment, payload_segment, header) 返回 bytes。它必须严格执行上面的 b64 开关，不得自行改写头部，不得忽略头部里的 b64，也不得把未编码载荷再编码后拼接。头部段必须为可 ASCII 编码的非空文本。

verify_one(token, key, policy) 返回 bool。任何解析或校验错误都返回 False，不向调用方抛异常。校验顺序为拆分、解码头部、解析头部、检查临界头、检查 b64、检查算法与密钥、解码载荷和签名、计算 HMAC、常量时间比较。签名输入必须使用当前令牌自己的头部段和载荷段重新计算，禁止跨令牌复用。载荷必须被签名覆盖，修改载荷段必须导致失败。

jws_batch(tokens, policy) 返回 dict，且只能有 ok 和 results 两个键。results 是按输入顺序排列的布尔列表；ok 当且仅当 results 全为 True。每个令牌必须独立解析，按头部 kid 从 policy 的 keys 映射取密钥；缺少 kid、找不到密钥、头部损坏或签名错误都只把该位置记为 False，不得中断整批，不得把前一个令牌的头部、载荷或待签名数据留给后一个令牌。空列表返回 ok 为 True、results 为空列表。

8 个桩
-------

1. split_compact(token) 返回 dict，拆分三段，段数不符报错。
2. decode_segment(text) 返回 bytes，严格解码，非法字符与填充错误报错。
3. parse_header(text) 返回 dict，解析头部，重复键报错。
4. check_critical(header, understood) 返回 bool，临界头必须全部被理解，否则拒绝。
5. check_alg(header, key, policy) 返回 bool，算法必须在白名单内且与密钥类型匹配。
6. signing_input(header_segment, payload_segment, header) 返回 bytes，待签名数据，编码开关必须生效。
7. verify_one(token, key, policy) 返回 bool，单签名校验，不参与编码时载荷不进入签名。
8. jws_batch(tokens, policy) 返回 dict，批量校验，各令牌独立。

10 个缺陷
----------

按题面顺序修复，每一步都要有对应测试支撑：

1. 编码开关只在头部出现真值判断，非真值也被当作不参与编码。
2. 不参与编码时仍把载荷拼进待签名数据，签名与声明不符。
3. 临界头未识别时不拒绝，未知扩展被忽略。
4. 临界头比较区分大小写但与规范不符，大小写变体绕过。
5. 算法白名单为空时默认放行任意算法。
6. 算法与密钥类型不做匹配校验，换算法仍通过。
7. 段解码使用宽松模式，多余填充被接受。
8. 头部重复键后者覆盖，临界头可被追加覆盖。
9. 载荷未绑定，签名可跨令牌复用。
10. 批量校验复用待签名数据，第二个令牌沿用第一个令牌的签名输入。

15 条测试
----------

tests/test_verify.py 恰好包含以下 15 条测试，函数名和数量都不得变化：

1. test_defect_01_b64_switch_only_accepts_boolean_false
2. test_defect_02_unencoded_payload_is_not_in_signing_input
3. test_defect_03_unknown_critical_header_is_rejected
4. test_defect_04_critical_names_are_case_sensitive
5. test_defect_05_empty_algorithm_whitelist_rejects_everything
6. test_defect_06_algorithm_must_match_key_type
7. test_defect_07_segment_decoding_is_strict
8. test_defect_08_duplicate_header_keys_are_rejected
9. test_defect_09_payload_is_bound_to_its_signature
10. test_defect_10_batch_does_not_reuse_signing_input
11. test_standard_token_verifies
12. test_tampered_payload_fails
13. test_unrecognized_critical_header_is_rejected
14. test_algorithm_not_in_whitelist_is_rejected
15. test_two_batch_runs_match_individual_verification

其中必须覆盖四条硬要求：不参与编码的载荷不得被当作已认证；未识别的临界头必须拒绝；算法与密钥必须匹配；多签名任一无效即整体失败。

交付检查
--------

1. 只修改 jws/_impl.py。
2. 保持 8 个公开函数的名称和参数不变。
3. 在仓库根目录运行 python -m pytest tests -q。
4. 目标输出是 15 passed，不能有 skip、xfail、warning 引发的降级。
5. 不要执行 git init，不要 push，不要联网。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

