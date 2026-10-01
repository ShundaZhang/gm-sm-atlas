# GM / SM reference project · 国密参考项目

Original readable Python 3.9+ implementations of SM3, SM4, AES-128 encryption, curveSM2 / NIST P-256 arithmetic, SM2 signatures, SM2 C1C3C2 encryption and the SM2 key-exchange algebra.
原创可读 Python 3.9+ 实现，含 SM3、SM4、AES-128 加密、curveSM2 / P-256 算术、SM2 签名、C1C3C2 加密及 SM2 密钥交换算术。

```sh
python3 -B test_reference.py
python3 -B demo.py
```

No Python packages are required. The two independent test methods additionally use the installed OpenSSL CLI (verified: **3.6.2**). Without that CLI they are clearly skipped. An installed but unsupported algorithm causes a failure, not a silent pass.
无需额外 Python 包。两个独立测试方法还使用安装的 OpenSSL CLI（验证版本 3.6.2）；未安装时明确跳过，安装但不支持算法时失败，不悄悄通过。

## Evidence · 验证

Ten methods cover public SM3 / SM4 / AES known answers, a historical SM2 draft signature vector, exact curve/subgroup properties, ID/message/point rejection, ciphertext tampering, and agreement of both key-exchange sides and confirmation tags.
十个方法覆盖公开 SM3 / SM4 / AES 答案、历史 SM2 草案签名向量、曲线 / 子群性质、身份 / 消息 / 点拒绝、密文篡改、双方交换及确认标签一致性。

Independent checks compare SM3 at 10 lengths and each block cipher at 8 key/block pairs, and test current-curve SM2 signatures and encryption in **both directions** against OpenSSL. The test adapts explicit raw ciphertext and DER representations. Temporary test files are cleaned automatically.
独立检查包含 SM3 的 10 组长度、每种分组密码的 8 组密钥 / 分组，以及当前曲线 SM2 签名与加密同 OpenSSL 双向互操作；明确转换 raw / DER，自动清理临时测试文件。

The historical signature vector in draft-shen-sm2-ecdsa-02 Appendix A.2 uses a **different test curve**. It is confined to that test, not treated as the current curveSM2 domain. The regular implementation and OpenSSL tests use GB/T 32918.5 / RFC 8998 parameters.
历史草案 A.2 使用不同测试曲线，仅用于该测试，不作为当前 curveSM2。普通实现及 OpenSSL 测试使用 GB/T 32918.5 / RFC 8998 参数。

## Scope · 范围

- SM3 inputs are byte-aligned; SM4/AES primitives process exactly one 16-byte block. No padding or authenticated application mode is supplied.
- SM2 ciphertext is `04 || xC1 || yC1 || C3 || C2`, with fixed 32-byte field elements. Alternative encodings need explicit adaptation.
- SM2 signatures take a message and identity, then compute ZA internally. Fixed-width raw and DER signatures are different encodings.
- The exchange core returns a key and the `02` / `03` confirmation tags. It does **not** implement a network state machine, verify incoming tags for a peer, authenticate certificates, or decide when a key is released.
- SHA-256 / SHA3-256 CLI comparisons use `hashlib`. AES-192/256, SM9, ZUC and production protocols are explained on the site rather than implemented here.

SM3 仅字节对齐；SM4/AES 仅单个 16 字节分组，无填充或应用模式。SM2 密文明确采用 C1C3C2；签名内部计算 ZA，编码必须明确。交换返回密钥与确认标签，但不实现网络状态机、对端标签验证、证书认证或密钥释放策略。SHA-2/3 用 hashlib，其他算法与协议由网站介绍。

## Teaching values · 教学数值

Every fixed private scalar / nonce in the demo and tests is a **public synthetic test value**, unsuitable as a real credential. No user key is requested. Some functions can generate randomness to explain range sampling; the code still has **no constant-time guarantee**.
所有固定私钥标量 / Nonce 都是公开合成测试值，不是可用凭据。不请求用户密钥；即使部分函数用随机数说明采样，代码仍无恒定时间保证。

Affine branches, Python integer operations and S-box lookup tables can leak. This is not a production cryptographic API or a certified product. Study the equations here; use a maintained and appropriately reviewed implementation for real secrets.
仿射分支、Python 整数及 S 盒查表可能泄漏；不是生产密码 API 或认证产品。这里用于学习等式，真实秘密应使用维护中且经过适当审查的实现。
