# clevis JWE 格式规范（解密路径）

本文记录 nbde-agent 必须兼容的 clevis `tang` 与 `sss` pin 格式。依据：

- clevis 22 源码：`src/pins/tang/clevis-decrypt-tang`、`src/pins/tang/clevis-encrypt-tang`、
  `src/pins/sss/{sss.c,clevis-encrypt-sss.c,clevis-decrypt-sss.c}`
- jose 源码：`lib/openssl/ecmr.c`、`lib/openssl/ecdhes.c`
- tang 15
- `tests/vectors/` 中由上述官方工具生成并经 `clevis decrypt` 验证的测试向量

关键词按 BCP 14（RFC 2119、RFC 8174）解释。

## 1. 外层容器

所有 clevis JWE 均为 **compact serialization**，五段以 `.` 分隔：

| 段 | 内容 | 实测长度（base64url） |
|---|---|---|
| 1 | protected header（JSON） | 视 pin 而定 |
| 2 | encrypted key | **恒为空**（`dir` 与 `ECDH-ES` 均为直接密钥协商） |
| 3 | IV | 16（12 字节） |
| 4 | ciphertext | 视明文长度 |
| 5 | tag | 22（16 字节） |

- `enc` MUST 为 `A256GCM`；其他值 MUST 拒绝。
- AES-256-GCM 的 AAD MUST 为第 1 段的 **ASCII 原文**（未解码的 base64url 字符串）。
- 第 2 段非空 MUST 拒绝。
- header 中出现 `zip` 或 `crit` MUST 拒绝（clevis 不产生）。
- pin 类型由 `clevis.pin` 决定；仅 `tang` 与 `sss` 受支持。

## 2. tang pin

### 2.1 header

```json
{
  "alg": "ECDH-ES",
  "enc": "A256GCM",
  "kid": "<服务端交换密钥的 JWK 指纹，S256>",
  "epk": { "kty": "EC", "crv": "P-521", "x": "…", "y": "…" },
  "clevis": {
    "pin": "tang",
    "tang": {
      "url": "http://host:port[/path]",
      "adv": { "keys": [ <签名密钥 ES512/verify>, <交换密钥 ECMR/deriveKey>, … ] }
    }
  }
}
```

- `alg` MUST 为 `ECDH-ES`。
- `epk` 是绑定时 jose 生成的临时公钥，即设计文档中的 **C**。
- `clevis.tang.adv` 是 **JWKS 对象**（adv JWS 的 payload），不是 JWS；JWE 中不保存 `thp`。
- `url` 是 tang 基址；请求地址为 `{url}/rec/{kid}`（clevis 直接字符串拼接，路径前缀可用）。

### 2.2 选取服务端交换密钥 S

在 `clevis.tang.adv.keys` 中寻找 RFC 7638 JWK 指纹（SHA-256，base64url，无填充）等于 `kid` 的密钥。

- 指纹输入 MUST 为 `{"crv":…,"kty":"EC","x":…,"y":…}` 按字典序、无空白的 JSON。
- clevis 还接受 SHA-1 指纹（长度 27）作为兼容；nbde-agent MUST 只接受 SHA-256（长度 43），
  遇到较短 `kid` MUST 拒绝。tang 15 默认生成 SHA-256。
- 找不到匹配 MUST 拒绝。
- 选中的密钥 `crv` MUST 与 `epk.crv` 相同，且 MUST 为 `P-521`。

adv 的签名在解密时**不**校验（clevis 亦不校验）：header 整体受 GCM 的 AAD 保护，篡改会在最终解密失败。

### 2.3 ECMR 运算（jose `ecmr.c`）

jose 的 `exc(lcl, rem)` 语义：

| lcl | rem | 结果 |
|---|---|---|
| 含私钥 d | 任意 | `d · rem` |
| 仅公钥 | 含私钥 | `lcl + rem` |
| 仅公钥 | 仅公钥 | `lcl − rem` |

clevis-decrypt-tang 的步骤与对应数学：

| clevis 步骤 | 数学 |
|---|---|
| `eph = gen(ECMR, crv)` | 随机标量 e，E = e·G |
| `xfr = exc(clt, eph)` | X = C + E |
| `POST {url}/rec/{kid}`，body = X 的公钥 JWK | 服务端返回 Y = s·X |
| `tmp = exc(eph, srv)` | T = e·S |
| `jwk = exc(rep, tmp)` | Z = Y − T = s·C |

- 请求体 MUST 为 `{"kty":"EC","crv":"P-521","x":…,"y":…}`，`Content-Type: application/jwk+json`。
  clevis 发送的 JWK 还带 `"alg":"ECMR"`；gate MUST 接受两种形式。
- 响应 MUST 为 `kty=EC`、`crv` 与请求相同的 JWK，且 MUST 为曲线上的有效点；否则 MUST 拒绝。
- e MUST 每次请求重新生成，MUST 在计算完成后清零。
- X、Y 的任一为单位元（无穷远点）MUST 拒绝。

### 2.4 内容密钥派生（jose `ecdhes.c` `derive`）

Z 被当作"外部交换结果"直接进入 Concat KDF（RFC 7518 §4.6）：

```
K = SHA-256( be32(1) ‖ Zx ‖ be32(len(alg)) ‖ alg ‖ be32(len(apu)) ‖ apu
             ‖ be32(len(apv)) ‖ apv ‖ be32(256) )
```

- `Zx`：Z 的 x 坐标，按 JWK `x` 编码的定长大端字节（P-521 为 66 字节）。
- `alg`：对 `ECDH-ES` 直接协商取 **`enc` 的值**，即 ASCII `A256GCM`。
- `apu`、`apv`：取 header 中同名字段的 base64url 解码值；缺省为空串（长度前缀仍写 0）。
  clevis 不产生这两个字段。
- 输出 32 字节，单轮 SHA-256 即足够。
- K 即 AES-256-GCM 内容密钥，用于解密 §1 的密文。

## 3. sss pin

### 3.1 header

```json
{
  "alg": "dir",
  "enc": "A256GCM",
  "clevis": {
    "pin": "sss",
    "sss": {
      "t": 2,
      "p": "<素数 p，32 字节大端，base64url>",
      "jwe": [ "<子 JWE compact 字符串>", … ]
    }
  }
}
```

- `alg` MUST 为 `dir`。
- `t` MUST 满足 `1 ≤ t ≤ len(jwe)`；否则 MUST 拒绝。
- `p` 由 `BN_generate_prime_ex(256 bit, safe=1)` 生成；解码后长度 L MUST 为 32。
  nbde-agent 不验证 p 的素性，但 MUST 拒绝偶数、≤ 2 或长度不符的 p。
- `jwe` 的每个元素 MUST 为字符串，内容为任意受支持 pin 的 compact JWE（可再次为 `sss`）。
- 嵌套深度 MUST ≤ 4（本项目约束；clevis 无限制）。

### 3.2 share

每个子 JWE 解密得到 **2L = 64 字节**：`x ‖ y`，各 L 字节大端。

- 子 JWE 明文长度不等于 2L MUST 视为该子 pin 失败。
- x MUST 满足 `0 < x < p`，y MUST 满足 `y < p`；否则视为失败。
- 参与组合的 share 中 x 重复 MUST 拒绝（插值分母为零）。

### 3.3 组合（拉格朗日插值求常数项）

取任意 t 个有效 share `(x_i, y_i)`：

```
k = Σ_i  y_i · Π_{j≠i} (0 − x_j) · (x_i − x_j)^{-1}   (mod p)
```

- k 按 L 字节大端编码（左侧补零），作为外层 JWE 的 AES-256-GCM 内容密钥（`alg=dir`，直接使用）。
- 多于 t 个 share 可用时，取先完成的 t 个（与 clevis 一致）。
- 组合中间值 MUST 存放于可清零的类型中。

### 3.4 并发语义（clevis-decrypt-sss）

clevis 以 epoll **并发**解密全部子 JWE，满足 t 个即停止并终止其余子进程；
剩余可能成功的子 pin 数 < t 时立即失败。nbde-agent MUST 采用相同语义。

## 4. 测试向量

`tests/vectors/` 由 `generate.sh` 使用官方 clevis 22 / tang 15 / jose 生成：

| 文件 | 结构 |
|---|---|
| `tang.jwe` | 单个 tang pin（tang-a） |
| `sss.jwe` | sss t=2，tang-a + tang-b |
| `nested-sss.jwe` | sss t=2，子 pin 为两个 sss t=1，各含一个 tang |
| `plaintext` | 三者共同的明文（64 字节） |
| `tang-a/`、`tang-b/` | **仅供测试**的 tang 密钥目录（含私钥） |

测试 MUST 以 `tang-*/` 中交换私钥 s 在进程内模拟 `/rec`（Y = s·X），无需运行 tangd。

## 5. 已据此解决的设计待验证项

| 项 | 结论 |
|---|---|
| sss 子 pin 是否并行 | 是（epoll 并发，满足 t 即停止） |
| tang URL 是否支持路径前缀 | 是（`$url/adv/$thp`、`$url/rec/$kid` 字符串拼接） |
| 解密时是否请求 `/adv` | 否；使用 JWE header 内嵌的 JWKS |
| P-521、A256GCM、SHA-256 指纹 | tang 15 + clevis 22 的默认值，已由向量确认 |
