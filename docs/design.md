# unlock-gate：eihort 网络绑定解锁方案（草案）

状态：草案，尚未实施。本文所有"待验证"项必须在 VM 测试中确认后才能进入实施。

## 0. 约定

本文中的关键词 "MUST"、"MUST NOT"、"REQUIRED"、"SHALL"、"SHALL NOT"、"SHOULD"、
"SHOULD NOT"、"RECOMMENDED"、"NOT RECOMMENDED"、"MAY" 和 "OPTIONAL" 按
BCP 14（[RFC 2119]、[RFC 8174]）解释，且仅在全部大写时具有该含义。

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174

## 1. 目标与范围

### 1.1 目标

1. eihort 在**断电、关机或被搬离**后，其磁盘内容不得仅凭 eihort 本身被解密，
   包括原机开机的情形。
2. 计划内重启 SHOULD 无需人工介入即可完成解锁。
3. 计划外开机（断电、看门狗复位、内核崩溃、机器被他人启动）MUST 需要用户显式批准。
4. 任何单一远端节点的失陷 MUST NOT 足以解密 eihort。
5. 所有网络解锁路径失效时，MUST 存在不依赖网络的人工回退路径。

### 1.2 威胁模型

主要对手为执法机构的取证行为：扣押硬件、离线镜像磁盘、原机开机、在本地网络内操作，
并可能对境内或受其影响的服务商施加法律压力。

### 1.3 不在范围内

以下情形本方案不提供保护，需由其他措施处理（见 §10.2）：

- 运行中被现场取证（密钥已在内存）。
- 对用户本人的强制。
- 同时控制 ≥2 台 gate 节点并取得 eihort 磁盘。
- 无 TPM 远程证明时，Secure Boot 被重置后的 evil maid。

## 2. 术语

| 术语 | 含义 |
|---|---|
| client | 被保护、需要解锁的主机。当前唯一 client 为 eihort |
| gate | 运行 unlock-gate 的远端节点，同时充当 Tang 服务器与策略层 |
| nbde-agent | client 在 initrd 中运行的 Rust 解锁客户端（§7） |
| P | LUKS keyslot 0 的随机口令，64 字节 |
| JWE | 官方 clevis 生成的、加密了 P 的 JWE 文件 |
| share | sss 中由某个 gate 的 Tang 交换密钥保护的一份 |
| arm | 运行中的 client 签发的、一次性的计划内重启授权 |
| approval | 用户经 SSH 在 gate 上下达的、一次性的时间窗授权 |
| release | gate 对一次 `/rec` 请求执行 ECMR 并返回结果 |
| budget | gate 上某 client 当前可用的 release 来源（arm 或 approval） |

## 3. 架构

### 3.1 节点

| 角色 | 主机 | 公网地址 | mesh 地址 |
|---|---|---|---|
| client | eihort | NAT 后（家庭宽带） | `fdcc::3` |
| gate `sgp` | yidhra | `216.195.195.184`, `2a0f:1cc6:b225:0:c744:d4a4:9364:2971` | `fdcc::4` |
| gate `nrt` | abhoth | `154.31.114.112`, `2403:18c0:1000:13a:343b:65ff:fe1b:7a0f` | `fdcc::5` |
| gate `tyo` | nodens | `193.123.164.59`, `2603:c021:8025:648e:0:dc5b:117f:5225` | `fdcc::8` |

- 门限 MUST 为 2-of-3，以 gate（而非地址）计数。
- azasos（HKG）MUST NOT 持有 share。理由：在本威胁模型下其失陷成本最低；纳入 2-of-4
  会降低安全性，纳入 3-of-4 不提升安全性且降低可用性。
- gate 节点 SHOULD 分属不同供应商与司法辖区。

### 3.2 组件

```
eihort initrd
  systemd-cryptsetup@crypt-root ── keyfile = /run/nbde/key.sock（AF_UNIX）
                                        │
  nbde-agent（Rust，Type=notify）◄───────┘
    sss t=2 → sss t=1 ×3 → tang
      └─ HTTP 直连 :7500 ──────────────────► gate ×3
                                               unlock-gate（Go，内嵌 tang.go）
                                                 公网 :7500   /c/{client}/adv, /c/{client}/rec/{kid}
                                                 mesh :7501   /v1/heartbeat, /v1/arm, /v1/disarm
                                                 ctl.sock     approve / deny / disarm / status
                                                 通知          Telegram Bot
运行中的 eihort
  clevis（仅绑定）、unlock-agent（心跳）、eihort-reboot（arm）──── mesh ────► gate ×3
```

### 3.3 分层职责

| 层 | 组件 | 职责 |
|---|---|---|
| 存储 | LUKS2（nvme）、`/persist/keys/*` | 数据加密 |
| 封装 | 官方 clevis（绑定）、nbde-agent（解密） | P ↔ JWE；sss 门限；tang pin |
| 交换 | Tang 协议（ECMR），tang.go | 盲化密钥交换；服务端不持有、不可见 share |
| 策略 | unlock-gate | 决定是否 release |
| 交付 | systemd-cryptsetup 的 AF_UNIX keyfile | 将 P 交给 LUKS |
| 传输 | 纯 HTTP / mesh | 仅可达性；**安全性 MUST NOT 依赖传输层** |

## 4. 密钥层级

```
recovery passphrase（离线纸质）─► LUKS keyslot 1 ─┐
                                                   ├─► LUKS volume key ─► nvme（/persist /var /nix）
P（64 字节随机）───────────────► LUKS keyslot 0 ─┘                         └─► /persist/keys/pool0-* ─► pool0
  ▲
  └─ JWE：CEK 经 sss 拆分；每份 share 由一个 gate 的 Tang 交换密钥保护
```

- P MUST 由 CSPRNG 生成，长度 MUST 为 64 字节，MUST NOT 以任何形式持久化于明文介质。
- recovery passphrase MUST 使用 argon2id keyslot，MUST 离线保存，MUST NOT 存储于任何联网设备。
- pool0 的密钥 MUST 存放于 `/persist/keys/`，权限 MUST 为 `root:root 0400`。
- LUKS header SHOULD 离线备份。

## 5. 绑定（官方 clevis）

绑定 MUST 使用官方 clevis，使 JWE 格式由参考实现产生。nbde-agent MUST NOT 实现加密或绑定。

### 5.1 pin 结构

```json
{
  "t": 2,
  "pins": { "sss": [
    { "t": 1, "pins": { "tang": [
      { "url": "http://216.195.195.184:7500/c/eihort",                        "thp": "<sgp>" },
      { "url": "http://[2a0f:1cc6:b225:0:c744:d4a4:9364:2971]:7500/c/eihort",  "thp": "<sgp>" } ] } },
    { "t": 1, "pins": { "tang": [
      { "url": "http://154.31.114.112:7500/c/eihort",                         "thp": "<nrt>" },
      { "url": "http://[2403:18c0:1000:13a:343b:65ff:fe1b:7a0f]:7500/c/eihort","thp": "<nrt>" } ] } },
    { "t": 1, "pins": { "tang": [
      { "url": "http://193.123.164.59:7500/c/eihort",                         "thp": "<tyo>" },
      { "url": "http://[2603:c021:8025:648e:0:dc5b:117f:5225]:7500/c/eihort",  "thp": "<tyo>" } ] } }
  ] }
}
```

- 外层 sss MUST 以 gate 为单位计数；同一 gate 的多个地址 MUST 置于同一内层 `t=1` sss 中。
  平铺多个地址到外层 MUST NOT 使用，否则单个 gate 即可满足门限。
- 每个 tang pin MUST 显式指定 `thp`。`thp` MUST 经可信信道（SSH 登录 gate 读取）获得，
  MUST NOT 依赖经公网 HTTP 获取的 adv 进行首次信任。
- URL MUST 使用 IP 字面量，initrd MUST NOT 依赖 DNS。

### 5.2 绑定流程（client 运行中执行）

1. 在每个 gate 上读取该 client 专属 Tang 签名密钥的 `thp`。
2. 生成 P：`head -c 64 /dev/urandom`，仅存放于 ramfs/tmpfs。
3. `clevis encrypt sss '<§5.1 配置>' < P > /persist/keys/crypt-root.jwe`。
4. `cryptsetup luksAddKey --key-slot 0 <dev>`，以 P 为新口令。
5. 在 ≥2 个 gate 上 `approve` 后执行 `nbde-agent check /persist/keys/crypt-root.jwe`，
   MUST 显示门限满足，且摘要与 `sha256(P)` 前 8 字节一致。
6. 销毁 P 的临时副本。
7. 重新安装 bootloader，使 JWE 进入 initrd（§7.6）。

### 5.3 JWE 的保密性

JWE 单独不能解密，但持有者可在 budget 有效期内抢先发起 `/rec`，从而取得 share
或耗尽 arm。因此：

- JWE MUST NOT 进入公开仓库或 Nix store。
- JWE MUST 以运行时路径（字符串）经 `boot.initrd.secrets` 进入 initrd。
- JWE 出现在 ESP 上是可接受的；能读取 ESP 的对手已具备物理接触能力。

## 6. unlock-gate 规范

### 6.1 配置（Nix 声明，非秘密）

```nix
services.unlock-gate = {
  enable = true;
  gateId = "sgp";
  publicListen = [ "216.195.195.184:7500" "[2a0f:…:2971]:7500" ];
  meshListen = [ "[fdcc::4]:7501" ];
  clients.eihort = {
    agentPublicKey = "<Ed25519 公钥，base64url>";
    allowFrom = [ ];            # OPTIONAL，CIDR 列表；空表示不限制
  };
  notify.telegram.tokenFile = config.vaultix.secrets.unlock-gate-tg.path;
  notify.telegram.chatId = "<chat id>";
};
```

- 每个 client MUST 拥有专属的 Tang 密钥集，存放于 `/var/lib/unlock-gate/<client>/`。
- gate MUST 支持多个 client，并 MUST 以 URL 中的 `{client}` 严格隔离密钥与策略。

### 6.2 状态

| 状态 | 存储 | 生命周期 |
|---|---|---|
| Tang 密钥 | 磁盘 `/var/lib/unlock-gate/<client>/`，`0700` | 持久 |
| client 公钥、策略 | Nix 配置 | 持久 |
| arm、approval、nonce 缓存、心跳、尝试记录 | **内存** | 进程生命周期 |
| 审计日志 | journald | 按系统保留策略 |

- arm 与 approval MUST 仅存于内存。gate 进程重启 MUST 导致所有 budget 失效（fail closed）。

### 6.3 公网接口（Tang 兼容）

监听：`publicListen`，纯 HTTP。官方 clevis（绑定与互通测试）与 nbde-agent 均使用此接口。

| 方法 | 路径 | 行为 |
|---|---|---|
| GET | `/c/{client}/adv` | 返回该 client 的 adv（JWS） |
| GET | `/c/{client}/adv/{thp}` | 返回以指定签名密钥签名的 adv |
| POST | `/c/{client}/rec/{kid}` | §6.6 决策；200 + JWK，或 403 |

- 未知 `{client}` 或 `{kid}` MUST 返回 404。
- 403 响应体 SHOULD 为 `{"error":"not_authorized"}`，MUST NOT 透露其他信息。
- 请求体 MUST 限制为 8 KiB；读、写、空闲超时 SHOULD 分别为 10 s、10 s、30 s。
- gate MUST 按来源 IP 限速，RECOMMENDED 值为每分钟 30 次 `/rec`。
- gate MUST 立即作出决策，MUST NOT 对 `/rec` 实施长轮询。

### 6.4 mesh 接口（供运行中的 client 使用）

监听：`meshListen`。防火墙 MUST 仅允许 mesh 接口访问该端口。

| 方法 | 路径 | 请求体 | 响应 |
|---|---|---|---|
| POST | `/v1/heartbeat` | JWS（§6.5，`typ=heartbeat`） | 204 / 401 / 409 |
| POST | `/v1/arm` | JWS（`typ=arm`） | 204 / 401 / 409 |
| POST | `/v1/disarm` | JWS（`typ=disarm`） | 204 / 401 / 409 |

- 401：签名、`aud`、`client` 或 `typ` 校验失败。
- 409：nonce 重复、`seq` 回退或 `iat` 超出容差。

### 6.5 签名消息

格式：JWS Compact Serialization，`alg` MUST 为 `EdDSA`（Ed25519），`typ` header MUST 为
`unlock-gate+jws`。

| 字段 | 类型 | 适用 | 要求 |
|---|---|---|---|
| `v` | int | 全部 | MUST 为 1 |
| `typ` | string | 全部 | `heartbeat` / `arm` / `disarm` |
| `aud` | string | 全部 | MUST 等于接收方 `gateId` |
| `client` | string | 全部 | MUST 为已配置的 client |
| `boot_id` | string | 全部 | client 的 `/proc/sys/kernel/random/boot_id` |
| `iat` | int | 全部 | Unix 秒；gate MUST 拒绝与本地时钟相差超过 120 s 的消息 |
| `seq` | uint64 | heartbeat | 同一 `boot_id` 内 MUST 严格递增 |
| `nonce` | string | arm、disarm | 16 字节 base64url；gate MUST 在 240 s 内拒绝重复 nonce |
| `ttl` | int | arm | 秒；MUST ≤ 600 |

- arm 的到期时间 MUST 以 gate 接收时刻加 `min(ttl, 600)` 计算，MUST NOT 以 client 时钟计算。
- 每个 client 同时 MUST 最多存在一个有效 arm；新 arm MUST 替换旧 arm。
- 心跳 MUST NOT 影响任何 release 决策，仅用于告警。arm MUST NOT 以心跳新鲜度为前提。

### 6.6 `/rec` 决策

```
收到 POST /c/{client}/rec/{kid}
  1. 校验 client、kid、请求体格式；失败 → 404 / 400
  2. 若 allowFrom 非空且来源地址不匹配 → 403，记录
  3. 若存在有效 arm → release，arm 作废，原因 "arm"
  4. 否则若存在有效 approval，且（未设 --from 或来源匹配）→ release，approval 作废，原因 "approval"
  5. 否则若处于宽限期且来源与宽限期源地址相同 → release，原因 "grace"
  6. 否则 → 403，记录尝试，按 §6.8 通知
```

- 一次 arm 或 approval MUST 只产生一次计入 budget 的 release，与请求来自 IPv4 还是 IPv6 无关。
- release 后 gate MAY 开启宽限期：60 s 内对**同一来源地址**的 `/rec` 继续 release，
  以容忍响应在传输中丢失。宽限期 MUST NOT 跨越来源地址。
- 每次 release 与拒绝 MUST 写入审计日志：时间、client、kid、来源地址、结果、原因。

### 6.7 管理接口

- 套接字：`/run/unlock-gate/ctl.sock`，`0600 root:root`；gate MUST 以 `SO_PEERCRED`
  校验对端 uid 为 0。
- 协议：每行一个 JSON 请求与响应。CLI：`unlock-gate ctl <command>`。

| 命令 | 作用 |
|---|---|
| `status [--client C]` | 心跳（最后时间、`boot_id`、`seq`）、arm、approval、最近 20 次尝试 |
| `approve --client C [--window 300] [--from CIDR]` | 创建 approval；`window` MUST ≤ 900 s |
| `deny --client C` | 清除 approval 与宽限期 |
| `disarm --client C` | 清除 arm |

- approval MUST 只能经 ctl 创建。gate MUST NOT 提供任何经网络创建 approval 的接口。

### 6.8 通知

| 事件 | 触发条件 |
|---|---|
| `heartbeat_lost` | 超过 180 s 未收到有效心跳 |
| `heartbeat_resumed` | 丢失后恢复，附新旧 `boot_id` |
| `unlock_denied` | 一次 403；同一 client 10 分钟内 MUST 至多通知一次 |
| `unlock_released` | 每次计入 budget 的 release，附原因 |
| `arm_received` | 收到有效 arm |

- 通知 SHOULD 只包含 gate、client、事件、时间、来源地址；MUST NOT 包含 JWE 或任何秘密。

### 6.9 进程加固

- gate SHOULD 以非 root 运行，通过 `StateDirectory` 访问 Tang 密钥，`ctl.sock` 经
  `RuntimeDirectory` 提供。若使用 `DynamicUser`，ctl 的对端校验 MUST 相应调整（待定）。
- gate SHOULD 启用 `ProtectSystem=strict`、`PrivateTmp`、`NoNewPrivileges`、
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`、`MemoryDenyWriteExecute`。

## 7. client（eihort）规范

### 7.1 运行时组件

| 组件 | 行为 |
|---|---|
| `unlock-agent.timer/service` | 每 60 s 经 mesh 向全部 gate 发送 heartbeat；失败仅记录日志 |
| `eihort-reboot` | 向全部 gate 发送 arm；**成功数 ≥ 2** 时执行 `systemctl reboot`，否则 MUST 中止并以非零退出 |
| agent 私钥 | `/persist/keys/unlock-agent.ed25519`，`root:root 0400`；公钥写入 gate 配置 |

- arm MUST 仅由用户显式执行 `eihort-reboot` 产生。arm MUST NOT 由 shutdown/reboot 钩子、
  UPS 事件、电源键、看门狗或任何自动化流程产生。
- `eihort-reboot` MUST 要求 root 权限。

### 7.2 nbde-agent：接口

单一二进制，两种模式：

```
nbde-agent [--config <path>]     # 守护模式，默认配置 /etc/nbde/agent.toml
nbde-agent check <jwe>           # 诊断模式
```

- 参数解析 MUST 仅使用 `std::env::args`，MUST NOT 引入参数解析库。
- 守护模式由 systemd 以 `Type=notify` 启动，自行绑定监听套接字并在绑定后发送 `READY=1`（§7.5）。
  不使用 socket 激活：将 `LISTEN_FDS` 的整数 fd 转为套接字需要 `unsafe`，与 §8.1 冲突。
- `check` 模式执行完整解锁流程（§7.4），输出每个 pin 与地址的结果及门限判定，
  并输出 `sha256(P)` 的前 8 字节。`check` MUST NOT 输出 P、CEK、share 或 Z。
- nbde-agent MUST NOT 提供 encrypt、bind、decrypt-to-stdout 或本地控制套接字。

### 7.3 nbde-agent：配置

```toml
attempt_timeout_secs = 30
retry_interval_secs  = 10
deadline_secs        = 900
socket               = "/run/nbde/key.sock"   # 默认值
console              = true                   # 写 /dev/console；默认 true

[[volume]]
name = "crypt-root"
jwe  = "/etc/nbde/crypt-root.jwe"
```

- 配置 MUST NOT 包含秘密。所有 gate 地址与 `thp` 来自 JWE 本身。
- 未知字段 MUST 导致启动失败。

### 7.4 nbde-agent：解密行为

**支持的 JWE 子集**

- 仅支持 clevis 的 `sss` 与 `tang` pin；其他 pin（`tpm2`、`null`、`pkcs11` 等）MUST 被拒绝。
- sss 嵌套深度 MUST ≤ 4；JWE 总大小 MUST ≤ 64 KiB。
- 格式 MUST 与官方 clevis 输出逐字节兼容，以官方工具生成的测试向量为准（§11）。

**tang pin**

1. 从 JWE header 内嵌的 adv 中按 `kid` 取得交换公钥 S。解密时 MUST NOT 请求 `/adv`。
2. 生成临时标量 e，发送 X = epk + e·G 至 `{url}/rec/{kid}`。
3. 收到 Y 后计算 Z = Y − e·S，按 RFC 7518 §4.6（ECDH-ES Concat KDF）派生内容密钥并解密。
4. 曲线与算法以 JWE header 为准；实现 MUST 拒绝 header 未声明或不支持的算法。

**sss pin**

- 子 pin MUST 并发执行；成功数达到 `t` 时 MUST 立即组合并放弃其余请求。
- 失败数超过 `n − t` 时，本轮 MUST 判定失败并进入重试。
- 恶意参数（`t = 0`、`t > n`、重复 share 坐标、超出模数的值）MUST 被拒绝。

**HTTP**

- 仅 HTTP/1.1 明文；MUST NOT 跟随重定向；MUST NOT 读取代理环境变量；
  响应体 MUST 限制为 8 KiB；单次请求超时为 `attempt_timeout_secs`。
- 200 以外的状态 MUST 视为该 pin 本轮失败；403 MUST 记录为 `denied`。

**重试**

- 每轮失败后等待 `retry_interval_secs` 重试，直至成功或达到 `deadline_secs`。
- 每轮 MUST 生成新的 e。

### 7.5 nbde-agent：AF_UNIX 交付

systemd-cryptsetup 将 keyfile 路径识别为 AF_UNIX 流套接字时，会连接并读取至 EOF；
其客户端套接字绑定于抽象地址 `\0<random>/cryptsetup/<volume>`。

- nbde-agent MUST 以 `SO_PEERCRED` 校验对端 uid 为 0。
- nbde-agent MUST 解析对端抽象地址中的 `<volume>`，只向配置中同名的卷交付；
  地址格式不符或卷名未知时 MUST 立即关闭连接且不写入任何数据。
- 若连接到达时 P 尚未就绪，nbde-agent SHOULD 保持连接直至 P 就绪或到达 deadline。
- 交付内容 MUST 为 P 的原始字节，无换行；写入完成后 MUST 关闭连接并立即清零 P。
- 到达 deadline 时，nbde-agent MUST 关闭所有挂起连接且不写入数据，然后以失败退出，
  使 systemd-cryptsetup 进入口令提示。
- nbde-agent SHOULD 随 initrd 启动即开始网络解锁，而非等待首个连接，以重叠网络等待时间。
- 套接字文件 MUST 为 `0600`，所在目录 MUST 为 `0700`；启动时 MAY 替换遗留的套接字文件，
  MUST NOT 替换非套接字文件。进程退出时 SHOULD 删除套接字文件。
- 每个卷的 P MUST 只交付一次；交付后的同卷请求 MUST 被拒绝（进入口令提示）。

### 7.6 initrd 集成

```nix
boot.initrd = {
  systemd.enable = true;
  systemd.network.enable = true;            # eno1：IPv4 DHCP + IPv6 SLAAC
  secrets."/etc/nbde/crypt-root.jwe" = "/persist/keys/crypt-root.jwe";   # 字符串路径
  luks.devices.crypt-root = {
    device = "/dev/disk/by-uuid/<uuid>";
    keyFile = "/run/nbde/key.sock";
    keyFileTimeout = 900;                   # 行为待验证（§12.1）
  };
  systemd.services.nbde-agent = {
    # 尽早启动；网络未就绪由 agent 自身重试处理，不排在 wait-online 之后。
    # Type=notify：绑定套接字后才视为启动完成，cryptsetup 排在其后。
    wantedBy = [ "systemd-cryptsetup@crypt\\x2droot.service" ];
    before = [ "systemd-cryptsetup@crypt\\x2droot.service" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "notify";
      NotifyAccess = "main";
      ExecStart = "${pkgs.nbde-agent}/bin/nbde-agent";
    };
  };
  systemd.storePaths = [ "${pkgs.nbde-agent}/bin/nbde-agent" ];
  network.ssh.enable = true;                # 回退；仅内网可达
};
```

- initrd MUST NOT 包含 clevis、jose、curl、DNS 依赖、CA 证书、代理凭据或 mesh 凭据。
- initrd 的 sshd MUST 仅接受用户公钥，SHOULD 仅在内网可达。

### 7.7 回退

| 操作 | 方法 |
|---|---|
| 放弃网络解锁 | 经 initrd ssh：`systemctl stop nbde-agent.service` |
| 输入 recovery passphrase | `systemd-tty-ask-password-agent`（initrd ssh）或 BMC 控制台 |

### 7.8 前置条件

以下条件 MUST 在启用本方案前满足：

1. nvme root 分区为 LUKS2；`/persist`、`/var`、`/nix` 均位于其上。
2. 两个 swap（nvme 分区与 SATA DOM）MUST 使用每次启动随机密钥；`resumeDevice` MUST 移除。
3. BIOS 管理员口令已设置；Secure Boot 处于 user mode，setup mode 已关闭。
4. BMC 已隔离网络并更换默认凭据。
5. recovery passphrase 已离线保存并实测可用。

## 8. nbde-agent 实现约束

### 8.1 通用

- 实现语言 MUST 为 Rust；crate MUST 声明 `#![forbid(unsafe_code)]`，系统调用经 `rustix` 的安全封装。
- 实现 MUST NOT 使用 `std::process::Command` 或以任何方式执行外部程序。
- 实现 MUST 为同步实现（标准线程），MUST NOT 引入异步运行时。
- 二进制 SHOULD 静态链接。

### 8.2 内存卫生

- 进程启动时 MUST 依次执行：`mlockall(MCL_CURRENT | MCL_FUTURE)`、`prctl(PR_SET_DUMPABLE, 0)`、
  `setrlimit(RLIMIT_CORE, 0)`。任一失败 MUST 终止启动。
- P、CEK、share、Z、临时标量 e MUST 存放于 `secrecy` 的秘密类型或实现 `ZeroizeOnDrop` 的类型中。
- 秘密缓冲区 SHOULD 预分配固定容量，避免扩容留下未清零副本。
- `memsafe` 等逐页 `mprotect` 方案 NOT RECOMMENDED：其无法覆盖依赖库内部副本，
  且进程级 `mlockall` 已覆盖换出风险。

### 8.3 错误处理

- 错误类型 MUST 使用 `snafu` 定义，按模块划分，并附带上下文（卷名、gate URL、阶段）。
- 错误的 `Display`/`Debug` MUST NOT 包含秘密，MUST NOT 回显 HTTP 响应体。
- 面向用户的状态 MUST 经三个渠道输出：`/dev/console`、`sd_notify` 的 `STATUS=`、journal。

### 8.4 依赖

| 用途 | crate |
|---|---|
| 椭圆曲线 | `p521`（`arithmetic`、`jwk`） |
| 对称加密与 KDF | `aes-gcm`、`sha2` |
| sss 模运算 | 大整数库，待 §12.1 第 1 项确认格式后选定 |
| 秘密与清零 | `secrecy`、`zeroize` |
| 错误 | `snafu` |
| 序列化 | `serde`、`serde_json`、`toml`、`base64ct` |
| 系统调用 | `rustix` |
| HTTP | `ureq`（关闭默认特性，不启用 TLS）或自行实现的最小 HTTP/1.1 客户端 |

### 8.5 模块与规模估算

| 模块 | 职责 | 估算行数 |
|---|---|---|
| `jose` | compact JWE、Concat KDF、A256GCM、JWK | 200–300 |
| `pin::tang` | ECMR 盲化交换 | 150–200 |
| `pin::sss` | 门限组合、递归分派、并发 | 200–250 |
| `http` | 最小 HTTP 客户端 | 50–150 |
| `sink` | AF_UNIX 交付、对端校验 | 120–180 |
| `config` | TOML 配置 | 80–120 |
| `agent` | 状态机、重试、deadline、多卷 | 200–300 |
| `ui` | console、sd_notify、journal | 60–100 |
| `secret` | 进程加固、秘密类型 | 40–60 |
| `main`、错误 | | 100–150 |
| **合计** | | **约 1,200–1,800**，其中安全关键约 700–1,000 |

## 9. 交互流程

### 9.1 计划内重启

```
用户: sudo eihort-reboot
  unlock-agent ─ POST /v1/arm ×3（mesh）─► 成功数 ≥ 2 ? reboot : 中止
initrd: nbde-agent ─ POST /c/eihort/rec/{kid}（HTTP，并发）─► 有 arm → 200，arm 作废
        凑足 2 份 → P → 经 key.sock 交给 systemd-cryptsetup → 解锁
gate: 通知 unlock_released(arm)
```

### 9.2 计划外开机

```
initrd: nbde-agent ─ POST /rec ─► 403（gate 记录并通知 unlock_denied）
        控制台：sgp denied / nrt denied / tyo unreachable；每 10 s 重试
用户: 收到通知 → ssh 至 gate → unlock-gate ctl status 核对来源与时间
      → unlock-gate ctl approve --client eihort（至少 2 个 gate）
initrd: 下一轮 → 200 ×2 → 解锁
```

用户 MUST 仅在能解释该次开机时批准；来源地址不符合预期时 MUST NOT 批准。

### 9.3 失败

```
deadline 内未凑足 2 份 → nbde-agent 关闭连接并退出 → 口令提示
  → 用户经 initrd ssh 或 BMC 输入 recovery passphrase
```

## 10. 运维与安全

### 10.1 运维

| 操作 | 步骤 |
|---|---|
| Tang 密钥轮换 | 生成新密钥 → 旧密钥从 adv 隐藏但仍接受 `/rec` → client 重新执行 §5.2 → 删除旧密钥 |
| gate 公网 IP 变更 | client 运行中重新执行 §5.2 |
| gate 丢失 Tang 密钥 | client 运行中：以新 `thp` 重新执行 §5.2；client 停机中：剩余 2 个 gate 仍可解锁 |
| 疑似 gate 失陷 | client 运行中立即：替换该 gate 的 pin、生成新 P、`luksKillSlot` 旧 slot 0 |
| 新增 gate | 重新执行 §5.2；门限调整 MUST 重新评估 §3.1 |

### 10.2 秘密清单与残余风险

| 秘密 | 位置 | 单独泄露的后果 |
|---|---|---|
| LUKS volume key | header（被包裹）；运行时内核内存 | 直接解密 |
| recovery passphrase | 离线纸质 | 直接解密 |
| P | JWE 内；解锁时短暂位于 nbde-agent 内存 | 直接解密 |
| JWE | ESP（initrd） | 无；但可在 budget 期内抢占 release |
| Tang 私钥 | 各 gate 磁盘 | 无；需另一 gate 与 JWE |
| agent 私钥 | `/persist`（FDE 内） | 可签发 arm；仅在 client 运行时可得 |
| gate ctl 访问（SSH root） | 用户的 SSH 密钥 | 可创建 approval；仍需 JWE |
| Telegram token | gate（vaultix） | 可伪造或拦截通知 |

取得 P 的最小条件：JWE，加上以下之一：(a) ≥2 个 gate 的 Tang 私钥或 ctl 访问；
(b) 有效 arm 或 approval 期间抢先请求。

| 残余风险 | 缓解 |
|---|---|
| 运行中被取证 | 无自动登录；`intel_iommu=on`；usbguard；机箱入侵检测；BMC 隔离 |
| evil maid（Secure Boot 被重置后替换 initrd） | BIOS 口令；仅批准可解释的开机；后续 MAY 引入 TPM quote |
| ≥2 gate 失陷 + 磁盘 | 分散供应商与辖区；监控 gate 完整性 |
| approval 窗口抢占 | 窗口短且一次性；MAY 使用 `--from` |
| 自研客户端的实现缺陷 | 仅实现解密路径；互通与攻击测试为合并前提（§11） |

### 10.3 隐私

- 公网 HTTP 暴露：client 开机时刻、目标 gate 地址、恒定的 `kid`（可关联多次开机）。
  盲化后的 JWK 不泄露信息；主动篡改仅导致解锁失败。
- 心跳与 arm 经 mesh 传输，不在公网暴露。
- Telegram 可见通知内容，故 §6.8 要求最小化。

## 11. 测试计划

以下测试 MUST 在合并前全部通过。

| 类别 | 用例 |
|---|---|
| 格式互通 | 以官方 clevis + tang 生成测试向量：单 tang、sss、嵌套 sss；nbde-agent MUST 全部正确解密 |
| 服务端互通 | 官方 clevis 对 unlock-gate 的 bind/decrypt；`/c/{client}` 路径前缀 |
| 正常流程 | arm 自动解锁；无 arm 时 403 → approve → 解锁 |
| 门限 | 1 个 gate 可达时失败；2 个时成功；同一 gate 的 IPv4 与 IPv6 不得凑成 2 份 |
| budget | arm 一次性；approval 一次性；宽限期仅同源；gate 重启后 budget 失效 |
| 签名消息 | 错误 `aud`/`client`、重复 nonce、`seq` 回退、`iat` 越界、`ttl` > 600 |
| 解析攻击 | 截断 JWE、超大 JWE、未知 pin、嵌套过深、`t=0`、`t>n`、重复坐标、超大响应 |
| 密码学篡改 | 修改 `y` → 解密失败且无泄露；`kid` 不匹配；绑定时 adv 被替换 → `thp` 校验失败 |
| AF_UNIX | 对端 uid 非 0 被拒；卷名不符被拒；P 未就绪时连接被保持；deadline 后关闭并回退 |
| 内存卫生 | `/proc/<pid>/status` 的 `VmLck` 非零；`dumpable` 为 0；`check` 输出不含秘密 |
| initrd | 回退口令提示；`systemctl stop` 中止；switch-root 后 agent 已退出 |
| 网络 | 仅 IPv4、仅 IPv6、gate 端口不可达 |

## 12. 待验证与后续工作

### 12.1 待验证

1. ~~官方 clevis 的 JWE 格式细节~~：已解决，见 nbde 仓库 `docs/clevis-format.md`
   （依据 clevis 22 / jose / tang 15 源码与官方工具生成的测试向量）。
2. ~~clevis tang URL 是否支持路径前缀~~：已解决，支持（`$url/adv/$thp`、`$url/rec/$kid` 字符串拼接）。
3. ~~systemd-cryptsetup 对端抽象地址的确切格式~~：已解决（VM 测试 `vm-cryptsetup-socket`，
   systemd 261.2）。实测为 `\0<16 个小写十六进制字符>/cryptsetup/<volume>`，对端 uid 为 0。
4. P 未就绪时保持连接：**部分解决**。实测 systemd-cryptsetup 阻塞等待（20 s 延迟后成功解锁，
   期间仅一次连接、未出现口令提示）；等待上限与 `keyFileTimeout` 在套接字场景下的语义仍待验证。
5. ~~agent 关闭连接且不写数据时~~：已解决。systemd-cryptsetup 视为密钥错误
   （"Failed to activate with key file … (Key data incorrect?)"），**立即**进入口令提示，
   且不会重新连接套接字；写入错误密钥时行为相同。
6. NixOS systemd initrd 中 `Type=notify` agent 与 `systemd-cryptsetup@` 的单元排序（stage 2 中已由
   `vm-daemon` 验证 notify 就绪、连接保持、deadline 回退与拒绝非法对端）。
7. `boot.initrd.secrets` 字符串路径经 lanzaboote 是否正确进入 initrd 且不进入 Nix store。
8. 从家庭网络（绕过 sing-box）到三台 gate `:7500` 的 IPv4 与 IPv6 实际可达性。

### 12.2 后续工作（不在本草案范围）

- TPM 远程证明：initrd 在 `/rec` 前提交 PCR 7/4 quote，gate 据此拒绝异常启动状态。
  TPM MUST NOT 用于封装 P。
- 审批体验改进（如 WebAuthn）。引入前 MUST 重新评估钓鱼与托管页面篡改风险。
- nvme 原地加密与 pool0 逐盘 LUKS 迁移的操作手册。
