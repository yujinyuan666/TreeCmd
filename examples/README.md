# treecmd 部署样例 · 阅读指南

这个目录里只有一份配置：**`node.yaml`** —— 它是唯一的权威样例，头部有"按角色最简起步"，
正文把全部字段逐条注释（每个字段标了【根/中继/叶】必填性与默认值）。
本页是配套的**部署走查**：目录约定、字段生效时机、报错对照、检查清单。

**建议阅读顺序：本页（三十秒速览）→ `node.yaml` 头部"按角色最简起步" → 需要时查 `node.yaml` 正文对应字段。**

---

## 1. 三十秒速览

**部署形态**：单服务器 · 一个节点一个进程 · 手工放 `node.yaml` 后启动 · **证书由程序签发与续期**
（父给子/其它客户端签发 + 运行期续签；**根节点的自签材料**部署时准备一次）。

**角色不用手写，由配置推导**：没有 `parents[]` 是**根**；有 `parents[]` 且有 `listen` 是**中继**；
有 `parents[]` 但没有 `listen` 是**叶**。三种角色的差别只有 4 个字段
（`node.listen`、`parents[]`、`security.ca_cert_path`、`security.ca_key_path`）——
每个字段归哪个角色，`node.yaml` 里都标着。

**叶子最小可运行配置**（就这 5 行，其余按约定补全）：

```yaml
node:
  id: 0198f0c0-0000-7000-8000-000000000003
parents:
  - id: 0198f0c0-0000-7000-8000-000000000001
    addr: 127.0.0.1:19443
```

---

## 2. 每个节点的目录里该有什么

各项都相对 `data_dir`（默认 = `node.yaml` 所在目录）。

### 启动前必须准备好（程序**绝不生成**）

| 路径 | 内容 | 谁来放 | 叶子 | 中继 | 根 |
|---|---|---|---|---|---|
| `keys/id_ed25519` | 本节点**私钥** | `treecmd-node -genkey` | 必需 | 必需 | 必需 |
| `keys/id_ed25519.pub` | 本节点**公钥** | 同上（成对） | 必需 | 必需 | 必需 |
| `certs/node.crt` | 本节点**身份证书** | 根：自签；其余：**向父入网换取**¹（程序签发） | 必需¹ | 必需¹ | 必需 |
| `certs/node.crt.ca` | 本节点**CA 证书**（给子签发） | 父在入网时一并签发；根由 `init_root.sh` 产出 | — | 必需 | 必需 |
| `keys/ca` | 本节点**CA 私钥**（给子签发）² | `treecmd-node -genkey -with-ca` | — | 必需 | 必需 |
| `trust/*.crt` | **信任锚**（校验父与对端） | 部署时投放（根自签的 CA 证书） | 必需 | 必需 | 可选³ |
| `enroll.token` | **入网许可**（与父端一致，`chmod 600`） | 部署时投放（两边内容必须一致） | 需要入网时 | 需要入网时 | — |

> ¹ 叶子 / 中继可以先**不放**身份证书：启动会以"待入网"状态起来，向父申请，由父用它自己的 CA 私钥签发后写入 `certs/node.crt`。**根没有父可签发，所以必须自带。**
> ² CA 私钥**必须是你自己预置的**（默认路径 `keys/ca`）—— 父不可能把自己的私钥给你。
> 这就是 `-genkey` 要加 `-with-ca` 的原因。
> ³ 根缺省会拿自己的 CA 证书当信任锚。

生成密钥对的命令：

```bash
treecmd-node -genkey -keydir keys                # 叶子（无下级）
treecmd-node -genkey -keydir keys -with-ca       # 根 / 中继（有下级，额外生成 CA 密钥对）
```

### 启动后由程序自己生成（你不用管）

| 路径 | 内容 |
|---|---|
| `certs/node.crt` | 入网换取到的身份证书 |
| `state.db` | bbolt 账本（指令 / 分配 / 报告 / 结果 / 水位 …） |
| `state.dat` | 运行态快照（原子写，默认每 30s） |
| `objects/` | >64MB 大结果的对象存储 |
| `node.log` / `node.pid` | `scripts/start_node.sh` 产出的日志与 PID |

---

## 3. 部署步骤

### 单机三节点示例（根 + 中继 + 叶子）

```bash
# ① 根：生成密钥对（含 CA）→ 放信任锚 → 启动
cd /srv/treecmd/root
treecmd-node -genkey -keydir keys -with-ca
mkdir -p trust certs && cp <根节点自签产出的 CA 证书> trust/
cp ../../examples/node.yaml node.yaml        # 保留根形态：改 node.id / listen 即可
treecmd-node -config node.yaml

# ② 根：投放入网许可（子节点要用同一串）
printf 'your-shared-token' > enroll.token && chmod 600 enroll.token
mkdir -p ../../relay/trust && cp trust/root_ca.crt ../../relay/trust/

# ③ 中继：生成密钥对（含 CA，因为有下级）→ 启动
cd /srv/treecmd/relay
treecmd-node -genkey -keydir keys -with-ca
printf 'your-shared-token' > enroll.token && chmod 600 enroll.token
cp ../../examples/node.yaml node.yaml        # 照 node.yaml 头部"中继"那段增删：
                                             # 填自己的 id + listen，补 parents[]
treecmd-node -config node.yaml               # 自动向父入网换证 → 自动注册

# ④ 叶子：只要密钥对 + 信任锚 + 许可
cd /srv/treecmd/leaf
treecmd-node -genkey -keydir keys            # 叶子不加 -with-ca
mkdir -p trust && cp ../relay/trust/root_ca.crt trust/
printf 'your-shared-token' > enroll.token && chmod 600 enroll.token
cp ../../examples/node.yaml node.yaml        # 照 node.yaml 头部"叶"那段增删：
                                             # 只留 node.id + parents[]（删掉 listen 与 ca_*）
treecmd-node -config node.yaml
```

### 用附带脚本起停（推荐）

```bash
scripts/start_node.sh <node.yaml>            # 启动（后台起，写 node.log / node.pid）
scripts/start_node.sh status <node.yaml>     # 查看状态
scripts/start_node.sh reload <node.yaml>     # = kill -USR1：证书脚本换证后立即重载
scripts/start_node.sh conf   <node.yaml>     # = kill -HUP：配置热更
scripts/start_node.sh stop   <node.yaml>
```

### 验证是否成功

```bash
# 在任意开了 api.http_addr 的节点上看拓扑与健康
curl -s 'http://127.0.0.1:18443/v1/tree' | python3 -m json.tool
curl -s 'http://127.0.0.1:18443/v1/health?depth=-1' | python3 -m json.tool   # total/healthy 应等于节点数-1

# 提交一条指令并看结果
CID=$(curl -s -XPOST 127.0.0.1:18443/v1/commands \
      -d '{"type":"noop","target":{"mode":"SUBTREE"},"aggregate":"COUNT","on_failure":"ALL_MUST_SUCCEED"}' \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["command_id"])')
sleep 2 && curl -s "127.0.0.1:18443/v1/commands/$CID" | python3 -m json.tool
```

---

## 4. 改一项配置，什么时候生效？（最实用的一张表）

| 改了什么 | 生效方式 |
|---|---|
| **`node.listen`、`api.http_addr`** | **必须重启**。监听端口只在启动时绑定 —— 发 SIGHUP 只会更新配置对象，不会重绑端口 |
| `command.*`、`health.*`、`query.*`、`persist.interval` | **SIGHUP 即刻生效**，不重注册 |
| `security.trusted_origins`、`security.health_viewers`、`query.query_viewers` | **SIGHUP 即刻生效**，不重注册 |
| `security.cert_reload.*` | **SIGHUP 即刻生效**，不重注册 |
| `security.enrollment.token` / `token_path` / `challenge_ttl` | **SIGHUP 即刻生效**，不重注册（换 token 不需要重注册） |
| `selfupdate.*` | **SIGHUP 即刻生效**，不重注册。⚠️ 它**不在父可下发的白名单里**（`ConfigPush` 只接受 `command./health./query./persist.`），全树改这一项要逐节点改文件 + SIGHUP |
| `node.id`、`node.listen`、`parents[]`、`security.identity_*`、`security.ca_*`、`security.enrollment.enabled|allow_ids`、`registration.backfill` | **SIGHUP ⇒ 自动触发全量重注册**（这些进 `config_hash`，旧会话作废并重连） |

**证书相关（不由 `node.yaml` 控制；签发与续期在程序里，文件被替换时由外部触发重载）：**

| 变更 | 生效范围 |
|---|---|
| 换**信任锚** / 换**对端**证书 | **只影响新连接**（信任锚在每次握手时求值）—— 不打断现有会话 |
| 换**本节点身份证书 / 私钥** | 写入 + 重载后，`cert_reload.on_change=reconnect`（默认）会**主动重连一次**；设 `lazy` 则只对新连接生效 |
| 证书**内容坏 / 身份不符 / 链不通 / 过期** | **fail-safe**：保留当前证书继续服务并打 ERROR，绝不弄挂在跑的节点 |
| 证书文件被**删除** | 子节点自动重新入网把文件补回；根节点继续用内存里的旧证书（记 `result=missing`） |

---

## 5. 信号一览

| 信号 | 作用 |
|---|---|
| `SIGUSR1` | **立即重载证书**（证书文件被替换后发这个，秒级生效；不发也会被轮询发现） |
| `SIGHUP` | **配置热更**（重读 `node.yaml`；只改运行参数就原地生效，改了 `config_hash` 字段则全量重注册） |
| `SIGINT` / `SIGTERM` | 优雅退出 |

配套日志关键字：`cert reload: applied` / `config reload:` / `REFUSE TO START:`。

---

## 6. 常见报错对照

启动就失败（`REFUSE TO START` 开头，这些是**故意**拦在启动前的）：

| 报错关键字 | 原因 | 处理 |
|---|---|---|
| `identity private key ... (私钥必须预置，程序绝不生成)` | 缺私钥文件 | `treecmd-node -genkey -keydir keys` |
| `identity public key ... (公钥必须预置)` | 缺公钥文件 | 同上（与私钥成对生成） |
| `does not match private key` / `does not match certificate` | 私钥、公钥、证书三者不配套 | 重新生成密钥对，或换成与该证书配套的密钥 |
| `cert identity "X" != node id "Y"` | `node.id` 与证书里的身份不一致 | 让两者统一（改 `node.id`，或让签发方按这个 ID 重签） |
| `CA certificate ... missing（该节点有子节点，必须有 CA 材料）` | 根 / 中继缺 CA 证书 | 用 `-genkey -with-ca` 重新生成，或由脚本投放 `certs/node.crt.ca` |
| `CA private key missing（本节点有子节点，必须预置）` | 根 / 中继缺 CA 私钥 | 同上（`-with-ca`） |
| `security.ca_cert_paths: ... no such file or directory` | 信任锚路径不存在 / 目录是空的 | 投放 CA 证书到 `trust/`，或把 `ca_cert_paths` 指向正确位置 |
| `lease constraint violated: renew_at(..)×3 > lease_ttl(..)` | 租约硬约束被违反 | 让 `renew_at × 3 ≤ lease_ttl`（默认 30s / 90s 正好满足） |
| `invalid security.cert_reload.on_change` | 值写错 | 只能 `reconnect` 或 `lazy` |
| `security.enrollment.token_path: no such file` | 配了 `token_path` 但文件不存在 | 投放 `enroll.token`（或改用 `token:` 直接写） |
| `[warn] node.yaml 权限为 644，建议 0600` | 只是告警，不阻断 | `chmod 600 node.yaml` |

启动成功但连不上父：

| 现象 | 排查方向 |
|---|---|
| 一直重连、日志有 `upstream session ended` | 父没起 / `parents[].addr` 写错（要填父的 **`listen`**，不是 `api.http_addr`）/ 父的端口没监听 |
| `CERT_UNTRUSTED` / `peer chain untrusted` | 你节点的信任锚里没有**签发父证书的那个 CA** —— 把该 CA 投放进 `trust/` |
| `peer identity "X" != expected "Y"` | `parents[].id` 写的不是父的真实 NodeID |
| `ERR_CYCLE` | 环：这个 NodeID 出现在了自己的祖先链上（父的真实 ID 填错了，或拓扑配成了环） |
| `CERT_REVOKED` | 该节点在本地 CRL 中（`curl /v1/crl` 可查） |
| 健康检查里某些节点 `UNREACHABLE` | 该节点进程没起 / 网络不通 / 刚断线正在退避重连 |
| 入网被拒（`ERR_ENROLL_*`） | 许可串与父端不一致；或父端配了 `allow_ids` 而没有把本节点 ID 列进去；或父端 `enrollment.enabled=false` |

> 排错第一步永远是：**启动日志**（`REFUSE TO START: ...` 那行 + 后面写清的原因），
> 以及在任一开了 API 的节点上看 `/v1/tree`（谁在线、谁跑的是哪份镜像）与 `/metrics`。
> 日志里同时会有节点身份、角色、信任锚数量、证书有效期与指纹、入网与热重载状态。

---

## 7. 想在 `node.yaml` 里找什么，去哪一段

| 你想知道 | 去哪看 |
|---|---|
| 我这个角色最少要写哪几行 | `node.yaml` 头部 **【按角色最简起步】**（根 / 中继 / 叶 三段，直接抄） |
| 某个字段归哪个角色、默认值是多少、进不进 `config_hash` | `node.yaml` 正文该字段的注释（每行都标着） |
| 启动前目录里必须有哪几样东西 | `node.yaml` 第二部分「本节点目录里应有什么」 |
| 命令怎么敲、怎么自检、怎么看状态 | `node.yaml` 第三部分「命令速查」 |
| 部署走查 / 字段生效时机 / 报错对照 / 检查清单 | 本页第 2～6、8 节 |

> 本页**不再维护**"各角色字段对照表"——那份信息已经合并进 `node.yaml` 的行内标记，避免两处各说一套。

---

## 8. 部署前检查清单

- [ ] 每个节点一个独立目录、一份 `node.yaml`，`node.id` 全局唯一且与证书身份一致
- [ ] 私钥 + 公钥已生成（`-genkey`）；根 / 中继加了 `-with-ca`
- [ ] 根 / 中继有 `certs/node.crt.ca` 与 `keys/ca`
- [ ] 所有非根节点的 `trust/` 里有**签发父证书的那个 CA**
- [ ] 子节点的 `parents[].id` / `addr` 填的是父的**真实 NodeID / `listen` 地址**
- [ ] 入网许可在父端与子端一致（`chmod 600`）
- [ ] 每个节点都能启动成功（日志里没有 `REFUSE TO START`）
- [ ] 端口规划：`listen` 与 `api.http_addr` 不要落在同一段互相冲突
- [ ] 已把证书脚本的换证动作接上 `kill -USR1 <pid>`（或接受 30s 内的轮询延迟）
