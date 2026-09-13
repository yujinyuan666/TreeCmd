# treecmd 部署样例 · 阅读指南

这个目录里的三份配置，加上这一份说明，应该足够你把程序部署起来。
**建议阅读顺序：本页 → `child.yaml`（最小形态）→ `root.yaml`（全字段详解）→ `relay.yaml`（中间层）。**

---

## 1. 三十秒速览

**部署形态**：单服务器 · 一个节点一个进程 · 手工放 `node.yaml` 后启动 · **证书由程序签发与续期**
（父给子/其它客户端签发 + 运行期续签；**根节点的自签材料**部署时准备一次）。

**角色不用手写，由配置推导出来：**

| 角色 | 判据 | 证书从哪来 | 要 `listen` | 要 `parents[]` | 样例 |
|---|---|---|---|---|---|
| `root` 根 | 没有 `parents[]` | **必须自带**（没有父能签发给它） | ✅ 必须 | ❌ 不写 | `root.yaml` |
| `relay` 中继 | 有 `parents[]` **且**有 `listen` | 自带或向父入网 | ✅ 必须 | ✅ 必须 | `relay.yaml` |
| `leaf` 叶子 | 有 `parents[]`，**没有** `listen` | 自带或向父入网 | ❌ 不写 | ✅ 必须 | `child.yaml` |

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
| `certs/node.crt.ca` | 本节点**CA 证书**（给子签发） | 父在入网时一并签发（程序签发） | — | 必需 | 必需 |
| `certs/ca.key` | 本节点**CA 私钥**（给子签发）² | `treecmd-node -genkey -with-ca` | — | 必需 | 必需 |
| `trust/*.crt` | **信任锚**（校验父与对端） | 部署时投放（根自签的 CA 证书） | 必需 | 必需 | 可选³ |
| `enroll.token` | **入网许可**（与父端一致，`chmod 600`） | 部署时投放（两边内容必须一致） | 需要入网时 | 需要入网时 | — |

> ¹ 叶子 / 中继可以先**不放**身份证书：启动会以"待入网"状态起来，向父申请，由父用它自己的 CA 私钥签发后写入 `certs/node.crt`。**根没有父可签发，所以必须自带。**
> ² CA 私钥**必须是你自己预置的** —— 父不可能把自己的私钥给你。这就是 `-genkey` 要加 `-with-ca` 的原因。
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
| `state.dat` | 运行态快照（原子写，默认每 10s） |
| `objects/` | >64MB 大结果的对象存储 |
| `node.log` / `node.pid` | `scripts/start_node.sh` 产出的日志与 PID |

---

## 3. 部署步骤

### 单机三节点示例（根 + 中继 + 叶子）

```bash
# ① 根：生成密钥对（含 CA）→ 放信任锚 → 自检 → 启动
cd /srv/treecmd/root
treecmd-node -genkey -keydir keys -with-ca
mkdir -p trust certs && cp <根节点自签产出的 CA 证书> trust/
cp ../../examples/root.yaml node.yaml        # 改成你的 node.id / listen
treecmd-node -check -config node.yaml        # 只读自检：不监听、不连接、不落盘
treecmd-node -config node.yaml

# ② 根：投放入网许可（子节点要用同一串）
printf 'your-shared-token' > enroll.token && chmod 600 enroll.token
mkdir -p ../../relay/trust && cp trust/root_ca.crt ../../relay/trust/

# ③ 中继：生成密钥对（含 CA，因为有下级）→ 自检 → 启动
cd /srv/treecmd/relay
treecmd-node -genkey -keydir keys -with-ca
printf 'your-shared-token' > enroll.token && chmod 600 enroll.token
cp ../../examples/relay.yaml node.yaml       # 填自己的 id、父的真实 id/addr、自己的 listen
treecmd-node -check -config node.yaml
treecmd-node -config node.yaml               # 自动向父入网换证 → 自动注册

# ④ 叶子：只要密钥对 + 信任锚 + 许可
cd /srv/treecmd/leaf
treecmd-node -genkey -keydir keys            # 叶子不加 -with-ca
mkdir -p trust && cp ../relay/trust/root_ca.crt trust/
printf 'your-shared-token' > enroll.token && chmod 600 enroll.token
cp ../../examples/child.yaml node.yaml       # 只需填：我是谁 + 父的真实 id/addr
treecmd-node -check -config node.yaml
treecmd-node -config node.yaml
```

### 用附带脚本起停（推荐）

```bash
scripts/start_node.sh <node.yaml>            # 启动（先自检，再后台起，写 node.log / node.pid）
scripts/start_node.sh status <node.yaml>     # 查看状态
scripts/start_node.sh check  <node.yaml>     # 只自检
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
| `node.id`、`parents[]`、`node.labels`、`node.capabilities`、`security.identity_*`、`security.ca_*`、`security.enrollment.enabled|allow_ids`、`registration.backfill` | **SIGHUP ⇒ 自动触发全量重注册**（这些进 `config_hash`，旧会话作废并重连） |

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

> 排错第一步永远是：**`treecmd-node -check -config node.yaml`**。
> 它只读、不监听、不连接、不落盘，会把节点身份、角色、信任锚数量、证书有效期与指纹、
> 能/不能给子签发、入网与热重载状态，以及**"按约定替你补全了哪些配置"**全部列出来。

---

## 7. 三份样例的差异（对照着看最快）

| 配置项 | `root.yaml` | `relay.yaml` | `child.yaml` |
|---|---|---|---|
| `node.id` | 自定（UUIDv7） | 自定 | 自定 |
| `node.listen` | ✅ 必须（子要连它） | ✅ 必须（子要连它） | ❌ 不写 |
| `parents[]` | ❌ 不写 | ✅ 必须 | ✅ 必须 |
| `security.identity_cert_path` | 必须**已存在** | 可不存在（入网） | 可不存在（入网） |
| `security.ca_cert_path` / `ca_key_path` | ✅ 必须 | ✅ 必须 | ❌ 不需要 |
| `security.ca_cert_paths` | 可选（缺省用自己的 CA） | ✅ 必须 | ✅ 必须 |
| `enrollment` 段的角色 | **父**（发证方，要 `token`） | 两侧都用 | **子**（换证方，要 `token`） |
| 建议 `api.http_addr` | ✅ 开（入口） | 可选 | 一般不开 |

另外：`treecmd-node -print-sample-config root|child|relay|leaf` 也能直接打印这几份样例，
内容更精简（不含本页的完整注释）；本目录的文件才是"阅读版"。

---

## 8. 部署前检查清单

- [ ] 每个节点一个独立目录、一份 `node.yaml`，`node.id` 全局唯一且与证书身份一致
- [ ] 私钥 + 公钥已生成（`-genkey`）；根 / 中继加了 `-with-ca`
- [ ] 根 / 中继有 `certs/node.crt.ca` 与 `certs/ca.key`
- [ ] 所有非根节点的 `trust/` 里有**签发父证书的那个 CA**
- [ ] 子节点的 `parents[].id` / `addr` 填的是父的**真实 NodeID / `listen` 地址**
- [ ] 入网许可在父端与子端一致（`chmod 600`）
- [ ] 每个节点 `-check` 通过，无 `REFUSE TO START`
- [ ] 端口规划：`listen` 与 `api.http_addr` 不要落在同一段互相冲突
- [ ] 已把证书脚本的换证动作接上 `kill -USR1 <pid>`（或接受 30s 内的轮询延迟）
