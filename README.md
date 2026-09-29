# treecmd —— 分布式树形指令执行系统（Go 实现）

按《架构方案 v3.21》落地的可运行实现：**一个进程同时是客户端与服务端**，
节点自下而上注册成树，指令自上而下分发，结果自下而上聚合到发起节点。

> 架构方案原文**不在本仓库**（路径 `../docs/架构方案.md` 是它在项目文档目录里的位置），需另处获取。

**部署形态**：单服务器、**一个节点一个进程**、手工放 `node.yaml` 后启动。**证书由程序管理**：
父节点通过「运行期入网」为子节点（以及其它客户端）签发证书，通过「运行期续签」换发新证书；
只有**根节点的自签材料**需要在部署时准备一次。程序同时支持"发现证书文件变更就重新加载"。
手工部署细节见 `docs/手动部署指南.md`。

## 快速开始

```bash
# 构建（全项目只有一个可执行文件：单节点入口）
go build -o bin/treecmd-node ./cmd/node
```

一个节点 = 一份 `node.yaml`（**手写、程序只读、绝不回写**）+ 一组身份材料 + 一个进程。
单服务器部署时按角色各拷一份配置与材料即可，细节见 `docs/手动部署指南.md`。

### 节点身份与元信息：`node.id` / `node.name` / `node.remark`

| 字段 | 说明 |
|------|------|
| `node.id` | 节点身份（UUIDv7），**必须与证书身份一致**。**可以留空** —— 程序会按下面的顺序自动定下来，**从不回写本文件**（ADR-050） |
| `node.name` | 节点名：人类可读地标记"我是谁"（如 `edge-sz-01`）。可省略 |
| `node.remark` | 备注：自由文本（如 `"1 号柜 3 号机位"`）。可省略 |

**`node.id` 留空时怎么定**（前一个命中即停止，全程只读）：

| 顺序 | 来源 | 说明 |
|---|---|---|
| 1 | `node.yaml` 里的 `node.id` | 显式指定，最高优先 |
| 2 | **已签发证书的身份**（CN 优先、SAN URI 兜底） | 证书就是身份 —— 所以**根节点不必在配置里写 id**：它自带证书，ID 自然从证书取 |
| 3 | **`state.dat` 的 `self.id`** | "还没拿到证书"那段窗口里的身份锚点，跨重启稳定 |
| 4 | 都没有 → 生成 UUIDv7 | 生成值**在上线前**就写进 `state.dat`（不是 `node.yaml`），此后固定 |

> **为什么放 `state.dat` 而不是写回配置**：`node.yaml` 是"人写的、要能进版本管理"的东西，
> 程序碰它就把"配置"变成了"状态"（ADR-005）。NodeID 属于**运行期状态**，`state.dat` 正是它的归宿
> —— 只由程序写、可丢弃重建、且已被 `.gitignore` 覆盖，**不需要给 ADR-005 开任何口子**。
>
> 两条边界：
> ① `state.dat` 与证书身份不一致 → **以证书为准**并告警（否则必然过不了启动强校验）；
> ② `node.id` 留空时程序会在上线前把它写进 `state.dat`；想知道拿到了什么 ID，首启后看启动日志
> （`node.id 未写定 → 本次生成 … node_id=<ID>`）或读 `state.dat` 的 `self.id` 即可拿到。

`node.name` / `node.remark` **只作展示用途**，不参与任何权限判定与摘要计算，也**不进 `config_hash`**：
改个显示名不会被当成拓扑变更。它们随每次注册上行（父端在 `/v1/tree` 里就能看到名字），
也随健康响应逐跳回传（根在 `/v1/health` 里能看到每个子节点的名字）。

```bash
# 改名后让它立刻同步给父：SIGHUP 即可（检测到元信息变化会主动重注册一次）
./scripts/start_node.sh conf node.yaml     # = kill -HUP

curl -s localhost:18443/v1/tree        # 本节点 + 直接子的 node_name / node_remark
curl -s 'localhost:18443/v1/health?depth=-1&detail=true&timeout=20s'   # 逐层都能看到名字
```

> 补充：**根节点仍然必须自带证书**（没有父可以签发它）。"根 + 无证书"会拒绝启动，
> 与 id 写没写无关 —— id 可以从证书取，证书本身没有就只能自带。

### 手工部署（三个便捷入口）

```bash
# 根节点**首次启动前**：生成它自己的信任锚材料（一次性 bootstrap，见 docs/手动部署指南.md 第二节）
# 根没有父，没有谁能给它签发证书，所以这一步必须在根的第一次启动之前做一次
./scripts/init_root.sh                         # **不带参数** = 就地在当前目录初始化，NodeID 自动生成 UUIDv7
./scripts/init_root.sh /opt/treecmd/root       # 也可以指定目录（NodeID 仍自动生成）
./scripts/init_root.sh /opt/treecmd/root <ID>  # 目录 + ID 都指定（天数是第 3、4 个位置参数）
./scripts/make_bootstrap.sh <本节点目录>       # 产出「入网引导凭据」（许可 + 本节点 CA 链）给下级

# 一次性生成本节点密钥对（程序**启动路径绝不生成密钥**，这是显式的部署工具）
./bin/treecmd-node -genkey -keydir keys            # 还有下级就加 -with-ca

# 配置从 examples/node.yaml 抄一份即可（唯一一份权威样例：头部有"按角色最简起步"，
# 正文逐字段标了【根/中继/叶】必填性与默认值；写出来的是根形态，中继/叶按标记增删）
cp examples/node.yaml node.yaml

# 起停 / 换证后重载 / 配置热更
./scripts/start_node.sh <node.yaml>            # 启动（后台起、记 pid）
./scripts/start_node.sh reload <node.yaml>     # = kill -USR1：证书脚本换证后立即重载
./scripts/start_node.sh conf   <node.yaml>     # = kill -HUP：配置热更
./scripts/start_node.sh stop   <node.yaml>
```

> 配置或身份材料有问题时不用提前检查：**启动强校验就在启动路径上** ——
> 任一条不过就 `REFUSE TO START: ...` 并以非零码退出，日志里把原因写清楚，
> `start_node.sh` 会把日志尾部直接打给你看。

### 可视化测试台（`test/`）

只想"看着"一棵树跑起来，不用手工敲 curl：

```bash
cd test
./demo.sh start     # 起 根 + 直接叶子 + 中继 + 中继下的叶子（3 层）+ 网页控制台
# 浏览器开 http://127.0.0.1:8899/  —— 提交指令、跟进度、看 TREE 聚合结果、扫全树健康、看指标
./demo.sh stop
```

控制台是单文件网页（零依赖、可离线），配一个**只转发本机**的本地代理解决跨源；
`./demo.sh start` 起的是一棵**真实进程树**，不是 mock。细节见 `test/README.md`。

**子节点的配置可以只有两项**（其余按约定补全：`keys/id_ed25519`、`certs/node.crt`、`enroll.token`…）
—— 材料上**只需要"自己的密钥 + 父给的一份凭据"**，**不需要从根拷任何证书**：

```yaml
node:
  id: <我是谁>
parents:
  - id: <父的真实 NodeID>
    addr: 127.0.0.1:19443
```

首次入网用的信任锚口径是**你的父**（父的 `certs/node.crt.ca` 整份文件，含父 CA 一路到根）；
入网成功之后连它也可以删掉 —— 信任锚改由**本节点自己的证书链**自举（见下表最后一行）。

### 证书生命周期：程序签发 / 程序续期 / 替换自动重载

| 能力 | 说明 |
|------|------|
| **根自签续期** | 根没有父、没有任何人能给它续签，但它自己就持有 CA 材料 ⇒ 剩余有效期不足生命期 1/3 时**自己重签自己**（`startSelfRenewLoop`）；**启动时若证书已进窗口（含已过期）也先续再启动** ⇒ 根的证书同样是"第一次启动之后不用管" |
| **有效期口径** | **身份证书 30 天**、**CA 证书 10 年**（都可用 `security.identity_cert_days` / `security.ca_cert_days` 覆盖；**默认值就是历史行为，改它不影响拓扑、不进 `config_hash`**）。续签窗口在生命期 2/3 处 ⇒ 身份证书每约 20 天换一次，留足容错 |
| **CA 证书也能在线轮换** | CA 证书**只换证书、不换密钥**（`ReissueCAFor`）：公钥不变 ⇒ 下级手里的旧 CA 证书在有效期内仍然有效、`trust/` 完全不用动、下级也不用重新入网。中继向**父**申请（`CertRenewReq.want_ca` + 提交当前那张 CA 证书证明"同一把密钥"），根则自己续（**先续 CA 证书、再用新 CA 证书重签身份证书**，顺序不能反）。指标 `ca_rotate_total{result}` |
| **运行期入网签发** | 子节点没有证书也能上线：`EnrollChallenge`（一次性 nonce）→ 子用**自己私钥**签 PoP → 提交身份公钥(+CA 公钥)与入网许可 → **父用自己的 CA 私钥签这两个公钥** → 子校验后原子写盘 + 热切换。**私钥全程不出本机**，程序既不生成也不接收私钥 |
| **入网引导凭据** | 子节点要的两样东西（**许可** = "父要不要收我"、**父的 CA 链** = "对端是不是父"）装进**一份文件**（`enroll.token`，格式见 `identity.ParseBootstrap`），由父一条 `scripts/make_bootstrap.sh` 产出 ⇒ 部署一个子节点**只拷一个文件**，不必再单独拷 CA。**许可**是唯一的授权判据：父端没配它就拒绝一切入网（它挡不住"自报某个 ID + 自建一对密钥"：NodeID 是公开信息、与密钥对没有密码学绑定） |
| **证书热重载** | 轮询（默认 30s，只做 `stat`，变了才读内容）+ **`SIGUSR1` 立即生效**；监视身份私钥/公钥/证书 + 本节点 CA 证书/私钥 + 全部信任锚 |
| **fail-safe** | 新证书**任何一项校验不过**（格式/身份/链/有效期）就**继续用当前证书**并打 ERROR —— 绝不会因为脚本投放了半个文件把在跑的节点弄挂。指标 `cert_reload_total{result=ok\|failed\|missing\|nochange}` |
| **生效范围** | 信任锚与对端证书只影响新连接；只有**本节点身份证书/私钥**变了才主动重连一次（`cert_reload.on_change: reconnect`；设 `lazy` 则完全不打断现有会话）。**换自己的 CA 证书不触发重连** —— TLS 上出示的是身份证书链，里面本来就不含自己的 CA 证书 |
| **信任锚口径 = 你的父** | `ca_cert_paths` 放的是**父的** `certs/node.crt.ca`（整份文件，含父 CA 到根）—— **不需要从根拷任何东西**。链能不能验通只看"能否接到某个锚"，`LoadOrScanTrustAnchors` 会把文件里的**整条链**都纳入锚池，所以"放父的"与"放根的"判定结果完全等价；而每个节点只对自己的父负责 ⇒ 换父、换根都只影响父那一层 |
| **信任锚可自举** | 入网拿到的证书链本身就是 `[我, 父CA, …, 根CA]` ⇒ 它自己就是现成的锚。`identity.ChainAnchors` 把 `chain[1:]`（跳过自己的叶子证书）登记成锚，于是**入网成功后 `trust/` 与 `security.ca_cert_paths` 都可以删掉**，日志留一行「信任锚来自自身证书链自举」。这条**不放宽任何语义**：链里的父 CA 本来就已经作为中间证书参与验链。注意别只截取"父那一张"，漏掉根会让**上级节点签发的跨跳委托（`ReqAuth`）在孙节点上验不过** |
| **信任锚给目录** | `ca_cert_paths: [trust]` —— 目录下 `*.crt`/`*.pem` 全部加载；**换 CA 只换文件、不改配置** |
| **证书撤下可自愈** | 证书文件被删 → 子节点自动重新入网把文件补回；根节点则继续用内存里的旧证书服务（并记 `result=missing`） |
| **首启顺序无关** | 子先起、父后起也能收敛：没证书/连不上都不会让进程退出，按退避（1s→2s→4s…30s）持续重试 |

> **CA 证书能在线轮换、但 CA 密钥不能。** 本机制只解决"证书到期 / 想缩短 CA 证书寿命"这一类需求。
> 真要**换 CA 密钥**（真换 CA）仍然需要全树重新分发 `trust/` —— 那是另一件事，
> 但可以靠"信任锚双活"慢慢推进：`ca_cert_paths` 里同时放新旧两张根证书，等所有子都换完再撤旧的。

### 可执行文件一致性：连上即比对，不一致就自同步

树是"父下发、子执行"的，子如果跑的是另一份镜像，行为就可能与父不一致 —— 而这类不一致的
症状是**"行为诡异"而不是"报错"**，是最难排查的一类故障。所以每个节点启动时先算一次自己
可执行文件的 sha256，把它放进**运行时配置**（`cfg.Build`，`yaml:"-"`：不来自 `node.yaml`、
不进 `config_hash`、也不落盘），之后子连上来时第一件事就是比对。

| 能力 | 说明 |
|------|------|
| **启动算哈希** | `os.Executable` + 解析符号链接（要替换的是链接指向的**真实文件**）+ 流式 sha256，一遍过。算不出来不致命：只记 ERROR，一致性检查整体降级为"不判定" |
| **连上第一件事** | 父在 `RegisterAck` 里回带自己的哈希 / 大小 / 签名；子拿到应答后**先比对再干活** —— 此刻心跳与拉取循环都还没起，**一条指令都还没执行过** |
| **一致** | 只比一个字符串，零额外开销；顺手清掉上次遗留的尝试痕迹 |
| **不一致** | `on_mismatch: sync`（默认）：就地向父 `BinaryReq` 拉取 → 逐片 crc32 + **片级 sha256（清单）** + 整份 sha256 + 父签名四重校验 → 原子替换 → `syscall.Exec` **原地重启** |
| **分片清单先行** | 子先 `BinaryManifestReq` 要一份"这份镜像由哪些片组成、每片 sha256 是多少"（`hub.manifestFor`：优先用片存里继承来的那份，没有就从本节点镜像现算）。拿到清单后**片级校验从 crc32 升级为 sha256** —— 这是"片可以对外转发"的唯一依据。拿不到清单（旧版本父 / `piece_store=false`）就**回退到老流程**，绝不因此不工作 |
| **片存 + 边收边转发** | 过校验的片落在 `<暂存目录>/pieces/<本节点ID>/`（**按节点隔离**，因为多个节点的可执行文件常同处一目录）。于是中继**还没收完、还没重启**就能把已收到的片转发给自己的直接子 ⇒ 收敛从"逐层串行"变成"流水线"。片存是**可丢的缓存**，删掉只会让下次从 0 重来 |
| **断点续传** | `BinaryReq.from_index` + 片存的"从第 0 片起的**连续前缀**"。片已集齐时（上次在拼装/替换前中断）直接拼装、不再向父申请一片。**最终统一从片存拼装**（而不是边收边追加）—— 续传时前半段只存在于片存里，追加会得到错位的文件 |
| **复用 Connect 流** | 不新增 RPC：请求与分片都走子已经建好的那条双向流。推送时**先等发送缓冲回落到一半以下再压下一片**，给同一时刻的心跳与终态帧留位置 |
| **方向单向** | 父永远是标准答案 ⇒ **升级自上而下**（根先换，中继再换，叶子最后跟）**；反过来把根换回旧版就等于整棵树回滚**，不用逐台登录 |
| **原地 exec** | PID 不变、fd 与环境保留，`nohup` + pidfile 的启动脚本原样可用。进程内状态全丢这件事框架本来就扛得住：`SELF_RUNNING` 的指令走 `Executor.OnRestart`，未上报结果在 `pending_result` 里等着重发，子节点断线自动重连 |
| **三重校验** | ① mTLS；② 父用**身份密钥**对 `(父ID, 哈希, 大小)` 签名，子用父的证书公钥**离线**验签；③ 每片 sha256（有清单时）+ 收齐后整份 sha256 逐字节校验 |
| **只对自己签发的直接子开放** | 服务端拿对端叶子证书验自己 CA 的签名，不是直接子一律拒（`ERR_BINARY_NOT_DIRECT_CHILD`）。片存里只可能有**过了 sha256 的片**，所以从片存供片不需要"磁盘文件仍是启动时那份"这个前提；从**自己的可执行文件**供片时必须复验（被换过就拒绝，绝不外发半成品） |
| **读片只认片号** | 片存的读取入口只接受**片号**（`Get(hash, index)`），绝不接受任意 offset —— 否则它就是一个任意文件读取的口子。目录权限 0700、按目标哈希分目录 |
| **供片并发有闸门** | `max_serve_concurrency`（默认 4）：中继可能一边向父拉、一边给多个孙推。满了**等到超时才拒**（`ERR_BINARY_BUSY`）而不是立刻拒 —— 子端一次失败要等下一轮重连才重试，立刻拒太容易拖慢收敛 |
| **fail-safe** | 拉取 / 落盘 / 替换任一步失败 → 保留当前镜像**继续服务** + ERROR + 指标；只有"替换成功"这一条路径必然重启 |
| **防重启循环** | 尝试计数**先落盘再动手**（跨 exec 存活在 `state.dat` 的 `self_update` 里）：同一目标哈希在一个窗口内最多 3 次，超了就锁住并告警，窗口一过自动清零重试 |
| **可观测** | 启动日志里有一行"运行时镜像"（hash/size/version/path）；`/v1/tree` 每个节点都带 `build_hash`、还有 `lagging_children`（>0 就是还没收敛）与 **`piece_store`**（每份镜像的 `have`/`total`/`bytes`/`ready` —— 流水线跑到哪了一目了然）；指标 `selfupdate_total{result}`、`selfupdate_serve_total{result}`、`selfupdate_pieces_received_total{result}`、`selfupdate_serve_pieces_total{source}`、`binary_info{hash}` |

```yaml
# 全部可省略（默认值就是"开启 + 不一致即同步"）
selfupdate:
  enabled: true            # 总开关
  on_mismatch: sync        # sync=同步并原地重启（默认）；warn=只告警不重启（先观察一轮时用）
  serve: true              # 是否把本节点的可执行文件发给直接子
  chunk_size: 256KB        # 分片大小（上限 4MB）
  max_bytes: 64MB          # 单次同步的字节上限（请求方与提供方都按它截断）
  sync_timeout: 60s
  max_attempts: 3          # 同一个目标哈希在 attempt_window 内最多试几次（防重启循环）
  attempt_window: 1h
  # dir: /opt/treecmd/staging   # 默认 = 可执行文件所在目录（**必须同文件系统**，rename 才是原子的）
  piece_store: true        # 镜像分片缓存：过 sha256 的片落盘，"边收边转发"+断点续传（默认开）
  max_serve_concurrency: 4 # 同时向几个直接子供片（中继一边向父拉、一边给孙推时要限流）
  # piece_store_max_bytes: 128MB  # 片存上限，默认 = max_bytes × 2；超了按最近使用时间清
```

```bash
# 升级（推荐顺序：先只换根，剩下的它自己往下传）
cp 新版/treecmd-node ./bin/treecmd-node     # 换的是磁盘上的文件；在跑的进程不受影响
./scripts/start_node.sh stop/start <node.yaml>
curl -s localhost:18443/v1/tree | grep -o '"lagging_children":[0-9]*'   # 等它归零就收敛完了
# 回滚：把根的二进制换回旧版并重启根 —— 全树自动跟随
```

三条边界：**只支持 unix**（重启手段就是 `syscall.Exec`，本项目的部署形态也没有 Windows）；
替换时会给上一版留一份 `<可执行文件>.prev`（回滚与排障用，程序不会自动删）；
全程**不碰 `node.yaml`**（哈希只活在运行时配置里）。

### 外部脚本：脚本放在二进制旁边，由父按需下发给子

脚本目录固定为 **`<可执行文件所在目录>/script/`**（与 selfupdate 的暂存目录同源口径）。
**解释器由脚本自己的 shebang 决定**，调用方不指定类型；脚本落盘时是 `0755`，可以手动执行。

```bash
# 一条指令只带**一个参数**（一个 JSON）：要跑哪个脚本 + 给它的数据
curl -s -XPOST localhost:18443/v1/commands -d '{"type":"script","aggregate":"TREE",
  "payload":"'"$(printf '%s' '{"script":"hello.sh","params":{"who":"tree"}}' | base64)"'"}'
```

| 能力 | 说明 |
|------|------|
| **脚本怎么到每个节点** | 执行前，每个节点先看本地 `script/<名字>` 的哈希与指令里的是否一致；不一致（或没有）就**向直接父索取**，父从自己的 `script/` 读出来分片回发（逐片 crc32 + 整份 sha256），子校验通过后**无条件覆盖**写盘，然后才执行。所以"根节点放脚本、其余节点自动拿到" |
| **为什么是子索取、不是父推送** | 指令投递本身是子主动拉的（`FetchCommands` 拉模式工作队列），父"推脚本"与子"拉指令"是两条独立时序 —— 由父单方面推，子可能在脚本落盘之前就拉到指令并开始执行 |
| **哈希从哪来** | 调用方**不用自己算**：发起节点在**签名之前**把本地脚本的 sha256 注入载荷，于是它落在 origin 签名的覆盖范围内（中间节点既改不了参数，也改不了"该跑哪个版本"）。顺带一道 fail-fast：发起节点上没有这个脚本，**提交就被拒**，不必等它铺到全树 |
| **父的身份背书** | 父在下发时会用**自己的身份私钥**对 `(脚本名, 整份哈希)` 签一次，只挂在最后一片上；子用 mTLS 拿到的**父公钥**验，并断言"签名者就是我这次的父"。它管的是**归因**（这份字节是谁给的），**不承担防篡改** —— 内容对不对始终由哈希比对负责。签名只在内存验、不落盘，所以它现在**不提供离线可验证性** |
| **参数怎么给脚本** | 那一个 JSON **原样**作为 `argv[1]`（不做 shell 解析，也就没有注入面） |
| **结果怎么回来** | 脚本往**本次执行的工作目录**写 `result.json`（固定名字），节点读它作为本节点结果（**缺失 = 空结果**，纯副作用型脚本不算失败）；stdout / stderr 只作日志（各留 1MB），退出码非 0 = 该节点失败，stderr 尾部进错误信息 |
| **结果上限 4MB** | 必须远小于 64MB —— 再大就会退化成对象存储引用，而引用**无法跨节点取回**。超限直接判失败并说明原因 |
| **进程怎么收** | 独立进程组（`Setpgid`）+ 中断时整组信号，先 `SIGTERM`、宽限 5s 再 `SIGKILL`；超时来自指令 deadline。**不会留下脚本 fork 出去的孙进程** |
| **不自动重跑** | 脚本可能不幂等（写库、发请求），所以 `script` 类型**拒绝"进程重启后自动重跑"**：落 `SELF_FAILED`，等人工确认后用 retry 接口重跑 |

⚠️ **两条必须知道的安全边界**：

1. **脚本以节点进程的身份运行，没有沙箱** —— 它能读写本机任意文件、能联网。信任边界 = 「谁能提交指令（`allowedOrigin`）」+「谁能写节点的 `script/` 目录」+「脚本哈希校验」+「父的身份背书」。别把脚本当成"受限制的东西"。
2. **脚本名走白名单**（`[A-Za-z0-9._-]`、≤128 字节），并且服务端会解析符号链接、**拒绝逃出脚本目录的文件** —— 否则一条 `{"script":"../../keys/id_ed25519"}` 就能把**节点身份私钥**当成脚本发给全树。下发侧只对"本节点 CA 签发的直接子"开放。

部署前提：**根节点的 `script/` 目录要有人放脚本**（其余节点自动下发）。目录不存在时启动会建一个空的。



每个节点启动时都要带**自己的私钥与公钥**（`security.identity_key_path` / `security.identity_pubkey_path`）：

- **程序绝不生成密钥**。启动时读不到私钥或公钥，直接 `REFUSE TO START` 并非零退出；
- 三者必须完全一致：**私钥 ↔ 公钥 ↔ 证书公钥**，且证书身份 == NodeID、证书链能验到信任锚、证书未过期；
- 有子节点的节点（根 / 中继）还必须预置 CA 私钥与 CA 证书，否则也拒绝启动。

启动时的强校验是**默认生效、无需开关**的：上面每一条不满足都会 `REFUSE TO START` 并以非零码退出，
日志里把原因写清楚（这是启动路径的一部分，不需要额外的检查开关）。

### HTTP API（有对外端点的节点）

```
POST /v1/commands                     提交指令（本节点即 OriginID 与聚合终点）
GET  /v1/commands/{id}                结果查询（跨节点沿路径前缀路由到持有者）
POST /v1/commands/{id}/cancel         取消
POST /v1/commands/{id}/retry?node=X   子节点重跑（RetryNode）；次数用尽时**父判该子失败**并回报 judged=FAILED
GET  /v1/health[?command_id=&depth=&detail=&timeout=]   健康度 / 指令轨迹 双模式
GET  /v1/tree                         本节点视角的拓扑
GET  /v1/crl                          查看本节点的吊销列表
POST /v1/crl?node=X                   吊销某节点（写本地 CRL、版本 +1、下发给直接子）
GET  /v1/forget?node=X                清理预览：某子节点会不会被允许清理、会被删掉什么（只读）
POST /v1/forget?node=X                清理失效的直接子节点（见下节）
GET  /v1/healthz
GET  /metrics                         Prometheus 文本
```

**这些端点是分等级的**：`POST` 那几条是**写操作**（其中 `/v1/crl` 与 `/v1/forget` 是不可逆的运维动作），
`GET` 那几条只读。访问控制只管写操作 —— 见下面「访问控制」小节。

```bash
curl -s -XPOST localhost:18443/v1/commands -d '{"type":"echo","payload":"aGVsbG8=","aggregate":"TREE"}'
# 手写的对外 API 调用（internal/exec/apis）：整棵子树各调一次上游，结果按 TREE 保层级聚合
curl -s -XPOST localhost:18443/v1/commands -d '{"type":"uuid_v4","aggregate":"TREE"}'
curl -s -XPOST localhost:18443/v1/commands -d '{"type":"remote_time","aggregate":"TREE"}'   # 各节点对时
# 执行外部脚本（internal/exec/script）：脚本放在 <可执行文件同目录>/script/，由父按需下发给子
curl -s -XPOST localhost:18443/v1/commands \
  -d '{"type":"script","payload":"'"$(printf '%s' '{"script":"hello.sh","params":{"who":"tree"}}' | base64)"'"}'
curl -s "localhost:18443/v1/health?depth=-1&timeout=20s"
curl -s "localhost:18443/v1/health?command_id=<ID>&depth=2&detail=true"
```

**谁都能当发起者**：只要该节点配了 `api.http_addr`（判定**不看角色**，根 / 中继 / 叶子一视同仁），
`POST /v1/commands` 提交的指令就以**它自己为 origin**。`Target` 只有 `SUBTREE` 一种模式（本节点 + 名下子树），
于是结果只落在这棵子树里 —— `handle.go` 里 `OriginId == 本节点 ⇒ sink=SELF`，本节点结果**不上报给自己的父**，
**祖先对这条指令一无所知**（拿它的 ID 去父节点查是 `NOT_FOUND`）。所以"从中继提交一条只影响中继及其子树的
指令"天然成立；要跑这件事见 `test/from-any-node.sh`。

### 访问控制：一律凭 user token，没有免签来源

`api.http_addr` 可以写成 `0.0.0.0`，而这个端口上躺着几个**不可逆**的动作：`POST /v1/crl` 吊销节点
（本节点不校验 `?node=` 与自己的关系，直接写 CRL 并推给所有直接子）、`POST /v1/forget` 一条事务
删掉注册表 / 水位 / 驱逐归档 / 结果副本、`POST /v1/commands` 让整棵子树执行指令；读接口也暴露拓扑与结果。

判定顺序（前一条命中就不再往下判）：

| # | 请求 | 结果 |
|---|------|------|
| ① | `api.tls.require: true` 且请求是明文 | 拒绝（403 `ERR_API_TLS_REQUIRED`），**含回环来源** |
| ② | `GET /v1/healthz`（存活探针） | **永远放行**（只回 ok / node_id / path，不触发跨节点调用） |
| ③ | 其余**一切请求（读接口也在内）** | 必须带 `X-Treecmd-Token`，且该 token 能在本节点 `user/` 目录里找到并验签通过；找不到 ⇒ 401 |

**为什么没有"本机免签"**：免签的判据只能是 TCP 对端地址，而这个地址会被**部署形态**改写 ——
API 端口前面一旦挂了反向代理 / 端口转发（nginx、`ssh -L`、frpc、`kubectl port-forward`…），
远程请求的对端全都变成 127.0.0.1，"本机"于是成了**所有人**的身份（历史上这里就是这么被绕过的，
后来加过"转发头检测 + `trusted_proxies` 白名单"来收紧，现已整套删除）。按网络位置区分身份这条路
本身就不成立，现在只看凭据：**回环、局域网、外网一视同仁**。

凭据由节点的 CA 签发、按人一份，落盘在节点目录的 `user/<用户名>`（目录 0700、文件 0600）：

```bash
treecmd-node -config root/node.yaml -adduser alice     # 生成 root/user/alice，里面就是 token
treecmd-node -config root/node.yaml -adduser bob       # 再给一个人
```

token 内容是一行 `<16 位随机串>.<base64(CA 对 域+用户名+随机串 的 Ed25519 签名)>`：
文件内容**就是**要出示的凭据（可整份拷给运维机）。**发完不用重启节点** —— API 侧按 `user/` 目录的
变化自动重扫，删掉文件即刻收回：

```bash
curl -H "X-Treecmd-Token: $(cat root/user/alice)" http://127.0.0.1:18443/v1/tree
rm root/user/alice                                        # 收回 alice 的权限（下一次请求即失效）
```

```yaml
api:
  http_addr: 0.0.0.0:18443        # 端点只认 token，配置里**没有** auth 段
  tls:                            # 【可选】不写=明文 HTTP（对外暴露时会打 WARN）
    cert_path: certs/api.crt      # 配了 cert+key 就改以 HTTPS 提供
    key_path: certs/api.key
    # ca_path + client_auth: require —— 走 mTLS（只加固传输层，不替代 token）
    require: true                 # true = 明文请求一律拒绝（含回环来源）
```

**跨不可信网络请开 `api.tls`**：token 是长期凭据、每个请求都会上线，明文 HTTP 上被抄走即可原样重放
（`api.tls.require: true` 能把明文这条路彻底关掉）。用 `scripts/api_call.py` 调（零依赖）：

```bash
scripts/api_call.py --host 192.168.1.10:18443 --token-file ./alice \
    --tls --cafile ./ca.crt POST '/v1/forget?node=<GUID>&mode=stale'
```

四条边界要知道：

- **token 只能由本节点 CA 签**（`security.ca_key_path`；没有 CA 材料的节点 `-adduser` 会直接失败）。
  扫描 `user/` 目录时逐份验签，**手动往目录里塞一个自己编的文件不算授权**（目录权限只是第二道）。
- **收回就删文件**：`rm user/<用户名>`，下一次请求即失效，不需要重启、也不需要碰别的用户。
  `-adduser` 默认拒绝覆盖已存在的文件（不悄悄换掉在用的凭据），要换一份加 `-force`。
- **`user/` 目录固定**在节点目录下（与 `state.dat` / `enroll.token` 同级），不进 `config_hash`，
  也没有配置项 —— 凭据的落点越少一个自由度越不容易配歪。
- **验收这条不变量**：`test/api-auth.sh`（无 token 401 · 伪造文件 401 · 签发即生效 · 删除即收回 ·
  转发头不改变结论 · TLS 上仍要 token）。其余打 API 的测试脚本用 `test/lib/apitoken.sh` 现签凭据。

### 失效节点清理：`/v1/forget`

### 失效节点清理：`/v1/forget`

误启动的实例、注册被拒但调过一元 RPC 的节点，会在父端留下**再也回不来的记录** ——
它们永远出现在 `/v1/tree`、把健康检查的 `known` 撑大、让节点长期显示 DEGRADED。
根因是"只增不减"：子节点掉线与被驱逐都**不删**内存注册表与 `state.dat.known_children`
（后者每 30s 由注册表全量重建，重启时又被预热回注册表，形成闭环）。

`/v1/forget` 就是这条回收通道，全部动作都在本节点的**一条 bbolt 写事务**里完成：

| 能力 | 说明 |
|------|------|
| **按 UUID 清理** | `POST /v1/forget?node=<UUIDv7>`；不带额外参数时走**最保守**的默认模式 |
| **先预览再动手** | `GET` 是只读预演：会不会被允许、会被删掉哪些条目（含计数），**不改任何数据** |
| **在线的一律不删** | 正在滚动重启的子节点会被 `hub.conn` 命中 → 拒绝；`force` 也**不能**越过这条护栏 |
| **默认只清孤立残留** | `mode=garbage`（默认）只清"从未进入过注册表"的垃圾；清"曾连上过的直接子"必须显式 `mode=stale` |
| **`force=1` 是二次确认** | 越过"沉默时长"与"模式范围"两条判定，只保留在线护栏 |
| **纯删除，不写半截** | 一次事务内删 `assignments`(+反向索引) / `child_watermark` / `evicted_children`；失败整体回滚 |
| **默认保留结果副本** | `child_reports`（父端权威结果）默认**保留**（那可能是某条指令唯一一份已完成结果）；`purge=1` 才删 |
| **顺手解开 cmdlog** | 删掉死子的未终态 assignment 后，`MinUnfinishedSeq` 才能推进 —— 否则一个死子会**永久钉住整棵树的 cmdlog 水位** |
| **内存与快照一起收敛** | 事务成功后才 `Reg.Remove` 并立即 `saveState()`，否则 30s 后周期落盘会把 `known_children` 写回来 |
| **可批量** | `POST /v1/forget?all=1` 对本节点名下所有直接子逐个尝试，逐条返回结果 |
| **可审计** | 日志 `AUDIT-FORGET`（childID / mode / force / 各桶删除条数 / 保留报告数）；指标 `forget_total{result}` |

```yaml
# 两个阈值决定"要多沉默才算失效"（都是误删防护，可不配）
forget:
  grace: 1h            # 孤立残留的沉默阈值（防"正在重试注册、马上会成功"的节点被误清）
  dead_threshold: 24h  # 长期离线真子的判定线（与 command.eviction_timeout 同值）
```

```bash
ROOT=localhost:18443           # 该子节点的**直接父**的 API 地址

# 1) 先预览：它会告诉你为什么允许/拒绝，以及下一步该加什么参数
curl -s "$ROOT/v1/forget?node=<UUIDv7>"

# 2) 最保守的清理（只对"从未进过注册表"的孤立残留生效）
curl -s -XPOST "$ROOT/v1/forget?node=<UUIDv7>"

# 3) 曾连上过的失效节点：显式声明它是长期离线的
curl -s -XPOST "$ROOT/v1/forget?node=<UUIDv7>&mode=stale"
# 4) 确认无误、要立刻删（越过沉默时长判定）
curl -s -XPOST "$ROOT/v1/forget?node=<UUIDv7>&force=1"
# 5) 连它名下的结果副本一起清
curl -s -XPOST "$ROOT/v1/forget?node=<UUIDv7>&force=1&purge=1"
# 6) 批量：本节点名下所有"可清"的子节点
curl -s -XPOST "$ROOT/v1/forget?all=1&mode=garbage"
```

拒绝时返回非 2xx，响应体里 `reason` 是机器可读的原因、`hint` 直接告诉你该加什么参数：
`409 ERR_CHILD_ONLINE`（在线）/ `409 ERR_NEEDS_STALE`（在注册表里，需 `mode=stale`）/
`412 ERR_TOO_RECENT`（沉默不够，需 `force=1`）/ `404 ERR_CHILD_NOT_FOUND`（查无此人）。

> **为什么 CLI 不直连数据库**：运行中的节点独占 `state.db`（`store.Open` 锁超时 5s），
> 离线进程根本打不开库，所以清理必须走 HTTP 在进程内完成。
> **为什么不做"掉线即自动删"**：会误伤滚动重启中的正常子节点，也丢掉了运维信息 —— 改为显式命令 + 预览。
> 设计取舍见 ADR-052；实现与逐条说明在 `internal/node/forget.go` 的注释里。

## 目录结构

```
api/proto/node.proto        协议定义：**手写的唯一契约**（64 message / 11 enum / 1 service / 6 rpc）
internal/pb/                protoc 生成的 Go 绑定（7,467 行）；**勿手改**，重新生成方式见本节末尾
internal/identity/          UUIDv7、Ed25519、与系统树同构的 PKI、证书签发与链校验、启动强校验、mTLS
  lifecycle.go              信任锚目录扫描 + **信任锚自举（ChainAnchors）** + PathStamp/PathDigest（变更判定）
                            + 按公钥签发 + 入网握手 TLS
internal/config/            node.yaml 加载 / 校验（含 renew_at×3 ≤ lease_ttl 硬约束）/ config_hash 白名单
  nodeid.go                 node.id 解析：配置 → 证书身份 → state.dat → 生成（**只读，不写任何文件**，ADR-050）
internal/canon/             canonical 编码（确定性序列化）+ NodeID 16 字节大端升序排序
internal/persist/           state.dat：临时文件 + fsync + rename 原子写
internal/store/             bbolt：meta / commands / cmdlog / assignments / assign_child / child_reports /
                            local_state / pending_result / results / child_watermark / crl /
                            pending_index / evicted_children + 本地文件系统对象存储（objects/）
internal/registry/          直接子节点表、路径前缀路由、祖先链与环检测（不做 Target 筛选）
internal/aggregate/         TREE / MERGE / SUM / COUNT / CUSTOM + OnFailure 精确判定公式
internal/exec/              Executor 接口（含 OnRestart）+ noop / echo / sleep / fail + 安全空执行器
  apis/                     手写的对外 API 调用：**一个 API 一个函数**（uuid_v4、remote_time）+ Register(reg) 登记进执行器表
  script/                   执行外部脚本（type: "script"）：进程组回收 / 超时 / 输出限长 / result.json 读取
internal/node/              组装：handle / waitChildren / terminal / 租约 / 取消 / 健康 / 查询 / HTTP API
  enroll.go                 运行期入网签发：服务端（许可+白名单+PoP 校验→用 CA 私钥签公钥）+ 客户端（换取并落盘）
  reload.go                 证书热重载：stat 优先的两级变更判定 + SIGUSR1 + fail-safe + 生效策略
  build.go                  可执行文件一致性：启动算哈希 / 连上即比对 / 拉取校验 / 原地 exec 重启
  auth.go                   ReqAuth 跨跳委托凭证：入口签一次、逐跳原样透传、每跳离线验链 + 按自己白名单校验
  crl.go                    吊销列表：版本单调递增、身份密钥签名、逐跳转发、重连 CRLReq 全量对齐
  forget.go                 失效节点清理（/v1/forget）：判定口径 + 在线护栏 + 一条事务清四个桶 + 批量
  lifecycle.go              证书续签 / 配置热更 / Reconcile 对账 / 驱逐归档 / 索引待重发队列
internal/observability/     Prometheus 文本指标（零依赖）+ /metrics
cmd/node/                   单节点入口（一个节点一个进程）
examples/                   手工部署样例（阅读版）
  README.md                 部署阅读指南：角色对照 / 目录约定 / 字段生效时机 / 报错对照 / 检查清单
  node.yaml                 唯一一份权威配置样例：头部"按角色最简起步"，正文逐字段标角色与默认值
scripts/init_root.sh        根节点首次启动前的自签材料（一次性 bootstrap；其后签发与续期都归程序）
                            **不带参数即可跑**：目录默认当前目录、NodeID 现场生成 UUIDv7
                            并产出该节点的「入网引导凭据」enroll.token（许可 + 它自己的 CA 链）
scripts/make_bootstrap.sh   给任何有下级的节点产出/升级入网引导凭据（默认沿用已有许可，不轮换）
scripts/start_node.sh       单节点起停 / 换证重载（SIGUSR1）/ 配置热更（SIGHUP）
test/                       可视化测试台：本地网页 + 反向代理 + 一键起演示树（见 test/README.md）
  index.html                单文件控制台（零依赖、可离线）：总览 / 拓扑 / 健康 / 指令 / 指标
  serve.py                  本地静态服务 + /api 反向代理（默认只转发本机，零依赖）
  demo.sh                   一键起"根 + 直接叶子 + 中继 + 中继下的叶子"（3 层）+ 起控制台
  selfupdate.sh             可执行文件自同步的端到端验证（起树 / 换版本 / 断言原地重启）
  forget.sh                 失效节点清理的端到端验证（起树 / 在线拒绝 / 掉线后清理 / 重启断言不回灌）
docs/                       手动部署指南、项目功能完整介绍、代码注释规范、四项外部经验借鉴方案
```

### 代码注释约定

**每个函数/方法都要有一段 doc comment**，说明「它是干嘛的」和「参数是什么东西」——
写法（首行函数名开头、参数/返回用 tab 缩进的块）见 **`docs/代码注释规范.md`**。
通读某个包时可以直接用 `go doc -all ./internal/config` 把注释按格式打出来。

### 生成代码（`internal/pb/`）：从哪来、怎么重新生成

`internal/pb/node.pb.go`（7,146 行）与 `internal/pb/node_grpc.pb.go`（321 行）**都是 protoc 自动生成的，不要手改**
—— 头部写着 `DO NOT EDIT`，下次生成会被覆盖；而全仓库有 **20 个文件**引用这个包，改错是全局性的。

| 文件 | 负责什么 |
|------|---------|
| `api/proto/node.proto` | **唯一的协议契约**（手写）：64 message / 11 enum / 1 service / 6 rpc |
| `internal/pb/node.pb.go` | **数据面**：每个 message → 一个 Go struct（字段编号写在 `protobuf:"bytes,N,..."` tag 里）、11 个枚举及其 `String()`、375 个 nil 安全的 `GetXxx()`、25 个 `oneof` 包装类型、协议自描述符 |
| `internal/pb/node_grpc.pb.go` | **调用面**：`NodeServiceClient` / `NodeServiceServer` 接口与 6 个 RPC 的桩 |

编解码本身在 `google.golang.org/protobuf` 运行时库里；这两个文件提供的是**内存布局 + 字段编号 + 反射信息**。
所以业务代码从不手写字节：`canon.Digest` 用的 `proto.MarshalOptions{Deterministic: true}` 就作用在这些类型上 ——
**wire 格式、摘要、签名三者一致性的根基，就是 `.proto` → `pb.go` 这条链。**

一次性准备（本机若没有）。**注意本机（以及多数 mac/开发机）默认没有 `protoc`**，
本项目用的是 `grpcio-tools` 自带的 protoc，所以不需要装 `protobuf-compiler`：

```bash
# ① protoc 本体：放在仓库外的固定位置，避免污染项目目录
python3 -m venv ~/.cache/treecmd-protoc
~/.cache/treecmd-protoc/bin/pip install -q grpcio-tools

# ② 两个生成插件（Go 侧）
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest          # 生成 node.pb.go
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest         # 生成 node_grpc.pb.go
```

改了 `api/proto/node.proto` 之后，重新生成：

```bash
~/.cache/treecmd-protoc/bin/python -m grpc_tools.protoc -I api/proto \
  --plugin=protoc-gen-go=$HOME/go/bin/protoc-gen-go \
  --plugin=protoc-gen-go-grpc=$HOME/go/bin/protoc-gen-go-grpc \
  --go_out=.      --go_opt=module=treecmd \
  --go-grpc_out=. --go-grpc_opt=module=treecmd \
  api/proto/node.proto
go build ./...        # 生成后一定要编译一遍
```

> 用哪个解释器很重要：真正的 `python -m grpc_tools.protoc` 需要**装了 grpcio-tools 的那个**解释器。
> 系统自带的 `python3` 通常没有这个包，直接跑会报 `No module named grpc_tools`。
>
> 当前生成产物对应的工具链版本（写在 `node.pb.go` 头部，换版本可能产生无关 diff）：
> `protoc-gen-go v1.36.12`、`protoc v7.35.1`。用上面这套重跑，输出与仓库里的现有文件**逐字节一致**（已验证幂等）。

三条硬规矩（proto 文件头部也写了）：

1. **字段编号一旦用过就不能改** —— 它是 wire 兼容的唯一依据；要改只能新增编号。
   （proto 里那些标着"已下线"的枚举值，就是为保留编号而留的。）
2. **`optional` 要显式用** —— proto3 标量分不清"没传"和"传了 0"，本项目一律靠 `*T` 指针 + `!= nil` 区分。
   例：`AttestDepth *int32` —— 不传 = 默认 1，显式传 `0` = 无上限（全树背书）。
3. **枚举第一个值必须是 `*_UNSPECIFIED = 0`**；所有摘要/签名一律对 canonical（确定性）编码取，
   repeated 字段在取摘要前按 NodeID 的 16 字节大端升序排序。

## 已实现的核心机制（对应方案章节）

- **双角色单进程**：`DownstreamHub`（服务端）+ `UpstreamLink`（客户端）+ `TaskEngine`（1.1，ADR-001/027）
- **拉模式工作队列**：`FetchCommands` 返回"seq 增量的新指令 ∪ 名下 Assignment 重投"，投递由 Assignment + 租约驱动，
  与内容水位解耦（3.1/3.2/ADR-022/036）；父端不信任客户端 `since_seq`（取 `max(客户端, 父侧权威水位)`）；
  响应构造与水位落盘同一事务，**绝不回退**；`fetch_response_max_bytes`(3.5MB) 父端兜底截断
- **租约**：`LeaseTTL` 只做活性检测、租约过期即回收（只看父时钟）、回收不推进 `attempt`（3.4）
- **下发背压（在途窗口）**：父端"已经交到子手上、还没回终态"的分派条数有上限，补上"只有字节上限"的缺口 ——
  没有它，一个子可以一次把它名下所有分派全拉走。
  「在途」= Assignment 处于 `LEASED` 且租约仍有效（`PENDING`、以及 `LEASED` 但租约已过期的僵尸租约都不算，
  否则一次父重启就能把窗口占满、把自己锁死）。
  `max_dispatch_inflight_per_child`（默认 8；因为单条指令对每个子只有 1 个 Assignment，所以它只在你
  同时压了 >8 条指令给同一个子时才生效）、`max_dispatch_inflight`（默认 0 = 不限）、
  `dispatch_window_adaptive`（按在线子数自适应，只会收紧）；超窗时**只限速、不丢任务**，
  计数落在 `dispatch_throttled_total{reason}` 上
- **`LocalBusy` 指数退避**：子说"忙"是它**本机全局**的（本地并发闸门满了），所以一批指令会被**同时**退回来。
  固定间隔会让它们在同一时刻齐刷刷重投、把刚要缓过来的子再打一遍；改成
  `min(local_busy_backoff << (n-1), local_busy_backoff_max)`（默认 3s 起、60s 封顶）让重投时刻自然错开。
  `attempt` 依旧不推进（退避只决定"什么时候再投"，不决定"第几次尝试"）；
  连续次数只在两处归零：收到 `InflightHint`（子报告正在跑，唯一的正向证据）与租约回收（状态不可知）
- **本地三态**：`NOT_STARTED/SELF_RUNNING/SELF_DONE/SELF_FAILED/SELF_CANCELLED/COMPLETED`；
  `SELF_RUNNING` 先落盘再执行（`OnRestart` 的唯一触发条件）；`SELF_DONE` 与两个本地终态绝不重跑（3.5，ADR-016/039）
- **终态单事务**：`terminal()` 一个 bbolt 事务里写 `local_state` + `CommandRecord.Status` + 结果归宿
  （`sink==SELF → results`，`sink==UPSTREAM → pending_result`，含唯一一处 `SelfResult` 裁剪）（1.1，ADR-037/046/049）
- **`waitChildren` 状态机**：进入顺序"重建上下文 → 审退出原因标记 → 命中对账 → 判空 → 写 RUNNING"；
  独立 `Deadline` timer + 带 jitter 的 tick；`applyEvent` 后立即判 `OnFailure` 上限；
  退出前落定未上报子的 Assignment 并落"退出原因标记"；`Cancelled/Deadline` 三态互斥（3.16，ADR-042/047/049）
- **收尾语义的三个要点**（都是"看着像小细节、踩过才知道要紧"的那类）：
  - **死线是兜底，不是"到点就抹掉已到手的事实"**：死线分支会**先复查等待集合**，
    已经没有待上报的子时按**正常完成**收敛 —— `select` 在"最后一个子上报"与"死线到点"同刻就绪时
    是随机挑分支的，不做这次复查就会判出 `TIMEOUT`，而 `result` 里其实全齐了。
  - **收尾时点名"始终没有上报的子"**：父会给**注册表里的每个直接子**建 Assignment（下发即执行，
    不做筛选），所以一个已废弃的**残留子节点**（重建过密钥 / 换过机器，旧 NodeID 留在 `known_children` 里）
    会让**之后每条指令**都白等到期限。日志里点名 + 给出 `/v1/forget` 的预览/清理命令，
    是运维唯一的线索（状态码只会说 TIMEOUT）。
  - **重试预算用尽 ⇒ 父侧判定该子失败**：`max_retry_node_count`（默认 3）用尽时把该子置为 `FAILED`
    （参与失败策略的 `NotDone` 统计，但**不进背书链** —— 它没有 Report.Sig，硬塞就是伪造背书），
    并回报 `judged: FAILED`。否则运维唯一的自救手段会用完即止，指令只能继续干等死线
- **`child_reports` 持久化闭环**：接受子报告 = 单事务（写权威副本 + 置 Assignment 终态 + 记生效 attempt），
  `ok=true` 语义 = "已持久化接受"；`waitChildren` 进入时由它重建已完成的支（ADR-048/049）
- **补报**：`pending_result` 先落盘 → 上报 → 收到 `ok` 才清理；三级路径（内联 / 分片 / 引用）由 `reportUpstream`
  按字节数自动选择；周期重发 + 每次 Fetch 成功顺手重发（单飞 + 批量上限 + 指数退避）（3.11）
- **取消**：`cancelCommand` 只置进程内原子标志 + `cancel()`；终态与 `children` 由持有 `childrenBuf` 的协程写；
  必经路径 = 续租响应回带终态（3.9，ADR-048/049）
- **下发即执行**：父节点下发的任务，子节点收到就执行本地部分，**框架不做任何按路径 / 标签的筛选**
  （`Target` 只保留 `SUBTREE` 一种语义；`NODE` / `SELECTOR` 提交时返回 `ERR_TARGET_NOT_SUPPORTED`）；
  `waitChildren` 仍保留"应发未发"对账兜底，覆盖对账窗口内新注册进来的子节点（3.16）
- **逐跳重签名与背书链**：下行 `HopChain` per-child 派生（对"即将发出的内容"取 Digest，先签后追加）；
  上行 `ChildAttest` 含 `Descendants`（`AttestDepth==0` 为无上限）；子节点四项校验（ChildID/ForwarderID/Digest/Sig）；
  origin 签名只覆盖创建后不可变字段、用内联 `OriginCert` 离线验（7.5/7.6，ADR-024/032/034）
- **身份与 PKI**：UUIDv7 + Ed25519（CSPRNG，绝不从 GUID 派生）、证书由父签发、PKI 与系统树同构、
  全链到根、启动强校验（文件/私钥/证书/链/一致性任一失败 fatal）、epoch 双主仲裁、环检测（7.1~7.9）
- **健康检查 / 指令轨迹**：双模式、`depth` 逐跳递减、`timeout_ms` 逐跳只减不增（留执行余量）、
  `detail` 控制完整对象、每节点身份签名 + 父端四步校验、`SubtreeSummary` 逐层累加、
  按查询重量三把锁单飞（在途即拒 429）（第 4 章，ADR-021）
- **结果落库与查询**：发起节点 `results` upsert 幂等；`ResultIndex` 内存缓存 + 结果索引上行到根（`ownerSig`/`hopSig`）+ 周期重推；
  查询沿父链上行找索引 → 从"确定为持有者祖先"的一跳沿 `owner_path` 下行 → 沿 `reqID → 上游跳` 转发表反向原路回（3.14，ADR-035/038/048）
- **持久化**：配置 / 状态分离、`config_hash` 白名单、`state.dat` 原子写、`next_cmd_seq` 权威值在 bbolt `meta`（只增不减）、
  保留水位 = `min(min{FetchedCmdSeq}, min{未终态 Assignment 的 LocalSeq})`（第 6 章）
- **后台任务**：租约回收（LeaseTTL/3）、驱逐扫描、指令日志清理、`pending_result` 重发、`state.dat` 落盘、
  results 清理、索引重推、驱逐归档回收、结果索引待重发、证书续签调度（13.6）

### 本轮新增（批次 A–E）

| 能力 | 实现要点 |
|------|---------|
| **CA 材料强校验** | `ValidateStartup` 对 CA 证书做与身份证书同强度的校验：`IsCA`、`keyUsage certSign`、有效期、**链到信任锚**、CN 含 nodeID；新增显式 `security.ca_cert_path`（不再靠 `<cert>.ca` 魔法路径） |
| **`AttestDepth` 语义修正** | proto 改 `optional int32`：不传 = 默认 1，**显式 0 = 无上限（全树背书）**；修掉"`RawChildren=true, AttestDepth=0` 被误拒"的缺陷 |
| **`Unreported` 显式建模** | 新增 `WaitResult.ParentJudged`；父侧判定的失败/超时**计入 `NotDone`**，同时 `Outcomes` 与背书链恢复严格 1:1（不再往 `Outcomes` 里塞无 Attest 的条目） |
| **CRL 吊销** | 版本单调递增（只应用更高版本）、发送方身份密钥签名、逐跳转发、重连 `CRLReq` 取全量对齐、服务端拦截器 + `serveConn` 双重拦截；`GET /v1/crl`、`POST /v1/revoke?node=` |
| **证书续签** | 父在子 Connect/RESUME 时检查剩余有效期，**进入 2/3 生命期窗口即换发** `CertRenewOffer`；子原子替换证书文件 + `TLSContainer` 热切换 + 重连握手；子侧每小时主动调度；TLS 层给"过期 ≤7 天"续签宽限，应用层只放行注册/续签帧 |
| **配置热更** | `SIGHUP` 重读 `node.yaml`：只改运行参数 → 原地热更；进 `config_hash` 的字段变了 → 触发全量重注册。父经 `ConfigPush{overrides}` 下发运行参数，子端**白名单校验**（只接受 `command./health./query./persist.`，绝不接受 identity/parents/listen） |
| **Reconcile 对账** | 子重连后上报本地未终态指令（完整 wire `Command`）；父内联 `OriginCert` 离线验 origin 签名 + 校验末条 `HopAttest` 指向自己 → 与我持有的派生结果逐字节比对：一致则重置 Assignment 重投，**不一致即拒绝并记审计**；父已无记录则按子上报内容重建 |
| **驱逐归档** | 驱逐前把该子名下未终态 Assignment 的**指令体归档**到 `evicted_children`；`ChildWatermark.evicted` 让它**退出保留水位计算**；子回来对账成功后清归档；归档保留期到期连同水位条目一并回收 |
| **对象存储引用** | 本地文件系统 `objects/<sha256[:2]>/<sha256>`，原子写 + 摘要寻址；>64MB 的结果走引用、父端按引用取回并校验摘要 |
| **`QueryData` 分片回传** | >256KB 的查询结果：先回元数据 `QueryResp{has_data}`，再沿同一回程发 `QueryData` 分片（逐片 gzip + crc32 + 持有者身份签名、**首片带证书链供入口离线验链**）；入口收齐拼装；超 `query_response_max_bytes` 降级为引用；校验失败回"校验失败"而不是 `NOT_FOUND` |
| **`ReqAuth` 跨跳委托** | 入口签一份短时委托（ViewerID / EntryCert / EntrySig / NotAfter / Kind / **ParamsHash 只绑定跨跳不变的 command_id+detail+Kind**）；每跳用预置根证书**离线**验链验签，再按**自己的** `health_viewers`（默认"直接父 + root"）/`query_viewers`（默认放行）决定是否服务/转发；拒绝落审计日志 |
| **CUSTOM 聚合器注册** | `aggregate.RegisterCustom/LookupCustom`；`aggregate=CUSTOM` 必须给 `aggregate_name`（随指令逐跳透传），未注册 → `ERR_UNKNOWN_CUSTOM_AGGREGATOR`；声明 `NeedsSelfResult()` 而未开 `raw_children` → 提交期即拒；内置 `subtree_count` / `audit_raw` 两个示例 |
| **`/metrics`** | 手写 Prometheus 文本（零依赖）：`node_up`、`children_count/known`、`command_inflight/pending_total`、`partial_total`、`pending_result_backlog`、`retention_floor`、`result_index_entries`、`clock_offset_ms`、`command_terminal_total{status}`、`fail_rate_1h`、`result_stored_total`、`untrusted_origin_rejected_total`、`selfupdate_total{result}`、`selfupdate_lagging_children`、`binary_info{hash}`、`forget_total{result}`、`dispatch_throttled_total{reason}`、`local_busy_total`、`child_dispatch_inflight{child}`、`dispatch_window_per_child`、`dispatch_window_total` … |
| **祖先 NodeID 链** | `RegisterAck.ancestor_ids`：环检测与 `health_viewers` 默认白名单（"直接父 + **root**"）都要按 ID 判定 —— 根的路径是 `"/"`，从路径里取不出它的 NodeID |
| **健康扫描可取消** | 健康/轨迹递归跟随 HTTP 请求的 `ctx`：调用方放弃即停止扇出与等待，避免"被丢弃的扫描"在后台堆积 |

## 协议与数据面

- **传输**：gRPC over HTTP/2 + TLS 1.3，mTLS 双向认证；`Connect` 双向流承载所有父 → 子控制帧
  （`CommandNotify` / `CommandCanceled` / `TerminalNotice` / `HealthReq` / `QueryReq` / 回程 `QueryResp`/`QueryData`）
- **序列化**：protobuf（`.proto` 是唯一协议约定；枚举 0 值一律 `*_UNSPECIFIED`，需显式设置的字段用 `optional`）
- **canonical 编码**：`proto.MarshalOptions{Deterministic:true}`；`repeated` 在取摘要前显式按
  **NodeID 的 16 字节大端升序**排序（不是字符串字典序）；时间字段一律 `google.protobuf.Timestamp`

## 实现说明（与方案的差异 / 有意取舍）

1. **PKI 中 CA 证书独立一张**：方案 7.7 的"CA 密钥按需生成 → 向父重签自身证书为 `CA:TRUE`"在本实现中改为
   "为有子节点的节点额外签发一张独立 CA 证书（`CA:TRUE`，含 CA 公钥）"。理由：方案写法会让"身份密钥"与"CA 密钥"
   落在同一张证书上，而子节点证书由 CA 密钥签发、其公钥却不在父的身份证书里，**标准 x509 链无法校验**。
   改动后"双密钥互相隔离"与"PKI 与树同构"都不变，且链校验成立。
2. **仍未实现（明确标注，均不在主链路正确性路径上）**：
   - **根 CA 轮换的双签过渡期**：`ca_cert_paths[]` 多锚已支持，但缺"同时信任新旧根 + 全树滚动重启"的运维编排；
   - **`evicted_children` 的跨节点取回**：归档在本节点，未做跨节点共享存储；
   - **对象存储的跨节点取回**：引用只保证"同一节点可取回"（本地文件系统）。跨节点共享需换成 S3/共享盘；
   - **`AttestDepth ≥ 2` 的递归背书校验**：`Descendants` 已回传，但父端默认只验直接子层，未实现审计态的递归验签；
   - **健康请求的应用层限流**：`health.rate_limit_per_sec` 已在配置里，未接入限流器（单飞互斥已实现）；
   - **`ConfigPush` 的下行策略**：仅支持父手写 `overrides` 下发，未做"根推到全树"的中心化分发；
   - **入网许可的时效性**：`enrollment.token` 是长期共享串（父端无状态），没有"一次性许可 / 许可过期"机制
     （它是**必需**的 —— 没有许可就拒绝一切入网）；
     要更强的话可以升级成"每节点一枚一次性许可（用后即废）"，那时"这次准入发给谁"才真正可限定；
   - **证书热重载不跟随符号链接目标**（按 `stat` 的 size+mtime 判定）；若你的脚本用 `ln -sf` 变更新链接目标，
     `lstat` 层面的 mtime 也会变，实测可触发；但若只替换目标文件内容而不动链接，则依赖目标文件的 mtime 变化。
3. **`AttestDepth` 已改为 `optional int32`**（不再有 0 值歧义）：不传 = 默认 1，显式 `0` = 无上限（全树背书）。
   唯一的行为变化是"不传 `attest_depth` 的指令默认只回传到直接子层"，与方案 7.5 一致。
4. **`Target` 只保留 `SUBTREE`**：环境是"父节点下发、子节点直接执行"，不做按路径 / 标签的筛选，
   因此 `SELECTOR`（标签选择器）与 `NODE`（点对点寻址）已下线，提交时返回 `ERR_TARGET_NOT_SUPPORTED`。
   proto 里保留了字段与枚举值，需要恢复点对点下发时改动面很小（提交校验 + `EnsureCreated` 的建 Assignment 范围）。
5. **`Unreported` 已显式建模**：父侧判定的终态子放在 `WaitResult.ParentJudged`（`Unreported` 的子集），
   计入 `NotDone`（否则"有子失败、整条指令却判成功"）；`Outcomes` 严格 = "收到过 Report 的子"，与 `Children` 背书链 1:1。
6. **健康响应的 `SubtreeSummary` / `TraceSummary`**：已**回写进方案 4.3**（`ChildHealth.Summary` / `ChildTrace.Summary`）——
   `detail=false` 时也必须回传，且明确"`detail` 只控制是否回完整对象、不控制汇总"。
7. **`Hub.handleHeartbeat` 除续租响应外**还会回一个 `HeartbeatAck` 帧承载 `t2`/`t3`（用于 EWMA 时钟偏移）与 `terminal[]`
   （"续租响应必须回带终态"那一半同一必经路径）。已**补进方案 5.6 的帧表**。
8. **`Startup` 强校验对 CA 证书同样严格**：新增显式 `security.ca_cert_path`（不再靠 `<cert>.ca` 魔法路径），
   并对 CA 证书校验 `IsCA` / `keyUsage certSign` / 有效期 / 链到信任锚 / CN 含 nodeID。
