# treecmd 可视化测试台

一个本地网页，用来**看着**一棵 treecmd 树跑指令：提交、跟踪、看结果、扫健康、看指标。
不依赖任何外部库，离线可用；不修改 treecmd 的任何代码。

本目录在仓库的 **`test/`** 下，`demo.sh` 会按自身位置自动找到仓库根（不需要配路径）。

## 三种用法

```bash
cd test

# ① 一条命令把"树 + 控制台"都起起来（推荐第一次用）
./demo.sh start          # 起 根 + 直接叶子 + 中继 + 中继下的叶子（3 层），再起控制台
./demo.sh status         # 看各节点活着没
./demo.sh logs relay     # 看某个节点的日志
./demo.sh stop           # 全停

# ② 只起控制台，连你自己的节点
python3 serve.py --target 127.0.0.1:18443        # 然后浏览器开 http://127.0.0.1:8899/

# ③ 连别的机器上的根节点
python3 serve.py --target 10.0.0.5:18443 --allow-any-host
```

打开 `http://127.0.0.1:8899/`，页面右上角可以随时改目标地址，不必重启代理。

## 为什么要一个代理（`serve.py`）

控制台在 `127.0.0.1:8899`，treecmd 的 HTTP API 在另一个端口 —— 浏览器按跨源处理会拒收响应。
本可以给 treecmd 加 CORS 头，但那是**动程序的安全面**只为方便测试工具，不值；所以让页面走同源
`/api/<path>`，由代理转发到目标地址。默认**只允许转发到本机**（`--allow-any-host` 放开），
避免这个本地端口变成一个可以打任意内网的跳板。

## 页面上能做什么

| 标签页 | 对应接口 | 说明 |
|---|---|---|
| 总览 | `/v1/tree` | 根的角色/名字/备注/labels/caps、在线子节点数、结果索引条数 |
| 拓扑 | `/v1/tree` | 本节点 + 直接子节点的树形视图（**只有一层**，见下） |
| 健康 | `/v1/health?depth=-1&detail=true` | 全树扫描：本节点 checks、子树汇总、每个直接子的状态与"它下面还连着几个" |
| 指令 | `/v1/commands` | 8 个预设场景 + 手填全部字段；提交后自动轮询到终态，TREE 聚合结果可递归展开；支持取消 / 按子节点重试 |
| 指标 | `/metrics` | 关键指标卡 + 全部 Prometheus 条目 |

预设场景：全树 echo(TREE)、全树计数(COUNT)、慢指令 sleep 2s、全树失败(fail)、
失败+BEST_EFFORT、失败+TOLERATE_N:2、标签筛选失败(k=v)、64KB 大载荷。

## 两个「只有一层」的诚实说明

`/v1/tree` 和 `/v1/health` 的 **JSON 都只展开本节点 + 直接子节点**：子节点的 API 地址不在响应里，
所以控制台看不到更深的层次。更深层的信息只有两个：`children_online`（该子下面还连着几个）与
`summary.total`（逐层累加，但**不含本节点自己** —— 4 个节点的树报 `total=3`，而 COUNT 聚合报 4）。

## 环境要求

Python 3（系统自带的 3.9 就能跑）与一个能访问到的 treecmd 根节点。

`demo.sh` 还需要仓库里的 `bin/treecmd-node`（`go build -o bin/treecmd-node ./cmd/node`）
和 `scripts/init_root.sh`；仓库根默认由脚本位置推导（`test/` 的上一级），
确实要指别处时用环境变量 `TREECMD_REPO` 覆盖。

## 可执行文件自同步怎么验（`selfupdate.sh`）

控制台看的是"树跑得对不对"；`selfupdate.sh` 看的是另一件事：**子节点跑的是不是父那一份镜像**。

```bash
./selfupdate.sh prepare    # 预生成 v1 / v2 两个"内容不同"的可执行文件（编译吃内存，单独跑更稳）
./selfupdate.sh all        # 起根(v2) + 三个子节点各自以 v1 启动 → 断言它们自己跟上并原地重启
./selfupdate.sh readonly   # 负向用例：暂存目录只读 → 断言 fail-safe（继续服务、不重启循环）
./selfupdate.sh stop
```

它断言的是四件硬事实：① 子节点确实向父申请了镜像；② 校验通过后**原地重启**（PID 必须不变）；
③ 磁盘上它自己那份文件真的变成了 v2 的内容；④ 整棵树收敛（根视角 `lagging_children=0`）。
另外还跑两条对照：**同版本时不得有任何同步动作**，以及**暂存目录只读时必须继续服务**。

> 脚本刻意**不**做"替换正在运行的可执行文件"这个动作。原因见 `internal/node/build.go` 的
> `commit()`：替换必须走"写暂存文件 + rename"，而 macOS 上"原地覆盖某个可执行文件之后立刻
> exec"会被内核直接判死（`Killed: 9`、日志一行都没有）—— 这正是程序自己用 rename 的原因。

## 运行产物（都已 gitignore）

`demo.sh` / `selfupdate.sh` 只在**本目录**下产出这些东西，不会污染仓库其它位置，也不需要提交：

| 路径 | 内容 |
|---|---|
| `demo/` | 演示集群的节点目录（含 **私钥与证书**，所以不能进版本库） |
| `logs/` | 各节点与控制台的日志 |
| `.demo.pids` | 进程 pid 表（`stop` / `status` 用） |
| `.selfupdate/` | `selfupdate.sh` 的工作区：各节点的二进制副本与节点目录 |

想彻底清干净：`./demo.sh stop && ./selfupdate.sh stop && rm -rf demo logs .demo.pids .selfupdate`。
