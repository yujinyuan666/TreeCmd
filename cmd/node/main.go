// Command node 是单节点入口：一个进程同时是客户端与服务端，形态由 node.yaml 决定。
//
// 典型的手工部署用法（单服务器、手工起进程、证书由外部脚本管理）：
//
//	treecmd-node -genkey -keydir keys -with-ca        # 一次性：生成本节点的密钥对（程序启动路径绝不生成）
//	treecmd-node -check   -config node.yaml           # 部署前自检：只读配置与证书，不监听不连接
//	treecmd-node          -config node.yaml           # 启动（证书暂缺时会先向父入网签发）
//	kill -USR1 <pid>                                  # 证书脚本换证后：立刻重载，无需重启
package main

import (
	"context"
	"crypto/ed25519"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"treecmd/internal/config"
	"treecmd/internal/identity"
	"treecmd/internal/node"
)

// main 解析命令行参数，并驱动单节点的整个生命周期（自检 / 入网 / 启动 / 信号处理）。
//
// 分支顺序是：-print-sample-config 打印样例 → -genkey 生成密钥 → 没有 -config 就打印用法并退出
// → 正常加载配置 → -check 只自检并退出 → -enroll 只入网并退出 → 否则启动并阻塞在信号循环里。
//
// 启动后的信号语义：
//
//	SIGHUP            —— 配置热更（只重读运行参数段；关键字段变了会自动触发全量重注册）
//	SIGUSR1           —— 立即检查并重载证书（外部证书脚本换证后用，秒级生效、无需重启）
//	SIGINT / SIGTERM  —— 优雅退出
//
// 出错时直接 os.Exit 带非零退出码，不返回。无参数、无返回值。
func main() {
	var (
		cfgPath  = flag.String("config", "", "node.yaml 路径")
		logLevel = flag.String("log-level", "info", "debug|info|warn|error")
		check    = flag.Bool("check", false, "只做部署前自检：校验配置与证书材料，不监听、不连接、不落盘")
		enroll   = flag.Bool("enroll", false, "只做一次运行期入网（向父换取证书并写入证书文件），然后退出")
		genkey   = flag.Bool("genkey", false, "一次性生成本节点密钥对（程序启动路径绝不生成密钥，这是显式的部署工具）")
		keyDir   = flag.String("keydir", "keys", "-genkey 的输出目录")
		withCA   = flag.Bool("with-ca", false, "-genkey 时一并生成 CA 密钥对（有子节点的节点才需要）")
		sample   = flag.String("print-sample-config", "", "打印带注释的样例配置：root | child | relay | leaf")
		force    = flag.Bool("force", false, "-genkey 时覆盖已存在的密钥文件")
	)
	flag.Parse()

	if *sample != "" {
		if err := printSampleConfig(*sample); err != nil {
			fmt.Fprintln(os.Stderr, "FAILED:", err)
			os.Exit(2)
		}
		return
	}
	if *genkey {
		if err := generateKeys(*keyDir, *withCA, *force); err != nil {
			fmt.Fprintln(os.Stderr, "genkey FAILED:", err)
			os.Exit(1)
		}
		return
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: treecmd-node -config <path/to/node.yaml> [flags]")
		fmt.Fprintln(os.Stderr, "       treecmd-node -check -config node.yaml")
		fmt.Fprintln(os.Stderr, "       treecmd-node -enroll -config node.yaml")
		fmt.Fprintln(os.Stderr, "       treecmd-node -genkey -keydir keys [-with-ca]")
		fmt.Fprintln(os.Stderr, "       treecmd-node -print-sample-config root|relay|leaf")
		flag.PrintDefaults()
		os.Exit(2)
	}

	logger := newLogger(*logLevel)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		logger.Error("load config failed", "err", err)
		os.Exit(1)
	}
	// node.id 的解析结论（ADR-050）：让"这个 ID 是哪来的"在启动时就一眼可见
	switch cfg.NodeIDSource {
	case config.IDFromGenerated:
		logger.Info("node.id 未写定 → 本次生成（将写入 state.dat，此后跨重启稳定）",
			"node_id", cfg.Node.ID, "state", cfg.NodeIDStatePath)
	case config.IDFromCert:
		logger.Info("node.id 取自证书身份", "node_id", cfg.Node.ID)
	case config.IDFromState:
		logger.Info("node.id 取自 state.dat", "node_id", cfg.Node.ID, "state", cfg.NodeIDStatePath)
	}
	if cfg.NodeIDWarning != "" {
		logger.Warn("node.id 来源冲突：" + cfg.NodeIDWarning)
	}
	if *check {
		os.Exit(runCheck(cfg))
	}

	n, err := node.NewWithPath(cfg, *cfgPath, logger)
	if err != nil {
		// 启动强校验失败一律 fatal（不放行）
		logger.Error("node init failed", "err", err)
		os.Exit(1)
	}

	if *enroll {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := n.EnsureCertificate(ctx); err != nil {
			logger.Error("enroll failed", "err", err)
			os.Exit(1)
		}
		logger.Info("enroll done", "cert", cfg.Security.IdentityCertPath)
		return
	}

	if err := n.Start(nil); err != nil {
		logger.Error("node start failed", "err", err)
		os.Exit(1)
	}
	if n.HasUsableCert() {
		logger.Info("node up", "role", string(cfg.Role()), "node_id", cfg.Node.ID)
	} else {
		logger.Warn("node up in ENROLLMENT mode（证书待签发）", "role", string(cfg.Role()), "node_id", cfg.Node.ID)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)
	for s := range sig {
		switch s {
		case syscall.SIGHUP:
			// SIGHUP = 配置热更（只在运行参数段生效；关键字段变了会自动触发全量重注册）
			if err := n.Reload(); err != nil {
				logger.Error("config reload failed", "err", err)
			}
		case syscall.SIGUSR1:
			// SIGUSR1 = 立即检查并重载证书（证书脚本换证后用它，秒级生效，无需重启）
			logger.Info("cert reload requested by SIGUSR1")
			n.TriggerCertReload("SIGUSR1")
		default:
			logger.Info("shutting down", "signal", s.String())
			n.Stop()
			return
		}
	}
}

// newLogger 按级别文本创建一个写往标准输出（os.Stdout）的文本格式日志器。
//
// 级别解析失败的（拼错、大小写不对）静默退回 info，不报错、不终止。
//
// 参数：
//
//	level — 级别文本，如 "debug" / "info" / "warn" / "error"
//
// 返回：
//
//	*slog.Logger — 已绑定级别的日志器
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

// runCheck 打印一份部署前自检报告，并返回进程退出码。
//
// 只读：不监听端口、不连接父节点、不落盘。报告内容全部来自 node.Check 的结论，
// 把"配置里补了哪些默认值""node.id 是哪来的""哪些是警告"逐条摊开给人看。
//
// 参数：
//
//	cfg — 已由 config.Load 加载并校验过的节点配置
//
// 返回：
//
//	int — 0 表示自检通过、可以启动；1 表示存在不可启动的问题（详见打印的 [不可启动] 行）
func runCheck(cfg *config.Config) int {
	rep, err := node.Check(cfg)
	// line 按固定列宽打印一行"标签  值"，让整份报告左右对齐。
	line := func(k, v string) { fmt.Printf("  %-22s %s\n", k, v) }
	fmt.Printf("== 配置与身份材料自检 ==\n")
	line("节点 ID", fmt.Sprintf("%s（来源：%s）", rep.NodeID, rep.NodeIDFrom))
	line("节点名", emptyDash(rep.NodeName))
	line("备注", emptyDash(rep.NodeRemark))
	line("形态", rep.Role)
	line("监听", emptyDash(rep.Listen))
	line("上游父", emptyDash(strings.Join(rep.Parents, ", ")))
	line("信任锚", fmt.Sprintf("%d 张（%s）", rep.TrustAnchors, emptyDash(strings.Join(rep.TrustAnchorPaths, ", "))))
	line("可签发子证书", yesNo(rep.CanIssueChildCerts))
	line("运行期入网", fmt.Sprintf("%s（许可 %s，白名单 %s）", onOff(rep.EnrollmentEnabled),
		yesNo(rep.EnrollTokenSet), emptyDash(strings.Join(rep.AllowIDs, ","))))
	line("证书热重载", fmt.Sprintf("%s（间隔 %s）", onOff(rep.CertReloadEnabled), rep.ReloadInterval))
	if rep.PendingEnroll {
		line("证书", "尚未签发 → 将向父入网换取")
	} else if rep.CertSerialOK {
		line("证书", fmt.Sprintf("有效至 %s（指纹 %s）", rep.CertNotAfter.Format(time.RFC3339), rep.CertFingerprint))
	}
	if cfg.NodeIDSource == config.IDFromGenerated {
		line("node.id", fmt.Sprintf("未写定 → 启动时生成 %s 并写入 %s（本次只读自检，未落盘）",
			cfg.Node.ID, cfg.NodeIDStatePath))
	} else if cfg.NodeIDSource != config.IDFromConfig {
		line("node.id", fmt.Sprintf("%s（来源：%s）", cfg.Node.ID, cfg.NodeIDSource))
	}
	line("监视路径", fmt.Sprintf("%d 个", len(rep.ReloadPaths)))
	if len(rep.AppliedDefaults) > 0 {
		fmt.Printf("  按约定补全的配置（%d 项，想显式覆盖就在 node.yaml 里写出来）：\n", len(rep.AppliedDefaults))
		for _, d := range rep.AppliedDefaults {
			fmt.Printf("    · %s\n", d)
		}
	}
	for _, w := range rep.Warnings {
		fmt.Printf("  [警告] %s\n", w)
	}
	if err != nil {
		fmt.Printf("\n[不可启动] %v\n", err)
		return 1
	}
	fmt.Printf("\n自检通过：可以启动。\n")
	return 0
}

// emptyDash 把空串换成破折号 "—"，用于在自检报告里表示"没有值"。
//
// 参数：
//
//	s — 待显示的文本
//
// 返回：
//
//	string — s 为空时返回 "—"，否则原样返回
func emptyDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// yesNo 把布尔值转成中文的"是 / 否"。
//
// 参数：
//
//	b — 待转换的布尔值
//
// 返回：
//
//	string — true 返回 "是"，false 返回 "否"
func yesNo(b bool) string {
	if b {
		return "是"
	}
	return "否"
}

// onOff 把布尔值转成中文的"开启 / 关闭"。
//
// 参数：
//
//	b — 待转换的布尔值
//
// 返回：
//
//	string — true 返回 "开启"，false 返回 "关闭"
func onOff(b bool) string {
	if b {
		return "开启"
	}
	return "关闭"
}

// generateKeys 一次性生成本节点的 Ed25519 密钥对，并写成私钥与 .pub 公钥两个文件。
//
// 注意与"启动路径"的区别：**启动时缺密钥一律拒绝启动**，程序绝不隐式生成；
// 这个子命令是显式的部署工具，只在你想用它的时候才生成。
//
// 内部先写 id_ed25519，withCA 为真时再写 ca；同名文件已存在且没有 -force 时直接报错，不覆盖。
//
// 参数：
//
//	dir    — 输出目录；不存在时以 0700 权限创建
//	withCA — true 时额外生成 CA 密钥对（只有还要给子节点签发的节点才需要）
//	force  — true 才覆盖已存在的密钥文件；false 遇到同名文件即报错
//
// 返回：
//
//	error — 建目录 / 生成密钥 / 写文件任一步失败时返回
func generateKeys(dir string, withCA, force bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// write 把一对密钥写到 dir/name（私钥）与 dir/name.pub（公钥）；
	// force 为假时遇到已存在的私钥文件直接报错，不覆盖。
	write := func(name string, priv ed25519.PrivateKey) error {
		keyPath := filepath.Join(dir, name)
		pubPath := keyPath + ".pub"
		if !force {
			if _, err := os.Stat(keyPath); err == nil {
				return fmt.Errorf("%s 已存在（加 -force 覆盖）", keyPath)
			}
		}
		if err := identity.WriteKeyFile(keyPath, priv); err != nil {
			return err
		}
		if err := identity.WritePublicKeyFile(pubPath, identity.PublicKeyOf(priv)); err != nil {
			return err
		}
		fmt.Printf("已生成 %s\n       %s\n", keyPath, pubPath)
		return nil
	}
	_, idPriv, err := identity.GenerateKeyPair()
	if err != nil {
		return err
	}
	if err := write("id_ed25519", idPriv); err != nil {
		return err
	}
	if withCA {
		_, caPriv, err := identity.GenerateKeyPair()
		if err != nil {
			return err
		}
		if err := write("ca", caPriv); err != nil {
			return err
		}
		fmt.Printf("\nCA 私钥用于为本节点的子节点签发证书（只给有子节点的节点生成）。\n")
	}
	fmt.Printf("\n下一步：\n  1) 把上面的路径填进 node.yaml 的 security.identity_key_path / identity_pubkey_path\n")
	if withCA {
		fmt.Printf("     以及 security.ca_key_path\n")
	}
	fmt.Printf("  2) treecmd-node -check -config node.yaml     # 自检\n")
	fmt.Printf("  3) treecmd-node -config node.yaml            # 启动（证书暂缺会自动向父入网）\n")
	return nil
}

// printSampleConfig 把带注释的样例 node.yaml 打印到标准输出。
//
// 样例内容按形态分支硬编码在函数里：header 是给人看的说明文字，body 是配置正文。
// 形态名不区分大小写，首尾空白会去掉。
//
// 参数：
//
//	role — 形态名，取值 root | relay | leaf | child（child 是"只写我是谁和父地址"的最小样例）
//
// 返回：
//
//	error — 形态名为空或不认识时返回；文案里会列出可选项
func printSampleConfig(role string) error {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return fmt.Errorf("请指定 root | relay | leaf")
	}
	var header, body string
	switch role {
	case "root":
		header = `# 根节点：没有父可以签发，证书（含 CA）必须自备（自签 CA 的完整命令见 docs/手动部署指南.md）。
# 它是全树信任锚的持有者（自己的 CA 证书）与最终聚合终点。`
		body = `node:
  id: 0198f0c0-0000-7000-8000-000000000001     # UUIDv7（等于证书身份）。**也可以留空**：首次启动会自动生成并写回本文件
  name: root-sz-01                              # 节点名：人类可读地标记"我是谁"（可省略）
  remark: "深圳机房 · 根节点"                    # 备注：自由文本（可省略）。name/remark 只作展示，随注册上行、API 可查
  listen: 127.0.0.1:19443                       # 根要对外监听（子节点连它）

# 根没有 parents[]

security:
  identity_key_path: keys/id_ed25519            # 【必须预置】程序绝不生成
  identity_pubkey_path: keys/id_ed25519.pub     # 【必须预置】与私钥成对
  identity_cert_path: certs/node.crt            # 身份证书链（自带）
  ca_cert_path: certs/node.crt.ca               # 本节点的 CA 证书（自带；用于给子节点签发）
  ca_key_path: keys/ca                          # 【必须预置】CA 私钥（用于给子节点签发）
  # 信任锚：可以给文件，也可以给**目录**（目录下 *.crt/*.pem 全加载，方便脚本投放与 CA 轮换）
  ca_cert_paths:
    - certs/node.crt.ca
  health_viewers: []                            # 留空 = 允许多少"直接父 + root"
  trusted_origins: []

  # 证书由你的脚本管理时：程序只负责"发现变了就重载"
  cert_reload:
    enabled: true
    interval: 30s            # 轮询兜底（最小 5s）
    on_change: reconnect     # reconnect=本节点证书/私钥变了就主动重连；lazy=只对新连接生效
    # paths: []              # 留空 = 自动监视身份私钥/公钥/证书 + CA 证书/私钥 + 信任锚

  # 运行期入网签发：根不需要（没有父），留空即可
  enrollment:
    enabled: false

api:
  http_addr: 127.0.0.1:18443                    # 提交指令 / 查结果 / 健康检查
command:
  lease_ttl: 90s
  renew_at: 30s                                  # 硬约束：renew_at × 3 ≤ lease_ttl
  max_deadline: 24h
  audit_retention: 168h
  eviction_timeout: 24h
health:
  max_health_fanout: 32
  health_response_max_bytes: 1MB
query:
  query_route_ttl: 10s
  max_query_routes: 4096
  query_response_max_bytes: 8MB
registration:
  backfill: NONE
persist:
  state_path: state.dat
  interval: 10s
data_dir: .`
	case "child":
		header = `# 子节点：**只需要"我是谁 + 父节点地址"两项就够**，其余全部按约定补全。
# 约定（都在 node.yaml 同目录）：
#   keys/id_ed25519 + id_ed25519.pub   本节点密钥对（必须先放好：treecmd-node -genkey）
#   certs/node.crt                     本节点证书——**不用自己准备**，启动时向父入网签发
#   trust/                             目录里放 CA 证书（信任锚；换 CA 只换文件，不改配置）
#   enroll.token                       入网许可（与父端一致；用 -check 能看出有没有认到）
# 约定目录/文件不存在时会给出明确报错；用 treecmd-node -check 一跑就清楚。`
		body = `node:
  id: 0198f0c0-0000-7000-8000-000000000003     # 我是谁（UUIDv7，等于证书身份）。**可以留空**：首次启动自动生成并写回
  name: edge-sz-03                              # 节点名：标记这个 node 的身份（可省略）
  remark: "1 号柜 3 号机位"                      # 备注（可省略）；两者都会随注册上行，API 可查

parents:
  - id: 0198f0c0-0000-7000-8000-000000000001    # 父的真实 NodeID
    addr: 127.0.0.1:19443                       # 父的监听地址

# —— 以下全部可省略（程序按约定补全，-check 会列出补了哪些）——
# security:
#   identity_key_path: keys/id_ed25519
#   identity_pubkey_path: keys/id_ed25519.pub
#   identity_cert_path: certs/node.crt
#   ca_cert_paths: [trust]        # 信任锚目录
#   ca_key_path: certs/ca.key     # 只有"还有下级"的中继才需要
#   cert_reload: { enabled: true, interval: 30s, on_change: reconnect }
#   enrollment: { enabled: true, token_path: enroll.token }`
	case "relay":
		header = `# 中继节点：有父也有子。
# 证书由父在"运行期入网"时签发（你只需预置密钥对）；因为还有下级，所以需要 CA 密钥对。
# 注意：本节点的 CA **证书**是父签发的，启动时还不存在，入网成功后由程序写入 ca_cert_path。`
		body = `node:
  id: 0198f0c0-0000-7000-8000-000000000002     # 也可以留空：首次启动自动生成并写回本文件
  name: relay-sz-02                             # 节点名（可省略）
  remark: "中继 · 二层"                          # 备注（可省略）
  listen: 127.0.0.1:19444                       # 中继要监听（它的子会连它）

parents:
  - id: 0198f0c0-0000-7000-8000-000000000001    # 必须是父的真实 NodeID（入网与校验都按它比对）
    addr: 127.0.0.1:19443

security:
  identity_key_path: keys/id_ed25519            # 【必须预置】
  identity_pubkey_path: keys/id_ed25519.pub     # 【必须预置】
  identity_cert_path: certs/node.crt            # 启动时通常还没有 → 由父签发后写入
  ca_key_path: keys/ca                          # 【必须预置】有子节点才需要（用于给自己的子签发）
  ca_cert_path: certs/node.crt.ca               # 父签发的 CA 证书会写到这
  ca_cert_paths:                                # 信任锚：能验到"根的 CA"即可
    - /etc/treecmd/trust            # ← 给**目录**：脚本往这里投放证书/轮换 CA 都不用改配置

  cert_reload:
    enabled: true
    interval: 30s
    on_change: reconnect

  enrollment:
    enabled: true                 # 没有证书时向父入网换取
    token: change-me-please       # 父端必须配同一个串；也可用 token_path 由脚本投放
    # allow_ids: [...]            # 父端才用：只允许这些 NodeID 入网（留空 = 只校验 token）

command:
  lease_ttl: 90s
  renew_at: 30s
health:
  max_health_fanout: 32
registration:
  backfill: NONE
persist:
  state_path: state.dat
data_dir: .`
	case "leaf":
		header = `# 叶子节点：只有父，没有子 → 不需要监听端口、不需要 CA 材料、不需要 HTTP API。
# 证书同样由父在运行期签发。`
		body = `node:
  id: 0198f0c0-0000-7000-8000-000000000003     # 可以留空：首次启动自动生成并写回本文件
  name: leaf-sz-03                              # 节点名（可省略）
  remark: "叶子 · 无下级"                        # 备注（可省略）

parents:
  - id: 0198f0c0-0000-7000-8000-000000000002
    addr: 127.0.0.1:19444

security:
  identity_key_path: keys/id_ed25519            # 【必须预置】
  identity_pubkey_path: keys/id_ed25519.pub     # 【必须预置】
  identity_cert_path: certs/node.crt            # 由父签发后写入
  ca_cert_paths:
    - /etc/treecmd/trust
  cert_reload:
    enabled: true
    interval: 30s
    on_change: reconnect
  enrollment:
    enabled: true
    token: change-me-please

command:
  lease_ttl: 90s
  renew_at: 30s
registration:
  backfill: NONE
persist:
  state_path: state.dat
data_dir: .`
	default:
		return fmt.Errorf("未知形态 %q（只支持 root | relay | leaf）", role)
	}
	fmt.Printf("%s\n\n%s\n", header, body)
	return nil
}
