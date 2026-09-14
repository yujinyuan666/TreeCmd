// Command node 是单节点入口：一个进程同时是客户端与服务端，形态由 node.yaml 决定。
//
// 典型的手工部署用法（单服务器、手工起进程、证书由外部脚本管理）：
//
//	treecmd-node -genkey -keydir keys -with-ca        # 一次性：生成本节点的密钥对（程序启动路径绝不生成）
//	treecmd-node          -config node.yaml           # 启动（证书暂缺时会先向父入网签发）
//	treecmd-node -enroll  -config node.yaml           # 只做一次运行期入网（换取证书落盘）后退出
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
	"syscall"
	"time"

	"treecmd/internal/config"
	"treecmd/internal/identity"
	"treecmd/internal/node"
)

// main 解析命令行参数，并驱动单节点的整个生命周期（入网 / 启动 / 信号处理）。
//
// 分支顺序是：-genkey 生成密钥 → 没有 -config 就打印用法并退出 → 正常加载配置
// → -enroll 只入网并退出 → 否则启动并阻塞在信号循环里。
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
		enroll   = flag.Bool("enroll", false, "只做一次运行期入网（向父换取证书并写入证书文件），然后退出")
		genkey   = flag.Bool("genkey", false, "一次性生成本节点密钥对（程序启动路径绝不生成密钥，这是显式的部署工具）")
		keyDir   = flag.String("keydir", "keys", "-genkey 的输出目录")
		withCA   = flag.Bool("with-ca", false, "-genkey 时一并生成 CA 密钥对（有子节点的节点才需要）")
		force    = flag.Bool("force", false, "-genkey 时覆盖已存在的密钥文件")
	)
	flag.Parse()

	if *genkey {
		if err := generateKeys(*keyDir, *withCA, *force); err != nil {
			fmt.Fprintln(os.Stderr, "genkey FAILED:", err)
			os.Exit(1)
		}
		return
	}
	if *cfgPath == "" {
		fmt.Fprintln(os.Stderr, "usage: treecmd-node -config <path/to/node.yaml> [flags]")
		fmt.Fprintln(os.Stderr, "       treecmd-node -enroll -config node.yaml")
		fmt.Fprintln(os.Stderr, "       treecmd-node -genkey -keydir keys [-with-ca]")
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
		logger.Info("node up", "role", string(cfg.Role()), "node_id", cfg.Node.ID, "build", n.Build().Short())
	} else {
		logger.Warn("node up in ENROLLMENT mode（证书待签发）",
			"role", string(cfg.Role()), "node_id", cfg.Node.ID, "build", n.Build().Short())
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
	fmt.Printf("  2) treecmd-node -config node.yaml            # 启动（证书暂缺会自动向父入网）\n")
	return nil
}
