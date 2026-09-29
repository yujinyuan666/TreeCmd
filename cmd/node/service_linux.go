//go:build linux

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// serviceName systemd 服务名（unit 文件名去掉 .service 后缀）。
const serviceName = "treecmd-node"

// systemdUnitPath unit 文件的落盘位置（systemd 系统级目录）。
const systemdUnitPath = "/etc/systemd/system/" + serviceName + ".service"

// installService 把 treecmd-node 注册为 systemd 服务（需 root）并立即启动。
//
// unit 内容：ExecStart 用本可执行文件绝对路径 + `-config <node.yaml 绝对路径>`，
// WorkingDirectory 取 node.yaml 所在目录（一节点一目录的部署约定，state/keys 等相对路径都落在节点目录里）。
// 写完 unit 后依次 systemctl daemon-reload → enable → start。
//
// 参数：
//
//	cfgPath — node.yaml 路径；为空时报错（ExecStart 必须落到具体配置）
//
// 返回：
//
//	error — 非 root / 路径解析 / 写 unit / systemctl 任一步失败时返回
func installService(cfgPath string) error {
	if cfgPath == "" {
		return fmt.Errorf("-install 需要 -config <node.yaml>：systemd 服务以该配置启动")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("安装系统服务需要 root 权限，请使用 sudo 运行：sudo %s -config %s -install",
			os.Args[0], cfgPath)
	}
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}
	cfgAbs, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	unit := fmt.Sprintf(`[Unit]
Description=treecmd 节点服务
After=network.target

[Service]
Type=simple
ExecStart=%s -config %s
WorkingDirectory=%s
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, exePath, cfgAbs, filepath.Dir(cfgAbs))
	if err := os.WriteFile(systemdUnitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("写 %s: %w", systemdUnitPath, err)
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", serviceName},
		{"start", serviceName},
	} {
		if err := runSystemctl(args...); err != nil {
			return err
		}
	}
	log.Printf("已安装并启动 %s 服务 (systemd)：%s", serviceName, systemdUnitPath)
	return nil
}

// uninstallService 注销 systemd 服务（需 root）：stop → disable → 删 unit → daemon-reload。
// stop / disable 失败不阻断后续清理（服务可能本来就没在跑）。
//
// 参数：无。
//
// 返回：
//
//	error — 非 root / 删 unit / daemon-reload 失败时返回
func uninstallService() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("卸载系统服务需要 root 权限，请使用 sudo 运行：sudo %s -uninstall", os.Args[0])
	}
	for _, args := range [][]string{
		{"stop", serviceName},
		{"disable", serviceName},
	} {
		_ = runSystemctl(args...) // 失败不阻断后续清理
	}
	if err := os.Remove(systemdUnitPath); err != nil {
		return fmt.Errorf("删 %s: %w", systemdUnitPath, err)
	}
	if err := runSystemctl("daemon-reload"); err != nil {
		return err
	}
	log.Printf("已卸载 %s 服务 (systemd)", serviceName)
	return nil
}

// serviceAction 执行一条服务操作：start / stop / restart / status。
// start / stop / restart 需 root；status 任何用户都可看，且其退出码反映运行状态
// （systemd 约定未运行 = 3），不算执行失败。
//
// 参数：
//
//	action — "start" / "stop" / "restart" / "status"
//
// 返回：
//
//	error — 未知操作 / 非 root / systemctl 执行失败时返回
func serviceAction(action string) error {
	switch action {
	case "start", "stop", "restart":
		if os.Geteuid() != 0 {
			return fmt.Errorf("%s 服务需要 root 权限，请使用 sudo 运行：sudo systemctl %s %s",
				action, action, serviceName)
		}
		return runSystemctl(action, serviceName)
	case "status":
		_ = runSystemctl("status", serviceName) // 退出码只是状态信号，透传输出即可
		return nil
	default:
		return fmt.Errorf("未知的服务操作 %q", action)
	}
}

// runSystemctl 执行一条 systemctl 子命令，输出直通到本进程的标准输出 / 标准错误。
//
// 参数：
//
//	args — systemctl 的子命令与参数（不含 "systemctl" 本身）
//
// 返回：
//
//	error — systemctl 不存在或以非零码退出时返回，错误里带上完整子命令便于定位
func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %v 失败: %w", args, err)
	}
	return nil
}
