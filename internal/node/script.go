package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"treecmd/internal/buildinfo"
	"treecmd/internal/exec/script"
)

// scriptDirName 是脚本目录的名字：`<可执行文件同目录>/script`。
const scriptDirName = "script"

// scriptDir 返回本节点的脚本目录。
//
// 目录口径与 selfupdate 的暂存目录、片存目录**同源**：相对可执行文件的真实位置推导
// （buildinfo 算哈希时已经把符号链接解析过了）—— 部署时"二进制在哪，脚本就在它旁边"。
//
// 算不出可执行文件路径时退化为当前工作目录（prepareScriptDir 会就此打一条告警）。
//
// 返回：
//
//	string — 脚本目录路径（目录本身可能还不存在）
func (n *Node) scriptDir() string {
	if p := n.Build().Path; p != "" {
		return filepath.Join(filepath.Dir(p), scriptDirName)
	}
	wd, err := os.Getwd()
	if err != nil {
		return scriptDirName
	}
	return filepath.Join(wd, scriptDirName)
}

// prepareScriptDir 启动时准备脚本目录：不存在就建一个空的，并清掉上次遗留的工作目录。
//
// 为什么"目录不存在"不算错误：脚本是运维自己放进去的，首次部署时根节点很可能还没放任何脚本。
// 建个空目录即可 —— 真去执行时自然会因为"没有这个脚本"而失败（fail-loud，不静默）。
//
// 返回：
//
//	error — 建目录或清理失败时返回；调用方只记日志，不因此拒绝启动
func (n *Node) prepareScriptDir() error {
	dir := n.scriptDir()
	if n.Build().Path == "" {
		n.Log.Warn("算不出可执行文件路径，脚本目录退化为当前工作目录", "dir", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("建脚本目录 %s 失败: %w", dir, err)
	}
	if err := script.CleanWorkTree(dir); err != nil {
		return err
	}
	n.Log.Info("脚本目录就绪", "dir", dir, "scripts", countScripts(dir))
	return nil
}

// countScripts 数一下脚本目录里有多少个可读的普通文件（只用于启动日志）。
//
// 参数：
//
//	dir — 脚本目录
//
// 返回：
//
//	int — 文件个数；目录读不了时为 0
func countScripts(dir string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.Type().IsRegular() {
			n++
		}
	}
	return n
}

// EnsureScript 保证脚本已在本地可用，并返回它的路径。这是 script.Provider 的实现。
//
// 流程：名字过白名单 → 本地文件"在脚本目录内 + 哈希一致"就直接用 → 否则向父索取 →
// 本地复算哈希 → **无条件覆盖**写盘（0755，可手动执行）。
//
// 覆盖是刻意无条件的：需求就是"遇到冲突无条件覆盖"。这也顺便把"script/ 里被人塞了
// 符号链接指向别处"这类情况自动修回来了 —— 覆盖会把链接本身换成一个真文件。
//
// 参数：
//
//	ctx     — 执行上下文；被取消会中断这次索取
//	name    — 脚本文件名（不含目录）
//	wantSHA — 指令里带的期望哈希（"sha256:"+十六进制；它已被 origin 签名覆盖，改不了）
//
// 返回：
//
//	string — 脚本路径（保证此刻存在、且内容哈希一致）
//	error  — 名字不合规、本地没有又索取失败、或收到的内容哈希不符时返回
func (n *Node) EnsureScript(ctx context.Context, name, wantSHA string) (string, error) {
	dir := n.scriptDir()
	path, err := script.ResolveInDir(dir, name)
	if err == nil {
		if got, _, _, herr := buildinfo.HashFile(path); herr == nil && got == wantSHA {
			return path, nil // 本地已经在位
		}
	}
	if n.up == nil || !n.up.isConnected() {
		n.Metrics.Inc("script_fetch_total", "result", "offline")
		return "", fmt.Errorf("本节点没有脚本 %s（期望 %s），且当前连不上父节点，无法下发", name, wantSHA)
	}
	data, err := n.up.fetchScript(ctx, name, wantSHA)
	if err != nil {
		n.Metrics.Inc("script_fetch_total", "result", "error")
		return "", err
	}
	if got := hashBytes(data); got != wantSHA {
		n.Metrics.Inc("script_fetch_total", "result", "mismatch")
		return "", fmt.Errorf("收到的脚本 %s 哈希不符：期望 %s，实际 %s（拒绝写入与执行）", name, wantSHA, got)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		n.Metrics.Inc("script_fetch_total", "result", "error")
		return "", fmt.Errorf("建脚本目录 %s 失败: %w", dir, err)
	}
	dst := filepath.Join(dir, name)
	if err := writeFileAtomic(dst, data, 0o755); err != nil {
		n.Metrics.Inc("script_fetch_total", "result", "error")
		return "", fmt.Errorf("写入脚本 %s 失败: %w", dst, err)
	}
	n.Metrics.Inc("script_fetch_total", "result", "ok")
	n.Log.Info("脚本已下发并覆盖", "name", name, "sha256", wantSHA, "bytes", len(data))
	return dst, nil
}

// hashBytes 算一段字节的 "sha256:"+十六进制，格式与 buildinfo.HashFile 保持一致。
//
// 参数：
//
//	b — 待哈希的字节
//
// 返回：
//
//	string — "sha256:" + 十六进制摘要
func hashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return buildinfo.HashPrefix + hex.EncodeToString(sum[:])
}
