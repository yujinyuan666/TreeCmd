// Package buildinfo 回答一个问题：**本进程此刻跑的是哪一份可执行文件**。
//
// 它只做三件事：定位自己的可执行文件、算它的 sha256（流式，一遍过）、给出跨节点比对的签名载荷。
// 为什么要有这么一层：树是"父下发、子执行"的，如果子跑的是另一份镜像，行为就可能与父不一致，
// 而且这类不一致**极难排查**（症状是"行为诡异"而不是"报错"）。把哈希摊到明面上，
// 父在注册应答里给一份、子自己算一份，两边一比就清楚了。
//
// 三条边界：
//   - **哈希是"启动那一刻的镜像"**：算完之后磁盘上的文件再被换掉，也不改变这个值。
//     真要去读文件对外服务时，必须先用 SameAsDisk 复验（否则会把半成品发出去）。
//   - **算不出来不算致命**：读不到可执行文件时只返回空哈希，由调用方决定怎么办（fail-soft）。
//   - **版本号不参与判定**：Version 只用于展示与日志；一切判定只看哈希。
package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"treecmd/internal/canon"
)

// HashPrefix 哈希的统一前缀。带上它是为了自描述：将来换算法时不会与老值混为一谈
// （字符串比对前先看前缀，前缀不同即"另一种东西"）。
const HashPrefix = "sha256:"

// Version 构建时注入的版本号（可留空）。
//
// 它**只用于展示**（启动日志、-check 报告），不参与任何判定 —— 判定一律看哈希。
// 注入方式：go build -ldflags "-X treecmd/internal/buildinfo.Version=v0.2.0"
var Version = "dev"

// Info 一份可执行文件的身份快照。
type Info struct {
	Path    string    // 绝对路径；已解析符号链接（要替换的是"真实的那份文件"）
	Hash    string    // "sha256:" + 64 位十六进制；读不到文件时是空串
	Size    int64     // 字节数
	ModTime time.Time // 文件 mtime（复验磁盘文件"是不是还是那一份"时的快路径依据）
	Version string    // 构建时注入的版本号（仅展示）
}

// Known 报告这份快照有没有哈希（即"算不算得出来"）。
//
// 接收者 i 是本节点可执行文件的快照。
//
// 返回：
//
//	bool — Hash 非空时为 true；false 表示这份快照不能用于任何比对
func (i Info) Known() bool { return i.Hash != "" }

// Short 返回哈希的短形式（去掉前缀后取前 12 位），用于日志与 /v1/tree 这类展示。
//
// 接收者 i 是本节点可执行文件的快照。完整哈希太长，日志里看前 12 位足够区分两份镜像。
//
// 返回：
//
//	string — 形如 "a1b2c3d4e5f6"；没有哈希时返回 "?"（而不是空串，避免日志里出现空字段）
func (i Info) Short() string {
	h := trimHash(i.Hash)
	if h == "" {
		return "?"
	}
	if len(h) > 12 {
		h = h[:12]
	}
	return h
}

// String 把快照渲染成一行给人看的文字，形如 "sha256:xxxx 12.3MB /path/to/treecmd-node"。
//
// 接收者 i 是本节点可执行文件的快照。
//
// 返回：
//
//	string — 没有哈希时形如 "未知（<err 上下文由调用方补>） <path>"
func (i Info) String() string {
	if !i.Known() {
		return fmt.Sprintf("未知(%s)", i.Path)
	}
	return fmt.Sprintf("%s %.1fMB %s", i.Short(), float64(i.Size)/1024/1024, i.Path)
}

// Compute 定位本进程的可执行文件并算出它的哈希与大小。
//
// 步骤：os.Executable 拿到路径 → EvalSymlinks 解析符号链接 → 流式算 sha256。
// 解析符号链接是必要的：部署时常用 `ln -sf` 指向版本化文件，**要替换的必须是链接指向的
// 真实文件**，否则替换的是链接本身、重启后跑的仍是旧目标。
//
// 返回：
//
//	Info — 快照；即使出错也会尽量填好 Path（便于日志里说清"读的是哪个文件"）
//	error — 定位不到可执行文件 / 打开或读取它失败时返回；此时 Info.Hash 为空串
func Compute() (Info, error) {
	info := Info{Version: Version}
	exe, err := os.Executable()
	if err != nil {
		return info, fmt.Errorf("定位本进程可执行文件失败: %w", err)
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	info.Path = exe
	hash, size, mod, err := HashFile(exe)
	if err != nil {
		return info, err
	}
	info.Hash, info.Size, info.ModTime = hash, size, mod
	return info, nil
}

// HashFile 流式算出某个文件的 sha256，并顺带带回字节数与 mtime。
//
// 流式（8MB 缓冲分块喂给 sha256）而不是整份读进内存：可执行文件几十 MB，
// 启动路径上没必要为此吃一份峰值内存。
//
// 参数：
//
//	path — 目标文件的路径
//
// 返回：
//
//	string    — HashPrefix + 64 位十六进制
//	int64     — 文件字节数
//	time.Time — 文件的 mtime
//	error     — 打不开 / 读失败 / stat 失败时返回
func HashFile(path string) (string, int64, time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, time.Time{}, fmt.Errorf("读取 %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return "", 0, time.Time{}, err
	}
	return HashPrefix + hex.EncodeToString(h.Sum(nil)), fi.Size(), fi.ModTime(), nil
}

// SameAsDisk 复验"磁盘上那个文件还是不是这份快照对应的那一份"。
//
// 为什么需要它：哈希是启动时算的，之后磁盘上的文件可能已经被换掉（换证脚本、人工覆盖、
// 或者本节点自己刚被升级过）。此时**绝不能**拿它去服务下游，否则下游会拿到一份
// "哈希对不上内容"的镜像。所以对外服务前先走这里。
//
// 快路径只 stat（size + mtime 都没变就认定没变），慢路径才重算整份哈希。
//
// 参数：
//
//	i — 启动时算出的那份快照
//
// 返回：
//
//	bool  — true 表示磁盘内容与快照一致（可以对外服务）
//	error — stat 或重算失败时返回
func SameAsDisk(i Info) (bool, error) {
	if i.Path == "" {
		return false, fmt.Errorf("快照没有路径")
	}
	fi, err := os.Stat(i.Path)
	if err != nil {
		return false, err
	}
	if fi.Size() == i.Size && fi.ModTime().Equal(i.ModTime) {
		return true, nil
	}
	// 慢路径：size 或 mtime 变了 —— 也可能是"仅 touch"，所以必须读内容才算数
	hash, size, _, err := HashFile(i.Path)
	if err != nil {
		return false, err
	}
	return hash == i.Hash && size == i.Size, nil
}

// SigPayload 给出"父对自己的镜像做承诺"时的签名载荷摘要。
//
// 父用身份私钥对它签名、子用父的证书公钥验签，绑定的三样东西缺一不可：
// 哪台父（nodeID）+ 哪份镜像（hash）+ 多大（size）。带上 size 是为了让"哈希算法不变但内容被裁短"
// 这种怪事也过不去。
//
// 参数：
//
//	nodeID — 签名方（父）的 NodeID
//	hash   — 被承诺的可执行文件哈希（带 HashPrefix）
//	size   — 被承诺的字节数
//
// 返回：
//
//	[]byte — 32 字节 SHA-256 摘要（按 canon 的长度前缀规则拼接，段边界也参与摘要）
func SigPayload(nodeID, hash string, size int64) []byte {
	return canon.DigestBytes([]byte(nodeID), []byte(hash), []byte(strconv.FormatInt(size, 10)))
}

// trimHash 去掉哈希的前缀，只留下十六进制部分。
//
// 参数：
//
//	h — 形如 "sha256:abc…" 的哈希；没有前缀时原样返回
//
// 返回：
//
//	string — 十六进制部分
func trimHash(h string) string {
	if len(h) > len(HashPrefix) && h[:len(HashPrefix)] == HashPrefix {
		return h[len(HashPrefix):]
	}
	return h
}
