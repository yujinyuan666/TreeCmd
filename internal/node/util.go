package node

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"time"

	"treecmd/internal/exec"
	"treecmd/internal/exec/apis"
	"treecmd/internal/exec/script"
)

// Logger 在 slog.Logger 之上补 Errorf/Warnf 等格式化方法（便于把方案里的注释直接落成日志）。
type Logger struct{ *slog.Logger }

// Errorf 以 printf 风格格式化后写 Error 级日志。
func (l *Logger) Errorf(f string, a ...any) { l.Error(fmt.Sprintf(f, a...)) }

// Warnf 以 printf 风格格式化后写 Warn 级日志。
func (l *Logger) Warnf(f string, a ...any) { l.Warn(fmt.Sprintf(f, a...)) }

// Infof 以 printf 风格格式化后写 Info 级日志。
func (l *Logger) Infof(f string, a ...any) { l.Info(fmt.Sprintf(f, a...)) }

// Debugf 以 printf 风格格式化后写 Debug 级日志。
func (l *Logger) Debugf(f string, a ...any) { l.Debug(fmt.Sprintf(f, a...)) }

// randInt63n 返回 [0, n) 区间内的随机 int64。
//
// 参数：
//
//	n — 上界（不含）；n <= 0 时直接返回 0
//
// 返回：取 8 字节密码学随机数后对 n 取模的结果；读随机数失败时返回 0。
func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[:]) % uint64(n))
}

// shortErr 截断错误信息（日志 / 上报用）。
//
// 参数：
//
//	err — 可能为 nil 的错误
//	max — 保留的最大字符数，超出则截断并追加 "..."
//
// 返回：err 为 nil 时返回空串，否则返回截断后的错误文本。
func shortErr(err error, max int) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

// tsMillis 把 time.Time 转成 Unix 毫秒时间戳。
func tsMillis(t time.Time) int64 { return t.UnixMilli() }

// millisToTime 把 Unix 毫秒时间戳还原成 time.Time。
func millisToTime(ms int64) time.Time { return time.UnixMilli(ms) }

// minDuration 返回 a、b 中较小的那个 time.Duration。
func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// itoa 把 int 转成十进制字符串。
func itoa(i int) string { return fmt.Sprintf("%d", i) }

// newExecRegistry 装配执行器注册表：项目内置的 noop / echo / sleep / fail、
// 手写在 internal/exec/apis 里的对外 API 调用（uuid_v4 / remote_time），
// 以及执行外部脚本的 script 类型（internal/exec/script）。
//
// 单独抽成一个函数是为了让"本节点能做哪些类型的指令"只有**一处**答案 ——
// SubmitCommand 的能力闸门看的是它，以后要给父端上报能力也是从这里取。
//
// 参数：
//
//	scriptDir — 脚本目录（`<可执行文件同目录>/script`）
//	sp        — 脚本提供者；通常就是本节点（*Node 实现了 script.Provider）
//
// 返回：
//
//	*exec.Registry — 可直接赋给 Node.Exec 的注册表
func newExecRegistry(scriptDir string, sp script.Provider) *exec.Registry {
	reg := exec.NewRegistry()
	apis.Register(reg)
	reg.Register(script.New(scriptDir, sp))
	return reg
}
