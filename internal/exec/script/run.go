package script

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// maxStdout / maxStderr 是脚本 stdout / stderr 各自保留的字节上限。
	//
	// 必须有上限：脚本里一个死循环 print 就能把节点内存吃光。超出的部分丢掉，
	// 但**总数照常统计**（见 cappedWriter），所以"丢了多少"在结果里看得见。
	maxStdout int64 = 1 << 20
	maxStderr int64 = 1 << 20

	// killGrace 是发出 SIGTERM 之后等多久升级成 SIGKILL。
	//
	// 留这段时间是为了让脚本自己收拾（删临时文件、回滚半途状态）；不能太长 ——
	// 上游还在等这条指令的结果。
	killGrace = 5 * time.Second
)

// outcome 是一次脚本执行的结果（不含业务结果 —— 那是 result.json 的事）。
type outcome struct {
	// ExitCode 脚本退出码；被信号终止时为 -1，一个字段都不解析不出时为 -1。
	ExitCode int
	// Stdout / Stderr 收上来的输出（已按上限截断）。
	Stdout []byte
	Stderr []byte
	// OutputDropped 输出是否因超过上限被丢掉了一部分。
	OutputDropped bool
	// OutputClosed 输出管道是否被 WaitDelay 强制关闭（脚本退出了，但它派生的孙进程还攥着管道）。
	// 为 true 说明收到的输出**可能不完整**，但退出码本身是可信的。
	OutputClosed bool
	// Killed 是否真的发出过 SIGKILL（说明脚本不肯好好退出）。
	Killed bool
	// Interrupted 是否因为 ctx 取消 / 超时而中断了这次执行。
	Interrupted bool
}

// runScript 起一个外部进程执行脚本：<脚本绝对路径> <params JSON>。
//
// 这是全项目唯一一处起外部进程的地方，下面五件事都由它负责（顺序即重要性）：
//
//  1. **独立进程组**：进程以 Setpgid 起在自己的组里，中断时整组发信号。只 kill 直接子进程的话，
//     脚本自己 fork 出来的孙进程会活下来变成孤儿，继续占端口、写文件。
//  2. **信号升级**：先 SIGTERM 让脚本自己收拾，killGrace 内没退出才 SIGKILL。
//  3. **永远把管道读干净**：stdout/stderr 用"永远收下、只保留前 N 字节"的写入端（cappedWriter）。
//     我们一旦停止读取，脚本就会卡死在写管道上永远不退出 —— 那比丢输出糟得多。
//  4. **不会永久挂住**：脚本退出后，它派生的孙进程可能还攥着输出管道不放，靠 cmd.WaitDelay
//     到点强制关管道让 Wait 返回（否则 Wait 会等管道 EOF，那就是永久挂住）。
//  5. **不误杀无关进程**：看门狗协程必须能被主协程等到退出，否则它可能在 PID 已被回收、
//     甚至被系统重新分配之后发信号。
//
// 参数：
//
//	ctx     — 执行上下文；取消 / 超时会中断这次执行（先 SIGTERM 整组，宽限后 SIGKILL）
//	path    — 脚本绝对路径（必须已经落盘且可执行；解释器由脚本自己的 shebang 决定）
//	params  — 那唯一一个参数，原样作为 argv[1] 传进去
//	workDir — 工作目录（脚本就在这里面跑，result.json 也写在这里）
//
// 返回：
//
//	*outcome — **永远非 nil**，即使出错也带回已收齐的输出与退出码
//	error    — 启动失败（找不到文件 / 没有执行权限 / 工作目录不存在）、等待过程出错，
//	           或因为 ctx 取消 / 超时被中断（包装了 ctx.Err()，框架据此落 SELF_CANCELLED）。
//	           注意：**脚本退出码非 0 不是 error**，它在 outcome.ExitCode 里
func runScript(ctx context.Context, path, params, workDir string) (*outcome, error) {
	out := &outcome{}
	stdout := newCappedWriter(maxStdout)
	stderr := newCappedWriter(maxStderr)

	cmd := exec.Command(path, params)
	cmd.Dir = workDir
	cmd.Env = os.Environ() // 继承：脚本基本上都需要 PATH / HOME / LANG
	cmd.Stdin = nil        // 接 /dev/null，不继承本进程 stdin（后台跑的东西不该有人能喂它）
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	// 独立进程组，中断时才能整组回收
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// 脚本退出后孙进程仍攥着管道时，到点强制关掉管道，让 Wait 能返回。
	// 到点被关掉时 Wait 返回 exec.ErrWaitDelay，下面按"退出码 0、输出可能不全"处理。
	cmd.WaitDelay = killGrace

	if err := cmd.Start(); err != nil {
		return out, fmt.Errorf("启动脚本失败 %s: %w", path, err)
	}
	pid := cmd.Process.Pid

	// 看门狗。这里刻意没用 exec.CommandContext：它的 Cancel 只在 CommandContext 构造的 Cmd 上生效，
	// 而且默认动作是 Process.Kill() —— 只打直接子进程，收不掉脚本 fork 出去的孙进程。
	// 用普通 exec.Command 时 os/exec 完全不碰 ctx，所以"取消"这件事只有本协程一个执行者。
	var interrupted, killed atomic.Bool
	stop := make(chan struct{})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
		case <-stop:
			return
		}
		interrupted.Store(true)
		_ = killGroup(pid, syscall.SIGTERM)
		timer := time.NewTimer(killGrace)
		defer timer.Stop()
		select {
		case <-stop:
		case <-timer.C:
			killed.Store(true)
			_ = killGroup(pid, syscall.SIGKILL)
		}
	}()

	waitErr := cmd.Wait()
	close(stop)
	// 必须等看门狗真的退出再往下走（理由见上面第 5 条）
	<-watchDone

	out.Interrupted = interrupted.Load()
	out.Killed = killed.Load()
	out.Stdout = stdout.bytes()
	out.Stderr = stderr.bytes()
	out.OutputDropped = stdout.dropped() || stderr.dropped()

	if out.Interrupted {
		// 包一层 ctx.Err()：框架靠 errors.Is(err, context.Canceled) 区分"被取消"与"失败"
		return out, fmt.Errorf("脚本 %s 被中断: %w", path, ctx.Err())
	}
	if waitErr == nil {
		return out, nil
	}
	var exitErr *exec.ExitError
	switch {
	case errors.As(waitErr, &exitErr):
		// 非零退出码 / 被信号终止：都是正常结果，填进 outcome 让调用方判定，不当错误
		out.ExitCode = exitErr.ExitCode() // 被信号终止时为 -1
		return out, nil
	case errors.Is(waitErr, exec.ErrWaitDelay):
		// 脚本自己退干净了，但它留下的孙进程还占着管道，被 WaitDelay 强制关掉 ——
		// "退出码 0、但输出可能不全"，不当失败
		out.OutputClosed = true
		return out, nil
	}
	return out, fmt.Errorf("等待脚本 %d 结束失败: %w", pid, waitErr)
}

// killGroup 给整个进程组发信号，而不是只给直接子进程。
//
// 参数里的 pid 是**进程组首进程**的 PID：子进程以 Setpgid 起在自己的新进程组里，
// 而新进程组的组 ID 就等于它的 PID，所以 kill(-pid) 正好命中"它以及它 fork 出来的一切"。
//
// 参数：
//
//	pid — 进程组首进程的 PID（也就是直接子进程的 PID）
//	sig — 要发送的信号
//
// 返回：
//
//	error — 进程组已经不存在时返回 ESRCH；调用方一般直接忽略，那说明它已经自己退干净了
func killGroup(pid int, sig syscall.Signal) error {
	return syscall.Kill(-pid, sig)
}

// cappedWriter 是一个"永远收下、只保留前 limit 个字节"的写入端。
//
// 为什么不是"写满就报错"：os/exec 的拷贝协程必须能一直往这里写完 ——
// 我们一旦停止接收，脚本就会卡死在写管道上，比丢输出糟得多。
type cappedWriter struct {
	mu    sync.Mutex
	buf   []byte
	total int64
	limit int64
}

// newCappedWriter 造一个上限为 limit 字节的写入端。
//
// 参数：
//
//	limit — 最多保留多少字节；小于 0 时按 0 处理（等于全丢，只统计总数）
//
// 返回：
//
//	*cappedWriter — 可以直接赋给 os/exec.Cmd 的 Stdout / Stderr
func newCappedWriter(limit int64) *cappedWriter {
	if limit < 0 {
		limit = 0
	}
	return &cappedWriter{limit: limit}
}

// Write 收下一段输出：前 limit 个字节留下，其余丢掉，两种情况的字节数都记进总数。
//
// 参数：
//
//	p — 脚本写出来的一段字节
//
// 返回：
//
//	int   — 恒为 len(p)，表示"全都收下了"，这样拷贝协程不会中断、脚本也不会卡住
//	error — 恒为 nil
func (w *cappedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.total += int64(len(p))
	if room := w.limit - int64(len(w.buf)); room > 0 {
		take := int64(len(p))
		if take > room {
			take = room
		}
		w.buf = append(w.buf, p[:take]...)
	}
	return len(p), nil
}

// bytes 取走保留下来的那部分内容（一份拷贝，之后写它不会影响调用方拿到的东西）。
//
// 返回：
//
//	[]byte — 前 limit 个字节；一个字节都没收到时是长度为 0 的切片（不是 nil）
func (w *cappedWriter) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]byte, len(w.buf))
	copy(out, w.buf)
	return out
}

// dropped 报告是否有内容被丢掉了。
//
// 返回：
//
//	bool — 收到的总字节数超过保留下来的字节数时为 true
func (w *cappedWriter) dropped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.total > int64(len(w.buf))
}

// tail 取一段输出的**尾部**并压成一行，供日志 / 错误信息用。
//
// 取尾部而不是头部：脚本失败的原因通常打在最后几行。
// 截断可能正好切在一个多字节字符中间，所以顺手把非法 UTF-8 换成 '?'，免得日志里出现乱码。
//
// 参数：
//
//	b   — 原始输出
//	max — 最多保留多少字节（从尾部算）
//
// 返回：
//
//	string — 单行文本；b 为空时返回空串
func tail(b []byte, max int) string {
	if len(b) == 0 {
		return ""
	}
	if len(b) > max {
		b = b[len(b)-max:]
	}
	s := strings.ReplaceAll(string(b), "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(strings.ToValidUTF8(s, "?"))
}
