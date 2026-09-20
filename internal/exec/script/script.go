// Package script 是「执行外部脚本」这一指令类型的实现。
//
// 脚本放在**可执行文件同目录的 `script/` 文件夹**里；**解释器由脚本自己的 shebang 决定**，
// 调用方不指定类型。一条指令只带一个参数（一个 JSON），它原样作为 `argv[1]` 交给脚本；
// 脚本把结果写进本次执行工作目录下的 `result.json`，节点读它作为本节点结果。
//
// 脚本本体不由调用方上传，而是**由父节点按需下发**（见 `internal/node/scriptserve.go`）：
// 每个节点执行前先确保本地 `script/<名字>` 存在且哈希与指令里的一致，不符就向父索取并覆盖。
// 父在下发时还会用自己的身份私钥对整份脚本签一份**背书**（见 SignMessage），
// 子节点用 mTLS 拿到的父公钥验 —— 于是"这份字节确实是我父给的"这件事也有密码学凭据。
//
// 安全边界（改这里之前务必知道）：
//
//   - **脚本以节点进程的身份运行，没有沙箱** —— 它能读写本机任意文件、能联网。
//     所以信任边界是三条：谁能提交指令（`allowedOrigin`）、谁能写节点的 `script/` 目录、
//     以及脚本哈希校验。别把脚本当成"受限制的东西"。
//   - **脚本名必须过 ValidName**（禁止路径穿越）。名字会被拼进 `<script dir>/<name>`，
//     放行 `..` 或 `/` 的话，一条 `{"script":"../../keys/id_ed25519"}` 就能把
//     **节点身份私钥**当成脚本下发出去。
//   - 参数是**被 origin 身份签名覆盖**的（`Command.Payload` 在签名内），
//     所以中间节点改不了参数、也改不了"该跑哪个版本的脚本"。
//   - 父的背书签名与上面的哈希**分工不同、别互相替代**：哈希（来自 origin 签名）管
//     **内容对不对**，背书签名管**这份字节是谁给的**。签名**不做**防篡改 —— 一份被改过的
//     脚本照样能被它的持有者签出合法签名；能发现"内容变了"的始终是哈希比对。
package script

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"treecmd/internal/buildinfo"
	"treecmd/internal/canon"
	"treecmd/internal/exec"
)

const (
	// Type 是指令类型名。**这是全局契约**：它出现在 /v1/commands 的 type 字段里，定下来别改
	// （改了历史指令会落到安全空执行器 ERR_UNSUPPORTED_TYPE）。
	Type = "script"

	// sigDomain 是脚本背书签名的域分隔串。
	//
	// 为什么要它：同一个身份私钥在这个系统里还签别的东西（指令的 origin 签名、逐跳 HopAttest）。
	// 域分隔串让"这串签名只可能是对某个脚本的背书"，不能挪到别的用途上重放。
	sigDomain = "treecmd/script/v1"

	// ResultFile 是脚本约定写出的结果文件名，放在本次执行的工作目录里。
	ResultFile = "result.json"

	// workSubdir 是工作目录的根（`<script dir>/.work/`），每次执行在里面建一个临时子目录。
	workSubdir = ".work"

	// maxResult 是 result.json 的大小上限（4MB）。
	//
	// **必须远小于 64MB**：结果三级通道里，超过 64MB 会退化成对象存储引用，
	// 而引用只保证"同一节点可取回"（README「实现说明」），根根本拿不到。
	// 与其让结果悄悄丢在中间，不如在这里明确失败。
	maxResult int64 = 4 << 20

	// maxPayload 是那一个参数 JSON 的上限（1MB，与 command.max_payload 同量级）。
	maxPayload = 1 << 20

	// tailBytes 是失败时带进错误信息的输出尾部长度。
	tailBytes = 512
)

// Provider 由节点实现：保证脚本已在本地（必要时向父索取并校验哈希），返回它的绝对路径。
//
// 抽成接口是为了让本包不认识"节点 / 父 / 连接"这些概念 —— 执行器只依赖交给它的东西。
type Provider interface {
	EnsureScript(ctx context.Context, name, wantSHA256 string) (string, error)
}

// payload 是被指令签名覆盖的那一个 JSON 参数。
//
// 调用方只需要给 `script` 与 `params` 两项：
//
//	{"script":"disk_check","params":{"path":"/var"}}
//
// **`sha256` 由发起节点在签名之前补进去**（见 PreparePayload）—— 这样"只允许一个参数"
// 与"脚本哈希不可篡改"能同时成立，调用方也不必自己算哈希。
type payload struct {
	// Script 脚本文件名（不含目录），必须过 ValidName。
	Script string `json:"script"`
	// Params 调用方给脚本的数据，任意合法 JSON；脚本自己解释。
	Params json.RawMessage `json:"params,omitempty"`
	// SHA256 脚本内容的哈希（"sha256:"+十六进制），由发起节点注入。
	SHA256 string `json:"sha256,omitempty"`
}

// Executor 是 "script" 指令类型的执行器。
//
// 它没有可变状态，可以并发使用：每次 Run 各建一个独立的工作目录与进程组。
type Executor struct {
	dir string
	p   Provider
}

// New 构造执行器。
//
// 参数：
//
//	dir — 脚本目录（通常是 `<可执行文件同目录>/script`）；不需要它已存在（Run 会按需创建）
//	p   — 脚本提供者；通常就是本节点自己
//
// 返回：
//
//	*Executor — 可直接注册进 exec.Registry
func New(dir string, p Provider) *Executor { return &Executor{dir: dir, p: p} }

// Type 返回指令类型名（恒为 "script"）。
//
// 返回：
//
//	string — 恒为 "script"
func (*Executor) Type() string { return Type }

// Validate 校验参数载荷：必须是 JSON 对象、脚本名合规、体积在上限内。
//
// **刻意不检查"脚本在不在本地"**：子节点此刻还没有这个脚本，那是 Run 里 EnsureScript 的事。
// 提交期能不能发现"根上没有这个脚本"，靠的是 PreparePayload 那道 fail-fast。
//
// 参数：
//
//	s — 指令输入；本方法只读 Payload
//
// 返回：
//
//	error — 载荷为空 / 超限 / 不是 JSON 对象 / 脚本名不合规时返回
func (e *Executor) Validate(s exec.Spec) error {
	_, err := parsePayload(s.Payload)
	return err
}

// Run 执行一次脚本：确保脚本在本地 → 建工作目录 → 起进程 → 读 result.json。
//
// 参数：
//
//	ctx — 执行上下文；取消 / 超时会中断这次执行（整组回收进程）
//	s   — 指令输入；Payload 是那一个 JSON 参数，会被**原样**作为 argv[1] 交给脚本
//	_   — 进度发射器；脚本是黑盒，没有值得上报的中间进度
//
// 返回：
//
//	any   — result.json 的内容（[]byte，由 exec.EncodeResult 原样上报）；
//	        脚本没写 result.json 时为空（纯副作用型脚本，不算失败）
//	error — 脚本不在本地且索取失败、起不来、被中断、退出码非 0、result.json 读不了或超限时返回
func (e *Executor) Run(ctx context.Context, s exec.Spec, _ exec.ProgressEmitter) (any, error) {
	p, err := parsePayload(s.Payload)
	if err != nil {
		return nil, err
	}
	// 本地有（且哈希一致）就直接用；没有或对不上就向父索取并**无条件覆盖**
	path, err := e.p.EnsureScript(ctx, p.Script, p.SHA256)
	if err != nil {
		return nil, err
	}

	work, err := e.newWorkDir(s)
	if err != nil {
		return nil, err
	}
	// 无论成败都清掉：诊断信息（stderr 尾部）已经进错误文案，不留垃圾
	defer os.RemoveAll(work)

	out, err := runScript(ctx, path, string(s.Payload), work)
	if err != nil {
		return nil, err
	}
	if out.ExitCode != 0 {
		return nil, fmt.Errorf("脚本 %s 退出码 %d；stderr: %s", p.Script, out.ExitCode, tail(out.Stderr, tailBytes))
	}
	return readResult(work)
}

// OnRestart 拒绝自动重跑。
//
// 脚本是不透明的：它可能有副作用（写库、发请求、删文件），而 selfupdate 的**原地重启**会让
// 框架对"停在 SELF_RUNNING"的指令再跑一次。返回 error ⇒ 框架把这条指令落成 SELF_FAILED，
// 等人工确认后用 retry 接口重跑，而不是闷头再来一遍。
//
// 参数：
//
//	_ — 框架恒传 true（表示上次进程是在执行到一半时退出的）；本实现不看它
//
// 返回：
//
//	error — 恒为非 nil（这就是它的用途）
func (*Executor) OnRestart(bool) error {
	return errors.New("脚本可能有副作用，拒绝自动重跑；请确认后手动 retry")
}

// PreparePayload 在指令被签名之前，把本地脚本的 sha256 补进载荷。
//
// 为什么必须在签名前：这样哈希也落在 origin 签名的覆盖范围内，中间节点既改不了参数、
// 也改不了"该跑哪个版本的脚本"。顺带得到一道 **fail-fast** —— 发起节点上根本没有这个脚本时，
// 提交就被拒，不必等它铺到全树再逐节点失败。
//
// 参数：
//
//	b — 调用方给的载荷（`{"script":"名字","params":...}`）
//
// 返回：
//
//	[]byte — 补上 sha256 之后的载荷；已经有了且与本地一致时原样返回（幂等）
//	error  — 载荷非法、或本地没有这个脚本、或已有的 sha256 与本地不符时返回
func (e *Executor) PreparePayload(b []byte) ([]byte, error) {
	p, err := parsePayload(b)
	if err != nil {
		return nil, err
	}
	path, err := ResolveInDir(e.dir, p.Script)
	if err != nil {
		return nil, fmt.Errorf("本节点没有可用的脚本 %s（应放在 %s）：%w", p.Script, e.dir, err)
	}
	got, _, _, err := buildinfo.HashFile(path)
	if err != nil {
		return nil, fmt.Errorf("算脚本 %s 的哈希失败: %w", path, err)
	}
	if p.SHA256 == got {
		return b, nil
	}
	if p.SHA256 != "" {
		return nil, fmt.Errorf("载荷里的 sha256 与本地脚本 %s 不一致：载荷 %s，本地 %s", p.Script, p.SHA256, got)
	}
	p.SHA256 = got
	out, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("重新编码载荷失败: %w", err)
	}
	return out, nil
}

// parsePayload 解析并校验那一个 JSON 参数。
//
// 参数：
//
//	b — 载荷原始字节
//
// 返回：
//
//	*payload — 解析结果；sha256 在提交期可能还是空的
//	error    — 为空 / 超限 / 不是 JSON 对象 / 脚本名不合规时返回
func parsePayload(b []byte) (*payload, error) {
	if len(b) == 0 {
		return nil, errors.New(`脚本指令必须带一个 JSON 参数，如 {"script":"disk_check","params":{}}`)
	}
	if int64(len(b)) > maxPayload {
		return nil, fmt.Errorf("参数 JSON 有 %d 字节，超过上限 %d", len(b), maxPayload)
	}
	var p payload
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf(`参数必须是 JSON 对象，如 {"script":"disk_check","params":{}}：%w`, err)
	}
	if err := ValidName(p.Script); err != nil {
		return nil, err
	}
	return &p, nil
}

// ResolveInDir 把脚本名解析成脚本目录下的一个真实文件路径，并保证它**没有逃出**该目录。
//
// 为什么名字过了 ValidName 还不够：ValidName 只排除了 `..` 与 `/`，挡不住**符号链接**。
// 有人在 `script/` 里放一个 `foo.sh -> ../../keys/id_ed25519`，服务端就会把节点身份私钥
// 当成脚本发给全树。所以真正打开文件之前，必须解析符号链接、再确认结果仍在目录里。
//
// 参数：
//
//	dir  — 脚本目录（必须已存在）
//	name — 脚本文件名（不含目录）
//
// 返回：
//
//	string — 解析（含符号链接）之后的真实路径
//	error  — 名字不合规、目录不可用、文件不存在、或解析后逃出了 dir 时返回
func ResolveInDir(dir, name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("脚本目录不可用 %s: %w", dir, err)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, name))
	if err != nil {
		return "", fmt.Errorf("脚本 %s 不可读: %w", name, err)
	}
	if real != root && !strings.HasPrefix(real, root+string(filepath.Separator)) {
		return "", fmt.Errorf("脚本 %s 解析后落在脚本目录之外（%s）—— 拒绝", name, real)
	}
	return real, nil
}

// ValidName 校验脚本文件名是否合规。**这是防路径穿越的唯一入口，提交期与服务端两处都要调。**
//
// 为什么是安全关键：名字会被拼进 `<script dir>/<name>`。放行 `..` 或 `/` 的话，
// 一条 `{"script":"../../keys/id_ed25519"}` 就能把节点身份私钥当成脚本下发出去。
//
// 规则：只允许 [A-Za-z0-9._-]，长度 1..128，且不得是 "." / ".."（不含 `/` 已经排除了路径分隔符）。
//
// 参数：
//
//	name — 脚本文件名（不含目录）
//
// 返回：
//
//	error — 为空 / 超长 / 含白名单外字符 / 等于 "." 或 ".." 时返回；文案可直接给人看
func ValidName(name string) error {
	if name == "" {
		return errors.New("脚本名不能为空")
	}
	if len(name) > 128 {
		return fmt.Errorf("脚本名过长（%d 字节 > 128）", len(name))
	}
	if name == "." || name == ".." {
		return fmt.Errorf("脚本名不能是 %q", name)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == '-':
		default:
			return fmt.Errorf("脚本名含非法字符 %q（只允许字母、数字、点、下划线、连字符）", string(c))
		}
	}
	return nil
}

// SignMessage 返回"父对这份脚本的背书"要签的规范消息摘要。
//
// **父签、子验共用这一处** —— 两边必须算出字节完全相同的东西，所以这条消息的定义只能有一份。
// 摘要走 canon（与项目里其他签名同一口径：签的永远是对 canonical 编码取的摘要），长度前缀
// 拼接保证了无歧义（`("ab","c")` 与 `("a","bc")` 不会算出同一个摘要）。
//
// 签名覆盖 (脚本名, 内容哈希) 两项：名字把"这份字节属于哪个脚本"固定住，哈希把内容固定住。
//
// 参数：
//
//	name   — 脚本文件名（不含目录）
//	sha256 — 整份脚本内容的哈希（"sha256:"+十六进制）
//
// 返回：
//
//	[]byte — 32 字节摘要，直接交给 identity.Sign / identity.Verify
func SignMessage(name, sha256 string) []byte {
	return canon.DigestBytes([]byte(sigDomain), []byte(name), []byte(sha256))
}

// newWorkDir 为本次执行建一个工作目录：`<script dir>/.work/<commandID>-<随机>/`。
//
// 用 MkdirTemp 而不是固定名字：同一条指令失败后重跑（人工 retry）会再来一次，
// 固定名字会撞上上一次留下的目录。
//
// 接收者 e 提供脚本目录。
//
// 参数：
//
//	s — 指令输入；用它的 CommandID 给目录起个能认出来的前缀
//
// 返回：
//
//	string — 工作目录的绝对/相对路径（脚本就在这里跑，result.json 也写在这里）
//	error  — 建目录失败时返回
func (e *Executor) newWorkDir(s exec.Spec) (string, error) {
	root := filepath.Join(e.dir, workSubdir)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("建脚本工作目录失败 %s: %w", root, err)
	}
	work, err := os.MkdirTemp(root, s.CommandID+"-")
	if err != nil {
		return "", fmt.Errorf("建脚本工作目录失败 %s: %w", root, err)
	}
	return work, nil
}

// readResult 读脚本写下的 result.json，作为本节点结果。
//
// 缺失**不算失败**：脚本可能是纯副作用型的（只做事、没有返回值），此时本节点结果为空。
//
// 参数：
//
//	work — 本次执行的工作目录
//
// 返回：
//
//	any   — 文件内容（[]byte 会被 exec.EncodeResult 原样上报）；文件不存在时返回 nil
//	error — 文件存在但读不了，或超过 maxResult 时返回
func readResult(work string) (any, error) {
	path := filepath.Join(work, ResultFile)
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("读不到 %s: %w", path, err)
	}
	if fi.Size() > maxResult {
		return nil, fmt.Errorf("%s 有 %d 字节，超过上限 %d；结果不能这么大 —— 超过 64MB 会退化成"+
			"对象存储引用，而引用无法跨节点取回", ResultFile, fi.Size(), maxResult)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	return b, nil
}

// CleanWorkTree 清掉上一次进程留下的工作目录残骸。
//
// 进程被 kill 或 selfupdate 原地重启时，正在跑的脚本会留下 `.work/<commandID>-xxxx/`。
// 启动时调用它最安全 —— 那时本节点还没有任何指令在跑。
//
// 参数：
//
//	dir — 脚本目录（`<可执行文件同目录>/script`）
//
// 返回：
//
//	error — 删除失败时返回；调用方记一条日志即可，不必因此拒绝启动
func CleanWorkTree(dir string) error {
	root := filepath.Join(dir, workSubdir)
	if err := os.RemoveAll(root); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清理脚本工作目录 %s 失败: %w", root, err)
	}
	return nil
}
