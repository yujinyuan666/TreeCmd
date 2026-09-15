// Package apis 是「手写对外 API 调用」的框架。
//
// 加一个接口只要两步：
//
//  1. **写一个方法体文件**：文件名 = 类型名去掉下划线（`uuid_v4` → `uuidv4.go`），
//     里面写一个 apiRun 形状的函数（函数名用驼峰：`uuidV4`），通常十几行；
//  2. **在 table 里加一行**：`"uuid_v4": uuidV4,`。
//
// 就这两步，框架两侧都不用动 —— 登记进执行器注册表由 Register 自动完成。
// 之后它就是一个可下发的指令类型：`POST /v1/commands` 里写 `{"type":"uuid_v4"}`，
// 整棵树每个节点各调一次这个 API，结果逐跳回传到发起节点。
//
// 为什么方法体文件能写得这么薄：exec.Executor 接口要 Type / Validate / OnRestart / Run 四个方法，
// 其中前三个对 HTTP 接口是恒定的，由 apiFunc 一次性兜住；方法体文件只需给出真正不一样的那个 Run。
//
// 两条约定：
//
//   - table 的 key（类型名）是**全局契约**，它出现在 /v1/commands 的 type 字段里，定下来别改。
//   - 默认"进程重启后重跑"。GET 只读接口无所谓；会创建资源的接口要在方法体里自己兜住 ——
//     抛 error 会让框架落 SELF_FAILED 等人工确认，而不是闷头再发一次。
package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"treecmd/internal/exec"
)

const (
	// callTimeout 单次外部调用的超时。比指令默认 deadline 短得多 —— 正常情况下是它先触发，
	// 一条卡死的上游不会把整条指令拖到超时。
	callTimeout = 15 * time.Second

	// maxBody 单次调用最多读多少字节响应体（4MB）。必须有上限：上游灌大响应时不能把节点内存吃掉。
	maxBody = 4 << 20
)

// httpClient 全包共用一个客户端：复用连接，别每次调用都新建（那样每个请求都要重新握手）。
// 超时按请求算；本机配了 HTTP_PROXY 时它也会照常生效。
var httpClient = &http.Client{Timeout: callTimeout}

// apiRun 一个 API 的实现体。**每个接口只需要写这么一个函数。**
//
// 参数：
//
//	ctx — 执行上下文；被取消时应当中断正在发的请求
//	s   — 指令输入；NodeID / Path 用于把结果和节点对上，Payload 是本接口自己的参数
//
// 返回：
//
//	any   — 结果值，会由 exec.EncodeResult 序列化成 JSON 上报（返回 []byte 则原样透传）
//	error — 失败时返回；框架会据此把这条指令在本节点判为 SELF_FAILED
type apiRun func(ctx context.Context, s exec.Spec) (any, error)

// table 是本框架的**唯一入口**：类型名 → 方法体。
//
// **加一个 API = 写一个方法体文件 + 在这里加一行。** 没有第三个地方要改 ——
// 登记进执行器注册表由 Register 自动做。
//
// key 是类型名，属全局契约（见包注释）。
var table = map[string]apiRun{
	"uuid_v4":     uuidV4,
	"remote_time": remoteTime,
}

// apiFunc 把 apiRun 适配成 exec.Executor：Type / Validate / OnRestart 由它一次性兜住，
// 只有 Run 转给真正的实现。这样每个 API 就不必重复写那三个恒定方法。
type apiFunc struct {
	name string
	run  apiRun
}

// Type 返回指令类型名，也就是 table 里写的那个名字。
func (f apiFunc) Type() string { return f.name }

// Validate 默认放行：参数校验留给实现自己（多数接口的"参数错"表现为上游返回 4xx）。
func (f apiFunc) Validate(exec.Spec) error { return nil }

// OnRestart 默认允许重跑，对应包注释里那条约定。
func (f apiFunc) OnRestart(bool) error { return nil }

// Run 把请求转给实现函数。
//
// 参数：
//
//	ctx — 执行上下文
//	s   — 指令输入
//	_   — 进度发射器；一次 HTTP 调用没有值得上报的中间进度
//
// 返回：
//
//	any   — 实现函数的结果
//	error — 实现函数返回的错误
func (f apiFunc) Run(ctx context.Context, s exec.Spec, _ exec.ProgressEmitter) (any, error) {
	return f.run(ctx, s)
}

// Register 把 table 里所有 API 登记进执行器注册表。
//
// 这是本包对外的唯一装配入口，调用方（internal/node 的装配路径）只需要这一行。
// 它按 table 全量登记，所以**加 API 时这里不用改**。
//
// 参数：
//
//	r — 执行器注册表；通常来自 exec.NewRegistry()（里面已有 noop / echo / sleep / fail）
func Register(r *exec.Registry) {
	for name, run := range table {
		r.Register(apiFunc{name: name, run: run})
	}
}

// getJSON 发一个 GET 并把响应按 JSON 解到 out —— 本包所有 API 共用的唯一工具。
//
// 参数：
//
//	ctx    — 上下文；被取消会立刻中断这次请求
//	rawURL — 目标地址，必须带 http:// 或 https:// 前缀
//	q      — 查询参数；交给 url.Values 转义，不要自己拼字符串
//	out    — 接收 JSON 的指针，如 *[]string
//
// 返回：
//
//	error — 传输失败（连不上 / 超时 / 取消）、地址不是 http(s)、状态码非 2xx、
//	        或响应体不是合法 JSON 时返回。文案里带状态码与响应体片段 ——
//	        上游常把真正的原因写在 body 里，只报状态码很难查
func getJSON(ctx context.Context, rawURL string, q url.Values, out any) error {
	if len(q) > 0 {
		rawURL += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("地址不合法 %q: %w", rawURL, err)
	}
	// 只放行 http/https：别的 scheme（file:// 之类）既不是本包的用途，也是不必要的口子
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return fmt.Errorf("只支持 http/https 地址，收到 %q", req.URL.Scheme)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "treecmd-apis")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("请求 %s 失败: %w", rawURL, err)
	}
	defer resp.Body.Close()

	// 多读 1 个字节：用它判断"是不是正好被截断了"，比信 Content-Length 可靠
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return fmt.Errorf("读取响应体失败: %w", err)
	}
	if int64(len(body)) > maxBody {
		body = body[:maxBody]
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("上游返回 HTTP %d: %s", resp.StatusCode, snippet(body))
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("响应不是预期的 JSON（片段 %q）: %w", snippet(body), err)
	}
	return nil
}

// snippet 把响应体压成一段单行文本，拼进错误信息（出错时上游常把原因写在 body 里）。
//
// 参数：
//
//	b — 响应体原始字节
//
// 返回：
//
//	string — 最多 200 字节、已去掉换行的文本
func snippet(b []byte) string {
	if len(b) > 200 {
		b = b[:200] // 可能切在多字节字符中间，下面统一把非法 UTF-8 换掉
	}
	return strings.TrimSpace(strings.ReplaceAll(strings.ToValidUTF8(string(b), "?"), "\n", " "))
}
