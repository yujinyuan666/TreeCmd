// Package exec 定义执行器接口与注册表。本方案只实现 noop / echo（ADR-012）；
// 代码里的 sleep 与 fail 是测试用执行器。
package exec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrUnsupportedType 未知 / 已下线的指令类型。
var ErrUnsupportedType = errors.New("ERR_UNSUPPORTED_TYPE")

// Spec 执行器输入。
//
// 一个任务被分发到本节点后，框架把它的基本信息打包成 Spec 交给执行器；
// 执行器只依赖这里的字段，不去读配置或网络。
type Spec struct {
	CommandID string
	NodeID    string
	Path      string
	Type      string
	Payload   []byte
	Labels    map[string]string
}

// ProgressEmitter 进度发射（可丢）。
type ProgressEmitter interface {
	Emit(stage string, pct float64, msg string)
}

// NopEmitter 空实现。
type NopEmitter struct{}

// Emit 什么都不做，用于不需要上报进度的调用方。
//
// 接收者 NopEmitter 是一个无状态的空实现；框架里默认传的就是它。
//
// 参数：
//
//	stage — 进度阶段名
//	pct   — 完成百分比；取值范围由调用方与实现自行约定，这里不做校验
//	msg   — 人类可读的进度说明
func (NopEmitter) Emit(string, float64, string) {}

// Executor 执行器接口（第 8 章）。
//
// 各个实现里的参数名可能被写成 _（因为没用到、避免编译报未使用），
// 参数含义一律以本接口的命名为准。
type Executor interface {
	Type() string
	Validate(spec Spec) error
	Run(ctx context.Context, spec Spec, emit ProgressEmitter) (any, error)
	// OnRestart 仅在"账本停在 SELF_RUNNING"时被调用；必须幂等；返回 error = 拒绝重跑（框架落 SELF_FAILED）。
	OnRestart(wasRunning bool) error
}

// NeedsSelfResult 若为 true，CUSTOM 聚合时必须开启 RawChildren（见 3.3 / ADR-048 第 10 条）。
type NeedsSelfResultProvider interface {
	NeedsSelfResult() bool
}

// base 提供默认 OnRestart（一律继续重跑）。
type base struct{}

// OnRestart 默认实现：残留由任务内部处理，继续重跑。
//
// 接收者 base 是个空结构体，被内嵌进各内置执行器，只为共享这一段默认行为。
//
// 参数：
//
//	wasRunning — true 表示上次进程是在任务执行到一半时退出的；这里被忽略
//
// 返回：
//
//	error — 恒为 nil，表示不拒绝重跑
func (base) OnRestart(bool) error { return nil }

// Noop 压测递归与聚合链路。
type Noop struct{ base }

// Type 返回执行器类型名 "noop"。
func (Noop) Type() string { return "noop" }

// Validate 校验任务输入：noop 对载荷没有任何要求，恒通过。
//
// 参数：
//
//	spec — 任务的输入；noop 不读取其中任何字段
//
// 返回：
//
//	error — 恒为 nil
func (Noop) Validate(Spec) error { return nil }

// Run "执行"noop 任务：不做任何事，立刻返回成功。
//
// 参数：
//
//	ctx  — 上下文；noop 不读它，取消与否都会立刻返回
//	spec — 任务的输入；只把 NodeID 与 Path 原样回显，不读 Payload
//	emit — 进度发射器；noop 不上报进度
//
// 返回：
//
//	any   — 一个 map，含 node / path / type 三个键，便于聚合时看出结果来自哪个节点
//	error — 恒为 nil
func (Noop) Run(_ context.Context, s Spec, _ ProgressEmitter) (any, error) {
	return map[string]any{"node": s.NodeID, "path": s.Path, "type": "noop"}, nil
}

// Echo 端到端验证：回显载荷 + 本节点标识。
type Echo struct{ base }

// Type 返回执行器类型名 "echo"。
func (Echo) Type() string { return "echo" }

// Validate 校验回显任务必须带非空载荷。
//
// 参数：
//
//	spec — 任务的输入；这里只检查 Payload 是否为空
//
// 返回：
//
//	error — Payload 长度为 0（含 nil）时返回 "echo requires non-empty payload"，否则 nil
func (Echo) Validate(s Spec) error {
	if len(s.Payload) == 0 {
		return errors.New("echo requires non-empty payload")
	}
	return nil
}

// Run 执行回显：把载荷和本节点信息打包返回，用于端到端验证。
//
// 参数：
//
//	ctx  — 上下文；echo 不读它
//	spec — 任务的输入；用到 NodeID、Path、Payload、Labels
//	emit — 进度发射器；echo 不上报进度
//
// 返回：
//
//	any   — 一个 map，含 node / path / len / echo / labels 五个键
//	error — 恒为 nil
//
// 其中 echo 是 Payload 直接按字符串转出来的，不做编码转换，内容不保证是合法 UTF-8。
func (Echo) Run(_ context.Context, s Spec, _ ProgressEmitter) (any, error) {
	out := map[string]any{
		"node":   s.NodeID,
		"path":   s.Path,
		"len":    len(s.Payload),
		"echo":   string(s.Payload),
		"labels": s.Labels,
	}
	return out, nil
}

// Sleep 用于测试（payload = 毫秒数），体现 ctx 取消传播。
type Sleep struct{ base }

// Type 返回执行器类型名 "sleep"。
func (Sleep) Type() string { return "sleep" }

// Validate 校验睡眠任务必须带载荷（毫秒数）。
//
// 参数：
//
//	spec — 任务的输入；只检查 Payload 是否为空，不在这里判断它是不是合法数字
//
// 返回：
//
//	error — Payload 长度为 0（含 nil）时返回 "sleep requires payload (milliseconds)"，否则 nil
func (Sleep) Validate(s Spec) error {
	if len(s.Payload) == 0 {
		return errors.New("sleep requires payload (milliseconds)")
	}
	return nil
}

// Run 睡眠指定毫秒数，睡眠期间可以被 ctx 取消。
//
// 取消传播是刻意做的：select 同时等 ctx.Done() 与定时器，谁先就绪就走谁，
// 所以上游取消指令时这里能立刻返回，不会把整段睡眠睡完。
//
// 参数：
//
//	ctx  — 上下文；被取消或超时时立即返回 ctx.Err()
//	spec — 任务的输入；Payload 是十进制毫秒数，如 "1500"
//	emit — 进度发射器；sleep 不上报进度
//
// 返回：
//
//	any   — 睡满时返回含 node / slept_ms 的 map
//	error — Payload 解析失败时返回包装后的错误；被取消时返回 ctx.Err()
func (Sleep) Run(ctx context.Context, s Spec, _ ProgressEmitter) (any, error) {
	var ms int
	if _, err := fmt.Sscanf(string(s.Payload), "%d", &ms); err != nil {
		return nil, fmt.Errorf("sleep payload must be milliseconds: %w", err)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(time.Duration(ms) * time.Millisecond):
	}
	return map[string]any{"node": s.NodeID, "slept_ms": ms}, nil
}

// Fail 测试用执行器：默认总是失败；payload 写成 "k=v" 时**只有标签匹配的节点**才失败。
//
// 注意：这是"执行器自己决定失败"，与框架的分发无关 —— 框架对收到的任务一律执行，不做任何筛选。
type Fail struct{ base }

// Type 返回执行器类型名 "fail"。
func (Fail) Type() string { return "fail" }

// Validate 校验失败任务：fail 对载荷没有要求，恒通过。
//
// 是否真的失败由 Run 根据载荷决定，不在这里判断。
//
// 参数：
//
//	spec — 任务的输入；这里不读取
//
// 返回：
//
//	error — 恒为 nil
func (Fail) Validate(Spec) error { return nil }

// Run 按载荷内容决定"失败"还是"成功并跳过"，用于测试失败传播与标签筛选。
//
// 载荷规则：空串或 "always" 一律失败；写成 "键=值" 时，只有本节点 Labels 里该键的值
// 正好相等才失败，否则返回一个带 fail_skipped=true 的成功结果；其它内容当成错误信息原样返回。
//
// 参数：
//
//	ctx  — 上下文；fail 不读它
//	spec — 任务的输入；用到 Payload（失败规则）与 Labels（按标签筛选）
//	emit — 进度发射器；fail 不上报进度
//
// 返回：
//
//	any   — 标签不匹配时返回含 node / path / fail_skipped 的 map
//	error — 需要失败时返回错误
func (Fail) Run(_ context.Context, s Spec, _ ProgressEmitter) (any, error) {
	spec := strings.TrimSpace(string(s.Payload))
	if spec == "" || spec == "always" {
		return nil, errors.New("intentional failure")
	}
	if kv := strings.SplitN(spec, "=", 2); len(kv) == 2 {
		if s.Labels[kv[0]] == kv[1] {
			return nil, fmt.Errorf("intentional failure at %s (label %s=%s)", s.Path, kv[0], kv[1])
		}
		return map[string]any{"node": s.NodeID, "path": s.Path, "fail_skipped": true}, nil
	}
	return nil, errors.New(spec)
}

// safeEmpty 未知 / 已下线类型的"安全空执行器"（绝不能返回 nil）。
// OnRestart 直接 return nil，但 Run 必须返回 ERR_UNSUPPORTED_TYPE —— 否则历史未知类型指令会被静默判成功。
//
// 它不实现 NeedsSelfResultProvider，字段 typeName 只是用来把类型名带回给调用方。
type safeEmpty struct {
	base
	typeName string
}

// Type 返回构造它时记下的那个类型名。
//
// 接收者 e 是被登记过的类型名包装出来的占位执行器。
func (e safeEmpty) Type() string { return e.typeName }

// Validate 对未知类型一律不通过。
//
// 参数：
//
//	spec — 任务的输入；这里不读取
//
// 返回：
//
//	error — 恒为 ErrUnsupportedType
func (safeEmpty) Validate(Spec) error { return ErrUnsupportedType }

// Run 对未知类型一律返回 ErrUnsupportedType，绝不返回 nil 结果。
//
// 这里返回错误而不是成功很关键：一旦返回成功，历史数据里已下线的指令就会被静默判为执行成功。
//
// 参数：
//
//	ctx  — 上下文；这里不读
//	spec — 任务的输入；这里不读
//	emit — 进度发射器；这里不上报
//
// 返回：
//
//	any   — 恒为 nil
//	error — 恒为 ErrUnsupportedType
func (safeEmpty) Run(context.Context, Spec, ProgressEmitter) (any, error) {
	return nil, ErrUnsupportedType
}

// Registry 执行器注册表。
type Registry struct {
	mu sync.RWMutex
	m  map[string]Executor
}

// NewRegistry 新建注册表，并装入四个内置执行器：noop / echo / sleep / fail。
//
// 返回：
//
//	*Registry — 可以直接使用的注册表
func NewRegistry() *Registry {
	r := &Registry{m: map[string]Executor{}}
	r.Register(Noop{})
	r.Register(Echo{})
	r.Register(Sleep{})
	r.Register(Fail{})
	return r
}

// Register 按执行器自己的类型名，把它登记进注册表。
//
// 接收者 r 是执行器注册表；内部有读写锁，可以并发调用。
//
// 参数：
//
//	e — 要登记的执行器；key 取 e.Type()，同类型名已存在时被新的覆盖
func (r *Registry) Register(e Executor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[knowType(e)] = e
}

// For 按类型名查执行器，未知类型返回安全空执行器而不是 nil。
//
// 接收者 r 是执行器注册表。
//
// 参数：
//
//	typeName — 执行器类型名，如 "echo"
//
// 返回：
//
//	Executor — 已注册的执行器；没注册过时返回一个 safeEmpty，它的 Validate 与 Run 都返回
//	           ErrUnsupportedType，所以调用方拿到的永远不是 nil，不需要判空
func (r *Registry) For(typeName string) Executor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.m[typeName]; ok {
		return e
	}
	return safeEmpty{typeName: typeName}
}

// Has 判断某个类型名是否已注册（供上报本节点能力时使用）。
//
// 接收者 r 是执行器注册表。
//
// 参数：
//
//	typeName — 执行器类型名
//
// 返回：
//
//	bool — true 表示已注册
func (r *Registry) Has(typeName string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.m[typeName]
	return ok
}

// Types 返回已注册的全部类型名，按字典序排序。
//
// 接收者 r 是执行器注册表。
//
// 返回：
//
//	[]string — 排序后的类型名；一个都没注册时返回长度为 0 的切片（不是 nil）
func (r *Registry) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for k := range r.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// knowType 取执行器的类型名，等价于直接调用 e.Type()。
//
// 参数：
//
//	e — 任意执行器
//
// 返回：
//
//	string — e.Type() 的返回值
func knowType(e Executor) string { return e.Type() }

// EncodeResult 把执行结果编码成要上报的字节。
//
// 编码规则：nil 返回空字节；本来就是 []byte 的原样透传（nil 也当成空字节）；其它类型走 JSON。
// 也就是说执行器可以直接返回 []byte 来控制线上字节，返回别的东西则必须能被 JSON 序列化。
//
// 参数：
//
//	v — 执行器的返回值；nil、[]byte，或任意可 JSON 序列化的值
//
// 返回：
//
//	[]byte — 上报字节；nil 与 nil []byte 都返回长度为 0 的切片（不是 nil）
//	error  — JSON 序列化失败时返回
func EncodeResult(v any) ([]byte, error) {
	if v == nil {
		return []byte{}, nil
	}
	if b, ok := v.([]byte); ok {
		if b == nil {
			return []byte{}, nil
		}
		return b, nil
	}
	return json.Marshal(v)
}
