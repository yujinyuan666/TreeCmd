// Package aggregate 实现聚合策略与失败策略判定（3.3 / ADR-029 / ADR-041）。
package aggregate

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"

	"treecmd/internal/pb"
)

// ChildOutcome 一个子节点在本节点的聚合输入：状态 + 数据成对（缺状态则 OnFailure 无从判定）。
type ChildOutcome struct {
	NodeID      string
	AssignState pb.AssignStatus
	LocalState  pb.LocalExecState
	Error       string
	SelfResult  []byte // 仅 RawChildren=true 时有值；非 CUSTOM 策略不参与聚合、只供审计
	Aggregated  []byte // 子子树聚合结果（非 CUSTOM 策略实际使用的就是它）
	Raw         []byte // RawChildren=true 时填充：该子上报的 Report.Aggregated 原始字节，仅供审计
	Attest      *pb.ChildAttest
}

// FailurePolicy 失败策略 + 参数。
type FailurePolicy struct {
	Kind     pb.FailurePolicy
	Tolerate float64 // TOLERATE_N 的 k / TOLERATE_PCT 的 p
}

// Context 聚合输入契约（所有策略统一吃这个结构，见 ADR-029）。
type Context struct {
	SelfNodeID string
	Self       []byte
	Children   []ChildOutcome
	Total      int // 等待集合大小 = len(Outcomes) + |Unreported|（TOLERATE_PCT 的分母）
	// ParentJudged 父侧自行判定终态的子（无 child_reports）→ 状态。
	// 它们是 Unreported 的子集；**必须计入 NotDone**，否则会出现"有子失败、整条指令却判成功"。
	ParentJudged map[string]pb.AssignStatus
	Policy       FailurePolicy
	Strategy     pb.AggregateStrategy
	// Deadline 到达时，final 只含"自身 + 已 DONE 的子"
	DeadlineHit bool
}

// CustomAggregator CUSTOM 策略的执行器接口（唯一签名）。
type CustomAggregator interface {
	Aggregate(ctx Context) ([]byte, error)
	// NeedsSelfResult 为 true 时必须开启 RawChildren，否则提交期即拒绝（ERR_CUSTOM_NEEDS_RAWFILDREN）。
	NeedsSelfResult() bool
}

// FailedChild 失败 / 未成功子节点的归类（只按 AssignStatus 判定）。
type FailedChild struct {
	NodeID     string `json:"node_id"`
	Status     string `json:"assign_status"`
	LocalState string `json:"local_state"`
	Error      string `json:"error,omitempty"`
}

// Result 聚合结果。
type Result struct {
	Final   []byte
	Failed  []FailedChild
	Blocked bool // Policy 判定为"阻断整体终态"（→ FAILED）
	Done    int
	NotDone int
	Total   int
}

// EvaluatePolicy 精确判定公式（ADR-041 第 1 条）：
//
//	NotDone > k                    → FAILED        （注意是 > 而非 ≥）
//	Total > 0 && NotDone/Total > p → FAILED
//	ALL_MUST_SUCCEED: NotDone > 0  → FAILED
//	BEST_EFFORT: 恒不阻断
//
// NotDone 只数 Outcomes 中 AssignStatus ∈ {FAILED, TIMEOUT}；未上报子只贡献 Total。
//
// 参数：
//
//	p            — 失败策略类型 + 阈值（TOLERATE_N 的 k，TOLERATE_PCT 的 p）
//	outcomes     — 已上报的直接子结果；只统计其中状态为 FAILED / TIMEOUT 的
//	total        — 等待集合大小，作为 TOLERATE_PCT 的分母
//	parentJudged — 可选。父侧自行判定终态、没有 child_reports 的子；其 FAILED / TIMEOUT 也要计入
//
// 返回：
//
//	bool — true 表示本次判定会阻断整条指令（整体终态转 FAILED）；false 表示不阻断
func EvaluatePolicy(p FailurePolicy, outcomes []ChildOutcome, total int, parentJudged ...map[string]pb.AssignStatus) bool {
	notDone := 0
	for _, o := range outcomes {
		switch o.AssignState {
		case pb.AssignStatus_ASSIGN_STATUS_FAILED, pb.AssignStatus_ASSIGN_STATUS_TIMEOUT:
			notDone++
		}
	}
	// 父侧自行判定的终态子同样计入（它们没有 child_reports，不在 Outcomes 里）
	for _, m := range parentJudged {
		for _, st := range m {
			switch st {
			case pb.AssignStatus_ASSIGN_STATUS_FAILED, pb.AssignStatus_ASSIGN_STATUS_TIMEOUT:
				notDone++
			}
		}
	}
	switch p.Kind {
	case pb.FailurePolicy_POLICY_ALL_MUST_SUCCEED:
		return notDone > 0
	case pb.FailurePolicy_POLICY_TOLERATE_N:
		return float64(notDone) > p.Tolerate
	case pb.FailurePolicy_POLICY_TOLERATE_PCT:
		if total <= 0 {
			return false
		}
		return float64(notDone)/float64(total) > p.Tolerate
	case pb.FailurePolicy_POLICY_BEST_EFFORT:
		return false
	}
	// 未指定：保守按"全部必须成功"
	return notDone > 0
}

// Aggregate 执行一次聚合：先挑出 DONE 的子，再按 Strategy 产出最终结果。
//
// 只有 AssignStatus == DONE 的子参与聚合；其余计入 NotDone 并进 failed[]。
// 无论选哪种策略，最后都会用 EvaluatePolicy 判定是否会阻断整体终态。
//
// 参数：
//
//	ctx    — 聚合输入：自身结果、子结果、总数、聚合策略与失败策略
//	custom — CUSTOM 策略要用的聚合器；非 CUSTOM 策略可为 nil
//
// 返回：
//
//	*Result — 最终结果、失败子清单、Done / NotDone / Total 计数
//	error   — 策略为 CUSTOM 但 custom 为 nil、策略未知、或底层聚合失败时返回
func Aggregate(ctx Context, custom CustomAggregator) (*Result, error) {
	res := &Result{Total: ctx.Total}
	done := make([]ChildOutcome, 0, len(ctx.Children))
	for _, c := range ctx.Children {
		if c.AssignState == pb.AssignStatus_ASSIGN_STATUS_DONE {
			done = append(done, c)
			res.Done++
		} else {
			res.NotDone++
			res.Failed = append(res.Failed, FailedChild{
				NodeID: c.NodeID, Status: statusName(c.AssignState), LocalState: localStateName(c.LocalState), Error: c.Error,
			})
		}
	}
	res.Blocked = EvaluatePolicy(ctx.Policy, ctx.Children, ctx.Total, ctx.ParentJudged)

	var (
		final []byte
		err   error
	)
	switch ctx.Strategy {
	case pb.AggregateStrategy_AGGREGATE_MERGE:
		final, err = merge(ctx.Self, done)
	case pb.AggregateStrategy_AGGREGATE_SUM:
		final, err = sum(ctx.Self, done)
	case pb.AggregateStrategy_AGGREGATE_COUNT:
		final, err = count(ctx.Self, done)
	case pb.AggregateStrategy_AGGREGATE_CUSTOM:
		if custom == nil {
			return nil, errors.New("aggregate=CUSTOM but no CustomAggregator registered")
		}
		final, err = custom.Aggregate(ctx)
		if err == nil {
			// CUSTOM 不豁免 Policy：框架在返回后统一再应用一次 Policy 判定（双保险）
			res.Blocked = res.Blocked || EvaluatePolicy(ctx.Policy, ctx.Children, ctx.Total, ctx.ParentJudged)
		}
	case pb.AggregateStrategy_AGGREGATE_TREE, pb.AggregateStrategy_AGGREGATE_UNSPECIFIED:
		final, err = tree(ctx.SelfNodeID, ctx.Self, done, res.Failed)
	default:
		return nil, fmt.Errorf("ERR_UNKNOWN_AGGREGATE: %v", ctx.Strategy)
	}
	if err != nil {
		return nil, err
	}
	if final == nil {
		final = []byte{}
	}
	res.Final = final
	sort.SliceStable(res.Failed, func(i, j int) bool { return res.Failed[i].NodeID < res.Failed[j].NodeID })
	return res, nil
}

// ---------- TREE：按 NodeID 组织嵌套结构，保留层级 ----------

type treeNode struct {
	NodeID   string          `json:"node_id"`
	Self     json.RawMessage `json:"self,omitempty"`
	Nodes    []*treeNode     `json:"nodes,omitempty"`
	Failed   []FailedChild   `json:"failed,omitempty"`
	Children int             `json:"children"`
}

// tree 把自身结果与各直接子的聚合结果组织成嵌套 JSON（TREE 策略，保留层级）。
//
// 每个 DONE 子先尝试把它的 Aggregated 当成一个 treeNode 解析：解析成功就用它自带的
// node_id / nodes / failed；否则退化成"node_id + 原始结果"。
//
// 参数：
//
//	selfNodeID — 本节点 NodeID，作为根节点的 node_id
//	self       — 本节点自身结果；是合法 JSON 则原样嵌入，否则按字符串编码
//	done       — 状态为 DONE 的子结果；取其 Aggregated 字段
//	failed     — 失败子节点归类；非空时挂到根节点的 failed 上
//
// 返回：
//
//	[]byte — 整棵树的 JSON 字节
//	error  — JSON 编码失败时返回
func tree(selfNodeID string, self []byte, done []ChildOutcome, failed []FailedChild) ([]byte, error) {
	root := &treeNode{NodeID: selfNodeID, Children: len(done) + len(failed)}
	if raw, ok := rawJSON(self); ok {
		root.Self = raw
	}
	if len(failed) > 0 {
		root.Failed = failed
	}
	for _, c := range done {
		n := &treeNode{}
		var inner struct {
			NodeID   string          `json:"node_id"`
			Nodes    []*treeNode     `json:"nodes"`
			Failed   []FailedChild   `json:"failed"`
			Children int             `json:"children"`
			Self     json.RawMessage `json:"self"`
		}
		if err := json.Unmarshal(c.Aggregated, &inner); err == nil && inner.NodeID != "" {
			n = &treeNode{NodeID: inner.NodeID, Self: inner.Self, Nodes: inner.Nodes, Failed: inner.Failed, Children: inner.Children}
		} else {
			n.NodeID = c.NodeID
			if raw, ok := rawJSON(c.Aggregated); ok {
				n.Self = raw
			}
		}
		if n.NodeID == "" {
			n.NodeID = c.NodeID
		}
		root.Nodes = append(root.Nodes, n)
	}
	sort.SliceStable(root.Nodes, func(i, j int) bool { return root.Nodes[i].NodeID < root.Nodes[j].NodeID })
	return json.Marshal(root)
}

// rawJSON 把任意字节转成能直接嵌进 JSON 的 RawMessage。
//
// 空输入返回 (nil, false)；合法 JSON 原样返回；其余按 JSON 字符串编码后返回。
//
// 参数：
//
//	b — 待转换的原始字节
//
// 返回：
//
//	json.RawMessage — 可嵌入的结果；b 为空时为 nil
//	bool            — false 表示 b 为空（此时不要把返回值写进 JSON）
func rawJSON(b []byte) (json.RawMessage, bool) {
	if len(b) == 0 {
		return nil, false
	}
	if json.Valid(b) {
		return json.RawMessage(b), true
	}
	q, _ := json.Marshal(string(b))
	return json.RawMessage(q), true
}

// ---------- MERGE：浅合并（同键后者覆盖） ----------

// merge 把自身结果与所有 DONE 子结果做浅合并：同键后者覆盖前者。
//
// 要求每一段都是扁平的 key/value JSON 对象；出现非对象或非法 JSON 直接报错。
//
// 参数：
//
//	self — 本节点自身结果
//	done — 状态为 DONE 的子结果；取其 Aggregated 字段
//
// 返回：
//
//	[]byte — 合并后的 JSON 对象
//	error  — 某一段不是合法 JSON 对象时返回
func merge(self []byte, done []ChildOutcome) ([]byte, error) {
	out := map[string]any{}
	apply := func(b []byte) error {
		if len(b) == 0 {
			return nil
		}
		m := map[string]any{}
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("MERGE requires flat key/value JSON, got %q: %w", trunc(b), err)
		}
		for k, v := range m {
			out[k] = v
		}
		return nil
	}
	if err := apply(self); err != nil {
		return nil, err
	}
	for _, c := range done {
		if err := apply(c.Aggregated); err != nil {
			return nil, err
		}
	}
	return json.Marshal(out)
}

// ---------- SUM / COUNT：只吃 DONE 子的数值结果 ----------

// sum 把自身与各 DONE 子结果中能识别出的数值相加，输出形如 {"sum": 总和} 的 JSON。
//
// 识别不出数值的输入直接跳过，不报错。
//
// 参数：
//
//	self — 本节点自身结果
//	done — 状态为 DONE 的子结果；取其 Aggregated 字段
//
// 返回：
//
//	[]byte — 形如 {"sum": 总和} 的 JSON
//	error  — JSON 编码失败时返回
func sum(self []byte, done []ChildOutcome) ([]byte, error) {
	total := 0.0
	for _, b := range append([][]byte{self}, aggBytes(done)...) {
		v, ok := numeric(b)
		if !ok {
			continue
		}
		total += v
	}
	return json.Marshal(map[string]any{"sum": total})
}

// count 统计 DONE 子树里"成功执行了本地部分"的节点数（COUNT 策略）。
//
// 自身计 1：自身结果非空记 1；每个 DONE 子若有数值结果就按该值累加，否则非空记 1。
//
// 参数：
//
//	self — 本节点自身结果；非空即计 1
//	done — 状态为 DONE 的子结果；取其 Aggregated 字段
//
// 返回：
//
//	[]byte — 形如 {"count": N} 的 JSON
//	error  — JSON 编码失败时返回
func count(self []byte, done []ChildOutcome) ([]byte, error) {
	n := 0.0
	if len(self) > 0 {
		n++
	}
	for _, c := range done {
		if v, ok := numeric(c.Aggregated); ok {
			n += v
		} else if len(c.Aggregated) > 0 {
			n++
		}
	}
	return json.Marshal(map[string]any{"count": int(n)})
}

// aggBytes 取出所有子结果的 Aggregated 字段，按原顺序拼成一个切片。
//
// 参数：
//
//	done — 状态为 DONE 的子结果
//
// 返回：
//
//	[][]byte — 与 done 等长、同顺序的聚合结果字节
func aggBytes(done []ChildOutcome) [][]byte {
	out := make([][]byte, 0, len(done))
	for _, c := range done {
		out = append(out, c.Aggregated)
	}
	return out
}

// numeric 从一段字节里尽力抽出一个数值。
//
// 依次尝试：先直接按数字解析；不行再按 JSON 对象解析，并从
// value / sum / count / n / result 这些键里找数字或可解析的数字字符串。
//
// 参数：
//
//	b — 待解析的原始字节
//
// 返回：
//
//	float64 — 解析出的数值
//	bool    — false 表示解析不出数值
func numeric(b []byte) (float64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	if f, err := strconv.ParseFloat(string(b), 64); err == nil {
		return f, true
	}
	m := map[string]any{}
	if err := json.Unmarshal(b, &m); err == nil {
		for _, key := range []string{"value", "sum", "count", "n", "result"} {
			if v, ok := m[key]; ok {
				switch t := v.(type) {
				case float64:
					return t, true
				case string:
					if f, err := strconv.ParseFloat(t, 64); err == nil {
						return f, true
					}
				}
			}
		}
	}
	return 0, false
}

// ---------- 枚举名（日志 / 结果用） ----------

// statusName 去掉 AssignStatus 枚举名的前缀，返回短名（如 DONE、FAILED）。
//
// 参数：
//
//	s — protobuf 的分配状态枚举值
//
// 返回：
//
//	string — 去掉 ASSIGN_STATUS_ 前缀后的名字；没有前缀则原样返回
func statusName(s pb.AssignStatus) string {
	return trimPrefix(s.String(), "ASSIGN_STATUS_")
}

// localStateName 去掉 LocalExecState 枚举名的前缀，返回短名。
//
// 参数：
//
//	s — protobuf 的本地执行状态枚举值
//
// 返回：
//
//	string — 去掉 LOCAL_STATE_ 前缀后的名字；没有前缀则原样返回
func localStateName(s pb.LocalExecState) string {
	return trimPrefix(s.String(), "LOCAL_STATE_")
}

// trimPrefix 若 s 以前缀 p 开头则去掉它，否则原样返回。
//
// 注意：s 必须严格长于 p 才会裁剪，相等时保持原样。
//
// 参数：
//
//	s — 原字符串
//	p — 待去掉的前缀
//
// 返回：
//
//	string — 去前缀后的字符串；未匹配时就是 s 本身
func trimPrefix(s, p string) string {
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

// trunc 把字节转成字符串，超过 64 字节则截断并追加省略号（用于拼错误信息）。
//
// 参数：
//
//	b — 待截断的原始字节
//
// 返回：
//
//	string — 最多 64 字节的字符串；被截断时以 ... 结尾
func trunc(b []byte) string {
	if len(b) > 64 {
		return string(b[:64]) + "..."
	}
	return string(b)
}

// Pct 求完成比例，用作进度百分比（用于进度抑制）。
//
// 结果被夹在 [0,1]：total<=0 时返回 0，done 超过 total 时返回 1。
//
// 参数：
//
//	done  — 已完成数量
//	total — 总数量（分母）
//
// 返回：
//
//	float64 — 0 到 1 之间的完成比例
func Pct(done, total int) float64 {
	if total <= 0 {
		return 0
	}
	return math.Min(1, float64(done)/float64(total))
}

// ParsePolicy 把策略文本解析成 FailurePolicy。
//
// 支持 "TOLERATE_N:3" / "TOLERATE_PCT:0.2" / "ALL_MUST_SUCCEED" / "BEST_EFFORT"：
// 空串按 ALL_MUST_SUCCEED 处理；名字未知、缺参数或参数不是数字时返回错误。
//
// 参数：
//
//	s — 策略文本，形如 "TOLERATE_N:3"
//
// 返回：
//
//	FailurePolicy — 解析出的策略类型与阈值
//	error         — 未知策略名 / 缺参数 / 参数非法时返回
func ParsePolicy(s string) (FailurePolicy, error) {
	if s == "" {
		return FailurePolicy{Kind: pb.FailurePolicy_POLICY_ALL_MUST_SUCCEED}, nil
	}
	name, arg, hasArg := s, "", false
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			name, arg, hasArg = s[:i], s[i+1:], true
			break
		}
	}
	switch name {
	case "ALL_MUST_SUCCEED":
		return FailurePolicy{Kind: pb.FailurePolicy_POLICY_ALL_MUST_SUCCEED}, nil
	case "BEST_EFFORT":
		return FailurePolicy{Kind: pb.FailurePolicy_POLICY_BEST_EFFORT}, nil
	case "TOLERATE_N":
		if !hasArg {
			return FailurePolicy{}, errors.New("TOLERATE_N requires :k")
		}
		k, err := strconv.Atoi(arg)
		if err != nil {
			return FailurePolicy{}, fmt.Errorf("TOLERATE_N: invalid k %q", arg)
		}
		return FailurePolicy{Kind: pb.FailurePolicy_POLICY_TOLERATE_N, Tolerate: float64(k)}, nil
	case "TOLERATE_PCT":
		if !hasArg {
			return FailurePolicy{}, errors.New("TOLERATE_PCT requires :p")
		}
		p, err := strconv.ParseFloat(arg, 64)
		if err != nil {
			return FailurePolicy{}, fmt.Errorf("TOLERATE_PCT: invalid p %q", arg)
		}
		return FailurePolicy{Kind: pb.FailurePolicy_POLICY_TOLERATE_PCT, Tolerate: p}, nil
	}
	return FailurePolicy{}, fmt.Errorf("ERR_UNKNOWN_POLICY: %q", s)
}

// PolicyName 把策略对象反向拼回文本形式（审计 / 响应用），与 ParsePolicy 互为逆操作。
//
// 参数：
//
//	p — 失败策略
//
// 返回：
//
//	string — 如 "TOLERATE_N:3"；类型未知时返回 "UNSPECIFIED"
func PolicyName(p FailurePolicy) string {
	switch p.Kind {
	case pb.FailurePolicy_POLICY_ALL_MUST_SUCCEED:
		return "ALL_MUST_SUCCEED"
	case pb.FailurePolicy_POLICY_TOLERATE_N:
		return "TOLERATE_N:" + strconv.Itoa(int(p.Tolerate))
	case pb.FailurePolicy_POLICY_TOLERATE_PCT:
		return "TOLERATE_PCT:" + strconv.FormatFloat(p.Tolerate, 'f', -1, 64)
	case pb.FailurePolicy_POLICY_BEST_EFFORT:
		return "BEST_EFFORT"
	}
	return "UNSPECIFIED"
}

// StrategyName 去掉 AggregateStrategy 枚举名的前缀，返回短名（如 TREE、MERGE）。
//
// 参数：
//
//	s — 聚合策略枚举值
//
// 返回：
//
//	string — 去掉 AGGREGATE_ 前缀后的名字；没有前缀则原样返回
func StrategyName(s pb.AggregateStrategy) string {
	return trimPrefix(s.String(), "AGGREGATE_")
}
