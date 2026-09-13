// CUSTOM 聚合器的注册入口（方案 3.3 / 3.15）。
//
// 注册在"进程启动时"完成（编译期注册表），提交指令时按名字查表：
//   - 名字不存在 → 提交即拒（ERR_UNKNOWN_CUSTOM_AGGREGATOR）；
//   - 聚合器声明 NeedsSelfResult() 而指令未开 RawChildren → 提交即拒（ERR_CUSTOM_NEEDS_RAWFILDREN）。
//
// 这两条都是"早失败"，避免"读到 nil 却以为是聚合出错"这类高成本排查。
package aggregate

import (
	"encoding/json"
	"sort"
	"sync"

	"treecmd/internal/pb"
)

// CustomFactory 构造一个 CUSTOM 聚合器实例。
type CustomFactory func() CustomAggregator

var (
	customMu sync.RWMutex
	customs  = map[string]CustomFactory{}
)

// RegisterCustom 注册一个 CUSTOM 聚合器工厂。
//
// 名字为空或工厂为 nil 时直接忽略；同名重复注册以最后一次为准。
//
// 参数：
//
//	name — 聚合器名字（指令里 aggregate 字段填的就是它）
//	f    — 每次调用都返回一个新聚合器实例的工厂函数
func RegisterCustom(name string, f CustomFactory) {
	if name == "" || f == nil {
		return
	}
	customMu.Lock()
	defer customMu.Unlock()
	customs[name] = f
}

// LookupCustom 按名字取一个新的聚合器实例（每次调用工厂新建一个）。
//
// 参数：
//
//	name — 聚合器名字
//
// 返回：
//
//	CustomAggregator — 新建的实例；这个名字没注册过时为 nil
//	bool             — false 表示名字不存在（提交期据此拒绝）
func LookupCustom(name string) (CustomAggregator, bool) {
	customMu.RLock()
	f, ok := customs[name]
	customMu.RUnlock()
	if !ok {
		return nil, false
	}
	return f(), true
}

// CustomNames 返回所有已注册聚合器的名字，按字典序升序排序（展示 / 审计用）。
//
// 返回：
//
//	[]string — 已注册的名字；没有任何注册时为空切片
func CustomNames() []string {
	customMu.RLock()
	defer customMu.RUnlock()
	out := make([]string, 0, len(customs))
	for k := range customs {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// init 在包初始化时注册两个内置聚合器：subtree_count 与 audit_raw。
func init() {
	RegisterCustom("subtree_count", func() CustomAggregator { return subtreeCount{} })
	RegisterCustom("audit_raw", func() CustomAggregator { return auditRaw{} })
}

// subtreeCount 统计"子树里成功执行了本地部分的节点数"（不吃 SelfResult）。
type subtreeCount struct{}

// Aggregate 统计子树中成功执行了本地部分的节点数（不吃 SelfResult）。
//
// 接收者 subtreeCount 是个无状态空结构体，只用来挂方法。
// 自身结果非空记 1；每个 DONE 子假如有 {"count":N} 就累加 N，否则非空记 1。
//
// 参数：
//
//	ctx — 聚合输入：自身结果 + 各直接子结果
//
// 返回：
//
//	[]byte — 形如 {"custom":"subtree_count","count":N} 的 JSON
//	error  — JSON 编码失败时返回
func (subtreeCount) Aggregate(ctx Context) ([]byte, error) {
	n := 0
	if len(ctx.Self) > 0 {
		n++
	}
	for _, c := range ctx.Children {
		if c.AssignState != pb.AssignStatus_ASSIGN_STATUS_DONE {
			continue
		}
		var inner struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(c.Aggregated, &inner); err == nil {
			n += inner.Count
		} else if len(c.Aggregated) > 0 {
			n++
		}
	}
	return json.Marshal(map[string]any{"custom": "subtree_count", "count": n})
}

// NeedsSelfResult 报告该聚合器不需要子节点的自身结果（恒为 false）。
func (subtreeCount) NeedsSelfResult() bool { return false }

// auditRaw 演示"需要子节点自身结果"的聚合器：必须开 RawChildren，否则提交即拒。
type auditRaw struct{}

// Aggregate 汇总每个直接子的自身结果摘要（审计用，需要 SelfResult）。
//
// 接收者 auditRaw 是个无状态空结构体，只用来挂方法。
// 它列出全部子（不过滤 DONE），每个子给出 node_id / assign_status / self_result。
//
// 参数：
//
//	ctx — 聚合输入；子节点的 SelfResult 只有在 RawChildren=true 时才有值
//
// 返回：
//
//	[]byte — 形如 {"custom":"audit_raw","self_len":N,"children":[...]} 的 JSON
//	error  — JSON 编码失败时返回
func (auditRaw) Aggregate(ctx Context) ([]byte, error) {
	type item struct {
		NodeID string `json:"node_id"`
		Status string `json:"assign_status"`
		Self   string `json:"self_result"`
	}
	items := make([]item, 0, len(ctx.Children))
	for _, c := range ctx.Children {
		items = append(items, item{NodeID: c.NodeID, Status: c.AssignState.String(), Self: string(c.SelfResult)})
	}
	return json.Marshal(map[string]any{
		"custom": "audit_raw", "self_len": len(ctx.Self), "children": items,
	})
}

// NeedsSelfResult 报告该聚合器需要子节点的自身结果（恒为 true）⇒ 指令必须开 RawChildren。
func (auditRaw) NeedsSelfResult() bool { return true }
