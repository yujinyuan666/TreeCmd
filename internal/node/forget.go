package node

import (
	"fmt"
	"time"

	"treecmd/internal/store"
)

// 失效子节点清理（`/v1/forget`；设计与取舍见 README 的「失效节点清理：`/v1/forget`」一节）。
//
// 为什么需要它：父端关于一个子节点的记录散落在内存注册表、state.dat.known_children 与
// bbolt 的四个桶里，而**子节点掉线与被驱逐都不会删这些记录**。于是"误启动的实例"、
// "注册被拒但调过一元 RPC 的节点"会留下再也回不来的残骸：它们永远出现在 /v1/tree、
// 把健康检查的 known 撑大、并让当前节点长期显示 DEGRADED。
//
// 设计取舍（三条护栏，见 ADR-052）：
//  1. **在线的一律不删** —— 正在滚动重启的子节点会被 hub.conn 命中，直接拒绝，force 也绕不过；
//  2. **默认只清孤立残留** —— 默认 mode=garbage 只清"从未进过注册表"的垃圾（正是误启动/注册失败
//     那一类），清"曾经正常的直接子"必须显式 mode=stale；
//  3. **force 只越过"沉默时长"判定，不越过在线判定** —— 它是"我知道我在做什么"的二次确认。

// 清理模式（`/v1/forget` 的 mode 参数）。
const (
	// ForgetGarbage 只清"从未进入过注册表"的孤立残留（默认）。
	ForgetGarbage = "garbage"
	// ForgetStale 清"曾经是正常的直接子、但已长期离线"的节点。
	ForgetStale = "stale"
)

// 拒绝原因（机器可读；到 HTTP 状态码的映射见 api.go 的 statusForForget）。
const (
	forgetErrBadMode    = "ERR_BAD_MODE"
	forgetErrOnline     = "ERR_CHILD_ONLINE"
	forgetErrNotFound   = "ERR_CHILD_NOT_FOUND"
	forgetErrNeedsStale = "ERR_NEEDS_STALE"
	forgetErrTooRecent  = "ERR_TOO_RECENT"
)

// ForgetOptions 一次清理请求的参数。
type ForgetOptions struct {
	// NodeID 要清理的子节点 NodeID（UUIDv7 文本）。
	NodeID string
	// Mode garbage（默认）/ stale。
	Mode string
	// Force 越过"沉默时长"与"模式范围"判定，只保留在线护栏。
	Force bool
	// Purge 连该子节点的 child_reports（父端权威结果副本）一起删。
	// 默认**保留**：那可能是某条指令唯一一份已完成结果，删了聚合就缺数据了。
	Purge bool
}

// ForgetPlan 判定结论与条目计数：GET 是只读预览，POST 执行后在同一结构上回填 Deleted。
type ForgetPlan struct {
	NodeID string `json:"node_id"`
	Mode   string `json:"mode"`
	Force  bool   `json:"force"`
	Purge  bool   `json:"purge"`

	// ---- 现场事实 ----
	Online       bool   `json:"online"`        // hub 上有活跃连接（= /v1/tree 的 online）
	Known        bool   `json:"known"`         // 在内存注册表里（含 Warm 预热出来的）
	Confirmed    bool   `json:"confirmed"`     // 真的连上过（Warm 预热不算）
	HasWatermark bool   `json:"has_watermark"` // bbolt 里有 child_watermark
	Evicted      bool   `json:"evicted"`       // 该水位已被标记驱逐
	Path         string `json:"path,omitempty"`
	Name         string `json:"name,omitempty"`
	LastSeen     string `json:"last_seen,omitempty"` // RFC3339；从未见过时省略

	// ---- 判定依据（阈值一起回给调用方，便于判断要不要加 force） ----
	SilenceSeconds int64 `json:"silence_seconds"`
	GraceSeconds   int64 `json:"grace_seconds"`
	DeadSeconds    int64 `json:"dead_threshold_seconds"`

	// ---- 待删/已删条目 ----
	Assignments  int `json:"assignments"`
	Reports      int `json:"reports"`
	EvictedItems int `json:"evicted_items"`

	// ---- 结论 ----
	Allowed bool          `json:"allowed"`
	Reason  string        `json:"reason,omitempty"`
	Hint    string        `json:"hint,omitempty"`
	Applied bool          `json:"applied"`
	Deleted *ForgetCounts `json:"deleted,omitempty"`
}

// ForgetCounts 实际删除掉的条目数（仅供执行后的审计与回执）。
type ForgetCounts struct {
	Assignments int  `json:"assignments"`
	Reports     int  `json:"reports"`
	Evicted     int  `json:"evicted"`
	Watermark   int  `json:"watermark"`
	Registry    int  `json:"registry"`
	StateSaved  bool `json:"state_saved"`
}

// ForgetPreview 只读预演：算出"会不会被允许、会被删掉什么"，**不碰任何数据**。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	opts — 清理参数（NodeID 必填，其余可有默认值）
//
// 返回：
//
//	*ForgetPlan — 判定结论；即使被判为不允许也正常返回（Allowed=false + Reason/Hint）
//	error       — 参数非法（NodeID 为空、mode 取值非法）时返回
func (n *Node) ForgetPreview(opts ForgetOptions) (*ForgetPlan, error) {
	return n.planForget(opts)
}

// planForget 组装只读判定：现场事实 → 阈值 → 结论。不修改任何状态。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	opts — 清理参数
//
// 返回：
//
//	*ForgetPlan — 含 Allowed / Reason / Hint 的完整判定
//	error       — 参数非法时返回
func (n *Node) planForget(opts ForgetOptions) (*ForgetPlan, error) {
	if opts.NodeID == "" {
		return nil, fmt.Errorf("ERR_BAD_REQUEST: empty node id")
	}
	mode := opts.Mode
	if mode == "" {
		mode = ForgetGarbage
	}
	if mode != ForgetGarbage && mode != ForgetStale {
		return nil, fmt.Errorf("ERR_BAD_MODE: mode 只能是 %s 或 %s", ForgetGarbage, ForgetStale)
	}

	now := time.Now()
	grace := n.C().Forget.GraceDuration()
	dead := n.C().Forget.DeadThresholdDuration()

	plan := &ForgetPlan{
		NodeID: opts.NodeID, Mode: mode, Force: opts.Force, Purge: opts.Purge,
		GraceSeconds: int64(grace.Seconds()), DeadSeconds: int64(dead.Seconds()),
	}

	// 在线判定：与 /v1/tree 的 online 同源（都是 hub.conn），保证"看得见的"与"判定的"一致。
	if n.hub != nil {
		if _, ok := n.hub.conn(opts.NodeID); ok {
			plan.Online = true
		}
	}
	// 注册表现场（含 Warm 预热出来的行）。
	if c, ok := n.Reg.Get(opts.NodeID); ok {
		plan.Known, plan.Confirmed = true, c.Confirmed
		plan.Path, plan.Name = c.Path, c.Name
	}
	// 存储现场 + 待删条目计数（一次只读事务）。
	_ = n.Store.View(func(tx *store.Tx) error {
		if w, ok := tx.GetWatermark(opts.NodeID); ok {
			plan.HasWatermark, plan.Evicted = true, w.Evicted
			if t := w.LastSeenAt.AsTime(); !t.IsZero() {
				plan.LastSeen = t.UTC().Format(time.RFC3339)
			}
		}
		plan.Assignments = len(tx.CommandIDsOfChild(opts.NodeID))
		plan.Reports = len(tx.ChildReportIDsOfChild(opts.NodeID))
		plan.EvictedItems = len(tx.EvictedCommandIDsOfChild(opts.NodeID))
		return nil
	})

	// 沉默时长：没见过 LastSeenAt 时视为"从来没有活动过"，取一个很大的值。
	// 该哨兵值只用于判定，不进响应（响应里 last_seen 与 silence_seconds 一并省略）。
	silence := time.Duration(1) << 62
	if plan.LastSeen != "" {
		if t, err := time.Parse(time.RFC3339, plan.LastSeen); err == nil {
			silence = now.Sub(t)
			plan.SilenceSeconds = int64(silence.Seconds())
		}
	}

	// ---- 结论 ----
	switch {
	case plan.Online:
		plan.Reason = forgetErrOnline
		plan.Hint = "该子节点当前在线（hub 上有活跃连接）。请先停掉它再清理；force 也不能越过这条护栏。"
	case !plan.Known && !plan.HasWatermark && plan.Assignments == 0 && plan.Reports == 0 && plan.EvictedItems == 0:
		plan.Reason = forgetErrNotFound
		plan.Hint = "本节点名下没有这个 NodeID 的任何记录（注册表、水位、分配、报告、归档都没有）。"
	case opts.Force:
		plan.Allowed = true // force 越过"模式范围"与"沉默时长"两条判定，只保留在线护栏
	case mode == ForgetGarbage && plan.Known:
		plan.Reason = forgetErrNeedsStale
		plan.Hint = "该 NodeID 在注册表里（曾连上过，或由 state.dat 预热出来），不属于默认的 garbage 范围。" +
			"确认它是失效节点就加 mode=stale；已确认无误、想立刻删就加 force=1。"
	case mode == ForgetGarbage && silence < grace:
		plan.Reason = forgetErrTooRecent
		plan.Hint = fmt.Sprintf("该 NodeID 在 %s 前还有活动，短于 garbage 的沉默阈值 %s（可能正在重试注册）。"+
			"确认要删就加 force=1。", shortDur(silence), shortDur(grace))
	case mode == ForgetStale && silence < dead:
		plan.Reason = forgetErrTooRecent
		plan.Hint = fmt.Sprintf("该 NodeID 在 %s 前还有活动，短于 stale 的判定线 %s（可能只是短暂掉线）。"+
			"确认要删就加 force=1。", shortDur(silence), shortDur(dead))
	default:
		plan.Allowed = true
	}
	return plan, nil
}

// Forget 执行清理：删掉该子节点在本节点上的全部记录（内存注册表 + bbolt 四个桶 + state.dat 兜底）。
//
// 接收者 n 是本节点实例。删除动作全在**一条 bbolt 写事务**里完成 —— 要么全删、要么回滚，
// 所以不会留下"删了一半"的中间态；事务成功后才动内存注册表并补一次 saveState（把
// state.dat.known_children 一起收敛，否则 30s 后周期落盘会把它写回来）。
//
// 参数：
//
//	opts — 清理参数
//
// 返回：
//
//	*ForgetPlan — 判定结论；被判为不允许时也返回（Allowed=false），便于调用方直接看原因
//	error       — 参数非法、判定不允许、或存储写入失败时返回
func (n *Node) Forget(opts ForgetOptions) (*ForgetPlan, error) {
	plan, err := n.planForget(opts)
	if err != nil {
		return nil, err
	}
	if !plan.Allowed {
		return plan, fmt.Errorf("%s: %s", plan.Reason, plan.Hint)
	}
	id := plan.NodeID
	counts := &ForgetCounts{}

	err = n.Store.Update(func(tx *store.Tx) error {
		counts.Assignments = len(tx.CommandIDsOfChild(id))
		if err := tx.DeleteAssignmentsOfChild(id); err != nil {
			return err
		}
		if opts.Purge {
			counts.Reports = len(tx.ChildReportIDsOfChild(id))
			if err := tx.DeleteChildReportsOfChild(id); err != nil {
				return err
			}
		}
		counts.Evicted = len(tx.EvictedCommandIDsOfChild(id))
		if err := tx.DeleteEvictedOfChild(id); err != nil {
			return err
		}
		if _, ok := tx.GetWatermark(id); ok {
			counts.Watermark = 1
		}
		return tx.DeleteWatermark(id)
	})
	if err != nil {
		n.Metrics.Inc("forget_total", "result", "store_error")
		return plan, fmt.Errorf("ERR_STORE: %w", err)
	}

	// 事务成功之后才动内存与快照：否则会出现"内存已删、盘上还在"，并被周期落盘写回。
	if _, ok := n.Reg.Get(id); ok {
		counts.Registry = 1
	}
	n.Reg.Remove(id)
	n.saveState()
	counts.StateSaved = true

	kept := plan.Reports - counts.Reports
	n.Log.Warn("AUDIT-FORGET", "node", id, "mode", plan.Mode, "force", opts.Force, "purge", opts.Purge,
		"online", plan.Online, "assignments", counts.Assignments, "reports_deleted", counts.Reports,
		"reports_kept", kept, "evicted", counts.Evicted, "watermark", counts.Watermark)
	n.Metrics.Inc("forget_total", "result", "ok")

	plan.Applied = true
	plan.Deleted = counts
	return plan, nil
}

// ForgetCandidates 列出本节点名下**所有**出现过的子节点 ID（注册表 ∪ 水位表）。
//
// 接收者 n 是本节点实例。它是批量清理的输入：把结果逐个喂给 Forget 即可。
//
// 返回：
//
//	[]string — 去重并按字典序排序的 NodeID 列表
func (n *Node) ForgetCandidates() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range n.Reg.Snapshot() {
		if c.NodeID != "" && !seen[c.NodeID] {
			seen[c.NodeID] = true
			out = append(out, c.NodeID)
		}
	}
	_ = n.Store.View(func(tx *store.Tx) error {
		for _, w := range tx.ScanWatermarks() {
			if w.ChildId != "" && !seen[w.ChildId] {
				seen[w.ChildId] = true
				out = append(out, w.ChildId)
			}
		}
		return nil
	})
	sortStrings(out)
	return out
}

// ForgetAll 批量清理：对名下每个子节点各跑一次 Forget，逐条返回结果。
//
// 接收者 n 是本节点实例。**单条失败不影响其他条目** —— 被判为不允许的（在线、太新……）
// 会以 Allowed=false 的形式留在结果里，便于运维一条条看过去。
//
// 参数：
//
//	opts — 清理参数；其中 NodeID 会被逐个候选覆盖
//
// 返回：
//
//	[]*ForgetPlan — 每个候选一条结果（按 NodeID 字典序）
//	int           — 实际清理成功的条数
func (n *Node) ForgetAll(opts ForgetOptions) ([]*ForgetPlan, int) {
	cands := n.ForgetCandidates()
	out := make([]*ForgetPlan, 0, len(cands))
	ok := 0
	for _, id := range cands {
		one := opts
		one.NodeID = id
		plan, err := n.Forget(one)
		if plan == nil {
			plan = &ForgetPlan{NodeID: id, Mode: one.Mode, Allowed: false,
				Reason: forgetErrBadMode, Hint: err.Error()}
		}
		if err == nil && plan.Applied {
			ok++
		}
		out = append(out, plan)
	}
	return out, ok
}

// shortDur 把时长渲染成便于读的紧凑形式（仅用于提示文案）。
//
// 参数：
//
//	d — 时长；超大值（"从来没有活动过"用的哨兵值）会被渲染成 "never"
//
// 返回：
//
//	string — 如 "3h20m" / "45s" / "never"
func shortDur(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d > time.Duration(1)<<40 {
		return "never"
	}
	return d.Truncate(time.Second).String()
}
