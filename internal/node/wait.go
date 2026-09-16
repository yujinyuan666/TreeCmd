package node

import (
	"context"
	"fmt"
	"sort"
	"time"

	"treecmd/internal/aggregate"
	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// WaitResult waitChildren 的返回值（ADR-042/046/047）：
// Cancelled / Deadline 三态互斥；Outcomes 只装"已上报"的子，与 Unreported 互斥无重叠。
type WaitResult struct {
	Outcomes   []aggregate.ChildOutcome
	Unreported []string
	// ParentJudged 父侧自行判定终态的子 → 状态（RetryNode 次数耗尽等）。
	// 它们是 Unreported 的子集：**不进 Children 背书链**（没有 Report.Sig，硬塞就是伪造背书），
	// 但必须参与 Policy 的 NotDone 统计。⇒ 这样 Outcomes 严格 = "收到过 Report 的子"，与 Children 1:1。
	ParentJudged map[string]pb.AssignStatus
	Children     []*pb.ChildAttest
	Cancelled    bool
	Deadline     bool
}

// waitChildren 等所有直接子节点上报结果，然后聚合成终态。
//
// 进入顺序（ADR-046 第 8 条）：重建上下文 → 审退出原因标记 → 命中对账 → 判空 → 写 RUNNING。
// 之后在"子报告事件 / tick / 上下文取消 / 本地 deadline"之间循环，直到可以收敛。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	ctx — 上层上下文；被取消时按 CANCELLED 收敛并尽快返回
//	c   — 指令体（wire 格式）；用到 Id / Deadline / Type 等字段
//
// 返回：
//
//	WaitResult — 聚合结论：已上报子结果、未上报子列表、父侧判定、背书链与退出原因标记
func (n *Node) waitChildren(ctx context.Context, c *pb.Command) WaitResult {
	ev := n.eventCh(c.Id)
	defer n.dropEvent(c.Id)

	// ① 重建上下文（读 assignments + child_reports）
	rep, wait, adj, unrep := n.partition(c.Id)
	outcomes, childrenBuf := n.buildOutcomes(c, rep)
	judged := parentJudgedOf(adj)

	finalize := func(cancelled, deadline bool) WaitResult {
		un := append([]string(nil), unrep...)
		for _, a := range wait {
			un = append(un, a.ChildId)
		}
		sort.SliceStable(un, func(i, j int) bool { return identity.NodeIDLess(un[i], un[j]) })
		st := pb.AssignStatus_ASSIGN_STATUS_TIMEOUT
		if cancelled {
			st = pb.AssignStatus_ASSIGN_STATUS_CANCELLED
		}
		reason := pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED
		switch {
		case cancelled:
			reason = pb.CommandStatus_COMMAND_STATUS_CANCELLED
		case deadline:
			reason = pb.CommandStatus_COMMAND_STATUS_TIMEOUT
		}
		if err := n.MarkUnreportedAtomic(c.Id, un, st, reason); err != nil {
			n.Log.Warn("MarkUnreportedAtomic failed", "cmd", shortID(c.Id), "err", err)
		}
		// 点名"始终没有上报的子"，并给出清理手段。
		//
		// 为什么要专门打这一条：父给**注册表里的每一个直接子**都建 Assignment（下发即执行，
		// 不做任何筛选），所以只要注册表里留着一个已废弃的残留子节点（重建过密钥、换过机器 ——
		// 它的旧 NodeID 会一直留在 known_children 里），**之后每条指令都要白等它到期限**。
		// 症状是"指令莫名其妙 TIMEOUT / PARTIAL，可别人的结果明明都是好的"，光看状态毫无线索；
		// 日志里点到名字，运维才知道该去 /v1/forget。
		//
		// 这里刻意**不**改成"建 Assignment 时就告警"：那一刻 `Confirmed=false` 的子既可能是
		// 残留节点、也可能只是"刚启动还没连上"（完全正常的瞬时状态），会天天误报。
		// 只有"最后真的没上报"才是零误报的证据。
		if len(un) > 0 {
			ids := make([]string, 0, len(un))
			for _, id := range un {
				ids = append(ids, shortID(id))
			}
			n.Log.Warn("收尾时有子节点始终没有上报（本指令按退出原因收尾）；若它们其实已废弃，"+
				"其记录会一直留在注册表里、让之后每条指令都白等到期限 —— "+
				"GET /v1/forget?node=<id> 可预览，POST /v1/forget?all=1 可清理",
				"cmd", shortID(c.Id), "unreported", len(un), "children", ids)
		}
		canon.SortAttests(childrenBuf)
		return WaitResult{Outcomes: outcomes, Unreported: un, ParentJudged: judged,
			Children: childrenBuf, Cancelled: cancelled, Deadline: deadline}
	}

	// ② 审退出原因标记：TIMEOUT / CANCELLED 不复位，直接以该原因返回
	if rec, ok := n.records(c.Id); ok {
		switch rec.Status {
		case pb.CommandStatus_COMMAND_STATUS_TIMEOUT:
			return finalize(false, true)
		case pb.CommandStatus_COMMAND_STATUS_CANCELLED:
			return finalize(true, false)
		}
	}

	// ③ 对账：应发未发（注册表变化 / 对账窗口内新注册进来的子）现场补建并立即投递
	reconcileUntil := time.Now().Add(n.C().Command.ReconcileWindow)
	wait = n.reconcile(c.Id, wait)

	// ④ 判空：对账后等待集合仍为空 → 直接返回（不写 RUNNING，省掉叶子的一次无意义写）
	if len(wait) == 0 {
		canon.SortAttests(childrenBuf)
		return WaitResult{Outcomes: outcomes, Unreported: unrep, ParentJudged: judged, Children: childrenBuf}
	}

	// ⑤ 写 RUNNING（同时是幂等复位：PARTIAL/PENDING → RUNNING）
	if err := n.writeRunning(c.Id); err != nil {
		n.Log.Warn("write RUNNING failed", "cmd", shortID(c.Id), "err", err)
	}

	deadline := canon.Time(c.Deadline)
	if deadline.IsZero() {
		deadline = time.Now().Add(n.C().DeadlineForType(c.Type))
	}
	dt := time.NewTimer(time.Until(deadline))
	defer dt.Stop()
	tk := time.NewTicker(jittered(n.C().Command.TickInterval, n.C().Command.TickInterval/5))
	defer tk.Stop()

	stuckMarked := false
	for {
		select {
		case <-ctx.Done():
			return finalize(true, false)
		case <-dt.C:
			// 死线到点。**先复查一遍"是不是其实已经全到齐了"**，再决定要不要判超时。
			//
			// 为什么必须复查：Go 的 select 在多个 case 同时就绪时是**随机**挑一个的，所以
			// "最后一个子的报告刚落库"与"死线刚好响"完全可能同一刻发生 —— 那时走这条分支就会
			// 判出 TIMEOUT，而 result 里其实所有人的结果都齐了（实测症状就是这个：
			// status=COMMAND_STATUS_TIMEOUT，result 却完整聚合好了）。
			//
			// 死线的语义是**兜底**（"还缺东西所以不能再等"），不是"到点就抹掉已经到手的事实"。
			// 什么都不缺就没有"超时"可言，此时按正常完成收敛（与 ev / tk 分支同一处理）。
			rep, wait, adj, unrep = n.partition(c.Id)
			outcomes, childrenBuf = n.buildOutcomes(c, rep)
			judged = parentJudgedOf(adj)
			if len(wait) == 0 {
				return finalize(false, false)
			}
			return finalize(false, true)
		case <-ev:
			rep, wait, adj, unrep = n.partition(c.Id)
			outcomes, childrenBuf = n.buildOutcomes(c, rep)
			judged = parentJudgedOf(adj)
			if len(wait) == 0 {
				return finalize(false, false)
			}
			// 收到 Report 后立即判 Policy（不能等 tick）
			if n.policyBlocked(c, outcomes, len(wait)+len(unrep), judged) {
				return finalize(false, false)
			}
		case <-tk.C:
			rep, wait, adj, unrep = n.partition(c.Id)
			outcomes, childrenBuf = n.buildOutcomes(c, rep)
			judged = parentJudgedOf(adj)
			if len(wait) == 0 {
				return finalize(false, false)
			}
			if n.policyBlocked(c, outcomes, len(wait)+len(unrep), judged) {
				return finalize(false, false)
			}
			// 对账窗口内继续补建（覆盖"对账之后才注册进来"的子节点）
			if time.Now().Before(reconcileUntil) {
				wait = n.reconcile(c.Id, wait)
			}
			// 卡住判定 → PARTIAL（继续等，不退出）
			if !stuckMarked && n.detectStuck(c.Id, wait) {
				stuckMarked = true
				n.markPartial(c.Id)
			}
		}
	}
}

// partition 把该指令下的 Assignment 分成四类：已上报 / 仍在等待 / 父侧判定 / 未上报。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	reported    — 已有 child_reports 权威副本的子
//	waiting     — 还没有终态、需要继续等的子
//	adjudicated — 父侧判定失败（如 RetryNode 次数耗尽）的子；参与 Policy，但不进背书链
//	unreported  — 已是终态、但既没收到报告也不是 FAILED 的子（按 NodeID 升序）
func (n *Node) partition(cmdID string) (reported []*pb.ChildReportRecord, waiting []*pb.AssignmentRecord, adjudicated []*pb.AssignmentRecord, unreported []string) {
	_ = n.Store.View(func(tx *store.Tx) error {
		for _, a := range tx.AssignmentsOfCommand(cmdID) {
			if cr, ok := tx.GetChildReport(cmdID, a.ChildId); ok {
				reported = append(reported, cr)
				continue
			}
			if !isTerminalAssign(a.Status) {
				waiting = append(waiting, a)
				continue
			}
			if a.Status == pb.AssignStatus_ASSIGN_STATUS_FAILED {
				// 父侧判定（RetryNode 次数耗尽）→ 进 Outcomes 参与 Policy，但不进背书链
				adjudicated = append(adjudicated, a)
				continue
			}
			unreported = append(unreported, a.ChildId)
		}
		return nil
	})
	sort.SliceStable(unreported, func(i, j int) bool { return identity.NodeIDLess(unreported[i], unreported[j]) })
	return
}

// buildOutcomes 由 child_reports 重建 Outcomes 与背书链（重启后不必等子重报）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	c   — 指令体；用于计算背书深度
//	rep — 该指令已有的子报告权威副本列表
//
// 返回：
//
//	[]aggregate.ChildOutcome — 交给聚合器使用的子结果，与 rep 一一对应
//	[]*pb.ChildAttest        — 与 Outcomes 一一对应的背书链
func (n *Node) buildOutcomes(c *pb.Command, rep []*pb.ChildReportRecord) ([]aggregate.ChildOutcome, []*pb.ChildAttest) {
	out := make([]aggregate.ChildOutcome, 0, len(rep))
	var children []*pb.ChildAttest
	for _, cr := range rep {
		out = append(out, aggregate.ChildOutcome{
			NodeID:      cr.ChildId,
			AssignState: mapLocalToAssign(cr.LocalState),
			LocalState:  cr.LocalState,
			Error:       cr.Error,
			SelfResult:  cr.SelfResult,
			Aggregated:  cr.Aggregated,
			Raw:         cr.Aggregated,
			Attest:      n.buildAttest(c, cr),
		})
		children = append(children, n.buildAttest(c, cr))
	}
	return out, children
}

// buildAttest 为一份子报告构造背书条目（ADR-047 第 5 条）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	c  — 指令体；AttestDepth / HopChain 决定要不要带上"孙"层背书
//	cr — 该子的权威报告副本
//
// 返回：
//
//	*pb.ChildAttest — 含 NodeId / Digest / ChildSig；满足深度条件时附 Descendants
func (n *Node) buildAttest(c *pb.Command, cr *pb.ChildReportRecord) *pb.ChildAttest {
	att := &pb.ChildAttest{NodeId: cr.ChildId, Digest: cr.Digest, ChildSig: cr.ChildSig}
	// Descendants 描述"孙"，处在 d+2 层（d = len(c.HopChain)）；
	// 未设置 → 默认 1（只到直接子层）；显式 0 → 无上限（全树背书）
	depth := int32(1)
	if c.AttestDepth != nil {
		depth = *c.AttestDepth
	}
	if depth == 0 || int32(len(c.HopChain)+2) <= depth {
		att.Descendants = cr.Children
	}
	return att
}

// mapLocalToAssign 把子的本地终态映射成父侧看到的 Assignment 状态：
// COMPLETED → DONE，SELF_FAILED → FAILED，SELF_CANCELLED → CANCELLED，其余 → FAILED。
//
// 参数：
//
//	s — 子的本地执行状态
//
// 返回：
//
//	pb.AssignStatus — 对应的 Assignment 状态
func mapLocalToAssign(s pb.LocalExecState) pb.AssignStatus {
	switch s {
	case pb.LocalExecState_LOCAL_STATE_COMPLETED:
		return pb.AssignStatus_ASSIGN_STATUS_DONE
	case pb.LocalExecState_LOCAL_STATE_SELF_FAILED:
		return pb.AssignStatus_ASSIGN_STATUS_FAILED
	case pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
		return pb.AssignStatus_ASSIGN_STATUS_CANCELLED
	}
	return pb.AssignStatus_ASSIGN_STATUS_FAILED
}

// policyBlocked 用当前已收集的 Outcomes + 父侧判定，立即判断 OnFailure 容忍上限是否已被突破
// （突破了就不必再等剩余子，可以马上收敛）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	c        — 指令体；从中取失败策略
//	outcomes — 已上报子的结果
//	total    — 参与统计的子总数（已上报 + 仍在等）
//	judged   — 父侧判定的子 → 状态
//
// 返回：
//
//	bool — true 表示策略上已可收敛
func (n *Node) policyBlocked(c *pb.Command, outcomes []aggregate.ChildOutcome, total int, judged map[string]pb.AssignStatus) bool {
	return aggregate.EvaluatePolicy(policyFrom(c), outcomes, total, judged)
}

// parentJudgedOf 把父侧判定的子整理成 map（nodeID → 状态）。
//
// 参数：
//
//	adj — 父侧判定的 Assignment 列表
//
// 返回：
//
//	map[string]pb.AssignStatus — 子节点 ID 到状态的映射；adj 为空时返回 nil
func parentJudgedOf(adj []*pb.AssignmentRecord) map[string]pb.AssignStatus {
	if len(adj) == 0 {
		return nil
	}
	out := make(map[string]pb.AssignStatus, len(adj))
	for _, a := range adj {
		out[a.ChildId] = a.Status
	}
	return out
}

// reconcile 做"应发未发"对账：本地注册表里还没有 Assignment 的直接子，现场补建并立即投递通知。
//
// 下发即执行 ⇒ 没有"命中判定"：凡是我的直接子节点且还没建 Assignment，都要补。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID   — 指令 ID
//	waiting — 当前还在等待的 Assignment 列表
//
// 返回：
//
//	[]*pb.AssignmentRecord — 原等待列表；补建成功时在其后追加新建的 Assignment
func (n *Node) reconcile(cmdID string, waiting []*pb.AssignmentRecord) []*pb.AssignmentRecord {
	have := map[string]bool{}
	for _, a := range waiting {
		have[a.ChildId] = true
	}
	added := false
	var newWaiting []*pb.AssignmentRecord
	_ = n.Store.Update(func(tx *store.Tx) error {
		rec, ok := tx.GetCommand(cmdID)
		if !ok {
			return nil
		}
		for _, ch := range n.Reg.Snapshot() {
			if have[ch.NodeID] {
				continue
			}
			if _, ok := tx.GetAssignment(cmdID, ch.NodeID); ok {
				continue
			}
			a := &pb.AssignmentRecord{
				CommandId: cmdID, ChildId: ch.NodeID, Status: pb.AssignStatus_ASSIGN_STATUS_PENDING,
				LocalSeq: rec.LocalSeq, NextAttempt: 1, UpdatedAt: canon.TS(tx.Now),
			}
			if err := tx.PutAssignment(a); err != nil {
				return err
			}
			newWaiting = append(newWaiting, a)
			added = true
		}
		return nil
	})
	if !added {
		return waiting
	}
	n.Log.Info("reconcile: 应发未发补建 Assignment", "cmd", shortID(cmdID), "added", len(newWaiting))
	if n.hub != nil {
		var seq int64
		_ = n.Store.View(func(tx *store.Tx) error {
			if rec, ok := tx.GetCommand(cmdID); ok {
				seq = rec.LocalSeq
			}
			return nil
		})
		for _, a := range newWaiting {
			n.hub.notify(a.ChildId, seq)
		}
	}
	return append(waiting, newWaiting...)
}

// detectStuck 判定是否有子"卡住"：被租约回收次数 ≥ lease_reclaim_cap，或离线超过 child_stuck_timeout。
// 起算点取 max(Assignment.LastReclaimAt, ChildWatermark.LastSeenAt)，两者都没有时退回 Assignment.UpdatedAt。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID   — 指令 ID；当前实现未使用它，判定只依赖 waiting 列表
//	waiting — 仍在等待的 Assignment 列表
//
// 返回：
//
//	bool — true 表示至少有一个子被判为卡住
func (n *Node) detectStuck(cmdID string, waiting []*pb.AssignmentRecord) bool {
	now := time.Now()
	stuck := false
	_ = n.Store.View(func(tx *store.Tx) error {
		for _, a := range waiting {
			if a.ReclaimCount >= n.C().Command.LeaseReclaimCap {
				stuck = true
			}
			start := time.Time{}
			if a.LastReclaimAt != nil {
				start = canon.Time(a.LastReclaimAt)
			}
			if wm, ok := tx.GetWatermark(a.ChildId); ok && wm.LastSeenAt != nil {
				if t := canon.Time(wm.LastSeenAt); t.After(start) {
					start = t
				}
			}
			if start.IsZero() {
				start = canon.Time(a.UpdatedAt)
			}
			if !start.IsZero() && now.Sub(start) > n.C().Command.ChildStuckTimeout {
				stuck = true
			}
		}
		return nil
	})
	return stuck
}

// markPartial 把该指令转成 PARTIAL（过渡态、不向上报结果）；只有 RUNNING / PENDING 会真的转。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID
func (n *Node) markPartial(cmdID string) {
	_ = n.Store.Update(func(tx *store.Tx) error {
		rec, ok := tx.GetCommand(cmdID)
		if !ok {
			return nil
		}
		if rec.Status == pb.CommandStatus_COMMAND_STATUS_RUNNING || rec.Status == pb.CommandStatus_COMMAND_STATUS_PENDING {
			rec.Status = pb.CommandStatus_COMMAND_STATUS_PARTIAL
			rec.UpdatedAt = canon.TS(tx.Now)
			return tx.PutCommand(rec)
		}
		return nil
	})
	n.Log.Warn("command PARTIAL（有子卡住，等运维 RetryNode 或 Deadline）", "cmd", shortID(cmdID))
}

// ---------- 接受子报告（父端，单事务） ----------

// acceptChildReport 接受子报告（ReportResult 路径，签名已在调用方验证过）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	childID — 上报的子节点 ID
//	rep     — 子报告体
//
// 返回：
//
//	error — 透传 acceptChildReportVerified 的结果
func (n *Node) acceptChildReport(childID string, rep *pb.Report) error {
	return n.acceptChildReportVerified(childID, rep)
}

// acceptChildReportVerified 一次单 bbolt 事务同时完成三件事（ADR-048）：
// ① 写 child_reports 权威副本；② 置 Assignment 终态 + 记生效 attempt；③ Outcomes 为内存缓存，由前两者重建。
// 只有事务提交后才回 ok = true（语义 = "已持久化接受"，不是"已在内存里处理过"）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	childID — 上报的子节点 ID（来自 mTLS 对端身份，不信报文里自报的字段）
//	rep     — 子报告体；若是对象存储引用形式，先按引用取回并校验摘要，再就地转成内联结果
//
// 返回：
//
//	error — 终态非法、引用取不回 / 摘要不符、找不到对应 Assignment 或账本事务失败时返回
func (n *Node) acceptChildReportVerified(childID string, rep *pb.Report) error {
	if rep.LocalState == pb.LocalExecState_LOCAL_STATE_UNSPECIFIED {
		return fmt.Errorf("ERR_INVALID_FINAL_STATE: report without local_state")
	}
	// 第三级：子上报的是对象存储引用 → 由本节点按引用取回并校验摘要（3.13）
	if rep.ResultRef != nil && len(rep.Aggregated) == 0 {
		if rep.ResultRef.Kind != pb.ResultRefKind_RESULT_REF_OBJECT_STORE {
			return fmt.Errorf("ERR_UNSUPPORTED_RESULT_REF: %v", rep.ResultRef.Kind)
		}
		b, err := n.Obj.Get(rep.ResultRef.Ref)
		if err != nil {
			return fmt.Errorf("ERR_RESULT_REF_FETCH: %w", err)
		}
		if len(rep.ResultRef.Hash) > 0 && string(canon.DigestBytes(b)) != string(rep.ResultRef.Hash) {
			return fmt.Errorf("ERR_RESULT_REF_HASH_MISMATCH")
		}
		rep.Aggregated = b
		rep.ResultRef = nil
	}
	canon.SortAttests(rep.Children)
	clone := cloneReportNoSig(rep)
	digest, err := canon.Digest(clone)
	if err != nil {
		return err
	}
	st := mapLocalToAssign(rep.LocalState)
	if err := n.Store.Update(func(tx *store.Tx) error {
		// 权威结果规则：已有权威结果 → 丢弃（真正的去重）；否则接受任意 attempt
		if _, ok := tx.GetChildReport(rep.CommandId, childID); ok {
			return nil
		}
		a, ok := tx.GetAssignment(rep.CommandId, childID)
		if !ok {
			return fmt.Errorf("NO_SUCH_ASSIGNMENT: %s/%s", shortID(rep.CommandId), shortID(childID))
		}
		if isTerminalAssign(a.Status) {
			return nil
		}
		cr := &pb.ChildReportRecord{
			CommandId: rep.CommandId, ChildId: childID, Attempt: rep.Attempt,
			LocalState: rep.LocalState, Error: rep.Error, SelfResult: rep.SelfResult,
			Aggregated: rep.Aggregated, ResultRef: rep.ResultRef, Children: rep.Children,
			Digest: digest, ChildSig: rep.Sig, ReceivedAt: canon.TS(tx.Now),
		}
		if err := tx.PutChildReport(cr); err != nil {
			return err
		}
		a.Status = st
		a.EffectiveAttempt = rep.Attempt
		a.UpdatedAt = canon.TS(tx.Now)
		if err := tx.PutAssignment(a); err != nil {
			return err
		}
		// 某子报 SELF_CANCELLED → 整条指令转 CANCELLED（父侧据此收敛）
		if st == pb.AssignStatus_ASSIGN_STATUS_CANCELLED {
			if rec, ok := tx.GetCommand(rep.CommandId); ok {
				rec.Status = pb.CommandStatus_COMMAND_STATUS_CANCELLED
				rec.UpdatedAt = canon.TS(tx.Now)
				if err := tx.PutCommand(rec); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	n.signal(rep.CommandId)
	return nil
}

// cloneReportNoSig 复制一份 Report 但不带签名（用于计算待签名 / 待验签的规范摘要）。
//
// 参数：
//
//	rep — 原报告
//
// 返回：
//
//	*pb.Report — 逐字段拷贝的新对象，Sig 留空
func cloneReportNoSig(rep *pb.Report) *pb.Report {
	c := &pb.Report{
		CommandId: rep.CommandId, NodeId: rep.NodeId, Attempt: rep.Attempt,
		LocalState: rep.LocalState, Error: rep.Error, SelfResult: rep.SelfResult,
		Aggregated: rep.Aggregated, ResultRef: rep.ResultRef, Children: rep.Children,
	}
	return c
}

// verifyReportSig 用 mTLS 对端证书公钥验 Report.Sig（第 1 步；第 2 步链校验由 mTLS 完成；
// 第 3 步 CRL / 有效期与第 4 步"证书身份 == NodeID"见 mTLS 拦截器 —— 本实现不做 CRL）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	peerPub — mTLS 对端证书里的 ed25519 公钥
//	rep     — 子报告体；计算摘要时会先摘掉 Sig
//
// 返回：
//
//	error — 无签名（SIG_MISSING）、摘要算不出或验签不过（SIG_INVALID）时返回
func (n *Node) verifyReportSig(peerPub []byte, rep *pb.Report) error {
	if len(rep.Sig) == 0 {
		return fmt.Errorf("SIG_MISSING")
	}
	d, err := canon.Digest(cloneReportNoSig(rep))
	if err != nil {
		return err
	}
	if !identity.Verify(peerPub, d, rep.Sig) {
		return fmt.Errorf("SIG_INVALID")
	}
	return nil
}
