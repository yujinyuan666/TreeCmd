package node

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"treecmd/internal/aggregate"
	"treecmd/internal/canon"
	"treecmd/internal/exec"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

const (
	inlineResultLimit = 256 * 1024       // 内联上限
	maxChunkedResult  = 64 * 1024 * 1024 // 分片上限，超过走对象存储引用
)

// handle 推进一条指令在本节点的完整生命周期（1.1）：
// 验签 → 执行本地部分 → 向直接子节点分发并等整棵子树 → 聚合成终态 → 上报父节点。
//
// 接收者 n 是本节点实例（一个进程就是一个节点）。
//
// 参数：
//
//	parent  — 上层上下文；被取消时会中断本地执行（随后按 CANCELLED 收尾）
//	c       — 指令体（wire 格式），含 id / 载荷 / 失败策略 / 聚合策略等
//	attempt — 第几次尝试（从 1 开始）；wire 上传 0 视为非法，这里会归一到 1
func (n *Node) handle(parent context.Context, c *pb.Command, attempt uint64) {
	if attempt == 0 {
		attempt = 1 // wire 上 attempt == 0 非法
	}
	ctx, cancel := context.WithCancel(parent)
	if !n.inflight.Enter(c.Id, attempt, cancel) {
		cancel()
		// 已有执行在跑 → 回"仍在处理"信号，让父承认在跑的 attempt 才是生效 attempt
		if n.up != nil {
			n.up.sendInflightHint(c.Id, n.inflight.Attempt(c.Id))
		}
		return
	}
	defer func() {
		n.inflight.Leave(c.Id)
		cancel()
	}()

	// 下行投递的指令：验 origin 签名（内联 OriginCert 离线验）+ 父的 HopAttest（四项）
	if c.OriginId != n.C().Node.ID && n.up != nil {
		if err := verifyOrigin(c); err != nil {
			n.Log.Warnf("origin 验签失败 cmd=%s: %v", shortID(c.Id), err)
			if terr := n.terminal(c, attempt, pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
				pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED, nil, err.Error(), nil); terr == nil {
				n.reportUpstream(c.Id, attempt)
			}
			return
		}
		pid, ppub := n.up.parentIdentity()
		if err := n.verifyHop(pid, ppub, c); err != nil {
			n.Log.Warnf("hop 校验失败 cmd=%s: %v", shortID(c.Id), err)
			if terr := n.terminal(c, attempt, pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
				pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED, nil, err.Error(), nil); terr == nil {
				n.reportUpstream(c.Id, attempt)
			}
			return
		}
	}

	st, _ := n.ledgerGet(c.Id)

	// 已终态：幂等命中，直接回放终态（只服务"运行中重投"场景）
	if st != nil {
		switch st.LocalState {
		case pb.LocalExecState_LOCAL_STATE_COMPLETED,
			pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
			pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
			n.reportUpstream(c.Id, attempt)
			return
		}
	}

	// ---------- 本地阶段 ----------
	if st == nil || st.LocalState != pb.LocalExecState_LOCAL_STATE_SELF_DONE {
		// OnRestart 不受 Target 约束：只要账本停在 SELF_RUNNING 就给执行器一次清理机会
		if st != nil && st.LocalState == pb.LocalExecState_LOCAL_STATE_SELF_RUNNING {
			ex := n.Exec.For(c.Type)
			if err := ex.OnRestart(true); err != nil {
				if terr := n.terminal(c, attempt, pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
					pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED, nil, "OnRestart refused: "+err.Error(), nil); terr != nil {
					n.Log.Errorf("terminal %s 落盘失败，本轮不报: %v", shortID(c.Id), terr)
					return
				}
				n.reportUpstream(c.Id, attempt)
				return
			}
		}

		// 下发即执行：收到任务的节点直接执行本地部分（不做任何 Target 筛选）
		if !n.acquireLocal() {
			if n.up != nil {
				n.up.sendLocalBusy(c.Id)
			}
			return // 容量不足 → LocalBusy 退回（不推进 attempt）
		}
		// 先落 SELF_RUNNING，再执行（OnRestart 的唯一触发条件）
		if err := n.markSelfRunning(c, attempt); err != nil {
			n.releaseLocal()
			n.Log.Warn("MarkSelfRunning failed", "cmd", shortID(c.Id), "err", err)
			return
		}
		res, err := n.runLocal(ctx, c)
		n.releaseLocal()
		if err != nil {
			if errors.Is(err, context.Canceled) || ctx.Err() == context.Canceled || n.inflight.CancelRequested(c.Id) {
				if terr := n.terminal(c, attempt, pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED,
					pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED, nil, "", nil); terr != nil {
					n.Log.Errorf("terminal %s 落盘失败，本轮不报: %v", shortID(c.Id), terr)
					return
				}
				n.reportUpstream(c.Id, attempt)
				return
			}
			if terr := n.terminal(c, attempt, pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
				pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED, nil, err.Error(), nil); terr != nil {
				n.Log.Errorf("terminal %s 落盘失败，本轮不报: %v", shortID(c.Id), terr)
				return
			}
			n.reportUpstream(c.Id, attempt)
			return
		}
		if err := n.markSelfDone(c.Id, attempt, res); err != nil {
			n.Log.Errorf("MarkSelfDone %s 落盘失败，本轮不继续: %v", shortID(c.Id), err)
			return
		}
	}

	cur, _ := n.ledgerGet(c.Id)
	var selfResult []byte
	if cur != nil {
		selfResult = cur.SelfResult
	}

	// ---------- 服务端阶段：向命中的子树分发、等子树 ----------
	if err := n.EnsureCreated(c); err != nil {
		n.Log.Errorf("EnsureCreated %s 失败，本轮不报: %v", shortID(c.Id), err)
		return
	}
	n.NotifyChildren(c)

	res := n.waitChildren(ctx, c)
	if res.Cancelled {
		if err := n.terminal(c, attempt, pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED,
			pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED, nil, "", res.Children); err != nil {
			n.Log.Errorf("terminal %s 落盘失败，本轮不报: %v", shortID(c.Id), err)
			return
		}
		n.reportUpstream(c.Id, attempt)
		return
	}

	strategy, err := strategyFrom(c)
	if err != nil {
		n.Log.Errorf("aggregate strategy %s: %v", shortID(c.Id), err)
		strategy = pb.AggregateStrategy_AGGREGATE_TREE
	}
	agg, err := aggregate.Aggregate(aggregate.Context{
		SelfNodeID:   n.C().Node.ID,
		Self:         selfResult,
		Children:     res.Outcomes,
		Total:        len(res.Outcomes) + len(res.Unreported),
		ParentJudged: res.ParentJudged,
		Policy:       policyFrom(c),
		Strategy:     strategy,
		DeadlineHit:  res.Deadline,
	}, n.customFor(c))
	if err != nil {
		n.Log.Errorf("aggregate %s failed: %v", shortID(c.Id), err)
		agg = &aggregate.Result{Final: []byte{}}
	}

	localState := pb.LocalExecState_LOCAL_STATE_COMPLETED
	serverStatus := pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED
	if res.Deadline {
		// 本地"执行超时失败" + 服务端 TIMEOUT（不能用 mapToCommandStatus 推出 FAILED）
		localState, serverStatus = pb.LocalExecState_LOCAL_STATE_SELF_FAILED, pb.CommandStatus_COMMAND_STATUS_TIMEOUT
	} else if agg.Blocked {
		localState = pb.LocalExecState_LOCAL_STATE_SELF_FAILED
	}
	if err := n.terminal(c, attempt, localState, serverStatus, agg.Final, "", res.Children); err != nil {
		n.Log.Errorf("terminal %s 落盘失败，暂不上报: %v", shortID(c.Id), err)
		return
	}
	n.Log.Info("command finished",
		"cmd", shortID(c.Id), "type", c.Type, "path", n.SelfPath(),
		"done", agg.Done, "not_done", agg.NotDone, "total", agg.Total,
		"local_state", localState.String(), "deadline_hit", res.Deadline)
	n.reportUpstream(c.Id, attempt)
}

// runLocal 执行指令的本地部分：取该类型的执行器，校验 Spec，跑一次，再把结果编码成字节。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	ctx — 执行上下文；取消会透传给执行器，中断本次执行
//	c   — 指令体；这里只用到 Id / Type / Payload
//
// 返回：
//
//	[]byte — 编码后的执行结果（exec.EncodeResult 的输出）
//	error  — 校验不通过或执行器返回错误时返回
func (n *Node) runLocal(ctx context.Context, c *pb.Command) ([]byte, error) {
	ex := n.Exec.For(c.Type)
	spec := exec.Spec{
		CommandID: c.Id, NodeID: n.C().Node.ID, Path: n.SelfPath(),
		Type: c.Type, Payload: c.Payload, Labels: n.C().Node.Labels,
	}
	if err := ex.Validate(spec); err != nil {
		return nil, err
	}
	v, err := ex.Run(ctx, spec, exec.NopEmitter{})
	if err != nil {
		return nil, err
	}
	return exec.EncodeResult(v)
}

// ---------- 本地三态（客户端视角） ----------

// ledgerGet 读该指令的本地执行记录（客户端视角三态所在的账本行）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	*pb.LocalCommandRecord — 本地记录；不存在时为 nil
//	bool                   — 是否读到
func (n *Node) ledgerGet(cmdID string) (*pb.LocalCommandRecord, bool) {
	var (
		r  *pb.LocalCommandRecord
		ok bool
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		r, ok = tx.GetLocal(cmdID)
		return nil
	})
	return r, ok
}

// markSelfRunning 把本地状态置为 SELF_RUNNING 并落盘；同时清空 Error 与 SelfResult
// （"失败/取消 ⇒ SelfResult 为空"的结构性保证）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	c       — 指令体；本函数会把指令体与本次 attempt 一起写进账本
//	attempt — 本次尝试序号
//
// 返回：
//
//	error — 账本事务失败时返回
func (n *Node) markSelfRunning(c *pb.Command, attempt uint64) error {
	return n.Store.Update(func(tx *store.Tx) error {
		lc, ok := tx.GetLocal(c.Id)
		if !ok {
			lc = &pb.LocalCommandRecord{CommandId: c.Id, Attempt: attempt}
		}
		lc.LocalState = pb.LocalExecState_LOCAL_STATE_SELF_RUNNING
		lc.Command = mustMarshal(c)
		lc.Error = ""
		lc.SelfResult = nil
		lc.LastUpstreamSeq = c.Seq
		lc.UpdatedAt = canon.TS(tx.Now)
		return tx.PutLocal(lc)
	})
}

// markSelfDone 把本地状态置为 SELF_DONE，并记录本次执行结果与"本次执行所属的那个 attempt"。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID      — 指令 ID
//	attempt    — 本次尝试序号，写入 LocalCommandRecord.Attempt
//	selfResult — 本地执行结果；为 nil 时归一成空字节切片
//
// 返回：
//
//	error — 账本事务失败时返回
func (n *Node) markSelfDone(cmdID string, attempt uint64, selfResult []byte) error {
	return n.Store.Update(func(tx *store.Tx) error {
		lc, ok := tx.GetLocal(cmdID)
		if !ok {
			lc = &pb.LocalCommandRecord{CommandId: cmdID}
		}
		lc.LocalState = pb.LocalExecState_LOCAL_STATE_SELF_DONE
		lc.Attempt = attempt
		if selfResult == nil {
			selfResult = []byte{}
		}
		lc.SelfResult = selfResult
		lc.UpdatedAt = canon.TS(tx.Now)
		return tx.PutLocal(lc)
	})
}

// terminal 终态写入的唯一入口：一个事务里同时写
// ① local_state ② CommandRecord.Status（若存在） ③ 结果归宿（results / pending_result）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	c            — 指令体；OriginId 等于本节点时结果落 SELF 归宿，否则落 pending_result 等上报
//	attempt      — 本次尝试序号
//	state        — 本地终态；只接受 COMPLETED / SELF_FAILED / SELF_CANCELLED，其他值返回错误
//	serverStatus — 服务端状态；为 UNSPECIFIED 时由 mapToCommandStatus(state) 推出
//	final        — 聚合后的最终结果；为 nil 时归一成空字节切片
//	errMsg       — 失败原因文案；成功时为空串
//	children     — 子节点背书链；写库前先排序
//
// 返回：
//
//	error — 终态非法或账本事务失败时返回
func (n *Node) terminal(c *pb.Command, attempt uint64, state pb.LocalExecState, serverStatus pb.CommandStatus,
	final []byte, errMsg string, children []*pb.ChildAttest) error {
	switch state {
	case pb.LocalExecState_LOCAL_STATE_COMPLETED, pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
		pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
	default:
		return fmt.Errorf("ERR_INVALID_TERMINAL_STATE: %v", state)
	}
	if final == nil {
		final = []byte{} // 归一化：Aggregated 与 ResultRef 不可能两个都为空
	}
	sink := pb.ResultSink_RESULT_SINK_UPSTREAM
	if c.OriginId == n.C().Node.ID {
		sink = pb.ResultSink_RESULT_SINK_SELF
	}
	canon.SortAttests(children)

	return n.Store.Update(func(tx *store.Tx) error {
		// ① 客户端视角
		lc, ok := tx.GetLocal(c.Id)
		if !ok {
			lc = &pb.LocalCommandRecord{CommandId: c.Id, Attempt: attempt}
		}
		lc.LocalState = state
		lc.Final = final
		lc.Error = errMsg
		lc.Command = nil // 终态后指令体可即时回收（PendingResult 自包含，见 6.4）
		lc.UpdatedAt = canon.TS(tx.Now)
		if err := tx.PutLocal(lc); err != nil {
			return err
		}
		// ② 服务端视角
		rec, hasRec := tx.GetCommand(c.Id)
		if hasRec {
			if serverStatus != pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED {
				rec.Status = serverStatus
			} else {
				rec.Status = mapToCommandStatus(state)
			}
			rec.UpdatedAt = canon.TS(tx.Now)
			if err := tx.PutCommand(rec); err != nil {
				return err
			}
		}
		status := mapToCommandStatus(state)
		if hasRec {
			status = rec.Status
		}
		// ③ 结果归宿
		if sink == pb.ResultSink_RESULT_SINK_SELF {
			return tx.PutResult(&pb.ResultRecord{
				CommandId: c.Id, Status: status, LocalState: state, Final: final, Children: children,
				CreatedAt: canon.TS(tx.Now), ExpireAt: canon.TS(tx.Now.Add(n.resultsRetention())),
				TraceSummary: fmt.Sprintf("children=%d", len(children)),
			})
		}
		// 非发起节点：必须落 pending_result（含 children 背书链），供"先落盘 → 再上报 → 收到 ok 才清理"
		// SelfResult 的唯一裁剪点在此（RawChildren=true 且本轮 COMPLETED 时才非空）
		var selfRes []byte
		if c.RawChildren && state == pb.LocalExecState_LOCAL_STATE_COMPLETED {
			selfRes = lc.SelfResult
		}
		pr := &pb.PendingResultRecord{
			CommandId: c.Id, NodeId: n.C().Node.ID, Attempt: attempt, LocalState: state, Error: errMsg,
			SelfResult: selfRes, Aggregated: final, Children: children,
			Sink: pb.ResultSink_RESULT_SINK_UPSTREAM, ReceivedAt: canon.TS(tx.Now),
		}
		return tx.PutPending(pr)
	})
}

// mapToCommandStatus 把本地终态映射成对外的指令状态：
// COMPLETED → COMPLETED，SELF_FAILED → FAILED，SELF_CANCELLED → CANCELLED，其余 → RUNNING。
//
// 参数：
//
//	s — 本地执行状态
//
// 返回：
//
//	pb.CommandStatus — 对应的对外状态
func mapToCommandStatus(s pb.LocalExecState) pb.CommandStatus {
	switch s {
	case pb.LocalExecState_LOCAL_STATE_COMPLETED:
		return pb.CommandStatus_COMMAND_STATUS_COMPLETED
	case pb.LocalExecState_LOCAL_STATE_SELF_FAILED:
		return pb.CommandStatus_COMMAND_STATUS_FAILED
	case pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
		return pb.CommandStatus_COMMAND_STATUS_CANCELLED
	}
	return pb.CommandStatus_COMMAND_STATUS_RUNNING
}

// resultsRetention 返回结果档案（results 表）的保留时长。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	time.Duration — command.audit_retention 的 4 倍；未配置（<= 0）时取 30 天
func (n *Node) resultsRetention() time.Duration {
	if n.C().Command.AuditRetention > 0 {
		return n.C().Command.AuditRetention * 4 // 结果档案默认 30 天量级
	}
	return 30 * 24 * time.Hour
}

// ---------- 上报（唯一数据源 = pending_result） ----------

// reportUpstream 只服务"非发起节点"：读 pending_result → 重签 → 按大小三级选择路径 → 发送；
// 收到 ok == true 才用独立事务清理 pending_result，否则累加失败次数做退避。
//
// 接收者 n 是本节点实例；没有上行链路（up == nil）或 pending_result 不存在时直接返回。
//
// 参数：
//
//	cmdID   — 指令 ID
//	attempt — 上报时携带的尝试序号（当前实现读 pending_result 里的 Attempt，此参数不再参与组包）
func (n *Node) reportUpstream(cmdID string, attempt uint64) {
	if n.up == nil {
		return
	}
	var pr *pb.PendingResultRecord
	_ = n.Store.View(func(tx *store.Tx) error {
		pr, _ = tx.GetPending(cmdID)
		return nil
	})
	if pr == nil {
		return // sink == SELF（已落 results）或已被确认清理
	}
	if pr.Sink == pb.ResultSink_RESULT_SINK_SELF {
		n.Log.Warn("pending_result with sink=SELF (should not exist), ignoring", "cmd", shortID(cmdID))
		return
	}
	rep := &pb.Report{
		CommandId: pr.CommandId, NodeId: n.C().Node.ID, Attempt: pr.Attempt,
		LocalState: pr.LocalState, Error: pr.Error, SelfResult: pr.SelfResult,
		Children: pr.Children,
	}
	switch {
	case pr.ResultRef != nil:
		rep.ResultRef = pr.ResultRef
		rep.Aggregated = nil
	default:
		rep.Aggregated = pr.Aggregated
		if rep.Aggregated == nil {
			rep.Aggregated = []byte{}
		}
	}
	sig, err := n.signReport(rep)
	if err != nil {
		n.Log.Warn("sign report failed", "cmd", shortID(cmdID), "err", err)
		return
	}
	rep.Sig = sig

	ok := false
	// 三级路径（3.11 / 3.13）：内联 / 分片 / 对象存储引用
	switch {
	case rep.ResultRef != nil:
		ok = n.up.report(rep, nil)
	case len(rep.Aggregated) <= inlineResultLimit:
		ok = n.up.report(rep, nil)
	case len(rep.Aggregated) <= maxChunkedResult:
		ok = n.up.streamResult(rep)
	default:
		ref, hash, err := n.Obj.Put(rep.Aggregated)
		if err != nil {
			n.Log.Warn("object store put failed", "cmd", shortID(cmdID), "err", err)
			return
		}
		rep.Aggregated = nil
		rep.ResultRef = &pb.ResultRef{
			Kind: pb.ResultRefKind_RESULT_REF_OBJECT_STORE, Ref: ref,
			Hash: hash, Size: int64(len(pr.Aggregated)),
		}
		ok = n.up.report(rep, nil)
	}
	if ok {
		_ = n.Store.Update(func(tx *store.Tx) error { return tx.DeletePending(cmdID) })
	} else {
		n.bumpPendingFailure(cmdID)
	}
}

// signReport 用本节点私钥给上报体签名：先克隆一份并清空 Sig、排序子背书，再算规范摘要并签名。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	rep — 待签名的上报体；本函数不修改它，内部先做克隆
//
// 返回：
//
//	[]byte — Ed25519 签名
//	error  — 规范摘要计算失败时返回
func (n *Node) signReport(rep *pb.Report) ([]byte, error) {
	clone := proto.Clone(rep).(*pb.Report)
	clone.Sig = nil
	canon.SortAttests(clone.Children)
	d, err := canon.Digest(clone)
	if err != nil {
		return nil, err
	}
	return identity.Sign(n.Id().Key, d), nil
}

// bumpPendingFailure 上报失败时把 pending_result 的 FailCount +1，并按指数退避设置下次重试时间
// （1s → 2s → …，上限 60s）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID；pending_result 已不存在时静默返回
func (n *Node) bumpPendingFailure(cmdID string) {
	_ = n.Store.Update(func(tx *store.Tx) error {
		pr, ok := tx.GetPending(cmdID)
		if !ok {
			return nil
		}
		pr.FailCount++
		backoff := time.Duration(1<<minInt(int(pr.FailCount), 6)) * time.Second
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
		pr.NextRetryAt = canon.TS(tx.Now.Add(backoff))
		return tx.PutPending(pr)
	})
}

// resendPending 周期重发到期的 pending_result：按批量上限扫一批，跳过还没到 NextRetryAt 的，
// 并用 resending 表做单飞（同一条不会并发重发）。
//
// 接收者 n 是本节点实例；没有上行链路时直接返回。
//
// 参数：
//
//	_ — 未使用的上下文（后台循环回调统一签名）
func (n *Node) resendPending(_ context.Context) {
	if n.up == nil {
		return
	}
	var list []*pb.PendingResultRecord
	_ = n.Store.View(func(tx *store.Tx) error {
		list = tx.ScanPending(int(n.C().Command.PendingResendBatch))
		return nil
	})
	now := time.Now()
	for _, pr := range list {
		if pr.NextRetryAt != nil && canon.Time(pr.NextRetryAt).After(now) {
			continue
		}
		n.pendingMu.Lock()
		if n.resending[pr.CommandId] {
			n.pendingMu.Unlock()
			continue
		}
		n.resending[pr.CommandId] = true
		n.pendingMu.Unlock()
		go func(id string, attempt uint64) {
			defer func() {
				n.pendingMu.Lock()
				delete(n.resending, id)
				n.pendingMu.Unlock()
			}()
			n.reportUpstream(id, attempt)
		}(pr.CommandId, pr.Attempt)
	}
}

// minInt 返回 a、b 中较小的一个。
//
// 参数：
//
//	a — 第一个整数
//	b — 第二个整数
//
// 返回：
//
//	int — 两者中的较小值
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
