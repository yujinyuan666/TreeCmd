package node

import (
	"context"
	"fmt"
	"hash/crc32"
	"time"

	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// Cancel 取消一条在途指令：置原子标志并调用它的 cancel()，
// 把取消信号注入正在执行的 runLocal 与正在等待的 waitChildren。
//
// 接收者 t 是本节点的在途指令表。
//
// 参数：
//
//	id — 指令 ID；表里没有对应条目时什么都不做
func (t *InflightTable) Cancel(id string) {
	t.mu.Lock()
	e, ok := t.m[id]
	t.mu.Unlock()
	if !ok {
		return
	}
	e.cancelled.Store(true)
	if e.cancel != nil {
		e.cancel()
	}
}

// cancelCommand 只做两件事：置进程内原子标志、调用取出的 cancel()。
// 不落盘、不写 CommandRecord.Status、不碰 assignments（终态与 children 由持有 childrenBuf 的协程写）。
//
// 接收者 n 是本节点实例。只在本节点确实有这条在途指令时才动作。
//
// 参数：
//
//	cmdID — 指令 ID
func (n *Node) cancelCommand(cmdID string) {
	if n.inflight.Running(cmdID) {
		n.inflight.Cancel(cmdID)
		n.Log.Info("cancel injected", "cmd", shortID(cmdID))
	}
}

// applyTerminal 收到父侧终态（主动帧 / 续租响应回带）→ 停本地 + 向自己的子树下发（同一机制逐层收敛）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID  — 指令 ID
//	status — 父下发的终态；非 CANCELLED / TIMEOUT / FAILED 一律忽略
func (n *Node) applyTerminal(cmdID string, status pb.CommandStatus) {
	switch status {
	case pb.CommandStatus_COMMAND_STATUS_CANCELLED, pb.CommandStatus_COMMAND_STATUS_TIMEOUT,
		pb.CommandStatus_COMMAND_STATUS_FAILED:
	default:
		return
	}
	if rec, ok := n.ledgerGet(cmdID); ok {
		switch rec.LocalState {
		case pb.LocalExecState_LOCAL_STATE_COMPLETED,
			pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
			pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
			return // 本地已终态，不再改
		}
	}
	n.cancelCommand(cmdID)
	n.propagateTerminal(cmdID, status)
}

// propagateTerminal 把终态落定到本节点作为服务端的 assignments，并通知直接子。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID  — 指令 ID
//	status — 终态；TIMEOUT 映射为 ASSIGN_STATUS_TIMEOUT，其余映射为 ASSIGN_STATUS_CANCELLED
func (n *Node) propagateTerminal(cmdID string, status pb.CommandStatus) {
	assign := pb.AssignStatus_ASSIGN_STATUS_CANCELLED
	if status == pb.CommandStatus_COMMAND_STATUS_TIMEOUT {
		assign = pb.AssignStatus_ASSIGN_STATUS_TIMEOUT
	}
	var children []string
	_ = n.Store.Update(func(tx *store.Tx) error {
		rec, ok := tx.GetCommand(cmdID)
		if !ok {
			return nil
		}
		rec.Status = status
		rec.UpdatedAt = canon.TS(tx.Now)
		if err := tx.PutCommand(rec); err != nil {
			return err
		}
		for _, a := range tx.AssignmentsOfCommand(cmdID) {
			if isTerminalAssign(a.Status) {
				continue
			}
			a.Status = assign
			a.UpdatedAt = canon.TS(tx.Now)
			if err := tx.PutAssignment(a); err != nil {
				return err
			}
			children = append(children, a.ChildId)
		}
		return nil
	})
	if n.hub != nil {
		for _, c := range children {
			n.hub.notifyCancel(c, cmdID)
		}
	}
	n.signal(cmdID) // 唤醒正在等待的 waitChildren
}

// CancelCommand 运维取消（HTTP API）：把 commands 表状态改为 CANCELLED 即可，不做递归等待；
// 另向直接子发一次取消通知（主动帧只是加速路径）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 要取消的指令 ID
//
// 返回：
//
//	error — 指令不存在返回 NOT_FOUND；已是终态返回 ErrTerminal
func (n *Node) CancelCommand(cmdID string) error {
	rec, ok := n.records(cmdID)
	if !ok {
		return fmt.Errorf("NOT_FOUND")
	}
	if isTerminalCommand(rec.Status) {
		return ErrTerminal
	}
	n.propagateTerminal(cmdID, pb.CommandStatus_COMMAND_STATUS_CANCELLED)
	n.cancelCommand(cmdID)
	// 主动帧只是加速路径；续租响应回带终态是必经路径（保证有限轮内必然到达）
	if n.hub != nil {
		for _, a := range n.assignmentsOf(cmdID) {
			n.hub.notifyCancel(a.ChildId, cmdID)
		}
	}
	return nil
}

// isTerminalCommand 判断指令状态是否为终态。
//
// 参数：
//
//	s — 指令状态
//
// 返回：
//
//	bool — COMPLETED / FAILED / TIMEOUT / CANCELLED 为 true，其余为 false
func isTerminalCommand(s pb.CommandStatus) bool {
	switch s {
	case pb.CommandStatus_COMMAND_STATUS_COMPLETED, pb.CommandStatus_COMMAND_STATUS_FAILED,
		pb.CommandStatus_COMMAND_STATUS_TIMEOUT, pb.CommandStatus_COMMAND_STATUS_CANCELLED:
		return true
	}
	return false
}

// RetryNode 运维恢复：把某子的 Assignment 标回 PENDING，四件事必须原子（3.12 / ADR-049 第 8 条）。
// 成功后还会通知该子重新投递。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID   — 指令 ID
//	childID — 要重投的子节点 ID
//
// 返回：
//
//	error — 指令不存在 / 指令非运行中或部分完成 / 无该子的 Assignment / 重试次数用尽 / 落盘失败
func (n *Node) RetryNode(cmdID, childID string) error {
	err := n.Store.Update(func(tx *store.Tx) error {
		rec, ok := tx.GetCommand(cmdID)
		if !ok {
			return fmt.Errorf("NOT_FOUND")
		}
		if rec.Status != pb.CommandStatus_COMMAND_STATUS_RUNNING && rec.Status != pb.CommandStatus_COMMAND_STATUS_PARTIAL {
			return ErrTerminal
		}
		a, ok := tx.GetAssignment(cmdID, childID)
		if !ok {
			return fmt.Errorf("NOT_FOUND: no assignment for child")
		}
		if a.RetryCount >= n.C().Command.MaxRetryNodeCount {
			return ErrRetryExhausted
		}
		a.Status = pb.AssignStatus_ASSIGN_STATUS_PENDING
		a.RetryCount++
		a.ReclaimCount = 0
		a.LastReclaimAt = canon.TS(tx.Now)
		a.NextAttempt = a.DeliveredAttempt + 1
		a.BackoffUntil = nil
		a.UpdatedAt = canon.TS(tx.Now)
		if err := tx.PutAssignment(a); err != nil {
			return err
		}
		rec.Status = pb.CommandStatus_COMMAND_STATUS_RUNNING
		rec.UpdatedAt = canon.TS(tx.Now)
		return tx.PutCommand(rec)
	})
	if err != nil {
		return err
	}
	if n.hub != nil {
		var seq int64
		_ = n.Store.View(func(tx *store.Tx) error {
			if rec, ok := tx.GetCommand(cmdID); ok {
				seq = rec.LocalSeq
			}
			return nil
		})
		n.hub.notify(childID, seq)
	}
	n.Log.Info("RetryNode", "cmd", shortID(cmdID), "child", shortID(childID))
	return nil
}

// ---------- 后台清理任务 ----------

// cleanupCommandLog 指令日志清理：不高于保留水位、已终态、且超过审计保留期三者同时满足才删除
// （未完成指令永不清理；已下发的 CANCELLED / TIMEOUT 也要留到子确认或重放窗口）。
//
// 接收者 n 是本节点实例；没有子（hub 为空）时直接返回。
//
// 参数：
//
//	_ — 未使用的 context（由统一的 loop 调度器传入）
func (n *Node) cleanupCommandLog(context.Context) {
	if n.hub == nil {
		return
	}
	now := time.Now()
	_ = n.Store.Update(func(tx *store.Tx) error {
		floor := tx.MinUnfinishedSeq()
		for _, wm := range tx.ScanWatermarks() {
			if wm.FetchedCmdSeq < floor {
				floor = wm.FetchedCmdSeq
			}
		}
		var victims []*pb.CommandRecord
		_, ids := tx.CmdLogAfter(0, 0)
		for _, id := range ids {
			rec, ok := tx.GetCommand(id)
			if !ok {
				continue
			}
			if rec.LocalSeq >= floor {
				continue
			}
			// 已下发给子的终态（CANCELLED/TIMEOUT）必须保留到子确认或重放窗口（见 3.9）
			if rec.Status == pb.CommandStatus_COMMAND_STATUS_CANCELLED ||
				rec.Status == pb.CommandStatus_COMMAND_STATUS_TIMEOUT {
				continue
			}
			if !isTerminalCommand(rec.Status) {
				continue
			}
			if rec.UpdatedAt != nil && now.Sub(canon.Time(rec.UpdatedAt)) < n.C().Command.AuditRetention {
				continue
			}
			victims = append(victims, rec)
		}
		for _, v := range victims {
			if err := tx.DeleteCommand(v.CommandId); err != nil {
				return err
			}
			_ = tx.DeleteAssignmentsOfCommand(v.CommandId)
			_ = tx.DeleteChildReportsOfCommand(v.CommandId)
		}
		return nil
	})
}

// cleanupResults results 档案清理 + 内存索引回收（两者 expireAt 对齐）。
//
// 接收者 n 是本节点实例。
func (n *Node) cleanupResults() {
	now := time.Now()
	var expired []string
	_ = n.Store.Update(func(tx *store.Tx) error {
		for _, r := range tx.ScanResults() {
			if r.ExpireAt != nil && canon.Time(r.ExpireAt).Before(now) {
				expired = append(expired, r.CommandId)
			}
		}
		for _, id := range expired {
			if err := tx.DeleteResult(id); err != nil {
				return err
			}
		}
		return nil
	})
	n.index.evictExpired(now)
	for _, id := range expired {
		n.Log.Debug("result expired and removed", "cmd", shortID(id))
	}
}

// repushIndexes 周期性重推结果索引（覆盖根重启后"全树索引清零"的窗口，见 3.14 / ADR-048 第 6 条）。
//
// 接收者 n 是本节点实例；没有父时直接返回。只重推尚未过期的结果记录。
func (n *Node) repushIndexes() {
	if n.up == nil {
		return
	}
	var recs []*pb.ResultRecord
	_ = n.Store.View(func(tx *store.Tx) error {
		recs = tx.ScanResults()
		return nil
	})
	now := time.Now()
	for _, r := range recs {
		if r.ExpireAt != nil && canon.Time(r.ExpireAt).Before(now) {
			continue
		}
		n.pushResultIndex(r)
	}
}

// pushResultIndex 结果写入后触发一次索引上行（ownerSig 由持有者签、hopSig 由本跳重签），
// 同时把该索引写入本地内存索引。
//
// 接收者 n 是本节点实例；没有父时直接返回。
//
// 参数：
//
//	r — 刚写入的结果记录
func (n *Node) pushResultIndex(r *pb.ResultRecord) {
	if n.up == nil {
		return
	}
	ownerPath := n.SelfPath()
	expire := canon.Time(r.ExpireAt)
	if expire.IsZero() {
		expire = time.Now().Add(n.resultsRetention())
	}
	w := canon.NewWriter().Str(r.CommandId).Str(ownerPath)
	ownerSig := identity.Sign(n.Id().Key, w.DigestOf())
	idx := &pb.ResultIndexUp{
		CommandId: r.CommandId, OwnerPath: ownerPath, ExpireAt: canon.TS(expire),
		OwnerSig: ownerSig, OriginId: n.C().Node.ID,
	}
	idx.HopSig = n.hopSign(idx)
	n.index.upsert(r.CommandId, ownerPath, expire)
	n.up.sendResultIndex(idx)
}

// hopSign 计算一条结果索引在本跳的签名（对 commandID、ownerPath、expireAt、ownerSig 做 canonical 编码后签名）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	idx — 待上行的结果索引
//
// 返回：
//
//	[]byte — 本跳的 ed25519 签名
func (n *Node) hopSign(idx *pb.ResultIndexUp) []byte {
	w := canon.NewWriter().Str(idx.CommandId).Str(idx.OwnerPath)
	if idx.ExpireAt != nil {
		w.I64(idx.ExpireAt.Seconds)
	}
	w.Bytes(idx.OwnerSig)
	return identity.Sign(n.Id().Key, w.DigestOf())
}

// crc32Of 计算字节串的 CRC32（IEEE 多项式）校验值。
func crc32Of(b []byte) uint32 { return crc32.ChecksumIEEE(b) }
