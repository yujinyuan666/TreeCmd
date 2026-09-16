package node

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"treecmd/internal/aggregate"
	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// EnsureCreated 完成"客户端视角 → 服务端视角"的转换：
// 以 commandID 为键建 CommandRecord（分配本节点新的 LocalSeq）+ 该指令的全部 Assignment。
// 必须是一次单 bbolt 事务（ADR-025 / 6.7）；重复调用幂等。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	c — 指令体；幂等键是 c.Id
//
// 返回：
//
//	error — 分配 LocalSeq 或账本事务失败时返回
func (n *Node) EnsureCreated(c *pb.Command) error {
	return n.Store.Update(func(tx *store.Tx) error {
		rec, ok := tx.GetCommand(c.Id)
		if !ok {
			seq, err := tx.AllocLocalSeq()
			if err != nil {
				return err
			}
			// 基础 Command：Seq = 本节点 LocalSeq；HopChain = 收到的那些；Deadline = 本节点持有的值
			base := proto.Clone(c).(*pb.Command)
			base.Seq = seq
			rec = &pb.CommandRecord{
				CommandId: c.Id, LocalSeq: seq, Command: mustMarshal(base),
				Status: pb.CommandStatus_COMMAND_STATUS_PENDING, UpdatedAt: canon.TS(tx.Now),
			}
			if err := tx.PutCommand(rec); err != nil {
				return err
			}
			n.Log.Debug("EnsureCreated", "cmd", shortID(c.Id), "local_seq", seq)
		}
		// 下发即执行：对每个直接子节点都建 Assignment（不做任何 Target 剪枝）
		for _, ch := range n.Reg.Snapshot() {
			if _, ok := tx.GetAssignment(c.Id, ch.NodeID); ok {
				continue
			}
			a := &pb.AssignmentRecord{
				CommandId: c.Id, ChildId: ch.NodeID,
				Status:   pb.AssignStatus_ASSIGN_STATUS_PENDING,
				LocalSeq: rec.LocalSeq, NextAttempt: 1, UpdatedAt: canon.TS(tx.Now),
			}
			if err := tx.PutAssignment(a); err != nil {
				return err
			}
		}
		return nil
	})
}

// NotifyChildren 在事务提交成功之后才给各子节点发"来拉取"通知；通知丢了靠子侧轮询兜底。
//
// 接收者 n 是本节点实例；没有下行 hub（没有子节点）时直接返回。
//
// 参数：
//
//	c — 指令体；用来取本节点为该指令分配的 LocalSeq，作为通知里携带的序号
func (n *Node) NotifyChildren(c *pb.Command) {
	if n.hub == nil {
		return
	}
	var seq int64
	_ = n.Store.View(func(tx *store.Tx) error {
		if rec, ok := tx.GetCommand(c.Id); ok {
			seq = rec.LocalSeq
		}
		return nil
	})
	for _, a := range n.assignmentsOf(c.Id) {
		n.hub.notify(a.ChildId, seq)
	}
}

// assignmentsOf 读该指令下的全部 Assignment。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	[]*pb.AssignmentRecord — 该指令下所有子节点的分派记录；没有时返回 nil
func (n *Node) assignmentsOf(cmdID string) []*pb.AssignmentRecord {
	var out []*pb.AssignmentRecord
	_ = n.Store.View(func(tx *store.Tx) error {
		out = tx.AssignmentsOfCommand(cmdID)
		return nil
	})
	return out
}

// assignment 读某（指令, 子节点）组合的分派记录。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID   — 指令 ID
//	childID — 子节点 ID
//
// 返回：
//
//	*pb.AssignmentRecord — 分派记录；不存在时为 nil
//	bool                 — 是否读到
func (n *Node) assignment(cmdID, childID string) (*pb.AssignmentRecord, bool) {
	var (
		a  *pb.AssignmentRecord
		ok bool
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		a, ok = tx.GetAssignment(cmdID, childID)
		return nil
	})
	return a, ok
}

// records 读该指令的服务端记录（CommandRecord）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	*pb.CommandRecord — 服务端记录；不存在时为 nil
//	bool              — 是否读到
func (n *Node) records(cmdID string) (*pb.CommandRecord, bool) {
	var (
		r  *pb.CommandRecord
		ok bool
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		r, ok = tx.GetCommand(cmdID)
		return nil
	})
	return r, ok
}

// MarkUnreportedAtomic 退出前落定"未上报子"的 Assignment（+ 可选写退出原因标记）。
// finalize 只写 assignments，绝不顺手写终态（终态的权威写入只有 terminal()）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID      — 指令 ID
//	unreported — 要落定的子节点 ID 列表；已是终态的直接跳过
//	st         — 给这些子写入的 Assignment 状态（如 TIMEOUT / CANCELLED）
//	reason     — 非 UNSPECIFIED 时，同时把 CommandRecord.Status 改成它
//
// 返回：
//
//	error — 账本事务失败时返回
func (n *Node) MarkUnreportedAtomic(cmdID string, unreported []string, st pb.AssignStatus, reason pb.CommandStatus) error {
	return n.Store.Update(func(tx *store.Tx) error {
		for _, child := range unreported {
			a, ok := tx.GetAssignment(cmdID, child)
			if !ok || isTerminalAssign(a.Status) {
				continue
			}
			a.Status = st
			a.UpdatedAt = canon.TS(tx.Now)
			if err := tx.PutAssignment(a); err != nil {
				return err
			}
		}
		if reason != pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED {
			if rec, ok := tx.GetCommand(cmdID); ok {
				rec.Status = reason
				rec.UpdatedAt = canon.TS(tx.Now)
				if err := tx.PutCommand(rec); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// writeRunning 把该指令置为 RUNNING 并刷新 UpdatedAt
// （waitChildren 进入时与 RetryNode 两处写入点）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID；CommandRecord 不存在时静默返回 nil
//
// 返回：
//
//	error — 账本事务失败时返回
func (n *Node) writeRunning(cmdID string) error {
	return n.Store.Update(func(tx *store.Tx) error {
		rec, ok := tx.GetCommand(cmdID)
		if !ok {
			return nil
		}
		rec.Status = pb.CommandStatus_COMMAND_STATUS_RUNNING
		rec.UpdatedAt = canon.TS(tx.Now)
		return tx.PutCommand(rec)
	})
}

// isTerminalAssign 判断 Assignment 是否已是终态：DONE / FAILED / TIMEOUT / CANCELLED。
//
// 参数：
//
//	s — Assignment 状态
//
// 返回：
//
//	bool — 是终态为 true
func isTerminalAssign(s pb.AssignStatus) bool {
	switch s {
	case pb.AssignStatus_ASSIGN_STATUS_DONE, pb.AssignStatus_ASSIGN_STATUS_FAILED,
		pb.AssignStatus_ASSIGN_STATUS_TIMEOUT, pb.AssignStatus_ASSIGN_STATUS_CANCELLED:
		return true
	}
	return false
}

// mustMarshal 用规范编码把 proto 消息序列化成字节；失败直接 panic（编码失败属编程错误）。
//
// 参数：
//
//	m — 待序列化的 proto 消息
//
// 返回：
//
//	[]byte — 规范编码后的字节
func mustMarshal(m proto.Message) []byte {
	b, err := canon.Bytes(m)
	if err != nil {
		panic(err)
	}
	return b
}

// ---------- Delivery 派生（per-child，ADR-034 / ADR-037） ----------

// deriveDelivery 为某子派生一条 Delivery：
// ① 拷贝基础 Command；② 缩短 Deadline（同一 attempt 内只算一次并落盘为派生基线）；
// ③ 对"即将发出的内容"取 Digest 并签一次；④ 追加 HopAttest。
// 同一 (commandID, childID, attempt) 的派生结果逐字节一致（Ed25519 签名确定 + 内容确定）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	a       — 该子的分派记录；派生结果会就地写回 a.ChildDeadline / a.DerivedAttempt / a.DerivedCommand
//	base    — 本节点持有的基础指令体（含本节点 LocalSeq 与已有的 HopChain）
//	attempt — 本次投递的尝试序号
//
// 返回：
//
//	*pb.Delivery — 可下发的投递体（含本次租约的过期时间）
//	error        — 摘要计算或反序列化失败时返回
func (n *Node) deriveDelivery(a *pb.AssignmentRecord, base *pb.Command, attempt uint64) (*pb.Delivery, error) {
	if a.DerivedAttempt != attempt || len(a.DerivedCommand) == 0 {
		childDeadline := canon.Time(base.Deadline).Add(-n.C().Command.ReserveForReport)
		if base.Deadline == nil {
			childDeadline = time.Now().Add(n.C().DeadlineForType(base.Type))
		}
		derived := proto.Clone(base).(*pb.Command)
		derived.Seq = base.Seq // Seq 恒等于本节点 LocalSeq（ADR-034）
		derived.Deadline = canon.TS(childDeadline)
		derived.HopChain = append([]*pb.HopAttest(nil), base.HopChain...)

		digest, err := canon.Digest(derived)
		if err != nil {
			return nil, err
		}
		sig := identity.Sign(n.Id().Key, digest)
		derived.HopChain = append(derived.HopChain, &pb.HopAttest{
			ForwarderId: n.C().Node.ID, ChildId: a.ChildId, Digest: digest, Sig: sig,
		})
		a.ChildDeadline = canon.TS(childDeadline)
		a.DerivedAttempt = attempt
		a.DerivedCommand = mustMarshal(derived)
	}
	cmd := &pb.Command{}
	if err := proto.Unmarshal(a.DerivedCommand, cmd); err != nil {
		return nil, err
	}
	leaseExpire := time.Now().Add(n.C().Command.LeaseTTL)
	return &pb.Delivery{Command: cmd, Attempt: attempt, LeaseExpireUnixMs: leaseExpire.UnixMilli()}, nil
}

// ---------- 上游侧：拉取工作队列 ----------

// buildFetchResponse 处理一次 FetchCommands（父端）：修子节点水位、按 Assignment 挑出该投递的指令、
// 派生 Delivery、把 Assignment 置为 LEASED，全部在同一个事务里完成。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	childID — 请求方的子节点 ID（来自 mTLS 对端身份）
//	req     — 客户端的拉取请求：SinceSeq 是客户端自报进度（会与父侧权威水位取较大者），
//	          MaxFetch 是本批最多几条（<= 0 时内容侧退回默认 512、投递侧不设条数上限）
//
// 返回：
//
//	*pb.FetchResponse — NewSeq（父侧权威的新水位）+ Deliveries（本批下发，受字节上限与在途窗口截断，可能为空）
//	error            — 账本事务失败时返回
func (n *Node) buildFetchResponse(childID string, req *pb.FetchRequest) (*pb.FetchResponse, error) {
	resp := &pb.FetchResponse{}
	maxBytes := int64(n.C().Command.FetchResponseMaxBytes)
	// 在途窗口（下发背压）。**放在事务外算**：自适应那一支要读在线子数，而在线子数是连接表的
	// 实时状态，没必要也不该在账本事务里读。
	perChildLimit := n.effectiveDispatchWindow()
	totalLimit := int64(n.C().Command.DispatchWindowTotal())
	err := n.Store.Update(func(tx *store.Tx) error {
		wm, ok := tx.GetWatermark(childID)
		if !ok {
			wm = &pb.ChildWatermark{ChildId: childID, FetchedCmdSeq: tx.LastAllocatedSeq(), LastSeenAt: canon.TS(tx.Now)}
		}
		wm.LastSeenAt = canon.TS(tx.Now)
		if err := tx.PutWatermark(wm); err != nil {
			return err
		}
		// 父端不信任客户端上报的 since_seq：effective_since = max(客户端, 父侧权威水位)
		effectiveSince := req.SinceSeq
		if wm.FetchedCmdSeq > effectiveSince {
			effectiveSince = wm.FetchedCmdSeq
		}
		// 内容侧：扫描"确实处理过的最大 seq"（含未命中本节点的那些）
		limit := int(req.MaxFetch)
		if limit <= 0 {
			limit = 512
		}
		seqs, _ := tx.CmdLogAfter(effectiveSince, limit)
		newSeq := effectiveSince
		if len(seqs) > 0 {
			newSeq = seqs[len(seqs)-1]
		}
		resp.NewSeq = newSeq

		// 投递侧：由 Assignment 驱动，与水位无关
		now := tx.Now
		used := int64(0)
		count := int32(0)
		// 在途数：进循环前先数一遍，之后每放行一条 +1（本轮事务里只有"放行"会让它变大，
		// 所以这样数出来的值与逐条重算等价）。窗口两个都关着时**不数** —— 不为没开的功能付费。
		inflightChild, inflightTotal := int64(0), int64(0)
		if perChildLimit > 0 || totalLimit > 0 {
			inflightChild, inflightTotal = countInflight(tx, childID, now)
		}
		for _, cmdID := range tx.CommandIDsOfChild(childID) {
			if req.MaxFetch > 0 && count >= req.MaxFetch {
				break
			}
			// 在途窗口打满 → 直接收工。**用 break 而不是 continue 是安全的**：两个计数在
			// 循环内只增不减，打满之后后面任何一条都不可能再被放行，继续扫描纯属白扫。
			// （注意与下面那个按字节的 break 区分开：那里后面的"小"指令本来还塞得进去，
			// 它 break 是出于带宽预算的取舍，不是因为"后面一定也不行"。）
			if perChildLimit > 0 && inflightChild >= perChildLimit {
				n.Metrics.Inc("dispatch_throttled_total", "reason", "child_window")
				break
			}
			if totalLimit > 0 && inflightTotal >= totalLimit {
				n.Metrics.Inc("dispatch_throttled_total", "reason", "total_window")
				break
			}
			a, ok := tx.GetAssignment(cmdID, childID)
			if !ok || isTerminalAssign(a.Status) {
				continue
			}
			if a.BackoffUntil != nil && canon.Time(a.BackoffUntil).After(now) {
				continue
			}
			// 动态修复：LEASED 且租约已过期（含父重启后租约失效）→ 就地回收为 PENDING
			if a.Status == pb.AssignStatus_ASSIGN_STATUS_LEASED {
				if a.Lease != nil && canon.Time(a.Lease.ExpireAt).After(now) {
					continue // 仍在有效租约内，不重复投递
				}
				a.Status = pb.AssignStatus_ASSIGN_STATUS_PENDING
				a.ReclaimCount++
				// 租约被回收 ⇒ 那个子的状态已经不可知（可能重启过、可能整个换了一批进程），
				// 连续被退回的次数从这里重新开始数 —— 否则一次颠簸会让退避永久停在封顶值。
				a.LocalBusyStreak = 0
				a.LastReclaimAt = canon.TS(now)
				a.NextAttempt = a.DeliveredAttempt + 1
			}
			rec, ok := tx.GetCommand(cmdID)
			if !ok {
				continue
			}
			base := &pb.Command{}
			if err := proto.Unmarshal(rec.Command, base); err != nil {
				continue
			}
			attempt := a.NextAttempt
			if attempt == 0 {
				attempt = 1
			}
			d, err := n.deriveDelivery(a, base, attempt)
			if err != nil {
				n.Log.Warn("derive delivery failed", "cmd", shortID(cmdID), "err", err)
				continue
			}
			sz := int64(proto.Size(d))
			if used+sz > maxBytes && count > 0 { // 父端兜底截断（3.2）
				break
			}
			used += sz
			inflightChild++
			inflightTotal++
			a.Status = pb.AssignStatus_ASSIGN_STATUS_LEASED
			a.Lease = &pb.Lease{Owner: childID, ExpireAt: canon.TS(millisToTime(d.LeaseExpireUnixMs)), Attempt: attempt}
			a.DeliveredAttempt = attempt
			a.UpdatedAt = canon.TS(now)
			if err := tx.PutAssignment(a); err != nil {
				return err
			}
			resp.Deliveries = append(resp.Deliveries, d)
			count++
		}
		// new_seq 的推进必须与 FetchedCmdSeq 的落盘在同一事务里（绝不允许水位回退）
		if resp.NewSeq > wm.FetchedCmdSeq {
			wm.FetchedCmdSeq = resp.NewSeq
		} else {
			resp.NewSeq = wm.FetchedCmdSeq
		}
		return tx.PutWatermark(wm)
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// touchChild 记录"该子最近一次出现"（唯一权威：ChildWatermark.LastSeenAt）；
// 该子还没有水位记录时，顺带把水位建到当前已分配的最大序号。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	childID — 子节点 ID
func (n *Node) touchChild(childID string) {
	_ = n.Store.Update(func(tx *store.Tx) error {
		wm, ok := tx.GetWatermark(childID)
		if !ok {
			wm = &pb.ChildWatermark{ChildId: childID, FetchedCmdSeq: tx.NextCmdSeq()}
		}
		wm.LastSeenAt = canon.TS(tx.Now)
		return tx.PutWatermark(wm)
	})
}

// countInflight 数一数"当前在途"的分派：指定子有几条、全节点共几条。
//
// 在途的判据只有一条：**状态是 LEASED，且租约仍在有效期内**。下面两种都**不算**，理由各不相同：
//
//   - PENDING（含被 LocalBusy 退回、正在退避的）：子还没拿到手，不该占窗口的名额。
//   - LEASED 但租约已过期：这是"父已经忘了它"的僵尸租约（父重启、或长丢包），本轮循环里
//     就会把它回收成 PENDING。**若把它也算进窗口，一次父重启就足以让窗口被一批永远
//     不会回来的租约占满，节点会把自己彻底锁死** —— 这条是必须写下来的，它不是洁癖。
//
// 参数：
//
//	tx      — 账本事务
//	childID — 要单独计数的子节点 ID
//	now     — 判定租约是否有效的"现在"；用 tx.Now，与同一周期里的其它时间判定共用同一个时钟
//
// 返回：
//
//	child — 该子的在途条数
//	total — 本节点所有直接子的在途条数（child 是它的子集）
func countInflight(tx *store.Tx, childID string, now time.Time) (child, total int64) {
	for _, a := range tx.ScanAssignments() {
		if a.Status != pb.AssignStatus_ASSIGN_STATUS_LEASED {
			continue
		}
		if a.Lease == nil || !canon.Time(a.Lease.ExpireAt).After(now) {
			continue
		}
		total++
		if a.ChildId == childID {
			child++
		}
	}
	return child, total
}

// inflightByChild 统计每个直接子的在途分派数（判据与 countInflight 完全一致，供指标用）。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	map[string]float64 — 键是 `child="<完整 NodeID>"`，值是该子的在途条数；没有在途时返回空 map。
//	                     聚合值不需要单独出一个指标：`sum(child_dispatch_inflight)` 就是它。
//
//	                     **键里用完整 NodeID 而不是前 8 位**：NodeID 是 UUIDv7（时间有序），
//	                     前 8 位就是毫秒时间戳 —— 同一秒启动的两个子前缀会一模一样，
//	                     拿前缀当标签会把两个子静默合并成一条曲线（这个坑本仓库已经踩过一次，
//	                     见片存目录名那次）。
func (n *Node) inflightByChild() map[string]float64 {
	out := map[string]float64{}
	now := time.Now()
	_ = n.Store.View(func(tx *store.Tx) error {
		for _, a := range tx.ScanAssignments() {
			if a.Status != pb.AssignStatus_ASSIGN_STATUS_LEASED {
				continue
			}
			if a.Lease == nil || !canon.Time(a.Lease.ExpireAt).After(now) {
				continue
			}
			out[`child="`+a.ChildId+`"`]++
		}
		return nil
	})
	return out
}

// effectiveDispatchWindow 算出本次投递实际生效的"每个直接子的在途窗口"。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	int64 — 生效窗口；**0 表示不限**。开了 dispatch_window_adaptive 时取
//	         min(配置值, max(1, 全局窗口 / 在线子数))：子在线的多就收紧、子掉线就放宽。
//	         刻意**只在自己那一档上收紧、不反过来把单子上限抬高** ——
//	         max_dispatch_inflight_per_child 是硬上限，自适应只是"在全局预算里给每个子分多少"。
func (n *Node) effectiveDispatchWindow() int64 {
	per := int64(n.C().Command.DispatchWindowPerChild())
	if per <= 0 || !n.C().Command.DispatchWindowAdaptive {
		return per
	}
	total := int64(n.C().Command.DispatchWindowTotal())
	if total <= 0 {
		return per
	}
	kids := int64(n.childOnline())
	if kids < 1 {
		kids = 1
	}
	share := total / kids
	if share < 1 {
		share = 1
	}
	if share < per {
		return share
	}
	return per
}

// reclaimExpiredLeases 租约过期扫描（节点级协程，LeaseTTL/3 周期）。
// 判据只看 Lease.ExpireAt（父时钟），不与 LastSeenAt 比较；回收时不推进 attempt（下次投递时才 +1）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	_ — 未使用的上下文（后台循环回调的统一签名）
func (n *Node) reclaimExpiredLeases(_ context.Context) {
	now := time.Now()
	_ = n.Store.Update(func(tx *store.Tx) error {
		for _, a := range tx.ScanAssignments() {
			if a.Status != pb.AssignStatus_ASSIGN_STATUS_LEASED {
				continue
			}
			if a.Lease == nil || canon.Time(a.Lease.ExpireAt).After(now) {
				continue
			}
			a.Status = pb.AssignStatus_ASSIGN_STATUS_PENDING
			a.ReclaimCount++
			// 与 buildFetchResponse 里的内联回收同一条理由：租约被回收说明那个子的状态
			// 已经不可知（重启 / 网络颠簸），连续被退回的次数从这里重新数。
			a.LocalBusyStreak = 0
			a.LastReclaimAt = canon.TS(tx.Now)
			a.NextAttempt = a.DeliveredAttempt + 1
			if err := tx.PutAssignment(a); err != nil {
				return err
			}
		}
		return nil
	})
}

// ResolveChildID 从 mTLS 对端证书推导子节点身份（不信任请求里自报的 node_id）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	peerNodeID — 从对端证书解析出的 NodeID（权威来源）
//	claimed    — 请求里自报的 node_id；非空且与 peerNodeID 不一致时报错
//
// 返回：
//
//	string — 最终采用的子节点 ID
//	error  — 对端身份为空，或自报与证书不符时返回
func (n *Node) ResolveChildID(peerNodeID, claimed string) (string, error) {
	if peerNodeID == "" {
		return "", fmt.Errorf("no peer identity")
	}
	if claimed != "" && claimed != peerNodeID {
		return "", fmt.Errorf("ERR_NODE_ID_MISMATCH: claimed %s, cert %s", claimed, peerNodeID)
	}
	return peerNodeID, nil
}

// policyFrom 由指令体取失败策略；两个字段都没设置时用默认值。
//
// 参数：
//
//	c — 指令体；读 OnFailure 与 TolerateValue，指针为 nil 表示未设置
//
// 返回：
//
//	aggregate.FailurePolicy — 默认 kind = POLICY_ALL_MUST_SUCCEED、Tolerate = 0
func policyFrom(c *pb.Command) aggregate.FailurePolicy {
	kind := pb.FailurePolicy_POLICY_ALL_MUST_SUCCEED
	var tol float64
	if c.OnFailure != nil {
		kind = *c.OnFailure
	}
	if c.TolerateValue != nil {
		tol = *c.TolerateValue
	}
	return aggregate.FailurePolicy{Kind: kind, Tolerate: tol}
}

// strategyFrom 由指令体取聚合策略（未设置 → TREE；显式设为 0 → 拒绝）。
//
// 参数：
//
//	c — 指令体；Aggregate 指针为 nil 表示未设置
//
// 返回：
//
//	pb.AggregateStrategy — 生效的聚合策略
//	error               — Aggregate 被显式设为 UNSPECIFIED 时返回
func strategyFrom(c *pb.Command) (pb.AggregateStrategy, error) {
	if c.Aggregate == nil {
		return pb.AggregateStrategy_AGGREGATE_TREE, nil
	}
	if *c.Aggregate == pb.AggregateStrategy_AGGREGATE_UNSPECIFIED {
		return pb.AggregateStrategy_AGGREGATE_UNSPECIFIED, fmt.Errorf("ERR_UNKNOWN_AGGREGATE: explicit 0 is rejected")
	}
	return *c.Aggregate, nil
}
