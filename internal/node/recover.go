package node

import (
	"time"

	"google.golang.org/protobuf/proto"

	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// reactivatePending 重启后重新激活本地未终态指令（6.4）。两类互斥：
//
//	A 未终态（NOT_STARTED / SELF_RUNNING / SELF_DONE）→ 一律调 handle，由 handle 自己的分支决定
//	B 已终态但父未确认（pending_result 存在）→ 只 reportUpstream 补报，不进 handle
//	B′ 已终态且父已确认 → 什么都不做
//
// 接收者 n 是本节点实例；每条待处理的指令各起一个协程，本函数自身不阻塞。
func (n *Node) reactivatePending() {
	var locals []*pb.LocalCommandRecord
	_ = n.Store.View(func(tx *store.Tx) error {
		locals = tx.ScanLocal()
		return nil
	})
	n.Log.Info("reactivatePending: 扫描本地账本", "entries", len(locals))
	for _, lc := range locals {
		switch lc.LocalState {
		case pb.LocalExecState_LOCAL_STATE_NOT_STARTED,
			pb.LocalExecState_LOCAL_STATE_SELF_RUNNING,
			pb.LocalExecState_LOCAL_STATE_SELF_DONE:
			if len(lc.Command) == 0 {
				n.Log.Warn("未终态指令缺少指令体，等待父侧重投", "cmd", shortID(lc.CommandId))
				continue
			}
			c := &pb.Command{}
			if err := proto.Unmarshal(lc.Command, c); err != nil {
				continue
			}
			attempt := lc.Attempt
			if attempt == 0 {
				attempt = 1 // wire 上 attempt == 0 非法
			}
			n.Log.Info("reactivatePending: 重新入队", "cmd", shortID(lc.CommandId), "state", lc.LocalState.String())
			go n.handle(n.backgroundContext(), c, attempt)
		case pb.LocalExecState_LOCAL_STATE_COMPLETED,
			pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
			pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
			var pr *pb.PendingResultRecord
			_ = n.Store.View(func(tx *store.Tx) error {
				pr, _ = tx.GetPending(lc.CommandId)
				return nil
			})
			if pr == nil {
				continue // B′：终态已闭环
			}
			n.Log.Info("reactivatePending: 补报（类别 B）", "cmd", shortID(lc.CommandId))
			go n.reportUpstream(lc.CommandId, maxU64(pr.Attempt, 1))
		}
	}
}

// maxU64 返回 a、b 中较大的一个。
//
// 参数：
//
//	a — 第一个无符号整数
//	b — 第二个无符号整数
//
// 返回：
//
//	uint64 — 两者中的较大值
func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

// 保证 time 被使用（供未来扩展的重试窗口）。
var _ = time.Now
