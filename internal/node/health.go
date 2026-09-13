package node

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// HealthRequest 参数（HTTP 层校验后传入）。
type HealthRequest struct {
	CommandID string
	Depth     int
	Detail    bool
	Timeout   time.Duration
	// Auth 逐跳原样透传的委托凭证（入口生成一次；本节点转发时不得改写）
	Auth *pb.ReqAuth
}

// Health 健康度 / 指令轨迹双模式入口（4.x）。同一周期只跑一轮（三把锁按查询重量分桶）。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	ctx — 请求上下文
//	req — 请求参数，含 CommandID / Depth / Detail / Timeout / Auth
//
// 返回：
//
//	*pb.HealthResponse — 已签名的响应
//	error             — 已有同类扫描在跑或采集失败时返回
func (n *Node) Health(ctx context.Context, req HealthRequest) (*pb.HealthResponse, error) {
	var mu *sync.Mutex
	switch {
	case req.Depth > 1 || req.Depth < 0:
		mu = &n.healthMuHeavy
	case req.Depth == 1:
		mu = &n.healthMuLight
	default:
		mu = &n.healthMuSelf
	}
	if !mu.TryLock() {
		return nil, fmt.Errorf("IN_PROGRESS: health sweep already running")
	}
	defer mu.Unlock()

	if req.Timeout <= 0 {
		req.Timeout = 5 * time.Second
	}
	if req.Auth == nil {
		req.Auth = n.makeReqAuth(req.CommandID, req.Detail, reqAuthKindHealth)
	}
	deadline := time.Now().Add(req.Timeout)
	resp, err := n.collect(ctx, req, 0, deadline)
	if err != nil {
		return nil, err
	}
	return n.signHealth(resp)
}

// collect 按是否带 CommandID 采集"健康度"或"指令轨迹"两种模式的结果。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	ctx      — 请求上下文
//	req      — 请求参数
//	hop      — 当前跳数（根节点为 0）
//	deadline — 本跳整体截止时刻
//
// 返回：
//
//	*pb.HealthResponse — 已填 NodeId / Path / Signer 与对应模式数据的响应
//	error             — 恒为 nil
func (n *Node) collect(ctx context.Context, req HealthRequest, hop int, deadline time.Time) (*pb.HealthResponse, error) {
	resp := n.stampNodeMeta(&pb.HealthResponse{NodeId: n.C().Node.ID, Path: n.SelfPath(), Signer: n.signerInfo()})
	if req.CommandID == "" {
		resp.Mode = pb.HealthMode_HEALTH_MODE_HEALTH
		rep := n.healthReport(ctx, req, hop, deadline)
		resp.Health = rep
	} else {
		resp.Mode = pb.HealthMode_HEALTH_MODE_COMMAND_TRACE
		trace := n.commandTrace(ctx, req, hop, deadline)
		resp.Command = trace
	}
	return resp, nil
}

// ---------- 健康度模式 ----------

// healthReport 采集健康度模式：本节点各项检查 + 递归子节点 + 子树汇总。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	ctx      — 请求上下文
//	req      — 请求参数（Depth 控制递归深度，Detail 控制每层是否回完整对象）
//	hop      — 当前跳数
//	deadline — 本跳整体截止时刻
//
// 返回：
//
//	*pb.HealthReport — 含 Checks / Metrics / Children / Summary
func (n *Node) healthReport(ctx context.Context, req HealthRequest, hop int, deadline time.Time) *pb.HealthReport {
	rep := &pb.HealthReport{Status: pb.HealthStatus_HEALTHY}
	uptime := time.Since(n.startedAt)
	inflight := n.inflightCount()
	pendingResult := n.pendingCount()
	checks := []*pb.CheckResult{
		{Name: "node_up", Status: pb.HealthStatus_HEALTHY, Detail: "running"},
	}
	// 父连接
	parentStatus := pb.HealthStatus_HEALTHY
	parentDetail := "connected"
	if n.up == nil {
		parentStatus, parentDetail = pb.HealthStatus_HEALTHY, "root (no parent)"
	} else if !n.up.isConnected() {
		parentStatus, parentDetail = pb.HealthStatus_DEGRADED, "reconnecting"
	}
	checks = append(checks, &pb.CheckResult{Name: "parent_link", Status: parentStatus, Detail: parentDetail})
	// 证书
	certStatus, certDetail := pb.HealthStatus_HEALTHY, fmt.Sprintf("valid until %s", n.Id().Cert.NotAfter.Format(time.RFC3339))
	if days := time.Until(n.Id().Cert.NotAfter).Hours() / 24; days <= 7 {
		certStatus, certDetail = pb.HealthStatus_DEGRADED, fmt.Sprintf("expires in %.1f days", days)
	}
	checks = append(checks, &pb.CheckResult{Name: "certificate", Status: certStatus, Detail: certDetail})
	// 指令积压
	backlogStatus := pb.HealthStatus_HEALTHY
	ratio := float64(inflight) / float64(maxInt32(1, n.C().Command.MaxInflight))
	if ratio >= 0.9 {
		backlogStatus = pb.HealthStatus_UNHEALTHY
	} else if ratio >= 0.5 {
		backlogStatus = pb.HealthStatus_DEGRADED
	}
	checks = append(checks, &pb.CheckResult{Name: "command_backlog", Status: backlogStatus,
		Detail: fmt.Sprintf("inflight=%d/%d", inflight, n.C().Command.MaxInflight)})
	// 失败率
	fr := n.failRate1h()
	frStatus := pb.HealthStatus_HEALTHY
	if fr > 0.10 {
		frStatus = pb.HealthStatus_UNHEALTHY
	} else if fr >= 0.01 {
		frStatus = pb.HealthStatus_DEGRADED
	}
	checks = append(checks, &pb.CheckResult{Name: "fail_rate_1h", Status: frStatus, Detail: fmt.Sprintf("%.3f", fr)})
	// 子节点
	childStatus := pb.HealthStatus_HEALTHY
	childDetail := "no children"
	if n.hub != nil {
		known := int32(len(n.Reg.Snapshot()))
		if known > 0 {
			online := int32(n.hub.ConnCount())
			childDetail = fmt.Sprintf("%d/%d online", online, known)
			if online < known {
				childStatus = pb.HealthStatus_DEGRADED
			}
		}
	}
	checks = append(checks, &pb.CheckResult{Name: "children", Status: childStatus, Detail: childDetail})
	rep.Checks = checks
	rep.Metrics = &pb.HealthMetrics{
		UptimeSeconds: int64(uptime.Seconds()), Inflight: int32(inflight),
		PendingCommands: int64(pendingResult), ChildrenOnline: int64(n.childOnline()),
		FailRate_1H: fr, MemMb: memMB(), PendingResultBacklog: int64(pendingResult),
	}
	rep.Status = worst(checks)

	// 子节点递归（depth 控制往多深；detail 控制每层是否回完整对象）
	if n.hub != nil && (req.Depth < 0 || req.Depth-hop > 0) {
		children := n.Reg.Snapshot()
		childReq := req
		if req.Depth != -1 {
			childReq.Depth = req.Depth - 1
		}
		// timeout_ms 是"本跳整体预算"：逐跳只减不增，且留下一点余量让本跳能在父的期限前回复
		childReq.Timeout = budgetFor(deadline)
		fanout := maxInt32(1, n.C().Health.MaxHealthFanout)
		sem := make(chan struct{}, fanout)
		var (
			wg  sync.WaitGroup
			mu  sync.Mutex
			sum = &pb.SubtreeSummary{}
			res = make([]*pb.ChildHealth, 0, len(children))
		)
		for _, c := range children {
			if ctx.Err() != nil {
				break // 调用方已放弃：不再往下扇出（避免无效负载堆积）
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(childID string) {
				defer wg.Done()
				defer func() { <-sem }()
				ch := n.queryChildHealth(ctx, childID, childReq)
				mu.Lock()
				defer mu.Unlock()
				res = append(res, ch)
				// 子树统计：本子 + 它上报的子树汇总（逐层累加，得到整棵子树的计数）
				cs := childSummary(ch)
				sum.Total += 1 + cs.GetTotal()
				sum.Healthy += boolToInt(ch.Status == pb.HealthStatus_HEALTHY) + cs.GetHealthy()
				sum.Degraded += boolToInt(ch.Status == pb.HealthStatus_DEGRADED) + cs.GetDegraded()
				sum.Unhealthy += boolToInt(ch.Status == pb.HealthStatus_UNHEALTHY) + cs.GetUnhealthy()
				sum.Unreachable += boolToInt(ch.Status == pb.HealthStatus_UNREACHABLE) + cs.GetUnreachable()
				sum.Anomalies = append(sum.Anomalies, cs.GetAnomalies()...)
				if ch.Status != pb.HealthStatus_HEALTHY {
					sum.Anomalies = append(sum.Anomalies, childID)
				}
			}(c.NodeID)
		}
		wg.Wait()
		rep.Children = res
		rep.Summary = sum
		base := worst(checks)
		if base == pb.HealthStatus_HEALTHY && (sum.Unhealthy > 0 || sum.Unreachable > 0) {
			base = pb.HealthStatus_DEGRADED
		}
		rep.Status = base
		// 体积控制：超过 health_response_max_bytes 时降级为"汇总 + truncated"（绝不静默截断）
		if sz := proto.Size(rep); int64(sz) > int64(n.C().Health.ResponseMaxBytes) {
			keep := rep.Summary
			rep = &pb.HealthReport{Status: rep.Status, Checks: rep.Checks, Metrics: rep.Metrics,
				Summary: keep, Truncated: true, Omitted: int32(len(res))}
		}
	} else {
		rep.Summary = &pb.SubtreeSummary{}
	}
	return rep
}

// queryChildHealth 向一个子节点发起健康查询并校验其响应，包装成 ChildHealth。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	ctx      — 请求上下文
//	childID  — 目标子节点 NodeID
//	childReq — 下发给子节点的请求参数
//
// 返回：
//
//	*pb.ChildHealth — 子节点状态；不可达 / 校验失败时带 Err
func (n *Node) queryChildHealth(ctx context.Context, childID string, childReq HealthRequest) *pb.ChildHealth {
	out := &pb.ChildHealth{NodeId: childID}
	// 先从注册表带上已知元信息（离线子节点也能显示名字），随后用子节点自报的值覆盖。
	if c, ok := n.Reg.Get(childID); ok {
		out.NodeName, out.NodeRemark = c.Name, c.Remark
	}
	if n.hub == nil {
		out.Status, out.Err = pb.HealthStatus_UNREACHABLE, "UNREACHABLE"
		return out
	}
	req := &pb.HealthReq{
		ReqId: fmt.Sprintf("%s-%d", shortID(n.C().Node.ID), time.Now().UnixNano()),
		Depth: int32(childReq.Depth), Detail: childReq.Detail,
		TimeoutMs: childReq.Timeout.Milliseconds(),
		ReqAuth:   childReq.Auth,
	}
	resp, err := n.hub.healthReq(ctx, childID, req)
	if err != nil {
		out.Status, out.Err = pb.HealthStatus_UNREACHABLE, err.Error()
		return out
	}
	// 四步校验（1 验签 / 2 链到根由 mTLS 完成 / 3 有效期 / 4 证书身份 == NodeID）
	digest, err := n.verifyHealthResp(childID, resp)
	if err != nil {
		out.Status, out.Err = pb.HealthStatus_UNHEALTHY, err.Error()
		return out
	}
	out.Status = statusOf(resp)
	// 元信息以子节点自报为准（它随子节点签名一起上来），注册表那份只是离线时的兜底
	if resp.NodeName != "" {
		out.NodeName = resp.NodeName
	}
	if resp.NodeRemark != "" {
		out.NodeRemark = resp.NodeRemark
	}
	// ChildHealth.Sig 是对 Digest 签名（detail=false 也能只带 Digest+Sig 的前提）
	out.Digest, out.Sig = digest, resp.Sig
	if resp.Mode == pb.HealthMode_HEALTH_MODE_HEALTH {
		out.Summary = subSummaryOf(resp.Health) // detail=false 也能逐层累加子树计数
		if childReq.Detail {
			out.Report = resp.Health
		}
	}
	return out
}

// verifyHealthResp 子节点回传必须用自己身份密钥签名，父端照做四步合法性校验。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	childID — 子节点 NodeID
//	resp    — 子节点返回的（已签名）响应
//
// 返回：
//
//	[]byte — 计算出的内容摘要（即签名覆盖的字节）
//	error  — 身份不符 / 缺签名 / 证书不可信 / 验签失败 / 证书过期时返回
func (n *Node) verifyHealthResp(childID string, resp *pb.HealthResponse) ([]byte, error) {
	if resp.NodeId != childID {
		return nil, fmt.Errorf("ID_MISMATCH")
	}
	if len(resp.Sig) == 0 {
		return nil, fmt.Errorf("SIG_INVALID")
	}
	clone := proto.Clone(resp).(*pb.HealthResponse)
	clone.Sig = nil
	d, err := canon.Digest(clone)
	if err != nil {
		return nil, err
	}
	// 公钥来自注册时上报的 pubkey（mTLS 对端证书亦等价）
	pub := n.childPub(childID)
	if pub == nil {
		return nil, fmt.Errorf("CERT_UNTRUSTED")
	}
	if !identity.Verify(pub, d, resp.Sig) {
		return nil, fmt.Errorf("SIG_INVALID")
	}
	if resp.Signer == nil || time.Now().After(resp.Signer.CertNotAfter.AsTime().Add(7*24*time.Hour)) {
		return nil, fmt.Errorf("CERT_EXPIRED")
	}
	return d, nil
}

// childPub 取当前在线子连接上报的 Ed25519 公钥（无 Hub 或子不在线时为 nil）。
//
// 接收者 n 是本节点。
func (n *Node) childPub(childID string) []byte {
	if n.hub == nil {
		return nil
	}
	if cc, ok := n.hub.conn(childID); ok {
		return cc.pub
	}
	return nil
}

// signHealth 本节点对响应签名（含 Signer，不含 Sig）。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	resp — 待签名的响应
//
// 返回：
//
//	*pb.HealthResponse — 填好 Sig 的响应
//	error             — 规范化失败时返回
func (n *Node) signHealth(resp *pb.HealthResponse) (*pb.HealthResponse, error) {
	clone := proto.Clone(resp).(*pb.HealthResponse)
	clone.Sig = nil
	d, err := canon.Digest(clone)
	if err != nil {
		return nil, err
	}
	resp.Sig = identity.Sign(n.Id().Key, d)
	return resp, nil
}

// signerInfo 构造签名者信息（本节点 ID、证书指纹、证书到期时间）。
//
// 接收者 n 是本节点。
//
// 返回：
//
//	*pb.SignerInfo — 本节点的签名者信息
func (n *Node) signerInfo() *pb.SignerInfo {
	return &pb.SignerInfo{NodeId: n.C().Node.ID, CertFingerprint: identity.Fingerprint(n.Id().Cert),
		CertNotAfter: canon.TS(n.Id().Cert.NotAfter)}
}

// stampNodeMeta 把本节点元信息（node.name / node.remark，ADR-051）写进响应。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	resp — 待填充元信息的响应
//
// 返回：
//
//	*pb.HealthResponse — 同一个响应（已填入名称与备注）
//
// 为什么不靠父端缓存：写进**本节点自己的**响应，它就随本节点签名一起上行
// （canon.Digest 覆盖除 Sig 外的整个 HealthResponse），父端不必信任自己的注册表也能看清"我是谁"。
func (n *Node) stampNodeMeta(resp *pb.HealthResponse) *pb.HealthResponse {
	resp.NodeName = n.C().Node.Name
	resp.NodeRemark = n.C().Node.Remark
	return resp
}

// serveHealthReqFromParent 收到父的 HealthReq 帧 → **先按自己的白名单校验委托** → 采集本子树 → 回 HealthResp。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	req — 父端下发的健康请求，含 ReqId / Depth / Detail / TimeoutMs / ReqAuth
func (n *Node) serveHealthReqFromParent(req *pb.HealthReq) {
	var resp *pb.HealthResponse
	if err := n.checkHealthReqAuth(req); err != nil {
		// 拒绝也要回一个**已签名**的响应，否则父端会把它记成 UNREACHABLE 而看不到"被拒"的原因
		resp = n.stampNodeMeta(&pb.HealthResponse{
			NodeId: n.C().Node.ID, Path: n.SelfPath(), Signer: n.signerInfo(),
			Mode: pb.HealthMode_HEALTH_MODE_HEALTH,
			Health: &pb.HealthReport{
				Status: pb.HealthStatus_UNHEALTHY,
				Checks: []*pb.CheckResult{{
					Name: "req_auth", Status: pb.HealthStatus_UNHEALTHY, Detail: err.Error(),
				}},
			},
		})
		resp, _ = n.signHealth(resp)
	} else {
		var err error
		resp, err = n.Health(context.Background(), HealthRequest{
			CommandID: req.CommandId, Depth: int(req.Depth), Detail: req.Detail,
			Timeout: time.Duration(req.TimeoutMs) * time.Millisecond, Auth: req.ReqAuth,
		})
		if err != nil {
			resp = n.stampNodeMeta(&pb.HealthResponse{NodeId: n.C().Node.ID, Path: n.SelfPath(), Signer: n.signerInfo(),
				Mode: pb.HealthMode_HEALTH_MODE_HEALTH, Health: &pb.HealthReport{Status: pb.HealthStatus_UNHEALTHY}})
			resp, _ = n.signHealth(resp)
		}
	}
	if n.up != nil {
		_ = n.up.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: n.C().Node.ID,
			Frame: &pb.UpFrame_HealthResp{HealthResp: &pb.HealthResp{ReqId: req.ReqId, Response: resp}}})
	}
}

// ---------- 指令轨迹模式 ----------

// commandTrace 采集指令轨迹模式：本节点的 local_state / command 记录 + 递归子节点分派。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	ctx      — 请求上下文
//	req      — 请求参数（CommandID 必填）
//	hop      — 当前跳数
//	deadline — 本跳整体截止时刻
//
// 返回：
//
//	*pb.CommandTrace — 含角色、状态、子节点轨迹与汇总
func (n *Node) commandTrace(ctx context.Context, req HealthRequest, hop int, deadline time.Time) *pb.CommandTrace {
	tr := &pb.CommandTrace{CommandId: req.CommandID}
	var (
		local   *pb.LocalCommandRecord
		rec     *pb.CommandRecord
		assigns []*pb.AssignmentRecord
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		local, _ = tx.GetLocal(req.CommandID)
		rec, _ = tx.GetCommand(req.CommandID)
		assigns = tx.AssignmentsOfCommand(req.CommandID)
		return nil
	})
	if local == nil && rec == nil {
		tr.Role = pb.TraceRole_TRACE_ROLE_UNSPECIFIED
		tr.Status = pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED
		tr.StatusSource = "NOT_FOUND"
		tr.Summary = &pb.TraceSummary{NotFound: 1}
		return tr
	}
	role := pb.TraceRole_TRACE_ROLE_UNSPECIFIED
	switch {
	case local != nil && len(assigns) > 0:
		role = pb.TraceRole_TRACE_BOTH
	case local != nil:
		role = pb.TraceRole_TRACE_SUBJECT
	default:
		role = pb.TraceRole_TRACE_DISPATCHER
	}
	tr.Role = role
	if local != nil {
		tr.LocalState = local.LocalState
		tr.SelfResult = &pb.ResultRef{Kind: pb.ResultRefKind_RESULT_REF_INLINE, Size: int64(len(local.Final))}
		tr.Error = local.Error
	}
	if rec != nil {
		tr.Status = rec.Status
		tr.StatusSource = "TASK_ENGINE"
	} else if local != nil {
		// 无 CommandRecord 但有 local_state → 由 LocalState 映射合成，不回 NOT_FOUND
		tr.Status = mapToLocalOnlyStatus(local.LocalState)
		tr.StatusSource = "LOCAL_STATE_ONLY"
	}
	summary := &pb.TraceSummary{}
	if n.hub != nil && (req.Depth < 0 || req.Depth-hop > 0) {
		childReq := req
		if req.Depth != -1 {
			childReq.Depth = req.Depth - 1
		}
		childReq.Timeout = budgetFor(deadline)
		for _, a := range assigns {
			if ctx.Err() != nil {
				break
			}
			ch := &pb.ChildTrace{NodeId: a.ChildId, Status: a.Status}
			if cr, ok := n.childReport(req.CommandID, a.ChildId); ok {
				ch.LocalState = cr.LocalState
				ch.Error = cr.Error
				if req.Detail {
					ch.Digest, ch.Sig = cr.Digest, cr.ChildSig
				}
			}
			if resp, err := n.hub.healthReq(ctx, a.ChildId, &pb.HealthReq{
				ReqId:     fmt.Sprintf("%s-%d", shortID(n.C().Node.ID), time.Now().UnixNano()),
				CommandId: req.CommandID, Depth: int32(childReq.Depth), Detail: req.Detail,
				TimeoutMs: childReq.Timeout.Milliseconds(),
				ReqAuth:   childReq.Auth,
			}); err == nil && resp != nil {
				if _, verr := n.verifyHealthResp(a.ChildId, resp); verr == nil && resp.Command != nil {
					// 子节点视角的 LocalState 回填；AssignStatus 仍以父端 assignments 为准
					ch.LocalState = resp.Command.LocalState
					ch.Summary = resp.Command.Summary
				} else if verr != nil {
					ch.Err = verr.Error()
				}
			} else if err != nil {
				ch.Err = "UNREACHABLE"
			}
			tr.Children = append(tr.Children, ch)
			summary.Total++
			// 子树轨迹汇总：本子 + 它上报的子树统计（detail=false 时也在）
			if cs := ch.Summary; cs != nil {
				summary.Total += cs.Total
				summary.Done += cs.Done
				summary.Failed += cs.Failed
				summary.Timeout += cs.Timeout
				summary.Cancelled += cs.Cancelled
				summary.Pending += cs.Pending
				summary.Leased += cs.Leased
				summary.NotFound += cs.NotFound
				summary.Anomalies = append(summary.Anomalies, cs.Anomalies...)
			}
			switch ch.Status {
			case pb.AssignStatus_ASSIGN_STATUS_DONE:
				summary.Done++
			case pb.AssignStatus_ASSIGN_STATUS_FAILED:
				summary.Failed++
				summary.Anomalies = append(summary.Anomalies, a.ChildId)
			case pb.AssignStatus_ASSIGN_STATUS_TIMEOUT:
				summary.Timeout++
				summary.Anomalies = append(summary.Anomalies, a.ChildId)
			case pb.AssignStatus_ASSIGN_STATUS_CANCELLED:
				summary.Cancelled++
			case pb.AssignStatus_ASSIGN_STATUS_PENDING:
				summary.Pending++
				summary.Anomalies = append(summary.Anomalies, a.ChildId)
			case pb.AssignStatus_ASSIGN_STATUS_LEASED:
				summary.Leased++
			}
		}
	}
	tr.Summary = summary
	return tr
}

// childReport 从本地存储读取某子节点对某指令的上报记录。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	cmdID   — 指令 ID
//	childID — 子节点 NodeID
//
// 返回：
//
//	*pb.ChildReportRecord — 上报记录
//	bool                 — 是否存在
func (n *Node) childReport(cmdID, childID string) (*pb.ChildReportRecord, bool) {
	var (
		r  *pb.ChildReportRecord
		ok bool
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		r, ok = tx.GetChildReport(cmdID, childID)
		return nil
	})
	return r, ok
}

// mapToLocalOnlyStatus 把仅有 local_state、没有 CommandRecord 的情况映射成指令状态。
//
// 参数：
//
//	s — 本地执行状态
//
// 返回：
//
//	pb.CommandStatus — 对应状态；无匹配时返回 RUNNING
func mapToLocalOnlyStatus(s pb.LocalExecState) pb.CommandStatus {
	switch s {
	case pb.LocalExecState_LOCAL_STATE_SELF_FAILED:
		return pb.CommandStatus_COMMAND_STATUS_FAILED
	case pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
		return pb.CommandStatus_COMMAND_STATUS_CANCELLED
	case pb.LocalExecState_LOCAL_STATE_SELF_DONE, pb.LocalExecState_LOCAL_STATE_COMPLETED:
		return pb.CommandStatus_COMMAND_STATUS_COMPLETED
	}
	return pb.CommandStatus_COMMAND_STATUS_RUNNING
}

// ---------- 工具 ----------

// inflightCount 返回当前正在执行的指令数。
//
// 接收者 n 是本节点。
func (n *Node) inflightCount() int {
	n.inflight.mu.Lock()
	defer n.inflight.mu.Unlock()
	return len(n.inflight.m)
}

// pendingCount 统计本地存储中处于 pending 的记录数。
//
// 接收者 n 是本节点。
func (n *Node) pendingCount() int {
	c := 0
	_ = n.Store.View(func(tx *store.Tx) error {
		c = len(tx.ScanPending(0))
		return nil
	})
	return c
}

// childOnline 返回当前在线子连接数（无 Hub 时为 0）。
//
// 接收者 n 是本节点。
func (n *Node) childOnline() int {
	if n.hub == nil {
		return 0
	}
	return n.hub.ConnCount()
}

// statusOf 把一条子节点响应折算成健康状态。
//
// 参数：
//
//	resp — 子节点的（健康度或轨迹模式）响应
//
// 返回：
//
//	pb.HealthStatus — 对应健康状态；无法判定时为 DEGRADED
func statusOf(resp *pb.HealthResponse) pb.HealthStatus {
	if resp.Mode == pb.HealthMode_HEALTH_MODE_HEALTH && resp.Health != nil {
		return resp.Health.Status
	}
	if resp.Mode == pb.HealthMode_HEALTH_MODE_COMMAND_TRACE && resp.Command != nil {
		switch resp.Command.Status {
		case pb.CommandStatus_COMMAND_STATUS_COMPLETED:
			return pb.HealthStatus_HEALTHY
		case pb.CommandStatus_COMMAND_STATUS_UNSPECIFIED:
			return pb.HealthStatus_UNREACHABLE
		default:
			return pb.HealthStatus_DEGRADED
		}
	}
	return pb.HealthStatus_DEGRADED
}

// childSummary 取子节点回传的子树汇总（detail=false 时也在）。
//
// 参数：
//
//	ch — 子节点健康结果
//
// 返回：
//
//	*pb.SubtreeSummary — 汇总；取不到时返回空汇总
func childSummary(ch *pb.ChildHealth) *pb.SubtreeSummary {
	if ch.Summary != nil {
		return ch.Summary
	}
	return subSummaryOf(ch.Report)
}

// budgetFor 计算下发给子节点的"剩余预算"：本跳剩余时间减去执行与回传余量。
//
// 参数：
//
//	deadline — 本跳截止时刻
//
// 返回：
//
//	time.Duration — 剩余预算；下限 100ms
func budgetFor(deadline time.Time) time.Duration {
	b := time.Until(deadline) - 150*time.Millisecond
	if b < 100*time.Millisecond {
		b = 100 * time.Millisecond
	}
	return b
}

// subSummaryOf 从健康报告里取子树汇总（报告或汇总为空时返回空汇总）。
func subSummaryOf(r *pb.HealthReport) *pb.SubtreeSummary {
	if r == nil || r.Summary == nil {
		return &pb.SubtreeSummary{}
	}
	return r.Summary
}

// boolToInt 把 bool 转成 int32（true→1，false→0）。
func boolToInt(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

// worst 取一组检查结果里最差的状态（UNHEALTHY > DEGRADED / UNREACHABLE > HEALTHY）。
//
// 参数：
//
//	checks — 各检查项结果
//
// 返回：
//
//	pb.HealthStatus — 汇总后的最差状态
func worst(checks []*pb.CheckResult) pb.HealthStatus {
	out := pb.HealthStatus_HEALTHY
	for _, c := range checks {
		switch c.Status {
		case pb.HealthStatus_UNHEALTHY:
			return pb.HealthStatus_UNHEALTHY
		case pb.HealthStatus_DEGRADED:
			out = pb.HealthStatus_DEGRADED
		case pb.HealthStatus_UNREACHABLE:
			out = pb.HealthStatus_DEGRADED
		}
	}
	return out
}

// memMB 返回进程已向系统申请的内存（MiB）。
func memMB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return float64(m.Sys) / (1024 * 1024)
}

// maxInt32 返回 a、b 中较大的那个。
func maxInt32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}

var _ = os.Getpid
