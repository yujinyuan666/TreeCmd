package node

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"treecmd/internal/canon"
	"treecmd/internal/config"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/persist"
)

// Upstream 上行侧（客户端角色）：注册 / 续接 / 拉取工作队列 / 心跳 / 续租 / 上报。
type Upstream struct {
	n *Node

	mu        sync.Mutex
	parentIdx int
	conn      *grpc.ClientConn
	client    pb.NodeServiceClient
	stream    pb.NodeService_ConnectClient
	sendCh    chan *pb.UpFrame
	done      chan struct{}
	connected bool
	sessionID string
	epoch     uint64
	lastSeq   int64
	offsetMS  int64 // EWMA 时钟偏移：remote ≈ local + offset
	parentID  string
	parentPub ed25519.PublicKey
	reqSeqs   map[string]chan *pb.HealthResponse
	queryResp map[string]chan *pb.QueryResp
	queryData map[string]*queryDataBuf

	stopOnce sync.Once
}

// queryDataBuf 收集一次查询数据的多个分片，收齐后由 notify 通知等待方。
type queryDataBuf struct {
	total  int32
	parts  map[int32][]byte
	final  bool
	resp   *pb.QueryResp
	notify chan struct{}
}

// newUpstream 创建上行侧对象，并用持久化状态（若存在）恢复会话 / 水位 / 时钟偏移。
//
// 参数：
//
//	n — 所属节点
//
// 返回：
//
//	*Upstream — 上行侧（客户端角色），初始为未连接状态
func newUpstream(n *Node) *Upstream {
	u := &Upstream{
		n: n, sendCh: make(chan *pb.UpFrame, 256), done: make(chan struct{}),
		reqSeqs: map[string]chan *pb.HealthResponse{}, queryResp: map[string]chan *pb.QueryResp{},
		queryData: map[string]*queryDataBuf{},
	}
	if st := n.state; st != nil {
		u.sessionID = st.Session.SessionID
		u.epoch = st.Session.Epoch
		u.lastSeq = st.Watermarks.LastCmdSeq
		u.offsetMS = st.ClockOffsetMS
		u.parentIdx = indexOfParent(n.C().Parents, st.Session.ParentID)
	}
	return u
}

// indexOfParent 找出指定父节点 ID 在列表中的下标，找不到返回 0。
func indexOfParent(ps []config.Parent, id string) int {
	for i, p := range ps {
		if p.ID == id {
			return i
		}
	}
	return 0
}

// start 在后台 goroutine 里启动自愈循环 supervise。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) start() {
	u.n.wg.Add(1)
	go func() {
		defer u.n.wg.Done()
		u.supervise()
	}()
}

// stop 关闭上行侧：关闭 done 通道并断开当前连接（只生效一次）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) stop() {
	u.stopOnce.Do(func() {
		close(u.done)
		u.mu.Lock()
		if u.conn != nil {
			_ = u.conn.Close()
		}
		u.mu.Unlock()
	})
}

// supervise 连接 → 注册 → 读写 → 断线重连（退避 1s→30s + jitter）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 每轮建连前先 ensureCert：没有证书时先完成运行期入网（拿到证书才能做 mTLS 握手）。
// 入网成功即 finishEnroll（把因为没证书而推迟的下行监听补起来），然后正常建连注册。
func (u *Upstream) supervise() {
	backoff := time.Second
	for {
		select {
		case <-u.done:
			return
		default:
		}
		parent := u.n.C().Parents[u.currentParent()]
		if !u.n.hasUsableCert() {
			// 入网是"慢路径"，用较长的超时与退避，且失败不打断整体循环
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := u.n.ensureCertWithLock(ctx, false)
			cancel()
			if err != nil {
				u.n.Log.Warn("enrollment pending", "parent", parent.ID, "err", err)
				u.markDisconnected()
				select {
				case <-u.done:
					return
				case <-time.After(jittered(backoff, backoff/2)):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			u.n.finishEnroll("upstream supervise")
		}
		err := u.runSession(parent)
		if err != nil && !errors.Is(err, context.Canceled) {
			u.n.Log.Warn("upstream session ended", "parent", parent.ID, "err", err)
		}
		u.markDisconnected()
		select {
		case <-u.done:
			return
		case <-time.After(jittered(backoff, backoff/2)):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// currentParent 返回当前父节点下标（越界时归零）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) currentParent() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.parentIdx >= len(u.n.C().Parents) {
		u.parentIdx = 0
	}
	return u.parentIdx
}

// markDisconnected 标记为未连接：清空 stream 并关闭当前连接。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) markDisconnected() {
	u.mu.Lock()
	u.connected = false
	u.stream = nil
	if u.conn != nil {
		_ = u.conn.Close()
		u.conn = nil
	}
	u.mu.Unlock()
}

// runSession 建立一条会话：dial → Connect → Register/Resume → 启动心跳与拉取循环。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	p — 要连接的父节点配置（地址等）
//
// 返回：
//
//	error — 建连 / 注册 / 读循环失败时返回（流正常 EOF 返回 nil）
func (u *Upstream) runSession(p config.Parent) error {
	creds := credentials.NewTLS(identity.ClientTLSConfig(u.n.certBox, u.n.rootsFn(), p.ID))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn, err := grpc.NewClient(p.Addr, grpc.WithTransportCredentials(creds),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(8<<20), grpc.MaxCallSendMsgSize(8<<20)))
	if err != nil {
		return err
	}
	u.mu.Lock()
	u.conn = conn
	u.client = pb.NewNodeServiceClient(conn)
	u.mu.Unlock()
	ctx = metadata.AppendToOutgoingContext(ctx, "proto-version", protoVersion)
	stream, err := u.client.Connect(ctx)
	if err != nil {
		return err
	}
	// 记录父身份（用于校验 HopAttest 的 ForwarderID 与签名）
	if pr, ok := peer.FromContext(stream.Context()); ok && pr.AuthInfo != nil {
		if ti, ok := pr.AuthInfo.(credentials.TLSInfo); ok && len(ti.State.PeerCertificates) > 0 {
			leaf := ti.State.PeerCertificates[0]
			u.mu.Lock()
			u.parentID = identity.NodeIDFromCert(leaf)
			if pub, ok := leaf.PublicKey.(ed25519.PublicKey); ok {
				u.parentPub = pub
			}
			u.mu.Unlock()
		}
	}
	u.mu.Lock()
	u.stream = stream
	u.epoch++
	u.sessionID = fmt.Sprintf("%s-%d", u.n.C().Node.ID[:8], time.Now().UnixNano())
	u.mu.Unlock()

	// 首帧：Register（状态缺失 / hash 不匹配 / 已过期时全量注册）
	reg := u.buildRegister()
	if err := stream.Send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_Register{Register: reg}}); err != nil {
		return err
	}
	ackFrame, err := stream.Recv()
	if err != nil {
		return err
	}
	ack := ackFrame.GetRegisterAck()
	if ack == nil || !ack.Ok {
		return fmt.Errorf("register rejected: %v", ack.GetReason())
	}
	// 环检测（子侧校验）：自身 NodeID 不得出现在父的祖先链中
	for _, a := range ack.AncestorIds {
		if a == u.n.C().Node.ID {
			return fmt.Errorf("ERR_CYCLE: ancestor chain contains self")
		}
	}
	u.n.Reg.SetSelfPath(ack.Path)
	u.n.selfPath.Store(ack.Path)
	u.n.ancestors.Store(ack.Ancestors)
	u.n.ancestorIDs.Store(ack.AncestorIds)
	u.mu.Lock()
	u.connected = true
	if u.lastSeq < ack.StartCmdSeq && u.lastSeq == 0 {
		u.lastSeq = ack.StartCmdSeq // 注册水位（新节点不回放历史）
	}
	u.mu.Unlock()
	u.n.Log.Info("registered", "path", ack.Path, "start_seq", ack.StartCmdSeq, "epoch", u.epoch, "reason", ack.Reason)

	// 本会话**唯一的读协程**：读帧 → 送通道。正常阶段与"自同步阶段"共用它，
	// 于是两个阶段都能带超时，而且读到一半放弃时帧不会丢在别处（谁在跑谁消费）。
	frames := make(chan recvResult, 1)
	go readFrames(ctx, stream, frames)

	// 写协程（必须在下面那段"自同步"之前起来：子要先把 BinaryReq 发出去）
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case f := <-u.sendCh:
				if err := stream.Send(f); err != nil {
					cancel()
					return
				}
			}
		}
	}()

	// 连上后的**第一件事**：比对自己的可执行文件哈希与父的。不一致就拉取、校验、原地重启。
	// 成功路径不会返回（进程镜像已被新镜像替换），所以下面这些只在"一致 / 跳过 / 失败兜底"时执行。
	u.n.checkParentBuild(u, frames, ack)

	// 重连后：取 CRL 全量 + 上报本地未终态指令对账 + 检查是否需要续签
	u.sendCRLReq()
	u.n.sendReconcile()
	u.n.checkSelfCertRenew()

	// 心跳 + 续租
	go u.heartbeatLoop(ctx, stream)
	// 拉取循环
	go u.fetchLoop(ctx)
	// 读循环（阻塞直到连接断开）
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-frames:
			if r.err != nil {
				if errors.Is(r.err, io.EOF) {
					return nil
				}
				return r.err
			}
			if err := u.dispatch(r.f); err != nil {
				u.n.Log.Warn("down frame error", "err", err)
			}
		}
	}
}

// recvResult 一条下行帧的读取结果：err 非空表示流结束 / 出错（此时 f 无意义）。
type recvResult struct {
	f   *pb.DownFrame
	err error
}

// readFrames 是本次会话唯一的读协程：把 stream 上的下行帧按序送进 ch，直到出错或会话结束。
//
// 为什么要有它（而不是在需要的地方直接 stream.Recv）：同一个 Connect 流既要被"自同步阶段"
// 消费（收可执行文件分片），又要被"正常阶段"消费（心跳回应 / 终态 / 配置下发…），
// 而且前者必须能带超时。把"读"收口到一个协程 + 一个通道，两个阶段就只是不同的消费者，
// 不会出现"两个协程同时 Recv"或者"放弃读之后帧被谁吞掉"这类问题。
//
// 参数：
//
//	ctx    — 会话上下文；取消后本协程立即退出（退出前尝试把手上这帧交出去，交不掉就丢）
//	stream — 本会话的 Connect 双向流（只读一侧）
//	ch     — 输出通道；容量 1 即可（消费方总是紧跟其后，缓冲太大只会掩盖卡顿）
func readFrames(ctx context.Context, stream pb.NodeService_ConnectClient, ch chan<- recvResult) {
	for {
		f, err := stream.Recv()
		select {
		case ch <- recvResult{f: f, err: err}:
		case <-ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

// buildRegister 组装注册请求：nonce / 公钥 / 监听地址 / 元信息，并对载荷签名。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 返回：
//
//	*pb.RegisterRequest — 首帧要发送的注册请求
func (u *Upstream) buildRegister() *pb.RegisterRequest {
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = byte(randInt63n(256))
	}
	payload := canon.NewWriter().Str(u.n.C().Node.ID).Bytes(u.n.Id().Key.Public().(ed25519.PublicKey)).Bytes(nonce).U64(u.epoch).Out()
	return &pb.RegisterRequest{
		NodeId: u.n.C().Node.ID, Pubkey: u.n.Id().Key.Public().(ed25519.PublicKey),
		Nonce: nonce, Epoch: u.epoch, Sig: identity.Sign(u.n.Id().Key, payload),
		ListenAddr: u.n.C().Node.Listen,
		// 元信息（ADR-051）：随每次注册/重注册上行，父端据此展示"我是谁"
		NodeName: u.n.C().Node.Name, NodeRemark: u.n.C().Node.Remark,
		ProtoVersion: protoVersion,
		// 本节点跑的是哪份镜像：父端只用它展示（/v1/tree），判定方向是反过来的
		// ——"子跟父的比"，所以这里上行的是"我自己的哈希"，不是"我希望的哈希"。
		BinaryHash: u.n.Build().Hash, BinarySize: u.n.Build().Size,
		// 自己的 CA 证书还剩几天：父手上只有子的身份证书，看不到它的 CA 证书，
		// 而 CA 证书过期会让本节点下次启动直接起不来 —— 所以由自己上报，父在 /v1/tree 里展示。
		CaNotAfterDays: caNotAfterDays(u.n.Id()),
	}
}

// ---------- 下行帧分发 ----------

// dispatch 按帧类型把父节点下发的一条帧分发到对应处理器。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	f — 下行帧，按 Frame 的 oneof 类型分发
//
// 返回：
//
//	error — 对应处理器返回的错误（未知帧返回 nil）
func (u *Upstream) dispatch(f *pb.DownFrame) error {
	switch body := f.Frame.(type) {
	case *pb.DownFrame_CommandNotify:
		u.n.signalFetch()
		return nil
	case *pb.DownFrame_CommandCanceled:
		u.n.applyTerminal(body.CommandCanceled.CommandId, pb.CommandStatus_COMMAND_STATUS_CANCELLED)
		return nil
	case *pb.DownFrame_Terminal:
		u.n.applyTerminal(body.Terminal.CommandId, body.Terminal.Status)
		return nil
	case *pb.DownFrame_HeartbeatAck:
		u.handleHeartbeatAck(body.HeartbeatAck)
		return nil
	case *pb.DownFrame_RevocationList:
		pid, ppub := u.parentIdentity()
		if err := u.n.applyCRL(pid, ppub, body.RevocationList); err != nil {
			u.n.Log.Warn("apply CRL failed", "err", err)
		}
		return nil
	case *pb.DownFrame_CertRenewOffer:
		if err := u.n.applyCertRenew(body.CertRenewOffer); err != nil {
			u.n.Log.Warn("apply cert renew failed", "err", err)
		}
		return nil
	case *pb.DownFrame_ConfigPush:
		u.n.applyConfigOverrides(body.ConfigPush.Reason, body.ConfigPush.Overrides)
		return nil
	case *pb.DownFrame_BinaryChunk:
		// 分片由"自同步阶段"自己消费（见 build.go 的 pullBinary）；跑到这里说明
		// 那次同步已经放弃，而父还在把剩下的片推完。丢掉即可 —— 父推完自己会停。
		if body.BinaryChunk.GetFinal() {
			u.n.Log.Debug("忽略迟到的可执行文件分片（本次同步已结束）",
				"hash", shortHash(body.BinaryChunk.GetHash()), "reason", body.BinaryChunk.GetReason())
		}
		return nil
	case *pb.DownFrame_HealthReq:
		go u.n.serveHealthReqFromParent(body.HealthReq)
		return nil
	case *pb.DownFrame_QueryReq:
		return u.n.handleQueryFromParent(body.QueryReq)
	case *pb.DownFrame_QueryResp:
		return u.n.forwardQueryResp(body.QueryResp)
	case *pb.DownFrame_QueryData:
		return u.n.forwardQueryData(body.QueryData)
	}
	return nil
}

// handleHeartbeatAck 处理心跳回应：用四时间戳估计时钟偏移，并应用带回的终态通知。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	ack — HeartbeatAck，含回显的发送时刻、父端接收 / 发送时刻与终态列表
func (u *Upstream) handleHeartbeatAck(ack *pb.HeartbeatAck) {
	// 当轮即算：t1 本端发、t2/t3 在 Ack 里、t4 本端收到时刻
	t4 := time.Now().UnixMilli()
	t1 := ack.EchoSendTsLocal
	t2, t3 := ack.RecvTs, ack.SendTs
	if t1 != 0 && t2 != 0 && t3 != 0 {
		offset := ((t2 - t1) + (t3 - t4)) / 2
		u.mu.Lock()
		u.offsetMS = (offset + 9*u.offsetMS) / 10 // EWMA α≈0.1
		u.mu.Unlock()
	}
	for _, t := range ack.Terminal {
		u.n.applyTerminal(t.CommandId, t.Status)
	}
}

// ---------- 心跳 ----------

// renewAtStep 周期循环的"小步长"。
//
// 心跳与拉取都按 `command.renew_at` 节拍跑，但**不能用 time.NewTicker**：Ticker 的周期在
// 创建那一刻就固定住了，而 renew_at 是**可热更的运行参数**（`command.` 段，文档承诺 SIGHUP 即生效）。
// 用 Ticker 的话，热更之后要等**旧周期**走完才生效 —— 实测就是这样：把 renew_at 从 30s 热更到 2s，
// 子节点仍然按 30s 的旧节奏拉取（验收脚本为此白等了一分钟）。
//
// 所以改成"按小步长醒来看一眼，到点了才干活"。步长决定判定误差上限（≤ 1s），
// 而每秒醒一次对一条网络循环的开销可以忽略；默认 30s 周期下的行为与 Ticker 完全一致。
const renewAtStep = time.Second

// renewAt 取当前生效的续租 / 拉取周期。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。**每次都现读配置**，所以 SIGHUP 改了
// `command.renew_at` 之后，下一小步就会按新周期走，不必等旧周期走完、也不必重连。
//
// 返回：
//
//	time.Duration — command.renew_at 的值；配成非正数时退回 30s 默认值
func (u *Upstream) renewAt() time.Duration {
	d := u.n.C().Command.RenewAt
	if d <= 0 {
		return 30 * time.Second
	}
	return d
}

// heartbeatLoop 按 RenewAt 周期发送心跳，并把在跑指令作为续租项带上。
//
// 周期判定走 renewAtStep + renewAt()（而不是 Ticker），这样 renew_at 热更立刻生效。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	ctx    — 会话上下文，取消后退出循环
//	stream — 当前 Connect 流
func (u *Upstream) heartbeatLoop(ctx context.Context, stream pb.NodeService_ConnectClient) {
	send := func() {
		u.n.inflight.mu.Lock()
		ids := make([]string, 0, len(u.n.inflight.m))
		for id := range u.n.inflight.m {
			ids = append(ids, id)
		}
		u.n.inflight.mu.Unlock()
		renews := make([]*pb.LeaseRenew, 0, len(ids))
		for _, id := range ids {
			renews = append(renews, &pb.LeaseRenew{CommandId: id, Attempt: u.n.inflight.Attempt(id)})
		}
		_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_Heartbeat{
			Heartbeat: &pb.Heartbeat{SendTsLocal: time.Now().UnixMilli(), Inflight: int32(len(ids)), Renew: renews},
		}})
	}
	send()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(renewAtStep):
			if time.Since(last) < u.renewAt() {
				continue
			}
			last = time.Now()
			send()
		}
	}
}

// ---------- 拉取工作队列 ----------

// fetchLoop 按 RenewAt 周期或收到拉取信号时拉取指令队列。
//
// 周期判定走 renewAtStep + renewAt()（而不是 Ticker），这样 renew_at 热更立刻生效 ——
// 这一点对下发背压尤其要紧：父只在**提交那一刻**通知一次，之后剩下的分派全靠子下一次轮询
// 才拿得到，所以"轮次间隔"就等于 renew_at。用 Ticker 的话，热更被窗口限速时白等一整个旧周期。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	ctx — 会话上下文，取消后退出循环
func (u *Upstream) fetchLoop(ctx context.Context) {
	// 链路建立后立即触发一次有界重发（3.11 触发点 3）
	go u.n.resendPending(ctx)
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-u.n.fetchNotify:
		case <-time.After(renewAtStep):
			if time.Since(last) < u.renewAt() {
				continue
			}
		}
		last = time.Now()
		u.fetchOnce(ctx)
	}
}

// fetchOnce 执行一次 FetchCommands：带上本地水位，取回后更新水位并启动执行。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	ctx — 会话上下文
func (u *Upstream) fetchOnce(ctx context.Context) {
	u.mu.Lock()
	cl := u.client
	last := u.lastSeq
	u.mu.Unlock()
	if cl == nil {
		return
	}
	req := &pb.FetchRequest{NodeId: u.n.C().Node.ID, SinceSeq: last, MaxFetch: 128, MaxBytes: 1 << 20}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cctx = metadata.AppendToOutgoingContext(cctx, "proto-version", protoVersion)
	resp, err := cl.FetchCommands(cctx, req)
	if err != nil {
		return
	}
	u.mu.Lock()
	if resp.NewSeq > u.lastSeq {
		u.lastSeq = resp.NewSeq
	}
	u.mu.Unlock()
	for _, d := range resp.Deliveries {
		go u.n.handle(ctx, d.Command, d.Attempt)
	}
}

// ---------- 上报 ----------

// report 内联上报（≤256KB）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	rep — 执行报告
//	_   — 预留的附加数据，当前实现未使用
//
// 返回：
//
//	bool — true 表示父已持久化接受
func (u *Upstream) report(rep *pb.Report, _ []byte) bool {
	u.mu.Lock()
	cl := u.client
	u.mu.Unlock()
	if cl == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "proto-version", protoVersion)
	resp, err := cl.ReportResult(ctx, rep)
	if err != nil {
		u.n.Log.Warn("report failed", "cmd", shortID(rep.CommandId), "err", err)
		return false
	}
	if !resp.Ok {
		u.n.Log.Warn("report rejected", "cmd", shortID(rep.CommandId), "reason", resp.Reason)
	}
	return resp.Ok
}

// streamResult 分片上报（>256KB，双向流 + 末片 final_state）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	rep — 执行报告，其 Aggregated 字段是要分片发送的大结果
//
// 返回：
//
//	bool — true 表示父端已收齐并接受
func (u *Upstream) streamResult(rep *pb.Report) bool {
	u.mu.Lock()
	cl := u.client
	u.mu.Unlock()
	if cl == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "proto-version", protoVersion)
	stream, err := cl.StreamResult(ctx)
	if err != nil {
		return false
	}
	chunkSize := int(u.n.C().Command.ChunkSize)
	total := int32((len(rep.Aggregated) + chunkSize - 1) / chunkSize)
	if total == 0 {
		total = 1
	}
	if total > u.n.C().Command.MaxChunkTotal {
		return false
	}
	if err := stream.Send(&pb.StreamFrame{Frame: &pb.StreamFrame_Begin{Begin: &pb.StreamBegin{
		CommandId: rep.CommandId, NodeId: u.n.C().Node.ID, Attempt: rep.Attempt, Total: total,
		Children: rep.Children, Error: rep.Error,
	}}}); err != nil {
		return false
	}
	ack, err := stream.Recv()
	if err != nil || !ack.Ok {
		return false
	}
	for i := int32(0); i < total; i++ {
		lo := int(i) * chunkSize
		hi := lo + chunkSize
		if hi > len(rep.Aggregated) {
			hi = len(rep.Aggregated)
		}
		c := &pb.ResultChunk{
			CommandId: rep.CommandId, NodeId: u.n.C().Node.ID, Attempt: rep.Attempt,
			Index: i, Total: total, Payload: rep.Aggregated[lo:hi], Crc32: crc32Of(rep.Aggregated[lo:hi]),
		}
		if i == total-1 {
			st := rep.LocalState
			c.FinalState = &st
			c.Error = rep.Error
		}
		c.Sig = identity.Sign(u.n.Id().Key, chunkSigPayload(c))
		if err := stream.Send(&pb.StreamFrame{Frame: &pb.StreamFrame_Chunk{Chunk: c}}); err != nil {
			return false
		}
	}
	for {
		ack, err := stream.Recv()
		if err != nil {
			return false
		}
		if ack.Final {
			return ack.Ok
		}
		if len(ack.Missing) == 0 && !ack.Ok {
			return false
		}
	}
}

// ---------- 上行帧发送 ----------

// send 把一帧上行数据放进发送缓冲（非阻塞，缓冲满或已停止则报错）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	f — 待发送的上行帧
//
// 返回：
//
//	error — 已停止或发送缓冲已满时返回
func (u *Upstream) send(f *pb.UpFrame) error {
	select {
	case u.sendCh <- f:
		return nil
	case <-u.done:
		return errors.New("upstream stopped")
	default:
		return errors.New("send buffer full")
	}
}

// sendLocalBusy 上行"本机繁忙"（请求父端把该指令退回队列）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	cmdID — 指令 ID
func (u *Upstream) sendLocalBusy(cmdID string) {
	_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_LocalBusy{
		LocalBusy: &pb.LocalBusy{CommandId: cmdID},
	}})
}

// sendInflightHint 上行"该指令我还在跑"（attempt 为 0 时按 1 处理）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	cmdID   — 指令 ID
//	attempt — 正在执行的 attempt
func (u *Upstream) sendInflightHint(cmdID string, attempt uint64) {
	if attempt == 0 {
		attempt = 1
	}
	_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_InflightHint{
		InflightHint: &pb.InflightHint{CommandId: cmdID, Attempt: attempt},
	}})
}

// forceReconnect 断开当前连接（supervise 会按退避重连，用于配置热更 / 证书换发后重新握手）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	reason — 断连原因，仅用于日志
func (u *Upstream) forceReconnect(reason string) {
	u.mu.Lock()
	if u.conn != nil {
		_ = u.conn.Close()
		u.conn = nil
	}
	u.mu.Unlock()
	u.n.Log.Info("force reconnect", "reason", reason)
}

// sendCertRenewReq 上行证书续签请求（身份证书，按需顺带 CA 证书）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	req — 续签请求；由 requestCertRenew 组装（含 want_ca 与当前 CA 证书）
func (u *Upstream) sendCertRenewReq(req *pb.CertRenewReq) {
	if req == nil {
		return
	}
	_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID,
		Frame: &pb.UpFrame_CertRenewReq{CertRenewReq: req}})
}

// sendCRLReq 上行吊销列表全量拉取请求。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) sendCRLReq() {
	_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID,
		Frame: &pb.UpFrame_CrlReq{CrlReq: &pb.CRLReq{}}})
}

// sendReconcile 上行对账帧：把本地未终态的指令原样带给父端。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	cmdID   — 指令 ID
//	command — 该指令的序列化内容
func (u *Upstream) sendReconcile(cmdID string, command []byte) {
	_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID,
		Frame: &pb.UpFrame_Reconcile{Reconcile: &pb.Reconcile{CommandId: cmdID, Command: command}}})
}

// sendResultIndex 上行结果索引（父端会逐跳重签后继续上行）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	idx — 结果索引
func (u *Upstream) sendResultIndex(idx *pb.ResultIndexUp) {
	_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_ResultIndex{
		ResultIndex: idx,
	}})
}

// sendHealthResp 上行健康检查响应（ReqId 由节点 ID 与 path 拼成）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	resp — 本节点的健康检查响应
func (u *Upstream) sendHealthResp(resp *pb.HealthResponse) {
	_ = u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_HealthResp{
		HealthResp: &pb.HealthResp{ReqId: resp.NodeId + ":" + resp.Path, Response: resp},
	}})
}

// sendQueryReq 上行查询请求。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	req — 查询请求
//
// 返回：
//
//	error — 发送失败时返回
func (u *Upstream) sendQueryReq(req *pb.QueryReq) error {
	return u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_QueryReq{QueryReq: req}})
}

// sendQueryResp 上行查询响应。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	resp — 查询响应
//
// 返回：
//
//	error — 发送失败时返回
func (u *Upstream) sendQueryResp(resp *pb.QueryResp) error {
	return u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_QueryResp{QueryResp: resp}})
}

// sendQueryData 上行查询数据。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	d — 查询数据
//
// 返回：
//
//	error — 发送失败时返回
func (u *Upstream) sendQueryData(d *pb.QueryData) error {
	return u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID, Frame: &pb.UpFrame_QueryData{QueryData: d}})
}

// ---------- 快照 ----------

// sessionSnapshot 取当前会话快照（父 ID、会话 ID、epoch），供持久化。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 返回：
//
//	persist.Session — 会话快照（MsgSeq 固定为 0）
func (u *Upstream) sessionSnapshot() persist.Session {
	u.mu.Lock()
	defer u.mu.Unlock()
	pid := ""
	if len(u.n.C().Parents) > 0 {
		pid = u.n.C().Parents[u.parentIdx%len(u.n.C().Parents)].ID
	}
	return persist.Session{ParentID: pid, SessionID: u.sessionID, Epoch: u.epoch, MsgSeq: 0}
}

// lastCmdSeq 返回本地已消费到的指令水位。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) lastCmdSeq() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lastSeq
}

// parentIdentity 返回父节点 ID 与其 Ed25519 公钥（用于校验下行逐跳签名）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) parentIdentity() (string, ed25519.PublicKey) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.parentID, u.parentPub
}

// offsetMSValue 返回估计的时钟偏移（毫秒，remote ≈ local + offset）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) offsetMSValue() int64 {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.offsetMS
}

// isConnected 返回当前会话是否已注册成功。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
func (u *Upstream) isConnected() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.connected
}
