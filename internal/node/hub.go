package node

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/registry"
	"treecmd/internal/store"
)

const protoVersion = "1.0"

// Hub 下行侧（服务端角色）：监听、鉴权、指令表、租约、通知、汇聚。
type Hub struct {
	pb.UnimplementedNodeServiceServer
	n      *Node
	srv    *grpc.Server
	lis    net.Listener
	mu     sync.Mutex
	conns  map[string]*childConn
	closed bool
}

// childConn 是 Hub 侧维护的一条子节点长连接及其发送缓冲、租约续期等状态。
type childConn struct {
	leaf     *x509.Certificate
	nodeID   string
	path     string
	stream   pb.NodeService_ConnectServer
	sendCh   chan *pb.DownFrame
	done     chan struct{}
	once     sync.Once
	epoch    uint64
	pub      ed25519.PublicKey
	mu       sync.Mutex
	healthCh map[string]chan *pb.HealthResponse
	lastSeen time.Time
}

// newHub 创建下行侧 Hub：监听配置里的地址，并装配 mTLS 服务端与拦截器。
//
// 参数：
//
//	n — 所属节点，提供配置、证书与日志；Hub 通过它访问存储与注册表
//
// 返回：
//
//	*Hub  — 已注册 NodeService、但尚未开始 Serve 的连接管理器
//	error — 监听端口失败时返回
func newHub(n *Node) (*Hub, error) {
	lis, err := net.Listen("tcp", n.C().Node.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", n.C().Node.Listen, err)
	}
	h := &Hub{n: n, lis: lis, conns: map[string]*childConn{}}
	creds := credentials.NewTLS(identity.ServerTLSConfig(n.certBox, n.rootsFn(), n.C().Security.EnrollmentEnabled()))
	h.srv = grpc.NewServer(
		grpc.Creds(creds),
		grpc.MaxRecvMsgSize(8<<20),
		grpc.MaxSendMsgSize(8<<20),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 5 * time.Second, PermitWithoutStream: true}),
		grpc.ChainUnaryInterceptor(h.unaryVersionCheck, h.unaryAudit),
	)
	pb.RegisterNodeServiceServer(h.srv, h)
	return h, nil
}

// start 在后台 goroutine 中启动 gRPC 服务，开始接受子节点连接。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 返回：
//
//	error — 恒为 nil；Serve 出错只记录日志
func (h *Hub) start() error {
	h.n.wg.Add(1)
	go func() {
		defer h.n.wg.Done()
		if err := h.srv.Serve(h.lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			h.n.Log.Error("grpc serve stopped", "err", err)
		}
	}()
	return nil
}

// stop 关闭 Hub：先断开所有子连接，再优雅停止 gRPC（2 秒内没停就强停）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
func (h *Hub) stop() {
	h.mu.Lock()
	h.closed = true
	conns := make([]*childConn, 0, len(h.conns))
	for _, cc := range h.conns {
		conns = append(conns, cc)
	}
	h.mu.Unlock()
	// 先断子连接，否则 GracefulStop 会等所有 Connect 流结束而挂住
	for _, cc := range conns {
		cc.close()
	}
	done := make(chan struct{})
	go func() {
		h.srv.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.srv.Stop()
	}
}

// ---------- 鉴权 ----------

// peerCertFromCtx 从 gRPC 上下文里取出对端的第一张 TLS 证书（mTLS 身份的来源）。
//
// 参数：
//
//	ctx — 处理本次 RPC 的上下文，peer 信息由 gRPC 服务端填入
//
// 返回：
//
//	*x509.Certificate — 对端叶子证书
//	error             — 无 peer 信息 / 非 TLS / 无证书时返回
func peerCertFromCtx(ctx context.Context) (*x509.Certificate, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, errors.New("no peer credentials")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("peer credentials are not TLS")
	}
	if len(ti.State.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificate")
	}
	return ti.State.PeerCertificates[0], nil
}

// isEnrollMethod 判定是否入网相关 RPC（唯一允许无客户端证书的方法）。
//
// 参数：
//
//	full — gRPC 完整方法名，形如 "/xxx.NodeService/Enroll"
//
// 返回：
//
//	bool — 方法名以 /Enroll 或 /EnrollChallenge 结尾时为 true
func isEnrollMethod(full string) bool {
	return strings.HasSuffix(full, "/Enroll") || strings.HasSuffix(full, "/EnrollChallenge")
}

// peerIdentity 从对端证书解析出 NodeID 与 Ed25519 公钥。
//
// 参数：
//
//	ctx — RPC 上下文
//
// 返回：
//
//	string            — 由证书推导的 NodeID
//	ed25519.PublicKey — 证书里的公钥
//	error             — 取证书失败或公钥不是 ed25519 时返回
func peerIdentity(ctx context.Context) (string, ed25519.PublicKey, error) {
	c, err := peerCertFromCtx(ctx)
	if err != nil {
		return "", nil, err
	}
	pub, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", nil, errors.New("peer key is not ed25519")
	}
	return identity.NodeIDFromCert(c), pub, nil
}

// unaryVersionCheck 一元 RPC 的版本检查拦截器：按客户端在 gRPC metadata 里带的 `proto-version`
// 做一次 major 校验（与 Connect 流上的帧级协商 `protoVersionOf` 同一口径）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	ctx     — RPC 上下文；metadata 从这里取
//	req     — 请求体（本拦截器不解析它）
//	info    — 方法信息，含 FullMethod
//	handler — 真正的业务处理器
//
// 返回：
//
//	interface{} — 业务处理器的返回值
//	error       — major 不一致时返回 FailedPrecondition（其余一律透传）
func (h *Hub) unaryVersionCheck(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// 覆盖所有一元 RPC（FetchCommands / ReportResult / EnrollChallenge / Enroll）。
	// 客户端会把 proto-version 写进 outgoing metadata（见 upstream.go）；这里：
	//   - 没带 → 放行（兼容不带该元数据的调用方）；
	//   - 带了 → major 必须一致；minor 允许不同（与帧级协商同口径，见 3.2 / ADR-014）。
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vs := md.Get("proto-version"); len(vs) > 0 {
			if v := strings.TrimSpace(vs[0]); v != "" && majorOf(v) != majorOf(protoVersion) {
				return nil, status.Errorf(codes.FailedPrecondition,
					"ERR_UNSUPPORTED_VERSION: client %s server %s (%s)", v, protoVersion, info.FullMethod)
			}
		}
	}
	return handler(ctx, req)
}

// unaryAudit 一元 RPC 的前置校验拦截器：放行入网方法，其余校验身份 / 吊销 / 证书过期。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	ctx     — RPC 上下文
//	req     — 请求体
//	info    — 方法信息，含 FullMethod
//	handler — 真正的业务处理器
//
// 返回：
//
//	interface{} — 业务处理器的返回值
//	error       — 身份缺失 / 证书被吊销 / 已过期时返回
func (h *Hub) unaryAudit(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	// 入网两条 RPC 是**唯一**允许"客户端没有证书"的入口（对方本来就还没有证书），
	// 它们的鉴权在 Enroll 实现里自己做：白名单 + 一次性挑战 + 私钥持有证明 + 入网许可。
	if isEnrollMethod(info.FullMethod) {
		return handler(ctx, req)
	}
	id, _, err := peerIdentity(ctx)
	if err != nil {
		h.n.Log.Warn("reject: peer identity unavailable", "method", info.FullMethod, "err", err)
		return nil, err
	}
	// ② 吊销拦截（每一跳都按自己的 CRL 判定，不信任上游）
	if h.n.isRevoked(id) {
		err := fmt.Errorf("CERT_REVOKED: %s", shortID(id))
		h.n.auditReject("crl_rpc", id, "", err)
		return nil, err
	}
	// ③ 续签宽限窗口：证书已过期的对端只允许走 Connect（续签 / 注册），其余 RPC 一律拒
	if leaf, cErr := peerCertFromCtx(ctx); cErr == nil && identity.PeerExpired(leaf) &&
		!strings.HasSuffix(info.FullMethod, "/Connect") {
		err := fmt.Errorf("CERT_EXPIRED: 证书已过期，只允许续签")
		h.n.auditReject("cert_expired", id, "", err)
		return nil, err
	}
	h.n.touchChild(id)
	return handler(ctx, req)
}

// ---------- 服务实现 ----------

// FetchCommands 处理子节点的拉取请求：校验 NodeID 后按水位组装可下发的指令列表。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	ctx — RPC 上下文；对端身份由其证书确定
//	req — 拉取请求，含 NodeId / SinceSeq / MaxFetch / MaxBytes
//
// 返回：
//
//	*pb.FetchResponse — 一批待执行的 Delivery（可能为空）
//	error             — 身份不可用 / NodeID 不符 / 组装失败时返回
func (h *Hub) FetchCommands(ctx context.Context, req *pb.FetchRequest) (*pb.FetchResponse, error) {
	childID, _, err := peerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if req.NodeId != "" && req.NodeId != childID {
		return nil, fmt.Errorf("ERR_NODE_ID_MISMATCH")
	}
	h.n.touchChild(childID)
	resp, err := h.n.buildFetchResponse(childID, req)
	if err != nil {
		return nil, err
	}
	// 链路刚恢复：顺手触发一次有界重发（3.11 触发点 3）
	if len(resp.Deliveries) > 0 {
		go h.n.resendPending(context.Background())
	}
	return resp, nil
}

// ReportResult 处理子节点的结果上报：验签 → 单事务接受 → 回 ok。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	ctx — RPC 上下文；对端身份由其证书确定
//	rep — 子节点的执行报告，含内联结果与签名
//
// 返回：
//
//	*pb.ReportResponse — Ok=true 表示父端已持久化接受
//	error             — 身份不可用或 NodeID 与证书不符时返回
func (h *Hub) ReportResult(ctx context.Context, rep *pb.Report) (*pb.ReportResponse, error) {
	childID, pub, err := peerIdentity(ctx)
	if err != nil {
		return nil, err
	}
	if rep.NodeId != "" && rep.NodeId != childID {
		return nil, fmt.Errorf("ERR_NODE_ID_MISMATCH: report claims %s, cert %s", rep.NodeId, childID)
	}
	if err := h.n.verifyReportSig(pub, rep); err != nil {
		h.n.Log.Warn("审计：子报告验签失败", "child", shortID(childID), "cmd", shortID(rep.CommandId), "err", err)
		return &pb.ReportResponse{Ok: false, Reason: err.Error()}, nil
	}
	if err := h.n.acceptChildReport(childID, rep); err != nil {
		h.n.Log.Warn("accept child report failed", "child", shortID(childID), "cmd", shortID(rep.CommandId), "err", err)
		return &pb.ReportResponse{Ok: false, Reason: err.Error()}, nil
	}
	return &pb.ReportResponse{Ok: true}, nil
}

// StreamResult 处理大结果的分片上行（双向流，见 3.13 / ADR-048）。
// 首帧 StreamBegin 后父先回收片许可；缺片走中途 UploadAck.missing 补传；收齐后回 final=true。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	stream — 双向流；子节点从它发 StreamBegin / ResultChunk，父端回 UploadAck
//
// 返回：
//
//	error — 帧非法或收齐后交给 acceptChildReportVerified 失败时返回
func (h *Hub) StreamResult(stream pb.NodeService_StreamResultServer) error {
	childID, pub, err := peerIdentity(stream.Context())
	if err != nil {
		return err
	}
	h.n.touchChild(childID)
	var (
		begin      *pb.StreamBegin
		buf        = map[int32][]byte{}
		got        int32
		total      int32
		allowed    bool
		finalChunk *pb.ResultChunk
	)
	ack := func(a *pb.UploadAck) error { return stream.Send(a) }
	for {
		frame, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		switch f := frame.Frame.(type) {
		case *pb.StreamFrame_Begin:
			b := f.Begin
			if b.NodeId != "" && b.NodeId != childID {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "NO_SUCH_ASSIGNMENT"})
				return nil
			}
			if b.Total > h.n.C().Command.MaxChunkTotal {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "TOTAL_TOO_LARGE"})
				return nil
			}
			if _, ok := h.n.assignment(b.CommandId, childID); !ok {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "NO_SUCH_ASSIGNMENT"})
				return nil
			}
			if err := h.n.checkAssignmentActiveAttempt(b.CommandId, childID, b.Attempt); err != nil {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "STALE_ATTEMPT"})
				return nil
			}
			begin, total, buf, got, allowed, finalChunk = b, b.Total, map[int32][]byte{}, 0, true, nil
			if err := ack(&pb.UploadAck{Ok: true, Final: false}); err != nil {
				return err
			}
		case *pb.StreamFrame_Chunk:
			c := f.Chunk
			if !allowed || begin == nil {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "NO_BEGIN"})
				return nil
			}
			if c.Total != total || c.Attempt != begin.Attempt {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "TOTAL_MISMATCH"})
				return nil
			}
			// final_state 的默认值陷阱：只有末片允许设置，非末片一律不设
			if c.Index == total-1 {
				if c.FinalState == nil {
					_ = ack(&pb.UploadAck{Ok: false, Reason: "INVALID_FINAL_STATE"})
					return nil
				}
				finalChunk = c
			} else if c.FinalState != nil {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "INVALID_FINAL_STATE"})
				return nil
			}
			if !identity.Verify(pub, chunkSigPayload(c), c.Sig) {
				_ = ack(&pb.UploadAck{Ok: false, Reason: "SIG_INVALID"})
				return nil
			}
			if _, dup := buf[c.Index]; !dup {
				cp := make([]byte, len(c.Payload))
				copy(cp, c.Payload)
				buf[c.Index] = cp
				got++
			}
			if got == total {
				var missing []int32
				for i := int32(0); i < total; i++ {
					if _, ok := buf[i]; !ok {
						missing = append(missing, i)
					}
				}
				if len(missing) > 0 {
					if err := ack(&pb.UploadAck{Ok: true, Final: false, Missing: missing}); err != nil {
						return err
					}
					continue
				}
				// 收齐：按 index 顺序拼接 → 按末片 final_state 决定终态 → 交父端持久化闭环
				joined := make([]byte, 0)
				for i := int32(0); i < total; i++ {
					joined = append(joined, buf[i]...)
				}
				rep := &pb.Report{
					CommandId: begin.CommandId, NodeId: childID, Attempt: begin.Attempt,
					LocalState: *finalChunk.FinalState, Error: firstNonEmpty(finalChunk.Error, begin.Error),
					Aggregated: joined, Children: begin.Children,
				}
				if err := h.n.acceptChildReportVerified(childID, rep); err != nil {
					_ = ack(&pb.UploadAck{Ok: false, Reason: err.Error()})
					return nil
				}
				return ack(&pb.UploadAck{Ok: true, Final: true})
			}
		}
	}
}

// firstNonEmpty 返回 a、b 中第一个非空字符串（都为空则返回空串）。
//
// 参数：
//
//	a — 优先返回的字符串
//	b — a 为空时的备选字符串
//
// 返回：
//
//	string — a 非空则为 a，否则为 b
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// chunkSigPayload 计算单个结果分片的签名载荷（canonical 编码）。
//
// 参数：
//
//	c — 结果分片；取其 CommandId / NodeId / Attempt / Index / Total / Crc32 / Payload
//
// 返回：
//
//	[]byte — 待签名 / 待验签的规范化字节串
func chunkSigPayload(c *pb.ResultChunk) []byte {
	w := canon.NewWriter()
	w.Str(c.CommandId).Str(c.NodeId).U64(c.Attempt).I64(int64(c.Index)).I64(int64(c.Total)).U64(uint64(c.Crc32)).Bytes(c.Payload)
	return w.Out()
}

// checkAssignmentActiveAttempt 校验某子节点对某指令的当前分派处于可接受的 attempt。
//
// 接收者 n 是本节点，提供指令 / 分派的本地存储。
//
// 参数：
//
//	cmdID   — 指令 ID
//	childID — 子节点 NodeID
//	attempt — 子节点声明的 attempt
//
// 返回：
//
//	error — 分派不存在 / 已终态 / attempt 与已投递值不符时返回
func (n *Node) checkAssignmentActiveAttempt(cmdID, childID string, attempt uint64) error {
	a, ok := n.assignment(cmdID, childID)
	if !ok {
		return ErrNotFound
	}
	if isTerminalAssign(a.Status) {
		return ErrTerminal
	}
	if a.DeliveredAttempt != 0 && attempt != a.DeliveredAttempt {
		return fmt.Errorf("STALE_ATTEMPT")
	}
	return nil
}

// ---------- Connect 双向流 ----------

// Connect 处理子节点的 Connect 双向流：读首帧，再按 Register / Resume 分发。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	stream — gRPC 双向流；第一帧必须是 Register 或 Resume
//
// 返回：
//
//	error — 首帧非法 / 身份不可用，或 serveConn 返回的错误
func (h *Hub) Connect(stream pb.NodeService_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	peerID, pub, err := peerIdentity(stream.Context())
	if err != nil {
		return err
	}
	switch f := first.Frame.(type) {
	case *pb.UpFrame_Register:
		return h.serveConn(stream, peerID, pub, f.Register, false)
	case *pb.UpFrame_Resume:
		return h.serveConn(stream, peerID, pub, &pb.RegisterRequest{NodeId: f.Resume.NodeId, Epoch: f.Resume.Epoch}, true)
	default:
		return fmt.Errorf("first frame must be Register or Resume")
	}
}

// serveConn 处理一条来自子节点的 Connect 双向流：先校验注册，再进入收发循环。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	stream — gRPC 双向流；子节点后续所有上行帧都从它读
//	peerID — 对端（子节点）的 NodeID，已由 mTLS 证书身份确定
//	pub    — 对端的 Ed25519 公钥，用于后续验签
//	reg    — 对端首帧带来的注册信息（Resume 时只填 NodeId / Epoch）
//	resume — 首帧是否为 Resume（断线续接）
//
// 返回：
//
//	error — 校验不通过（环 / 身份不符 / epoch 过旧）或流结束时返回
func (h *Hub) serveConn(stream pb.NodeService_ConnectServer, peerID string, pub ed25519.PublicKey, reg *pb.RegisterRequest, resume bool) error {
	peerLeaf, _ := peerCertFromCtx(stream.Context())
	// ① 吊销拦截：CRL 命中的节点一律拒绝（"有人在试探"的最早信号）
	if h.n.isRevoked(peerID) {
		err := fmt.Errorf("CERT_REVOKED: %s 在本地 CRL 中", shortID(peerID))
		h.n.auditReject("crl_connect", peerID, "", err)
		return err
	}
	// ① 身份一致性（证书身份是唯一来源）
	if reg.NodeId != "" && reg.NodeId != peerID {
		return fmt.Errorf("ERR_NODE_ID_MISMATCH")
	}
	// ② 环检测：注册方的 NodeID 不得出现在本节点的祖先链里（否则它会成为自己的祖先）
	if reg.NodeId == h.n.C().Node.ID {
		return fmt.Errorf("ERR_CYCLE: child claims my own NodeID")
	}
	for _, a := range h.n.AncestorIDs() {
		if a == reg.NodeId {
			return fmt.Errorf("ERR_CYCLE: %s is an ancestor of me", shortID(reg.NodeId))
		}
	}
	// ③ 版本协商
	if v := protoVersionOf(stream); v != "" && majorOf(v) != majorOf(protoVersion) {
		return fmt.Errorf("ERR_UNSUPPORTED_VERSION: client %s server %s", v, protoVersion)
	}

	var (
		ack      *pb.RegisterAck
		fetched  int64
		path     string
		fallback bool
	)
	err := h.n.Store.Update(func(tx *store.Tx) error {
		wm, known := tx.GetWatermark(peerID)
		// 双主仲裁：只接受严格更大的 epoch（若已有活跃连接）
		if cur, ok := h.conn(peerID); ok && reg.Epoch <= cur.epoch {
			return fmt.Errorf("STALE_EPOCH: current %d, incoming %d", cur.epoch, reg.Epoch)
		}
		if !known {
			path = registry.Join(h.n.SelfPath(), peerID)
			fetched = tx.LastAllocatedSeq() // 注册水位 = "最后已分配的 seq"（取 N，不是 N+1）
			wm = &pb.ChildWatermark{ChildId: peerID, FetchedCmdSeq: fetched, LastSeenAt: canon.TS(tx.Now), LastEpoch: reg.Epoch}
		} else {
			path = existingOr(h.n, peerID, registry.Join(h.n.SelfPath(), peerID))
			if resume {
				fallback = false
			}
			wm.LastEpoch = reg.Epoch
			wm.LastSeenAt = canon.TS(tx.Now)
			fetched = wm.FetchedCmdSeq
		}
		if err := tx.PutWatermark(wm); err != nil {
			return err
		}
		ancestors := append([]string{h.n.SelfPath()}, h.n.Ancestors()...)
		ancestorIDs := append([]string{h.n.C().Node.ID}, h.n.AncestorIDs()...)
		ack = &pb.RegisterAck{
			Ok: true, Path: path, Ancestors: ancestors, AncestorIds: ancestorIDs, StartCmdSeq: fetched,
			ServerProtoVersion: protoVersion, Epoch: reg.Epoch,
		}
		return nil
	})
	if err != nil {
		_ = stream.Send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_RegisterAck{
			RegisterAck: &pb.RegisterAck{Ok: false, Reason: err.Error()},
		}})
		return err
	}
	if fallback {
		ack.Reason = "RESUME_FALLBACK"
	}
	if err := stream.Send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_RegisterAck{RegisterAck: ack}}); err != nil {
		return err
	}

	cc := &childConn{
		leaf: peerLeaf, nodeID: peerID, path: path, stream: stream, sendCh: make(chan *pb.DownFrame, 256),
		done: make(chan struct{}), epoch: reg.Epoch, pub: pub, healthCh: map[string]chan *pb.HealthResponse{}, lastSeen: time.Now(),
	}
	h.attach(cc)
	defer h.detach(cc)

	// 注册表：标签摘要（子树摘要）由子上报；name/remark 是 ADR-051 的展示用元信息
	child := &registry.Child{
		NodeID: peerID, Path: path, Labels: labelsFrom(reg), Caps: reg.Capabilities,
		Name: reg.NodeName, Remark: reg.NodeRemark,
		ListenAddr: reg.ListenAddr, Confirmed: true, RegisteredAt: time.Now(), LastEpoch: reg.Epoch,
	}
	h.n.Reg.Upsert(child)
	h.n.Log.Info("child registered", "child", shortID(peerID), "path", path, "epoch", reg.Epoch,
		"start_seq", fetched, "resume", resume, "name", reg.NodeName)

	// 注册后顺带：推 CRL（版本更高才发）+ 检查子证书是否进入续签窗口（父即时换发）
	h.n.pushCRL(peerID)
	h.n.maybeOfferRenew(cc, peerLeaf)

	// 写协程
	go func() {
		for {
			select {
			case <-cc.done:
				return
			case f := <-cc.sendCh:
				if err := stream.Send(f); err != nil {
					cc.close()
					return
				}
			}
		}
	}()

	// 读循环
	for {
		f, err := stream.Recv()
		if err != nil {
			h.n.Log.Info("child disconnected", "child", shortID(peerID))
			return nil
		}
		h.n.touchChild(peerID)
		if err := h.dispatch(cc, f); err != nil {
			h.n.Log.Warn("upstream frame error", "child", shortID(peerID), "err", err)
		}
	}
}

// dispatch 按帧类型把子节点的一条上行帧分发到对应处理器。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc — 发来该帧的子连接
//	f  — 上行帧，按 Frame 的 oneof 类型分发
//
// 返回：
//
//	error — 对应处理器返回的错误（未知帧返回 nil）
func (h *Hub) dispatch(cc *childConn, f *pb.UpFrame) error {
	switch body := f.Frame.(type) {
	case *pb.UpFrame_Heartbeat:
		return h.handleHeartbeat(cc, body.Heartbeat)
	case *pb.UpFrame_HealthResp:
		cc.mu.Lock()
		ch, ok := cc.healthCh[body.HealthResp.ReqId]
		if ok {
			delete(cc.healthCh, body.HealthResp.ReqId)
		}
		cc.mu.Unlock()
		if ok {
			select {
			case ch <- body.HealthResp.Response:
			default:
			}
		}
		return nil
	case *pb.UpFrame_LocalBusy:
		return h.handleLocalBusy(cc, body.LocalBusy)
	case *pb.UpFrame_InflightHint:
		return h.handleInflightHint(cc, body.InflightHint)
	case *pb.UpFrame_CrlReq:
		h.n.pushCRL(cc.nodeID)
		return nil
	case *pb.UpFrame_CertRenewReq:
		h.n.maybeOfferRenew(cc, cc.leaf)
		return nil
	case *pb.UpFrame_Reconcile:
		return h.n.handleReconcile(cc.nodeID, body.Reconcile)
	case *pb.UpFrame_ResultIndex:
		h.n.index.upsert(body.ResultIndex.CommandId, body.ResultIndex.OwnerPath, canon.Time(body.ResultIndex.ExpireAt))
		if h.n.up != nil {
			// 逐跳重签后继续上行（hopSig 单层替换）
			h.n.up.sendResultIndex(body.ResultIndex)
		}
		return nil
	case *pb.UpFrame_QueryReq:
		return h.n.handleQueryFromChild(cc, body.QueryReq)
	case *pb.UpFrame_QueryResp:
		return h.n.forwardQueryResp(body.QueryResp)
	case *pb.UpFrame_QueryData:
		return h.n.forwardQueryData(body.QueryData)
	}
	return nil
}

// handleHeartbeat 处理子节点心跳：对续租项回带终态并延长租约，最后回 HeartbeatAck。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc — 发来心跳的子连接
//	hb — 心跳帧，含本端发送时间戳与要续租的指令列表
//
// 返回：
//
//	error — 发送 HeartbeatAck 失败时返回
func (h *Hub) handleHeartbeat(cc *childConn, hb *pb.Heartbeat) error {
	now := time.Now()
	ack := &pb.HeartbeatAck{EchoSendTsLocal: hb.SendTsLocal, RecvTs: now.UnixMilli(), SendTs: now.UnixMilli()}
	// 必经路径：续租响应必须回带终态（取消 / 超时靠它收敛，见 3.9）
	for _, r := range hb.Renew {
		a, ok := h.n.assignment(r.CommandId, cc.nodeID)
		if !ok {
			continue
		}
		if a.Status == pb.AssignStatus_ASSIGN_STATUS_CANCELLED || a.Status == pb.AssignStatus_ASSIGN_STATUS_TIMEOUT ||
			a.Status == pb.AssignStatus_ASSIGN_STATUS_FAILED {
			status := pb.CommandStatus_COMMAND_STATUS_CANCELLED
			switch a.Status {
			case pb.AssignStatus_ASSIGN_STATUS_TIMEOUT:
				status = pb.CommandStatus_COMMAND_STATUS_TIMEOUT
			case pb.AssignStatus_ASSIGN_STATUS_FAILED:
				status = pb.CommandStatus_COMMAND_STATUS_FAILED
			}
			ack.Terminal = append(ack.Terminal, &pb.TerminalNotice{CommandId: r.CommandId, Status: status})
			continue
		}
		if rec, ok := h.n.records(r.CommandId); ok &&
			(rec.Status == pb.CommandStatus_COMMAND_STATUS_CANCELLED || rec.Status == pb.CommandStatus_COMMAND_STATUS_TIMEOUT) {
			ack.Terminal = append(ack.Terminal, &pb.TerminalNotice{CommandId: r.CommandId, Status: rec.Status})
			continue
		}
		// 续租：延长租约（只在 attempt 匹配时）
		_ = h.n.Store.Update(func(tx *store.Tx) error {
			a2, ok := tx.GetAssignment(r.CommandId, cc.nodeID)
			if !ok || isTerminalAssign(a2.Status) {
				return nil
			}
			if a2.Lease == nil {
				a2.Lease = &pb.Lease{Owner: cc.nodeID, Attempt: a2.DeliveredAttempt}
			}
			a2.Lease.ExpireAt = canon.TS(tx.Now.Add(h.n.C().Command.LeaseTTL))
			a2.UpdatedAt = canon.TS(tx.Now)
			return tx.PutAssignment(a2)
		})
	}
	cc.mu.Lock()
	cc.lastSeen = now
	cc.mu.Unlock()
	return cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_HeartbeatAck{HeartbeatAck: ack}})
}

// handleLocalBusy 处理子节点的"本机繁忙"：把分派退回 PENDING 并设置短退避（不推进 attempt）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc — 发来该帧的子连接
//	lb — LocalBusy 帧，含指令 ID
//
// 返回：
//
//	error — 更新存储失败时返回
func (h *Hub) handleLocalBusy(cc *childConn, lb *pb.LocalBusy) error {
	// LocalBusy 不推进 attempt：释放回 PENDING + 短退避
	return h.n.Store.Update(func(tx *store.Tx) error {
		a, ok := tx.GetAssignment(lb.CommandId, cc.nodeID)
		if !ok || isTerminalAssign(a.Status) {
			return nil
		}
		a.Status = pb.AssignStatus_ASSIGN_STATUS_PENDING
		a.NextAttempt = a.DeliveredAttempt // 不推进
		a.BackoffUntil = canon.TS(tx.Now.Add(h.n.C().Command.LocalBusyBackoff))
		a.UpdatedAt = canon.TS(tx.Now)
		return tx.PutAssignment(a)
	})
}

// handleInflightHint 处理子节点的"我还在跑"提示：把 attempt 回滚到子节点实际在跑的 attempt。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc — 发来该帧的子连接
//	ih — InflightHint 帧，含指令 ID 与 attempt
//
// 返回：
//
//	error — 更新存储失败时返回
func (h *Hub) handleInflightHint(cc *childConn, ih *pb.InflightHint) error {
	// 父回滚 attempt 推进、不再重投，直到收到它的终态
	return h.n.Store.Update(func(tx *store.Tx) error {
		a, ok := tx.GetAssignment(ih.CommandId, cc.nodeID)
		if !ok || isTerminalAssign(a.Status) {
			return nil
		}
		a.NextAttempt = ih.Attempt
		a.DeliveredAttempt = ih.Attempt
		a.InflightHintSeen = true
		a.UpdatedAt = canon.TS(tx.Now)
		return tx.PutAssignment(a)
	})
}

// ---------- 连接管理 ----------

// attach 把子连接登记进连接表；若同 NodeID 已有旧连接则关掉旧的（新 epoch 顶替）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc — 新建立的子连接
func (h *Hub) attach(cc *childConn) {
	h.mu.Lock()
	old := h.conns[cc.nodeID]
	h.conns[cc.nodeID] = cc
	h.mu.Unlock()
	if old != nil {
		old.close() // 新 epoch 踢掉旧连接
	}
}

// detach 从连接表移除子连接（仅当表里存的还是它自己），并关闭该连接。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc — 要移除的子连接
func (h *Hub) detach(cc *childConn) {
	h.mu.Lock()
	if cur, ok := h.conns[cc.nodeID]; ok && cur == cc {
		delete(h.conns, cc.nodeID)
	}
	h.mu.Unlock()
	cc.close()
}

// conn 按 NodeID 查找当前子连接，第二个返回值表示是否命中。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
func (h *Hub) conn(childID string) (*childConn, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c, ok := h.conns[childID]
	return c, ok
}

// ConnCount 返回当前在线的子连接数量。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
func (h *Hub) ConnCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.conns)
}

// close 关闭该子连接（关闭 done 通道），只生效一次。
//
// 接收者 cc 是 Hub 侧维护的一条子节点连接。
func (cc *childConn) close() {
	cc.once.Do(func() { close(cc.done) })
}

// send 把一帧下行数据放进发送缓冲（非阻塞，缓冲满或连接已关则报错）。
//
// 接收者 cc 是 Hub 侧维护的一条子节点连接。
//
// 参数：
//
//	f — 待发送的下行帧
//
// 返回：
//
//	error — 连接已关闭或发送缓冲已满时返回
func (cc *childConn) send(f *pb.DownFrame) error {
	select {
	case cc.sendCh <- f:
		return nil
	case <-cc.done:
		return errors.New("connection closed")
	default:
		return errors.New("send buffer full")
	}
}

// notify 通知子节点来拉取（发 CommandNotify，带上最新 seq）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	childID — 目标子节点 NodeID
//	seq     — 通知里带回的指令序号
func (h *Hub) notify(childID string, seq int64) {
	if cc, ok := h.conn(childID); ok {
		_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_CommandNotify{
			CommandNotify: &pb.CommandNotify{Seq: seq},
		}})
	}
}

// sendCRL 向某子推送吊销列表（DownFrame）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	childID — 目标子节点 NodeID
//	rl      — 吊销列表
func (h *Hub) sendCRL(childID string, rl *pb.RevocationList) {
	if cc, ok := h.conn(childID); ok {
		_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_RevocationList{RevocationList: rl}})
	}
}

// notifyCancel 主动取消帧（加速路径；必经路径是续租响应回带终态）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	childID — 目标子节点 NodeID
//	cmdID   — 要取消的指令 ID
func (h *Hub) notifyCancel(childID, cmdID string) {
	if cc, ok := h.conn(childID); ok {
		_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_CommandCanceled{
			CommandCanceled: &pb.CommandCanceled{CommandId: cmdID},
		}})
	}
}

// healthReq 向某子下发健康检查 / 指令轨迹请求，并等待其响应。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	ctx     — 调用方上下文；取消后立刻停止等待
//	childID — 目标子节点 NodeID
//	req     — HealthReq 请求，含 ReqId / Depth / Detail / TimeoutMs
//
// 返回：
//
//	*pb.HealthResponse — 子节点返回的响应
//	error             — 子连接不可达 / 超时 / 上下文取消时返回
func (h *Hub) healthReq(ctx context.Context, childID string, req *pb.HealthReq) (*pb.HealthResponse, error) {
	cc, ok := h.conn(childID)
	if !ok {
		return nil, fmt.Errorf("UNREACHABLE")
	}
	ch := make(chan *pb.HealthResponse, 1)
	cc.mu.Lock()
	cc.healthCh[req.ReqId] = ch
	cc.mu.Unlock()
	defer func() {
		cc.mu.Lock()
		delete(cc.healthCh, req.ReqId)
		cc.mu.Unlock()
	}()
	if err := cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_HealthReq{HealthReq: req}}); err != nil {
		return nil, err
	}
	select {
	case r := <-ch:
		return r, nil
	case <-time.After(time.Duration(req.TimeoutMs) * time.Millisecond):
		return nil, fmt.Errorf("TIMEOUT")
	case <-cc.done:
		return nil, fmt.Errorf("UNREACHABLE")
	case <-ctx.Done():
		// 调用方（HTTP 请求）已放弃 ⇒ 立刻停止等待，避免"被丢弃的扫描"在后台堆积
		return nil, ctx.Err()
	}
}

// sendQueryReqDown 向某子下发查询请求。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	childID — 目标子节点 NodeID
//	req     — 查询请求
//
// 返回：
//
//	error — 子连接不可达或发送失败时返回
func (h *Hub) sendQueryReqDown(childID string, req *pb.QueryReq) error {
	cc, ok := h.conn(childID)
	if !ok {
		return fmt.Errorf("UNREACHABLE")
	}
	return cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_QueryReq{QueryReq: req}})
}

// sendQueryRespDown 把查询响应 / 数据转发给某子。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	childID — 目标子节点 NodeID
//	resp    — 查询响应
//
// 返回：
//
//	error — 子连接不可达或发送失败时返回
func (h *Hub) sendQueryRespDown(childID string, resp *pb.QueryResp) error {
	cc, ok := h.conn(childID)
	if !ok {
		return fmt.Errorf("UNREACHABLE")
	}
	return cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_QueryResp{QueryResp: resp}})
}

// sendQueryDataDown 向某子下发查询数据。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	childID — 目标子节点 NodeID
//	d       — 查询数据
//
// 返回：
//
//	error — 子连接不可达或发送失败时返回
func (h *Hub) sendQueryDataDown(childID string, d *pb.QueryData) error {
	cc, ok := h.conn(childID)
	if !ok {
		return fmt.Errorf("UNREACHABLE")
	}
	return cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_QueryData{QueryData: d}})
}

// ---------- 小工具 ----------

// protoVersionOf 从 Connect 流的 gRPC metadata 里读取 proto-version。
//
// 参数：
//
//	stream — Connect 双向流
//
// 返回：
//
//	string — proto-version 的值；缺失时为空串
func protoVersionOf(stream pb.NodeService_ConnectServer) string {
	md, ok := metadata.FromIncomingContext(stream.Context())
	if !ok {
		return ""
	}
	if v := md.Get("proto-version"); len(v) > 0 {
		return v[0]
	}
	return ""
}

// majorOf 取版本号的主版本部分（第一个 '.' 之前的内容）。
//
// 参数：
//
//	v — 版本字符串，如 "1.0"
//
// 返回：
//
//	string — 主版本，如 "1"
func majorOf(v string) string {
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			return v[:i]
		}
	}
	return v
}

// labelsFrom 把注册请求里的 "k=v" 标签列表解析成 map。
//
// 参数：
//
//	r — 注册请求，其 Labels 形如 {"zone=az1", "gpu=1"}
//
// 返回：
//
//	map[string]string — 键值对；没有 '=' 的项被忽略
func labelsFrom(r *pb.RegisterRequest) map[string]string {
	out := map[string]string{}
	for _, l := range r.Labels {
		for i := 0; i < len(l); i++ {
			if l[i] == '=' {
				out[l[:i]] = l[i+1:]
				break
			}
		}
	}
	return out
}

// existingOr 优先返回注册表里已知的子节点 path，没有则用 fallback。
//
// 参数：
//
//	n        — 本节点，提供注册表
//	childID  — 子节点 NodeID
//	fallback — 注册表里查不到时使用的路径
//
// 返回：
//
//	string — 已知 path 或 fallback
func existingOr(n *Node, childID, fallback string) string {
	if c, ok := n.Reg.Get(childID); ok && c.Path != "" {
		return c.Path
	}
	return fallback
}

var _ = proto.Clone
