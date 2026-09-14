package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"treecmd/internal/aggregate"
	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// SubmitRequest 提交指令入参（3.15）。
type SubmitRequest struct {
	Type       string `json:"type"`
	Payload    []byte `json:"-"`
	PayloadB64 string `json:"payload"`
	// 只支持「下发即执行」：mode 缺省或 SUBTREE 均可；显式给 NODE / SELECTOR 一律拒绝
	Target struct {
		Mode string `json:"mode"`
	} `json:"target"`
	OnFailure string `json:"on_failure"`
	Aggregate string `json:"aggregate"`
	// aggregate=CUSTOM 时必填：CUSTOM 聚合器名字（提交期即校验是否存在、是否需要 RawChildren）
	AggregateName string `json:"aggregate_name"`
	MaxDuration   string `json:"max_duration"`
	Idempotent    bool   `json:"idempotent"`
	RawChildren   bool   `json:"raw_children"`
	// 背书链深度：不传 → 默认 1（只到直接子层）；显式 0 → 无上限（全树背书）
	AttestDepth *int32 `json:"attest_depth"`
}

// SubmitResult 提交响应。
type SubmitResult struct {
	CommandID string `json:"command_id"`
	LocalSeq  int64  `json:"local_seq"`
	OwnerPath string `json:"owner_path"`
}

// ulid 生成 26 字符的 Crockford-base32 时间有序 ID（48bit ms + 80bit 随机）。
//
// 返回：
//
//	string — 生成的 ID
//	error  — 读取随机数失败时返回
func ulid() (string, error) {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	enc := base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)
	// 128bit → 26 字符：前面补 2 个 0 bit
	s := enc.EncodeToString(append([]byte{0, 0}, b[:]...))
	if len(s) > 26 {
		s = s[len(s)-26:]
	}
	return s, nil
}

// SubmitCommand 创建一个指令：校验入参 → 组装并签名 Command → 单事务落盘 → 异步推进。
//
// 接收者 n 是本节点。
//
// 参数：
//
//	req      — 提交请求（类型 / 载荷 / 目标 / 失败策略 / 聚合 / 截止时间等）
//	originID — 发起者 NodeID，用于校验是否被允许
//
// 返回：
//
//	*SubmitResult — 成功时含 CommandID / LocalSeq / OwnerPath
//	error         — 未授权 / 参数非法 / 落盘失败时返回
func (n *Node) SubmitCommand(req SubmitRequest, originID string) (*SubmitResult, error) {
	if !n.allowedOrigin(originID) {
		return nil, fmt.Errorf("ERR_UNAUTHORIZED_ORIGIN")
	}
	if req.Type == "" {
		return nil, fmt.Errorf("ERR_TYPE_REQUIRED")
	}
	// 能力校验：类型必须在本节点登记的执行器里（X 自己也在"命中集合"里，默认 SUBTREE 含自身）
	if !n.Exec.Has(req.Type) {
		return nil, fmt.Errorf("ERR_CAPABILITY_UNSUPPORTED: type %q not registered", req.Type)
	}
	payload := req.Payload
	if payload == nil && req.PayloadB64 != "" {
		dec, err := base64Decode(req.PayloadB64)
		if err != nil {
			return nil, fmt.Errorf("ERR_INVALID_PAYLOAD: %w", err)
		}
		payload = dec
	}
	if int64(len(payload)) > int64(n.C().Command.MaxPayload) {
		return nil, fmt.Errorf("ERR_PAYLOAD_TOO_LARGE: %d > %d", len(payload), n.C().Command.MaxPayload)
	}

	// Target：只有"整棵子树、人人执行"一种语义（父节点下发的任务，子节点收到即执行）
	target := &pb.Target{}
	switch strings.ToUpper(strings.TrimSpace(req.Target.Mode)) {
	case "", "SUBTREE":
		m := pb.TargetMode_TARGET_SUBTREE
		target.Mode = &m
	case "NODE", "SELECTOR":
		return nil, fmt.Errorf("ERR_TARGET_NOT_SUPPORTED: %q 已下线；当前为「下发即执行」，父节点下发的任务子节点直接执行", req.Target.Mode)
	default:
		return nil, fmt.Errorf("ERR_TARGET_NOT_SUPPORTED: 未知模式 %q（只支持 SUBTREE）", req.Target.Mode)
	}

	// 失败策略
	policy, err := aggregate.ParsePolicy(strings.TrimSpace(req.OnFailure))
	if err != nil {
		return nil, err
	}
	// 聚合策略
	strategy := pb.AggregateStrategy_AGGREGATE_TREE
	switch strings.ToUpper(strings.TrimSpace(req.Aggregate)) {
	case "", "TREE":
		strategy = pb.AggregateStrategy_AGGREGATE_TREE
	case "MERGE":
		strategy = pb.AggregateStrategy_AGGREGATE_MERGE
	case "SUM":
		strategy = pb.AggregateStrategy_AGGREGATE_SUM
	case "COUNT":
		strategy = pb.AggregateStrategy_AGGREGATE_COUNT
	case "CUSTOM":
		strategy = pb.AggregateStrategy_AGGREGATE_CUSTOM
	default:
		return nil, fmt.Errorf("ERR_UNKNOWN_AGGREGATE: %q（不静默降级为 TREE）", req.Aggregate)
	}
	var customAgg aggregate.CustomAggregator
	if strategy == pb.AggregateStrategy_AGGREGATE_CUSTOM {
		name := strings.TrimSpace(req.AggregateName)
		if name == "" {
			return nil, fmt.Errorf("ERR_UNKNOWN_CUSTOM_AGGREGATOR: aggregate=CUSTOM 时必须给 aggregate_name（已注册：%v）",
				aggregate.CustomNames())
		}
		a, ok := aggregate.LookupCustom(name)
		if !ok {
			return nil, fmt.Errorf("ERR_UNKNOWN_CUSTOM_AGGREGATOR: %q 未注册（已注册：%v）", name, aggregate.CustomNames())
		}
		// 更硬的一层保护：聚合器声明需要 SelfResult 而指令未开 RawChildren ⇒ 提交期即拒
		if np, ok := a.(interface{ NeedsSelfResult() bool }); ok && np.NeedsSelfResult() && !req.RawChildren {
			return nil, fmt.Errorf("ERR_CUSTOM_NEEDS_RAWFILDREN: %q 需要 SelfResult，请开 raw_children", name)
		}
		customAgg = a
	}
	// 背书链深度（7.5）：未设置 → 默认 1；显式 0 → 无上限（全树背书）
	attestDepth := int32(1)
	unlimited := false
	if req.AttestDepth != nil {
		attestDepth = *req.AttestDepth
		unlimited = attestDepth == 0
	}
	if req.RawChildren && !unlimited && attestDepth < 2 {
		// 注意：0 是无上限特例，必须放行（写成裸的 attest_depth < 2 会把 0 也拒掉）
		return nil, fmt.Errorf("ERR_INVALID_ATTEST_DEPTH: RawChildren=true 要求 AttestDepth ≥ 2 或 0（无上限）")
	}

	now := time.Now()
	dur := n.C().DeadlineForType(req.Type)
	if req.MaxDuration != "" {
		d, err := time.ParseDuration(req.MaxDuration)
		if err != nil {
			return nil, fmt.Errorf("ERR_INVALID_DURATION: %q（格式须为 Go time.ParseDuration，如 1h30m）", req.MaxDuration)
		}
		dur = d
	}
	if dur > n.C().Command.MaxDeadline {
		dur = n.C().Command.MaxDeadline
	}
	deadline := now.Add(dur)
	if !deadline.After(now) {
		return nil, fmt.Errorf("ERR_INVALID_DEADLINE")
	}

	id, err := ulid()
	if err != nil {
		return nil, err
	}
	c := &pb.Command{
		Id: id, Type: req.Type, Payload: payload, Target: target,
		CreatedAt: canon.TS(now), Deadline: canon.TS(deadline), OriginDeadline: canon.TS(deadline),
		OnFailure: pointer(policy.Kind), Aggregate: pointer(strategy),
		RawChildren: req.RawChildren, AttestDepth: &attestDepth, Idempotent: req.Idempotent,
		OriginId: originID, AggregateName: req.AggregateName,
	}
	if policy.Kind == pb.FailurePolicy_POLICY_TOLERATE_N || policy.Kind == pb.FailurePolicy_POLICY_TOLERATE_PCT {
		c.TolerateValue = pointer(policy.Tolerate)
	}
	// OriginCert：发起者证书链（串接 PEM），供任一跳离线验签
	var chainPEM []byte
	for _, cert := range n.Id().Chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	c.OriginCert = chainPEM
	sig, err := n.signOrigin(c)
	if err != nil {
		return nil, err
	}
	c.OriginSig = sig

	// 大小校验：payload ≤ max_payload 且整条 Command 的 canonical 编码 ≤ max_command_bytes（两道都要过）
	if sz, _ := canon.Bytes(c); int64(len(sz)) > int64(n.C().Command.MaxCommandBytes) {
		return nil, fmt.Errorf("ERR_COMMAND_TOO_LARGE: %d > %d", len(sz), n.C().Command.MaxCommandBytes)
	}

	// 创建事务：分配 LocalSeq + 写指令日志 + 剪枝写 Assignment + 写 X 的 local_state 初值（ADR-025）
	res := &SubmitResult{CommandID: id, OwnerPath: n.SelfPath()}
	err = n.Store.Update(func(tx *store.Tx) error {
		seq, err := tx.AllocLocalSeq()
		if err != nil {
			return err
		}
		base := proto.Clone(c).(*pb.Command)
		base.Seq = seq
		rec := &pb.CommandRecord{CommandId: id, LocalSeq: seq, Command: mustMarshal(base),
			Status: pb.CommandStatus_COMMAND_STATUS_PENDING, UpdatedAt: canon.TS(tx.Now)}
		if err := tx.PutCommand(rec); err != nil {
			return err
		}
		for _, ch := range n.Reg.Snapshot() {
			a := &pb.AssignmentRecord{CommandId: id, ChildId: ch.NodeID,
				Status: pb.AssignStatus_ASSIGN_STATUS_PENDING, LocalSeq: seq,
				NextAttempt: 1, UpdatedAt: canon.TS(tx.Now)}
			if err := tx.PutAssignment(a); err != nil {
				return err
			}
		}
		lc := &pb.LocalCommandRecord{CommandId: id, LocalState: pb.LocalExecState_LOCAL_STATE_NOT_STARTED,
			Command: mustMarshal(c), LastUpstreamSeq: seq, UpdatedAt: canon.TS(tx.Now)}
		if err := tx.PutLocal(lc); err != nil {
			return err
		}
		res.LocalSeq = seq
		return nil
	})
	if err != nil {
		return nil, err
	}
	if customAgg != nil {
		n.registerCustom(id, customAgg)
	}
	// 202 之后再异步推进（handle 里的 EnsureCreated 是幂等复用）
	go n.handle(n.backgroundContext(), c, 1)
	return res, nil
}

// signOrigin origin 签名只覆盖"创建后不得改动"的字段（Seq / HopChain / Deadline 不入签）。
//
// 接收者 n 是本节点（origin）。
//
// 参数：
//
//	c — 待签名的指令
//
// 返回：
//
//	[]byte — 签名
//	error  — 规范化失败时返回
func (n *Node) signOrigin(c *pb.Command) ([]byte, error) {
	signed := proto.Clone(c).(*pb.Command)
	signed.Seq = 0
	signed.Deadline = nil
	signed.HopChain = nil
	signed.OriginSig = nil
	d, err := canon.Digest(signed)
	if err != nil {
		return nil, err
	}
	return identity.Sign(n.Id().Key, d), nil
}

// verifyOrigin 任一跳用内联 OriginCert 离线验 origin 签名与身份，**不需要联网**。
//
// 签名覆盖的是"创建后不可变"的那部分字段：计算摘要前会把 Seq / Deadline / HopChain /
// OriginSig 这四个"逐跳会变的"字段清空，所以同一个指令在每一跳算出的摘要都相同。
// 注意：这里**不做任何时间窗校验**（不比对 CreatedAt、也不看 Deadline）——
// 超时/过期由等待逻辑（waitChildren 的 Deadline）负责，放在这一层会把重启后的
// 对账重投（Reconcile）也一起误杀。
//
// 参数：
//
//	c — 待验证的指令，含 OriginSig 与 OriginCert
//
// 返回：
//
//	error — 缺签名 / 证书、链非法、验签失败或身份不符时返回
func verifyOrigin(c *pb.Command) error {
	if len(c.OriginSig) == 0 || len(c.OriginCert) == 0 {
		return fmt.Errorf("ERR_ORIGIN_MISSING")
	}
	chain, err := parsePEMChain(c.OriginCert)
	if err != nil || len(chain) == 0 {
		return fmt.Errorf("ERR_ORIGIN_CERT_INVALID")
	}
	signed := proto.Clone(c).(*pb.Command)
	signed.Seq = 0
	signed.Deadline = nil
	signed.HopChain = nil
	signed.OriginSig = nil
	d, err := canon.Digest(signed)
	if err != nil {
		return err
	}
	edPub, ok := chain[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("ERR_ORIGIN_CERT_INVALID: not ed25519")
	}
	if !identity.Verify(edPub, d, c.OriginSig) {
		return fmt.Errorf("ERR_ORIGIN_SIG_INVALID")
	}
	if got := identity.NodeIDFromCert(chain[0]); got != c.OriginId {
		return fmt.Errorf("ERR_ORIGIN_ID_MISMATCH")
	}
	return nil
}

// verifyHop 子节点校验 HopChain 最后一条（四项：ChildID / ForwarderID / Digest / Sig）。
//
// 接收者 n 是本节点（验签方，即子节点）。
//
// 参数：
//
//	parentID  — 期望的转发者（父）NodeID；为空则跳过该项校验
//	parentPub — 父节点公钥；为空则跳过签名校验
//	c         — 收到的指令
//
// 返回：
//
//	error — 链为空 / ChildID 不符 / ForwarderID 不符 / Digest 不符 / 验签失败时返回
func (n *Node) verifyHop(parentID string, parentPub []byte, c *pb.Command) error {
	if len(c.HopChain) == 0 {
		return fmt.Errorf("ERR_HOPCHAIN_EMPTY")
	}
	last := c.HopChain[len(c.HopChain)-1]
	if last.ChildId != n.C().Node.ID {
		return fmt.Errorf("HOP_CHILD_MISMATCH: attest for %s, I am %s", shortID(last.ChildId), shortID(n.C().Node.ID))
	}
	if parentID != "" && last.ForwarderId != parentID {
		return fmt.Errorf("HOP_FORWARDER_MISMATCH")
	}
	// Digest 与"自己实收内容去掉末条 HopAttest"一致
	clone := proto.Clone(c).(*pb.Command)
	clone.HopChain = clone.HopChain[:len(clone.HopChain)-1]
	d, err := canon.Digest(clone)
	if err != nil {
		return err
	}
	if string(d) != string(last.Digest) {
		return fmt.Errorf("HOP_DIGEST_MISMATCH")
	}
	if len(parentPub) > 0 && !identity.Verify(parentPub, last.Digest, last.Sig) {
		return fmt.Errorf("HOP_SIG_INVALID")
	}
	return nil
}

// pointer 返回 v 的指针，便于给 proto 的 optional 字段赋值。
func pointer[T any](v T) *T { return &v }

// base64Decode 依次尝试标准与"无填充标准"两种 base64 解码。
//
// 参数：
//
//	s — 待解码字符串
//
// 返回：
//
//	[]byte — 解码结果
//	error  — 两种编码都失败时返回
func base64Decode(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// parsePEMChain 从 PEM 字节流里解析出所有 CERTIFICATE 证书。
//
// 参数：
//
//	b — PEM 编码的证书链
//
// 返回：
//
//	[]*x509.Certificate — 解析出的证书（按出现顺序）
//	error               — 某张证书解析失败时返回
func parsePEMChain(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
