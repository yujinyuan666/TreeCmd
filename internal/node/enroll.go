package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"treecmd/internal/config"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
)

// 运行期入网签发（父签发子）。
//
// 场景：部署是单服务器手工起进程，子节点的证书由它自己的父签发；子节点启动时手上**只有密钥对**，
// 没有证书。流程：
//
//	子：EnrollChallenge ──► 父（下发一次性 nonce，绑定"父 NodeID + 子 NodeID"）
//	子：用**自己的私钥**对 (nonce || 父ID || 子ID) 签名（PoP），连同身份公钥（以及有下级时的 CA 公钥）
//	    与入网许可 token 一起提交
//	父：校验许可 + 白名单 + PoP → 用**自己的 CA 私钥**签这两个公钥 → 回身份证书链与 CA 证书链
//	子：校验响应（身份 == 自己、公钥 == 本机公钥、链到信任锚）→ 原子写证书文件 → 热切换 → 正常握手
//
// 三个要点：
//   - **私钥不出子机**：请求里只有公钥；父的响应里只有证书。程序既不生成也不接收任何私钥。
//   - **许可不是唯一门槛，但它是唯一的"授权"判据**：还要 PoP，拿着 token 但没有对应私钥的人
//     签不出有效的 PoP。反过来，**没有 token 就一定放行不了** —— 见下面 enrollCredential。
//   - **父必须有 CA 材料**：没有就明确拒绝（`ERR_ENROLL_NO_CA`），而不是发一张假的证书出去。

// enrollCredential 读并解析本节点的**入网引导凭据**（`security.enrollment.token` / `token_path`）。
//
// 两侧都用它，但用法不同：
//   - 父端只取 `Permit` 做常量时间比对（这是"父要不要收你"的唯一判据）；
//   - 子端取 `Permit` 提交申请，并且**凭据里可能内嵌父的 CA 证书链** —— 那是首跳的信任锚来源，
//     于是子节点部署时只需要这一份文件（见 identity.ParseBootstrap）。
//
// **每次现读**（不缓存）：与"换 token 不需要重注册、SIGHUP/投放即生效"的既有语义一致。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	*identity.Bootstrap — 解析结果（许可与锚都可能为空）
//	error               — 读不到凭据文件 / 内容不符合凭据格式时返回（fail-fast，不静默当成"没许可"）
func (n *Node) enrollCredential() (*identity.Bootstrap, error) {
	raw, err := n.C().Security.EnrollCredentialRaw()
	if err != nil {
		return nil, err
	}
	return identity.ParseBootstrap(raw)
}

// enrollPermitAbsent 报告"本节点手上没有可用的入网许可"（仅用于启动期提醒与子端早失败）。
//
// 接收者 n 是本节点实例。凭据读不到、格式不合法、或解析出来没有 permit，都算"没有"。
// **真正的判定不在这里**：父端在 Hub.Enroll ② 拒绝，子端在 ensureCertForce 提前失败。
//
// 返回：
//
//	bool — 拿不到非空许可时为 true
func (n *Node) enrollPermitAbsent() bool {
	cred, err := n.enrollCredential()
	return err != nil || cred.Permit == ""
}

// ---------- 服务端 ----------

type enrollChallenge struct {
	nonce    []byte
	issuedAt time.Time
	expireAt time.Time
}

// EnrollChallenge 下发一次性挑战。返回的 nonce 只能用于"这一次"申请。
//
// 接收者 h 是本节点的下行 Hub（子节点连上来的那个方向）。
//
// 参数：
//
//	ctx — RPC 上下文（本函数未使用）
//	req — 挑战请求；req.NodeId 是申请入网的子节点 ID
//
// 返回：含 nonce、父 NodeID、过期时间的响应；未开启入网或 node_id 为空时返回错误。
//
// 顺带清理已过期的挑战条目，避免内存里的 map 无界增长。
func (h *Hub) EnrollChallenge(ctx context.Context, req *pb.EnrollChallengeReq) (*pb.EnrollChallengeResp, error) {
	n := h.n
	cfg := n.C()
	if !cfg.Security.EnrollmentEnabled() {
		return nil, fmt.Errorf("ERR_ENROLL_DISABLED: 本节点未开启 security.enrollment.enabled")
	}
	if req.NodeId == "" {
		return nil, fmt.Errorf("ERR_ENROLL_BAD_REQUEST: node_id 为空")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("ERR_ENROLL_NONCE: %w", err)
	}
	now := time.Now()
	ttl := cfg.Security.EnrollChallengeTTL()
	n.enrollMu.Lock()
	if n.challenges == nil {
		n.challenges = map[string]enrollChallenge{}
	}
	// 清理过期条目，避免无界增长
	for k, v := range n.challenges {
		if now.After(v.expireAt) {
			delete(n.challenges, k)
		}
	}
	n.challenges[req.NodeId] = enrollChallenge{nonce: nonce, issuedAt: now, expireAt: now.Add(ttl)}
	n.enrollMu.Unlock()

	n.Log.Info("enroll: challenge issued", "requester", shortID(req.NodeId), "ttl", ttl.String())
	return &pb.EnrollChallengeResp{
		Nonce:         nonce,
		ParentNodeId:  cfg.Node.ID,
		ExpiresAtUnix: now.Add(ttl).Unix(),
	}, nil
}

// Enroll 校验许可与私钥持有证明，然后用本节点 CA 私钥签发对方的公钥。
//
// 接收者 h 是本节点的下行 Hub。
//
// 注意：这条 RPC 是**允许客户端不提供证书**的（入网时对方本来就没有证书），所以它自己必须扛住鉴权：
// 白名单 / 许可 token / 一次性 nonce / PoP，四道都在下面。
//
// 参数：
//
//	ctx — RPC 上下文
//	req — 入网请求：NodeId、IdentityPubkey、Nonce、PoofSig（PoP 签名）、Permit（许可 token），
//	      CaPubkey / CaPoofSig（对方有下级时才带）、ListenAddr、Note
//
// 返回：通过时返回 ok=true 与证书链；被拒绝时返回 ok=false + reason 且 error 为 nil
// （把拒绝原因交回对端自助排错，同时不让 gRPC 层把它记成"调用成功"）。
func (h *Hub) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	n := h.n
	cfg := n.C()
	// deny 返回 (响应, error)。响应里的 reason 让对端能自助排错，error 让 gRPC 层
	// 不至于把拒绝记成"调用成功"。
	deny := func(reason string) (*pb.EnrollResponse, error) {
		n.auditReject("enroll_denied", req.NodeId, "", errors.New(reason))
		n.Metrics.Inc("enroll_total", "result", "denied")
		return &pb.EnrollResponse{Ok: false, Reason: reason}, nil
	}

	if !cfg.Security.EnrollmentEnabled() {
		return deny("ERR_ENROLL_DISABLED: 本节点未开启入网签发")
	}
	if req.NodeId == "" {
		return deny("ERR_ENROLL_BAD_REQUEST: node_id 为空")
	}
	// ① 入网许可 —— **唯一的授权判据：许可为空就拒绝一切入网**。
	//
	// 这里**曾经**还有一道 `allow_ids` 白名单（"只允许这些 NodeID 入网"），已删除：
	// allow_ids 里装的是 NodeID，而 NodeID 是**公开**信息（`/v1/tree` 就能读到）；
	// 而 PoP 只证明"提交者持有它提交的那对公钥的私钥"，**证明不了"它就是那个 NodeID"** ——
	// NodeID 与密钥对之间有意没有任何密码学绑定（`node.id` 还允许留空自动生成）。
	// 于是"自报一个白名单里的 ID + 自建一对密钥"就能换到一张 CN 等于该 ID 的真证书：
	// 既绕开了授权，又能与真节点撞 ID（父是按 NodeID 索引子节点的）。
	// ⇒ 白名单**不是**一道能独立成立的闸门，留着只会让人以为多了一层保护。想限定
	// "这一次准入发给谁"，正确做法是**每节点一枚一次性许可**，而不是给一份 ID 名单。
	cred, err := n.enrollCredential()
	if err != nil {
		return deny("ERR_ENROLL_TOKEN_READ: " + err.Error())
	}
	if cred.Permit == "" {
		return deny("ERR_ENROLL_NO_PERMIT_POLICY: 本节点未配置入网许可（security.enrollment.token / token_path）" +
			" ⇒ 拒绝一切入网。入网认证只有许可一个口径：NodeID 是公开信息、与密钥对没有密码学绑定，" +
			"给一份 ID 名单挡不住「自报某个 ID + 自建一对密钥」")
	}
	if subtle.ConstantTimeCompare([]byte(cred.Permit), []byte(req.Permit)) != 1 {
		return deny("ERR_ENROLL_BAD_PERMIT: 入网许可不正确")
	}
	// ③ 一次性挑战
	n.enrollMu.Lock()
	ch, ok := n.challenges[req.NodeId]
	if ok {
		delete(n.challenges, req.NodeId) // 无论成败都消费掉，防重放
	}
	n.enrollMu.Unlock()
	if !ok {
		return deny("ERR_ENROLL_NO_CHALLENGE: 没有待用的挑战，请先调用 EnrollChallenge")
	}
	if time.Now().After(ch.expireAt) {
		return deny("ERR_ENROLL_CHALLENGE_EXPIRED: 挑战已过期")
	}
	if subtle.ConstantTimeCompare(ch.nonce, req.Nonce) != 1 {
		return deny("ERR_ENROLL_CHALLENGE_MISMATCH: 挑战不匹配")
	}
	// ④ 私钥持有证明（PoP）
	idPub := ed25519.PublicKey(req.IdentityPubkey)
	if len(idPub) != ed25519.PublicKeySize {
		return deny("ERR_ENROLL_BAD_PUBKEY: 身份公钥不是 ed25519")
	}
	pop := identity.POPMessage(ch.nonce, cfg.Node.ID, req.NodeId)
	if !identity.Verify(idPub, pop, req.PoofSig) {
		return deny("ERR_ENROLL_POP_INVALID: 私钥持有证明验签失败")
	}
	var caPub ed25519.PublicKey
	if len(req.CaPubkey) > 0 {
		caPub = ed25519.PublicKey(req.CaPubkey)
		if len(caPub) != ed25519.PublicKeySize {
			return deny("ERR_ENROLL_BAD_CA_PUBKEY: CA 公钥不是 ed25519")
		}
		if !identity.Verify(caPub, pop, req.CaPoofSig) {
			return deny("ERR_ENROLL_CA_POP_INVALID: CA 私钥持有证明验签失败")
		}
	}
	// ⑤ 签发（只用公钥；本节点必须有 CA 材料）
	issued, err := n.Id().IssueForPubkeys(req.NodeId, idPub, caPub)
	if err != nil {
		return deny("ERR_ENROLL_NO_CA: " + err.Error())
	}
	n.Log.Info("enroll: certificate issued",
		"child", shortID(req.NodeId), "with_ca", caPub != nil,
		"not_after", issued.NotAfter.Format(time.RFC3339),
		"listen", req.ListenAddr, "note", req.Note)
	n.Metrics.Inc("enroll_total", "result", "issued")
	return &pb.EnrollResponse{
		Ok: true, CertChain: issued.CertChain, CaCertChain: issued.CACertChain,
		NotAfterUnix: issued.NotAfter.Unix(), IssuedBy: cfg.Node.ID,
	}, nil
}

// ---------- 客户端 ----------

// hasUsableCert 是否持有"可用"的证书（存在且未过期）。
//
// 接收者 n 是本节点实例。
//
// 返回：身份与证书都非空、且当前时间早于证书 NotAfter 时为 true。
func (n *Node) hasUsableCert() bool {
	id := n.Id()
	if id == nil || id.Cert == nil {
		return false
	}
	return time.Now().Before(id.Cert.NotAfter)
}

// ensureCertWithLock 入网互斥包装：同一时刻只允许一个入网流程在跑
// （上行 supervise 与"证书被删后的自愈"可能同时触发）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	ctx   — 上下文
//	force — 透传给 ensureCertForce：true 时忽略内存里已有的证书，强制换新
//
// 返回：已有入网在跑时直接返回错误；否则返回 ensureCertForce 的结果，
// 退出时用 defer 把 enrolling 标志复位。
func (n *Node) ensureCertWithLock(ctx context.Context, force bool) error {
	if n.enrolling.Swap(true) {
		return errors.New("enrollment already in progress")
	}
	defer n.enrolling.Store(false)
	return n.ensureCertForce(ctx, force)
}

// ensureCert 保证本节点持有可用证书（已有就直接返回）。
//
// 接收者 n 是本节点实例；等价于 ensureCertForce(ctx, false)。
//
// 参数：
//
//	ctx — 上下文
//
// 返回：拿到可用证书返回 nil，否则返回错误。
func (n *Node) ensureCert(ctx context.Context) error { return n.ensureCertForce(ctx, false) }

// ensureCertForce 确保本节点持有可用证书，必要时逐个配置里的父节点尝试运行期入网。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	ctx   — 上下文
//	force — force=false 时"内存里已有可用证书"即返回；
//	       force=true 时忽略内存状态，一律去换一张（用于把被删掉的证书文件补回来）
//
// 返回：任意一个父入网成功即返回 nil；全部失败返回包装过的最后一个错误。
func (n *Node) ensureCertForce(ctx context.Context, force bool) error {
	if !force && n.hasUsableCert() {
		return nil
	}
	cfg := n.C()
	if !cfg.Security.EnrollmentEnabled() {
		return fmt.Errorf("NO_CERT: 证书不可用且未开启运行期入网（security.enrollment.enabled）")
	}
	cred, err := n.enrollCredential()
	if err != nil {
		return err
	}
	if cred.Permit == "" {
		// 没有许可就不必白试一轮：父端一定会拒（许可为空即拒绝一切入网，见 Hub.Enroll ②）。
		// 提前失败，并把"该放哪份文件"直接写进错误里。
		return fmt.Errorf("NO_CERT: 证书不可用，且没有入网许可（security.enrollment.token / token_path）—— " +
			"父端会因为许可为空而拒绝一切入网。请把父产出的引导凭据投放到 token_path 指向的文件" +
			"（凭据里除 permit 外还可以内嵌父的 CA 链，那样连 trust/ 都不用了）")
	}
	var lastErr error
	for _, p := range cfg.Parents {
		if err := n.enrollWith(ctx, p, cred.Permit); err != nil {
			lastErr = err
			n.Log.Warn("enroll: attempt failed", "parent", shortID(p.ID), "err", err)
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no parents configured")
	}
	return fmt.Errorf("enroll failed with all parents: %w", lastErr)
}

// enrollWith 向指定父完成一次入网（挑战 → PoP → 提交 → 校验响应 → 落盘 → 热切换）。
//
// 接收者 n 是本节点实例；全程私钥不出本机，只提交公钥。
//
// 参数：
//
//	ctx   — 上下文
//	p     — 目标父节点（ID + 地址）；服务端身份必须是它
//	permit — 入网许可串（取自引导凭据；为空时本函数不会被调用 —— 父端一定会拒）
//
// 返回：任一步失败返回错误；成功时证书已原子写盘并完成热切换。
func (n *Node) enrollWith(ctx context.Context, p config.Parent, permit string) error {
	cfg := n.C()
	myID := cfg.Node.ID
	myPriv := n.Id().Key
	if myPriv == nil {
		return errors.New("identity private key missing")
	}
	myPub := identity.PublicKeyOf(myPriv)

	// 入网握手：不带客户端证书，但**必须**把服务端验到信任锚 + 身份必须是配置里的父
	creds := credentials.NewTLS(identity.NewEnrollClientTLSConfig(n.rootsPool(), p.ID))
	conn, err := grpc.NewClient(p.Addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("dial parent %s: %w", p.Addr, err)
	}
	defer conn.Close()
	cli := pb.NewNodeServiceClient(conn)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	ch, err := cli.EnrollChallenge(ctx, &pb.EnrollChallengeReq{NodeId: myID})
	if err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if ch.ParentNodeId != "" && ch.ParentNodeId != p.ID {
		return fmt.Errorf("challenge from unexpected parent %s (配置里是 %s)", shortID(ch.ParentNodeId), shortID(p.ID))
	}
	pop := identity.POPMessage(ch.Nonce, p.ID, myID)
	req := &pb.EnrollRequest{
		NodeId:         myID,
		IdentityPubkey: myPub,
		Nonce:          ch.Nonce,
		PoofSig:        identity.Sign(myPriv, pop),
		Permit:         permit,
		ListenAddr:     cfg.Node.Listen,
		Note:           "runtime enrollment",
	}
	// 有下级（根 / 中继）才需要 CA 材料；叶子不需要，也就不会提交 CA 公钥
	if cfg.HasDownstream() && cfg.Security.CAKeyPath != "" {
		caKey, err := identity.LoadIdentityKey(cfg.Security.CAKeyPath)
		if err != nil {
			return fmt.Errorf("load CA key: %w", err)
		}
		caPub := identity.PublicKeyOf(caKey)
		req.CaPubkey = caPub
		req.CaPoofSig = identity.Sign(caKey, pop)
	}
	resp, err := cli.Enroll(ctx, req)
	if err != nil {
		return fmt.Errorf("enroll rpc: %w", err)
	}
	if !resp.Ok {
		return fmt.Errorf("被父拒绝: %s", resp.Reason)
	}

	// ---- 校验响应：只接受"确实是我、链到信任锚"的证书 ----
	//
	// 用**本节点当前生效的锚池**，而不是只从 security.ca_cert_paths 重新读一遍：
	// 锚池在启动期已经由"配置锚 ∪ 引导凭据里内嵌的父 CA 链 ∪ 自身证书链自举"合并而成
	// （见 loadIdentity）。若这里退回"只读 ca_cert_paths"，那么"只带一份引导凭据、
	// 没配 ca_cert_paths"的节点会卡死在这一步 —— 父端明明已经签发成功，
	// 子端却报 `no trust anchor loaded`（实测踩到过）。
	anchors := identity.PoolCerts(n.rootsPool())
	chain, err := identity.ParseChainPEM(resp.CertChain)
	if err != nil || len(chain) == 0 {
		return fmt.Errorf("响应证书链无法解析: %v", err)
	}
	if got := identity.NodeIDFromCert(chain[0]); got != myID {
		return fmt.Errorf("响应证书身份不符: %s != %s", got, myID)
	}
	certPub, ok := chain[0].PublicKey.(ed25519.PublicKey)
	if !ok || !certPub.Equal(myPub) {
		return fmt.Errorf("响应证书的公钥与本机私钥不匹配")
	}
	var caChain []*x509.Certificate
	if len(resp.CaCertChain) > 0 {
		caChain, err = identity.ParseChainPEM(resp.CaCertChain)
		if err != nil || len(caChain) == 0 {
			return fmt.Errorf("响应 CA 证书链无法解析: %v", err)
		}
	}

	// 组装身份材料后走**与启动同一强度**的校验（含 CA 材料校验）
	id := &identity.Identity{NodeID: myID, Key: myPriv, Cert: chain[0], Chain: chain}
	if cfg.HasDownstream() {
		if cfg.Security.CAKeyPath == "" {
			return errors.New("本节点有子节点但没有 CA 私钥，无法持有 CA 身份")
		}
		caKey, err := identity.LoadIdentityKey(cfg.Security.CAKeyPath)
		if err != nil {
			return fmt.Errorf("load CA key: %w", err)
		}
		id.CAKey = caKey
		if len(caChain) > 0 {
			id.CACert = caChain[0]
			id.CAChain = caChain
		}
	}
	if err := identity.ValidateStartup(id, anchors, myPub); err != nil {
		return fmt.Errorf("入网响应未通过启动强度校验: %w", err)
	}

	// ---- 落盘（原子写）后再热切换：崩在中间也是"要么旧、要么新"，不会有半个证书 ----
	if err := identity.WriteCertChainFile(cfg.Security.IdentityCertPath, chain); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if len(caChain) > 0 && cfg.Security.CACertPath != "" {
		if err := identity.WriteCertChainFile(cfg.Security.CACertPath, caChain); err != nil {
			return fmt.Errorf("write CA cert: %w", err)
		}
	}
	n.idPtr.Store(id)
	n.certBox.Set(identity.TLSCertFrom(id))
	// 信任锚：把**刚拿到的这条证书链里的 CA** 并进池。于是"首次入网用的那份父 CA"到此完成使命 ——
	// 运行期用新锚，重启则由 loadIdentity 从证书链自举出同一批锚，trust/ 里那份文件可以删掉。
	n.roots.Store(identity.NewPool(mergeAnchors(anchors, identity.ChainAnchors(chain))...))
	// 我们自己刚写过证书文件 → 重算监视基线，否则这次改动会被当成"外部变更"或反过来漏检
	n.refreshReloadBaseline()
	n.Log.Info("enroll: certificate installed",
		"parent", shortID(p.ID), "not_after", canonTime(chain[0]), "fingerprint", certSha256(chain[0]))
	n.Metrics.Inc("enroll_total", "result", "installed")
	return nil
}

// finishEnroll 入网成功后的收尾：把因为"没有证书"而推迟启动的下行服务补起来。
//
// 接收者 n 是本节点实例；随后再确保上行会话也起起来。
//
// 参数：
//
//	reason — 触发原因，仅用于日志
func (n *Node) finishEnroll(reason string) {
	if n.hub == nil && n.C().HasDownstream() {
		if err := n.startHub(); err != nil {
			n.Log.Error("start downstream after enroll failed", "err", err)
		} else {
			n.Log.Info("downstream started after enrollment", "listen", n.C().Node.Listen, "reason", reason)
		}
	}
	n.ensureStartedUpstream()
}

// startHub 启动下行服务（幂等）。
//
// 接收者 n 是本节点实例；已经启动过就直接返回 nil。
//
// 返回：创建或启动 Hub 失败时返回错误，否则 nil。
func (n *Node) startHub() error {
	if n.hub != nil {
		return nil
	}
	hub, err := newHub(n)
	if err != nil {
		return err
	}
	n.hub = hub
	if err := hub.start(); err != nil {
		return err
	}
	n.Log.Info("downstream listening", "listen", n.C().Node.Listen, "path", n.SelfPath())
	return nil
}

// ensureStartedUpstream 上行会话还没起就起起来（入网后可能才具备条件）。
//
// 接收者 n 是本节点实例；已有会话、或本节点没有父时不动作。
func (n *Node) ensureStartedUpstream() {
	if n.up == nil && n.C().HasUpstream() {
		n.up = newUpstream(n)
		n.up.start()
	}
}

// ---------- 对外的小封装（命令行入口用） ----------

// EnsureCertificate 只做"确保有可用证书"：已有就直接返回，否则走一次运行期入网。
//
// 接收者 n 是本节点实例；供 `-enroll` 子命令（"只入网、不常驻"）使用。
// 带互斥，同一时刻只会有一个入网流程在跑。
//
// 参数：
//
//	ctx — 上下文
//
// 返回：
//
//	error — 拿到可用证书返回 nil，否则返回错误
func (n *Node) EnsureCertificate(ctx context.Context) error { return n.ensureCertWithLock(ctx, true) }

// HasUsableCert 报告本节点是否已持有可用证书（存在且未过期）。
//
// 接收者 n 是本节点实例；它是 hasUsableCert 的对外封装，供启动时打印
// "正常上线 / 待入网"那行日志用。
//
// 返回：
//
//	bool — 持有未过期证书时为 true
func (n *Node) HasUsableCert() bool { return n.hasUsableCert() }
