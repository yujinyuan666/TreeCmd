package node

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"treecmd/internal/canon"
	"treecmd/internal/config"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// ---------- 证书续签（7.7） ----------

const renewWindowNumerator = 2 // 在证书生命期 2/3 处主动续签

// needRenew 判断某证书是否进入续签窗口（剩余有效期 < 生命期的 1/3）。
//
// 参数：
//
//	cert — 待判断的证书；nil 视为不需要续签
//
// 返回：
//
//	bool — true 表示应尽快换发新证书
func needRenew(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	total := cert.NotAfter.Sub(cert.NotBefore)
	if total <= 0 {
		return true
	}
	remain := time.Until(cert.NotAfter)
	return remain < total/time.Duration(3)
}

// maybeOfferRenew 父在子 Connect / RESUME 时检查其证书剩余有效期，处于续签窗口即立即换发：
// 通过 DownFrame 把新证书链下发给该子。
//
// 接收者 n 是本节点实例；本方法在父这一侧执行。
//
// 参数：
//
//	cc   — 子的连接
//	leaf — 子的叶子证书；nil 或未进窗口时直接返回
func (n *Node) maybeOfferRenew(cc *childConn, leaf *x509.Certificate) {
	if leaf == nil || !needRenew(leaf) {
		return
	}
	chainPEM, err := identity.ReissueFor(leaf, n.Id())
	if err != nil {
		n.Log.Warn("cert renew: reissue failed", "child", shortID(cc.nodeID), "err", err)
		return
	}
	n.Log.Info("cert renew: offering new certificate", "child", shortID(cc.nodeID),
		"old_not_after", leaf.NotAfter.Format(time.RFC3339))
	_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_CertRenewOffer{
		CertRenewOffer: &pb.CertRenewOffer{CertChain: chainPEM, Reason: "renewal window (2/3 of lifetime)"},
	}})
}

// applyCertRenew 子收到换发：校验新证书仍是本节点身份且能验到信任锚，写入本地证书文件后
// 热更新 TLS 证书容器，并让现有连接以新证书重新握手。
//
// 接收者 n 是本节点实例；本方法在子这一侧执行。
//
// 参数：
//
//	offer — 父下发的 CertRenewOffer（内含 PEM 证书链）
//
// 返回：
//
//	error — 空链 / 链解析失败 / 身份不符 / 链不受信 / 写盘失败时返回；此时不替换内存中的证书
func (n *Node) applyCertRenew(offer *pb.CertRenewOffer) error {
	if len(offer.CertChain) == 0 {
		return fmt.Errorf("ERR_EMPTY_CERT_CHAIN")
	}
	chain, err := identity.ParseChainPEM(offer.CertChain)
	if err != nil || len(chain) == 0 {
		return fmt.Errorf("ERR_INVALID_CERT_CHAIN: %v", err)
	}
	// 新证书必须仍是本节点身份，且能验到信任锚
	if got := identity.NodeIDFromCert(chain[0]); got != n.C().Node.ID {
		return fmt.Errorf("ERR_CERT_IDENTITY_MISMATCH: %s vs %s", got, n.C().Node.ID)
	}
	inters := x509.NewCertPool()
	for _, c := range chain[1:] {
		inters.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: n.rootsPool(), Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("ERR_CERT_UNTRUSTED: %w", err)
	}
	// 先落盘（崩溃也不会丢新证书），再热切换
	if err := identity.WriteCertChainFile(n.C().Security.IdentityCertPath, chain); err != nil {
		return err
	}
	n.Id().Cert = chain[0]
	n.Id().Chain = chain
	n.certBox.Set(identity.TLSCertFrom(n.Id()))
	n.Log.Info("cert renewed", "not_after", chain[0].NotAfter.Format(time.RFC3339))
	// 让现有连接以新证书重新握手
	if n.up != nil {
		go n.up.forceReconnect("cert-renewed")
	}
	return nil
}

// checkSelfCertRenew 检查本节点证书是否进入续签窗口，是则向父请求续签。
//
// 接收者 n 是本节点实例。每次成功 Connect / RESUME 时顺带调用（保证恢复连接后第一时间拿到新证）。
func (n *Node) checkSelfCertRenew() {
	if !needRenew(n.Id().Cert) {
		return
	}
	n.Log.Info("cert renew: requesting on connect", "not_after", n.Id().Cert.NotAfter.Format(time.RFC3339))
	n.up.sendCertRenewReq("on connect (renewal window)")
}

// startCertRenewLoop 启动子节点本地的续签调度：每小时检查一次，进入窗口即主动请求续签
// （不依赖当前是否正连父；每次成功 Connect 也会顺带检查）。
//
// 接收者 n 是本节点实例；没有父（即本节点是根）时直接返回。
func (n *Node) startCertRenewLoop() {
	if n.up == nil {
		return
	}
	n.loop(time.Hour, 2*time.Minute, "cert-renew-check", func(context.Context) {
		if needRenew(n.Id().Cert) {
			n.Log.Info("cert renew: requesting from parent", "not_after", n.Id().Cert.NotAfter.Format(time.RFC3339))
			n.up.sendCertRenewReq("local schedule (2/3 of lifetime)")
		}
	})
}

// ---------- 根的自签续期（根没有父，只能自己签自己） ----------

// applySelfRenew 把自签续期得到的新证书链落盘，并同步更新内存里的身份包。
//
// 调用方**必须先用 `identity.ValidateStartup` 校验过新证书**再调它（见 loadIdentity / renewSelfCert）：
// 本函数只负责"写下去 + 换内存"，不做任何校验，以免把一张坏证书覆盖到好证书上。
//
// 参数：
//
//	cfg   — 本节点配置；写回目标是 security.identity_cert_path
//	id    — 本节点身份包（会被就地更新 Cert / Chain）
//	chain — 校验通过的新证书链，chain[0] 是新身份证书
//
// 返回：
//
//	error — 写盘失败时返回；此时内存与磁盘都保持原样
func applySelfRenew(cfg *config.Config, id *identity.Identity, chain []*x509.Certificate) error {
	if err := identity.WriteCertChainFile(cfg.Security.IdentityCertPath, chain); err != nil {
		return err
	}
	id.Cert, id.Chain = chain[0], chain
	return nil
}

// withChain 用一条新的证书链复制一份身份包（**不改原对象**）。
//
// 用途：先拿"换证后长什么样"去跑一遍启动强校验，通过了再决定要不要真的落盘。
//
// 参数：
//
//	id    — 原身份包（提供 NodeID / 私钥 / CA 材料）
//	chain — 待校验的新证书链
//
// 返回：
//
//	*identity.Identity — 只把 Cert / Chain 换掉的副本，其余字段原样引用
func withChain(id *identity.Identity, chain []*x509.Certificate) *identity.Identity {
	return &identity.Identity{
		NodeID: id.NodeID, Key: id.Key, Cert: chain[0], Chain: chain,
		CAKey: id.CAKey, CACert: id.CACert, CAChain: id.CAChain,
	}
}

// reissueChainForSelf 用本节点 CA 重签自己的身份证书并解析成证书链（**不落盘**）。
//
// 参数：
//
//	id — 本节点身份包；id.Cert 提供身份名与公钥，CAKey/CACert/CAChain 提供签发材料
//
// 返回：
//
//	[]*x509.Certificate — 新证书链（[新身份证书, 本节点 CA 证书…]）
//	error               — 无 CA 材料 / 旧证书不是 Ed25519 / 新证书身份与旧的不一致时返回
func reissueChainForSelf(id *identity.Identity) ([]*x509.Certificate, error) {
	if id == nil || id.Cert == nil {
		return nil, errors.New("identity certificate missing")
	}
	if id.CAKey == nil || id.CACert == nil {
		return nil, errors.New("no CA material to sign with（本节点不持 CA 私钥与 CA 证书）")
	}
	pemBytes, err := identity.ReissueFor(id.Cert, id)
	if err != nil {
		return nil, err
	}
	chain, err := identity.ParseChainPEM(pemBytes)
	if err != nil || len(chain) == 0 {
		return nil, fmt.Errorf("自签续期结果无法解析: %v", err)
	}
	// 续签是"同一身份换一张证"，身份变了说明中间出了错，宁可失败
	if got := identity.NodeIDFromCert(chain[0]); got != id.NodeID {
		return nil, fmt.Errorf("自签续期后的证书身份不符: %s != %s", got, id.NodeID)
	}
	return chain, nil
}

// renewSelfCert 运行期的自签续期：重签 → 与启动同一强度校验 → 原子落盘 → 热切换 TLS 材料。
//
// 接收者 n 是本节点实例；带互斥，同一时刻只会有一个自续在跑。
//
// 参数：
//
//	reason — 触发原因（仅用于日志）
//
// 返回：
//
//	error — 无 CA 材料 / 新证书校验不过 / 落盘失败时返回；失败时**继续用旧证书**（fail-safe）
func (n *Node) renewSelfCert(reason string) error {
	n.selfRenewMu.Lock()
	defer n.selfRenewMu.Unlock()

	if !n.canSelfRenew() {
		return errors.New("本节点不能自签续期（有父的节点由父签发；没有 CA 材料则无从自签）")
	}
	cur := n.Id()
	chain, err := reissueChainForSelf(cur)
	if err != nil {
		return err
	}
	// 先按"启动同一强度"校验**新证书**再落盘：宁可续不上，也不能把一张坏证书写进去
	pub, err := identity.LoadPublicKeyFile(n.C().Security.IdentityPubKeyPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}
	if err := identity.ValidateStartup(withChain(cur, chain), identity.PoolCerts(n.rootsPool()), pub); err != nil {
		return fmt.Errorf("自签续期未通过启动强度校验: %w", err)
	}
	if err := applySelfRenew(n.C(), cur, chain); err != nil {
		return err
	}
	n.certBox.Set(identity.TLSCertFrom(cur))
	// 这份文件是我们自己写的 → 重算监视基线，免得被当成"外部变更"再触发一轮重载
	n.refreshReloadBaseline()
	n.Log.Info("cert self-renew: applied", "reason", reason,
		"not_after", canonTime(chain[0]), "fingerprint", certSha256(chain[0]))
	return nil
}

// canSelfRenew 本节点能否"自签续期"：**没有父**（即根），且自己持有 CA 材料。
//
// 有父的节点一律不自签：它的身份证书必须由父签发，自己签自己会破坏"父签发子"的授权模型。
//
// 接收者 n 是本节点实例（要求已完成装配、n.up 已确定）。
//
// 返回：
//
//	bool — true 表示可以自己重签自己的身份证书
func (n *Node) canSelfRenew() bool {
	if n.up != nil {
		return false
	}
	id := n.Id()
	return id != nil && id.Cert != nil && id.CAKey != nil && id.CACert != nil
}

// startSelfRenewLoop 启动"根自签续期"调度：没有父、但持有 CA 材料的节点（即根）每小时检查一次，
// 进入续签窗口就自己重签一张。
//
// 与 startCertRenewLoop 互斥且互补：有父的节点由**父**给它签（子自己没 CA 材料）；
// 没有父的就是根，只能自签。
//
// 接收者 n 是本节点实例。
func (n *Node) startSelfRenewLoop() {
	if !n.canSelfRenew() {
		return // 有父（走"父给子签"）或没有 CA 材料（无从自签）
	}
	n.loop(time.Hour, 2*time.Minute, "cert-self-renew", func(context.Context) {
		if !needRenew(n.Id().Cert) {
			return
		}
		n.Log.Info("cert self-renew: certificate in renewal window", "not_after", canonTime(n.Id().Cert))
		if err := n.renewSelfCert("local schedule (2/3 of lifetime)"); err != nil {
			n.Log.Warn("cert self-renew failed", "err", err)
		}
	})
}

// ---------- 配置热更（SIGHUP / ConfigPush） ----------

// Reload 重新读取 node.yaml：只允许运行参数变更；进 config_hash 的字段一变就全量重注册。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	error — 启动时未记录配置路径、或配置文件读取/校验失败时返回；成功（含已触发重连）返回 nil
func (n *Node) Reload() error {
	if n.cfgPath == "" {
		return fmt.Errorf("no config path recorded (启动时未传 -config)")
	}
	old := n.C()
	fresh, err := config.Load(n.cfgPath)
	if err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	// Build 是程序填的运行时字段（不来自 node.yaml）：热更会整体换掉配置对象，
	// 所以这里必须把它补回去，否则"我是哪份镜像"在新对象上就丢了。
	fresh.Build = n.selfBuild
	if fresh.ConfigHash() != old.ConfigHash() {
		// 影响拓扑 / 会话 / 身份 / 父列表 / 监听地址的字段变了 → 旧会话必须失效
		n.cfg.Store(fresh)
		n.Log.Warn("config reload: 关键字段变更 → 触发全量重注册（旧会话失效）")
		if n.up != nil {
			go n.up.forceReconnect("config-hash-changed")
		}
		return nil
	}
	// 元信息（node.name / node.remark，ADR-051）不进 config_hash —— 改个显示名不该被当成拓扑变更。
	// 但它要能同步给父：所以这里主动重注册一次（否则得等下次自然重连才生效）。
	metaChanged := fresh.Node.Name != old.Node.Name || fresh.Node.Remark != old.Node.Remark
	n.cfg.Store(fresh)
	if metaChanged {
		n.Log.Info("config reload: 节点元信息变更 → 重注册以同步给父",
			"name", fresh.Node.Name, "remark", fresh.Node.Remark)
		if n.up != nil {
			go n.up.forceReconnect("node-meta-changed")
		}
		return nil
	}
	n.Log.Info("config reload: 仅运行参数热更（config_hash 未变，不重注册）")
	return nil
}

// applyConfigOverrides 应用父经 ConfigPush 下发的运行参数覆盖：逐项解析 key=value，
// 非运行参数白名单的项忽略并告警（只允许运行参数段）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	reason    — 下发原因（仅用于日志）
//	overrides — "key=value" 形式的覆盖项列表
func (n *Node) applyConfigOverrides(reason string, overrides []string) {
	if len(overrides) == 0 {
		return
	}
	fresh := *n.C() // 浅拷贝：只改运行参数段
	applied := 0
	for _, kv := range overrides {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		key, val := kv[:i], kv[i+1:]
		if !allowedHotKey(key) {
			n.Log.Warn("ConfigPush 忽略非运行参数项", "key", key, "reason", reason)
			continue
		}
		if applyRuntimeParam(&fresh, key, val) {
			applied++
		}
	}
	n.cfg.Store(&fresh)
	n.Log.Info("ConfigPush applied", "reason", reason, "applied", applied, "total", len(overrides))
}

// allowedHotKey 判断配置键是否属于可热更的运行参数段（运行参数，不进 config_hash）。
//
// 参数：
//
//	key — 配置键名
//
// 返回：
//
//	bool — 是否以 command./health./query./persist. 开头
func allowedHotKey(key string) bool {
	for _, p := range []string{"command.", "health.", "query.", "persist."} {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// applyRuntimeParam 按配置键把字符串取值解析出来并写入配置对象的对应字段。
//
// 参数：
//
//	c   — 就地修改的配置对象（只动运行参数段）
//	key — 配置键名
//	val — 字符串形式的取值
//
// 返回：
//
//	bool — 键被识别且解析成功时为 true
func applyRuntimeParam(c *config.Config, key, val string) bool {
	// dur 解析时长字符串（如 "30s"），成功则写入 d
	dur := func(d *time.Duration) bool {
		v, err := time.ParseDuration(val)
		if err != nil {
			return false
		}
		*d = v
		return true
	}
	// sz 解析字节大小字符串（如 "1MB"），成功则写入 d
	sz := func(d *config.ByteSize) bool {
		v, err := config.ParseByteSize(val)
		if err != nil {
			return false
		}
		*d = config.ByteSize(v)
		return true
	}
	// num 解析整数，成功则写入 d
	num := func(d *int32) bool {
		v, err := strconv.Atoi(val)
		if err != nil {
			return false
		}
		*d = int32(v)
		return true
	}
	switch key {
	case "command.lease_ttl":
		return dur(&c.Command.LeaseTTL)
	case "command.renew_at":
		return dur(&c.Command.RenewAt)
	case "command.max_deadline":
		return dur(&c.Command.MaxDeadline)
	case "command.child_stuck_timeout":
		return dur(&c.Command.ChildStuckTimeout)
	case "command.local_busy_backoff":
		return dur(&c.Command.LocalBusyBackoff)
	case "command.audit_retention":
		return dur(&c.Command.AuditRetention)
	case "command.eviction_timeout":
		return dur(&c.Command.EvictionTimeout)
	case "command.lease_reclaim_cap":
		return num(&c.Command.LeaseReclaimCap)
	case "command.max_retry_node_count":
		return num(&c.Command.MaxRetryNodeCount)
	case "command.max_inflight":
		return num(&c.Command.MaxInflight)
	case "command.max_payload":
		return sz(&c.Command.MaxPayload)
	case "command.fetch_response_max_bytes":
		return sz(&c.Command.FetchResponseMaxBytes)
	case "health.max_health_fanout":
		return num(&c.Health.MaxHealthFanout)
	case "health.health_response_max_bytes":
		return sz(&c.Health.ResponseMaxBytes)
	case "query.query_response_max_bytes":
		return sz(&c.Query.QueryResponseMaxBytes)
	case "query.req_auth_ttl":
		return dur(&c.Query.ReqAuthTTL)
	case "persist.interval":
		return dur(&c.Persist.Interval)
	}
	return false
}

// ---------- 重连对账（Reconcile，3.7） ----------

// sendReconcile 子重连后向父上报本地仍未终态的指令（父离线验 origin 签名后重建）。
//
// 接收者 n 是本节点实例；本方法在子这一侧执行，没有父时直接返回。
func (n *Node) sendReconcile() {
	if n.up == nil {
		return
	}
	var locals []*pb.LocalCommandRecord
	_ = n.Store.View(func(tx *store.Tx) error {
		locals = tx.ScanLocal()
		return nil
	})
	sent := 0
	for _, lc := range locals {
		switch lc.LocalState {
		case pb.LocalExecState_LOCAL_STATE_NOT_STARTED,
			pb.LocalExecState_LOCAL_STATE_SELF_RUNNING,
			pb.LocalExecState_LOCAL_STATE_SELF_DONE:
		default:
			continue // 已终态：不参与对账
		}
		if len(lc.Command) == 0 {
			continue
		}
		n.up.sendReconcile(lc.CommandId, lc.Command)
		sent++
	}
	if sent > 0 {
		n.Log.Info("reconcile: 上报本地未终态指令", "count", sent)
	}
}

// handleReconcile 父端处理子上报的对账请求：① 内联 OriginCert 离线验 origin 签名；
// ② 与我持有的指令体逐字节比对；一致（或无记录）则重建 / 重置该子的 Assignment 并重新投递；
// 不一致即拒绝并告警。
//
// 接收者 n 是本节点实例；本方法在父这一侧执行。
//
// 参数：
//
//	childID — 上报的子节点 ID
//	r       — 对账请求（含指令 ID 与完整 wire Command）
//
// 返回：
//
//	error — 解包失败 / 验签或跳证明失败 / 指令体不一致 / 无对应 Assignment 时返回
func (n *Node) handleReconcile(childID string, r *pb.Reconcile) error {
	c := &pb.Command{}
	if err := proto.Unmarshal(r.Command, c); err != nil {
		return fmt.Errorf("ERR_BAD_RECONCILE: %w", err)
	}
	if c.Id != r.CommandId {
		return fmt.Errorf("ERR_BAD_RECONCILE: command id mismatch")
	}
	if err := verifyOrigin(c); err != nil {
		n.auditReject("reconcile_origin", childID, c.Id, err)
		return err
	}
	// 子必须是自己名下的、且 Command 末条 HopAttest 指向自己
	if err := n.verifyHop(n.C().Node.ID, nil, c); err != nil {
		n.auditReject("reconcile_hop", childID, c.Id, err)
		return err
	}

	rec, hasRec := n.records(c.Id)
	if hasRec && rec != nil {
		// 父仍持有指令体 → 用同一 attempt 重新派生，逐字节比对
		a, ok := n.assignment(c.Id, childID)
		if !ok {
			return fmt.Errorf("NO_SUCH_ASSIGNMENT")
		}
		base := &pb.Command{}
		if err := proto.Unmarshal(rec.Command, base); err != nil {
			return err
		}
		if a.DerivedCommand != nil {
			// 已有派生基线：直接比对（canonical 编码逐字节）
			if string(a.DerivedCommand) != string(r.Command) {
				d1, _ := canon.Digest(mustUnmarshalCommand(a.DerivedCommand))
				d2, _ := canon.Digest(c)
				if string(d1) != string(d2) {
					n.auditReject("reconcile_mismatch", childID, c.Id, fmt.Errorf("指令体与父侧记录不一致"))
					return fmt.Errorf("ERR_RECONCILE_MISMATCH")
				}
			}
		}
		_ = n.Store.Update(func(tx *store.Tx) error {
			a2, ok := tx.GetAssignment(c.Id, childID)
			if !ok || isTerminalAssign(a2.Status) {
				return nil
			}
			a2.Status = pb.AssignStatus_ASSIGN_STATUS_PENDING
			a2.NextAttempt = maxU64(a2.DeliveredAttempt, 1)
			a2.BackoffUntil = nil
			a2.UpdatedAt = canon.TS(tx.Now)
			return tx.PutAssignment(a2)
		})
		_ = n.Store.Update(func(tx *store.Tx) error { return tx.DeleteEvicted(childID, c.Id) })
		n.hub.notify(childID, rec.LocalSeq)
		n.Log.Info("reconcile: 复用已有记录并重投", "child", shortID(childID), "cmd", shortID(c.Id))
		return nil
	}

	// 父已无记录（曾被清理 / 曾被驱逐）→ 用子上报的完整 wire Command 重建
	if ev, ok := n.evicted(childID, c.Id); ok {
		_ = proto.Unmarshal(ev.Command, c)
		n.Log.Info("reconcile: 从 evicted_children 归档恢复", "child", shortID(childID), "cmd", shortID(c.Id))
	}
	var seq int64
	if err := n.Store.Update(func(tx *store.Tx) error {
		s, err := tx.AllocLocalSeq()
		if err != nil {
			return err
		}
		seq = s
		rec2 := &pb.CommandRecord{CommandId: c.Id, LocalSeq: s, Command: r.Command,
			Status: pb.CommandStatus_COMMAND_STATUS_RUNNING, UpdatedAt: canon.TS(tx.Now)}
		if err := tx.PutCommand(rec2); err != nil {
			return err
		}
		a := &pb.AssignmentRecord{CommandId: c.Id, ChildId: childID,
			Status: pb.AssignStatus_ASSIGN_STATUS_PENDING, LocalSeq: s, NextAttempt: 1, UpdatedAt: canon.TS(tx.Now)}
		if err := tx.PutAssignment(a); err != nil {
			return err
		}
		return tx.DeleteEvicted(childID, c.Id)
	}); err != nil {
		return err
	}
	n.hub.notify(childID, seq)
	n.Log.Warn("reconcile: 父侧无记录，已按子上报的指令体重建并重投", "child", shortID(childID), "cmd", shortID(c.Id), "local_seq", seq)
	return nil
}

// mustUnmarshalCommand 把 Command 的 protobuf 字节反序列化；出错时忽略错误，返回未被填充的 Command。
//
// 参数：
//
//	b — Command 的 protobuf 编码字节
//
// 返回：
//
//	*pb.Command — 反序列化结果（失败时字段为空）
func mustUnmarshalCommand(b []byte) *pb.Command {
	c := &pb.Command{}
	_ = proto.Unmarshal(b, c)
	return c
}

// evicted 在本节点的 evicted_children 归档里查一条被驱逐指令的记录。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	childID — 子节点 ID
//	cmdID   — 指令 ID
//
// 返回：
//
//	*pb.EvictedEntry — 命中时的归档条目
//	bool            — 是否命中
func (n *Node) evicted(childID, cmdID string) (*pb.EvictedEntry, bool) {
	var (
		e  *pb.EvictedEntry
		ok bool
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		e, ok = tx.GetEvicted(childID, cmdID)
		return nil
	})
	return e, ok
}

// ---------- 驱逐与归档（3.7） ----------

// scanEvictions 驱逐扫描（5m 周期）：超 eviction_timeout 未出现的子节点置 EVICTED（从保留水位计算中剔除），
// 并先把它名下未终态 Assignment 的指令体归档到 evicted_children —— 否则会出现"子还在跑、父已无记录"的悬挂。
//
// 接收者 n 是本节点实例；本方法在父这一侧执行，没有子（hub 为空）时直接返回。
//
// 参数：
//
//	_ — 未使用的 context（由统一的 loop 调度器传入）
func (n *Node) scanEvictions(_ context.Context) {
	if n.hub == nil {
		return
	}
	now := time.Now()
	err := n.Store.Update(func(tx *store.Tx) error {
		for _, wm := range tx.ScanWatermarks() {
			if wm.Evicted || wm.LastSeenAt == nil {
				continue
			}
			if now.Sub(canon.Time(wm.LastSeenAt)) <= n.C().Command.EvictionTimeout {
				continue
			}
			archived := 0
			// 按该子名下所有指令遍历
			for _, cmdID := range tx.CommandIDsOfChild(wm.ChildId) {
				a, ok := tx.GetAssignment(cmdID, wm.ChildId)
				if !ok || isTerminalAssign(a.Status) {
					continue
				}
				rec, ok := tx.GetCommand(cmdID)
				if !ok {
					continue
				}
				e := &pb.EvictedEntry{
					ChildId: wm.ChildId, CommandId: cmdID, Command: rec.Command,
					ArchivedAt: canon.TS(tx.Now),
					ExpireAt:   canon.TS(tx.Now.Add(n.C().Command.EvictionArchiveRetention)),
				}
				if err := tx.PutEvicted(e); err != nil {
					return err
				}
				archived++
			}
			wm.Evicted = true
			wm.EvictedAt = canon.TS(tx.Now)
			if err := tx.PutWatermark(wm); err != nil {
				return err
			}
			n.Log.Warn("child evicted", "child", shortID(wm.ChildId),
				"last_seen", canon.Time(wm.LastSeenAt).Format(time.RFC3339), "archived", archived)
		}
		return nil
	})
	if err != nil {
		n.Log.Warn("eviction scan failed", "err", err)
	}
}

// cleanupEvicted 归档保留期到期后回收归档条目与该子的 ChildWatermark（否则表无界增长）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	_ — 未使用的 context（由统一的 loop 调度器传入）
func (n *Node) cleanupEvicted(_ context.Context) {
	now := time.Now()
	_ = n.Store.Update(func(tx *store.Tx) error {
		for _, e := range tx.ScanEvicted() {
			if e.ExpireAt != nil && canon.Time(e.ExpireAt).Before(now) {
				_ = tx.DeleteEvicted(e.ChildId, e.CommandId)
			}
		}
		for _, wm := range tx.ScanWatermarks() {
			if !wm.Evicted || wm.EvictedAt == nil {
				continue
			}
			if now.Sub(canon.Time(wm.EvictedAt)) > n.C().Command.EvictionArchiveRetention {
				n.Log.Info("evicted entry reclaimed", "child", shortID(wm.ChildId))
				_ = tx.DeleteWatermark(wm.ChildId)
			}
		}
		return nil
	})
}

// resendResultIndexes 结果索引待重发队列（3.14）：上报失败的索引入队持久化，链路通后重发。
//
// 接收者 n 是本节点实例；没有父时直接返回。每次最多取 32 条，逐条重发后从队列删除。
func (n *Node) resendResultIndexes() {
	if n.up == nil {
		return
	}
	var pending map[string][]byte
	_ = n.Store.View(func(tx *store.Tx) error {
		pending = tx.ScanPendingIndex(32)
		return nil
	})
	for cmdID, raw := range pending {
		idx := &pb.ResultIndexUp{}
		if err := proto.Unmarshal(raw, idx); err != nil {
			_ = n.Store.Update(func(tx *store.Tx) error { return tx.DeletePendingIndex(cmdID) })
			continue
		}
		n.up.sendResultIndex(idx)
		_ = n.Store.Update(func(tx *store.Tx) error { return tx.DeletePendingIndex(cmdID) })
	}
}

// queuedResultIndex 把待重发索引入队（上报失败时调用），并累加对应的指标计数。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	idx — 待重发的结果索引上报
func (n *Node) queuedResultIndex(idx *pb.ResultIndexUp) {
	b, err := proto.Marshal(idx)
	if err != nil {
		return
	}
	_ = n.Store.Update(func(tx *store.Tx) error { return tx.PutPendingIndex(idx.CommandId, b) })
	n.Metrics.Inc("result_index_pending_resend_total")
}
