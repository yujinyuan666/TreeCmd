package node

import (
	"context"
	"crypto/ed25519"
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

// handleCertRenewReq 父端处理子的续签请求（含可选的 CA 证书续签）。
//
// 与 maybeOfferRenew 的分工：
//   - maybeOfferRenew 是"父在子 Connect / RESUME 时看到**叶子证书**进窗口就顺手换发"，
//     它只看身份证书；
//   - 本函数是"子显式请求"，**CA 证书只有这一条路径能换** —— 父手上只有子的身份证书
//     （mTLS 握手拿到的就是叶子证书），并不知道子的 CA 证书什么时候过期，所以由子自报。
//
// 一次应答里两边各算各的，**都可以为空**：本次只换 CA 证书、或只换身份证书，都是正常组合；
// 两个都空就不发（避免制造无意义的帧）。
//
// 接收者 n 是本节点（父侧）。本方法由 dispatch 在读循环里调用，所以发送走 cc.send
// （非阻塞）—— 一帧证书链远小于缓冲上限，不必像分片那样限速。
//
// 参数：
//
//	cc  — 发起请求的子连接
//	req — 子发来的续签请求
func (n *Node) handleCertRenewReq(cc *childConn, req *pb.CertRenewReq) {
	if cc == nil {
		return
	}
	offer := &pb.CertRenewOffer{}
	if needRenew(cc.leaf) {
		chainPEM, err := identity.ReissueFor(cc.leaf, n.Id())
		if err != nil {
			n.Log.Warn("cert renew: reissue failed", "child", shortID(cc.nodeID), "err", err)
		} else {
			offer.CertChain = chainPEM
			offer.Reason = req.GetReason()
		}
	}
	if req.GetWantCa() {
		caPEM, err := n.reissueChildCA(cc, req.GetCaCert())
		if err != nil {
			n.Log.Warn("ca renew: refused", "child", shortID(cc.nodeID), "err", err)
			n.Metrics.Inc("ca_rotate_total", "result", "refused")
		} else {
			offer.CaCertChain = caPEM
			n.Metrics.Inc("ca_rotate_total", "result", "offered")
		}
	}
	if len(offer.CertChain) == 0 && len(offer.CaCertChain) == 0 {
		n.Log.Debug("cert renew: nothing to offer", "child", shortID(cc.nodeID), "reason", req.GetReason())
		return
	}
	n.Log.Info("cert renew: offering", "child", shortID(cc.nodeID),
		"cert", len(offer.CertChain) > 0, "ca", len(offer.CaCertChain) > 0, "reason", req.GetReason())
	_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion,
		Frame: &pb.DownFrame_CertRenewOffer{CertRenewOffer: offer}})
}

// reissueChildCA 校验子提交的"当前 CA 证书"，并用本节点 CA 重签一张**同一把密钥**的新 CA 证书。
//
// 为什么必须让子把当前那张 CA 证书一起交上来：这是"只换证书、不换密钥"唯一的依据。
// 如果父只是"你说 want_ca 我就签一个 CA 证书"，那么拿到子身份密钥的人就能借续签之名
// 把子的 CA 公钥换掉 —— 那是另一件需要全树重新分发 trust/ 的事，绝不该被静默允许。
//
// 四道校验：能解析 / IsCA + certSign / CN 含该子 ID / 能验到本节点的信任锚。
// 通过之后签出来的新 CA 证书，公钥与 CN 都沿用提交的那张（见 identity.ReissueCAFor）。
//
// 接收者 n 是本节点（父侧）。
//
// 参数：
//
//	cc    — 发起请求的子连接（提供权威的子节点 ID）
//	caDER — 子提交的当前 CA 叶子证书（DER）
//
// 返回：
//
//	[]byte — 新 CA 证书链（PEM）；校验不过时为 nil
//	error  — 本节点无 CA 材料 / 子未提交证书 / 四项校验任一不过 / 签发失败时返回
func (n *Node) reissueChildCA(cc *childConn, caDER []byte) ([]byte, error) {
	if n.Id().CAKey == nil || n.Id().CACert == nil {
		return nil, errors.New("本节点没有 CA 材料，无法签发 CA 证书")
	}
	if cc == nil || cc.nodeID == "" {
		return nil, errors.New("ERR_CHILD_UNKNOWN: 拿不到子节点的权威身份")
	}
	if len(caDER) == 0 {
		return nil, errors.New("ERR_CA_CERT_MISSING: 请求 CA 续签时必须同时提交当前的 CA 证书")
	}
	oldCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("ERR_CA_CERT_UNPARSEABLE: %w", err)
	}
	if !oldCA.IsCA || oldCA.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("ERR_CA_CERT_INVALID: 提交的证书不是 CA 证书（缺 basicConstraints/keyUsage）")
	}
	if !strings.Contains(oldCA.Subject.CommonName, cc.nodeID) {
		return nil, fmt.Errorf("ERR_CA_CERT_CN_MISMATCH: CN %q 不含子节点 ID %s",
			oldCA.Subject.CommonName, shortID(cc.nodeID))
	}
	// 它必须是"本树里签发出来的"：把本节点的 CA 链当作中间证书，让它接到本节点的信任锚。
	// 这一条同时挡住"拿别的树的 CA 证书来换一张我们签的"。
	// patchChain = [待验的 CA 证书, 本节点 CA 链...]：中间证书要一并给出，才能逐级上溯。
	patchChain := append([]*x509.Certificate{oldCA}, n.Id().CAChain...)
	if err := identity.ChainToAnchor(patchChain, identity.PoolCerts(n.rootsPool()), 0); err != nil {
		return nil, fmt.Errorf("ERR_CA_CERT_UNTRUSTED: %w", err)
	}
	_, pemBytes, err := identity.ReissueCAFor(oldCA, n.Id())
	return pemBytes, err
}

// applyCertRenew 子收到换发：校验新证书仍是本节点身份且能验到信任锚，写入本地证书文件后
// 热更新 TLS 证书容器，并让现有连接以新证书重新握手。
//
// 一次 offer 里可能带两种东西，**CA 证书链先处理**（身份证书链的签发者可能就是它）：
//   - CertChain   新的身份证书链（父用自身 CA 重签**同一把身份公钥**）
//   - CaCertChain 新的 **CA 证书链**（父用自身 CA 重签**同一把 CA 公钥**）—— 可空
//
// 两者**都可以单独出现**：本次只轮换 CA 证书、身份证书还没进窗口，是完全正常的组合。
// 两个都空才视为协议错误。
//
// 接收者 n 是本节点实例；本方法在子这一侧执行。
//
// 参数：
//
//	offer — 父下发的 CertRenewOffer
//
// 返回：
//
//	error — 空链 / 解析失败 / 身份不符 / 链不受信 / 写盘失败时返回；此时不替换内存中的证书
func (n *Node) applyCertRenew(offer *pb.CertRenewOffer) error {
	gotCA := false
	if len(offer.GetCaCertChain()) > 0 {
		if err := n.applyCACertRenew(offer.GetCaCertChain()); err != nil {
			return err
		}
		gotCA = true
	}
	if len(offer.CertChain) == 0 {
		if !gotCA {
			return fmt.Errorf("ERR_EMPTY_CERT_CHAIN")
		}
		return nil // 只轮换了 CA 证书，不动身份证书
	}
	chain, err := identity.ParseChainPEM(offer.CertChain)
	if err != nil || len(chain) == 0 {
		return fmt.Errorf("ERR_INVALID_CERT_CHAIN: %v", err)
	}
	// 新证书必须仍是本节点身份，且能接到信任锚。
	// 走 identity.ChainToAnchor 而不是裸 Verify：它会认下"CA 证书已在线轮换"的形态
	// （链末端与信任锚同密钥、不同证书），否则轮换一次之后续签就再也装不上了。
	if got := identity.NodeIDFromCert(chain[0]); got != n.C().Node.ID {
		return fmt.Errorf("ERR_CERT_IDENTITY_MISMATCH: %s vs %s", got, n.C().Node.ID)
	}
	if err := identity.ChainToAnchor(chain, identity.PoolCerts(n.rootsPool()), 0); err != nil {
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

// applyCACertRenew 处理 offer 里的 CA 证书链（**子侧**）。
//
// 三道校验，任何一道不过都不落盘、继续用旧 CA 证书（fail-safe）：
//
//  1. **只是"同一把密钥换一张证书"** —— 新 CA 证书的公钥必须与当前那张**逐字节相同**。
//     这一条是"CA 证书轮换不破坏下级信任"的前提，也是"不许借续签之机换掉 CA 密钥"的闸门。
//  2. CA 证书的基本属性必须与**启动强校验同口径**（IsCA / keyUsage certSign / CN 含本节点 ID），
//     否则换了以后本节点下次启动就会 REFUSE TO START。
//  3. 新 CA 证书链能验到本节点的信任锚。
//
// 注意**不重建信任锚池**：信任锚是父 / 根，不是自己；轮换自己的 CA 证书跟它没有关系。
// 也**不触发重连**：TLS 上出示的是身份证书链（id.Chain），里面并不含本节点自己的 CA 证书，
// 所以换 CA 证书不影响现有会话。
//
// 接收者 n 是本节点实例；本方法在子这一侧执行。
//
// 参数：
//
//	pemBytes — 父下发的 CA 证书链（PEM 串接），pemBytes[0] 是新 CA 证书
//
// 返回：
//
//	error — 本节点没有 CA 私钥 / 解析失败 / 换公钥 / 属性不符 / 不受信 / 写盘失败时返回
func (n *Node) applyCACertRenew(pemBytes []byte) error {
	id := n.Id()
	if id == nil || id.CAKey == nil || id.CACert == nil {
		return errors.New("ERR_CA_UNEXPECTED: 本节点没有 CA 材料，不该收到 CA 证书续签")
	}
	chain, err := identity.ParseChainPEM(pemBytes)
	if err != nil || len(chain) == 0 {
		return fmt.Errorf("ERR_INVALID_CA_CERT_CHAIN: %v", err)
	}
	newCA := chain[0]
	// ① 同一把密钥 —— 这是整个机制成立的前提，所以放在最前面
	oldPub, ok1 := id.CACert.PublicKey.(ed25519.PublicKey)
	newPub, ok2 := newCA.PublicKey.(ed25519.PublicKey)
	if !ok1 || !ok2 || !oldPub.Equal(newPub) {
		return errors.New("ERR_CA_KEY_CHANGED: 父给的 CA 证书换了公钥 —— " +
			"本项目只支持轮换 CA 证书、不支持轮换 CA 密钥（换密钥要全树重新分发 trust/）")
	}
	// ② 与启动强校验同口径
	if !newCA.IsCA {
		return errors.New("ERR_CA_CERT_INVALID: 新 CA 证书 basicConstraints 不是 CA:TRUE")
	}
	if newCA.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("ERR_CA_CERT_INVALID: 新 CA 证书缺少 keyUsage certSign")
	}
	if !strings.Contains(newCA.Subject.CommonName, n.C().Node.ID) {
		return fmt.Errorf("ERR_CA_CERT_CN_INVALID: CN %q 不含本节点 ID %s", newCA.Subject.CommonName, shortID(n.C().Node.ID))
	}
	// ③ 能接到信任锚（同样走 ChainToAnchor：它认下"同密钥、不同证书"的轮换形态）
	if err := identity.ChainToAnchor(chain, identity.PoolCerts(n.rootsPool()), 0); err != nil {
		return fmt.Errorf("ERR_CA_CERT_UNTRUSTED: %w", err)
	}
	if n.C().Security.CACertPath == "" {
		return errors.New("ERR_NO_CA_CERT_PATH: 本节点未配置 security.ca_cert_path，无法落盘 CA 证书")
	}
	// 先落盘再热切换（与身份证书同一顺序）
	if err := identity.WriteCertChainFile(n.C().Security.CACertPath, chain); err != nil {
		return err
	}
	id.CACert, id.CAChain = newCA, chain
	// 这份文件是我们自己写的 → 重算监视基线，免得被当成"外部变更"再触发一轮重载
	n.refreshReloadBaseline()
	n.Metrics.Inc("ca_rotate_total", "result", "installed")
	n.Log.Warn("CA 证书已更新（同一把密钥、只换证书）：本节点此后给下级签发用的是新证书，"+
		"而下级手里的旧 CA 证书在其有效期内仍然有效 —— 不需要重新入网、不需要重新分发 trust/",
		"ca_not_after", canonTime(newCA), "ca_fingerprint", certSha256(newCA))
	return nil
}

// checkSelfCertRenew 检查本节点证书是否进入续签窗口，是则向父请求续签。
//
// 接收者 n 是本节点实例。每次成功 Connect / RESUME 时顺带调用（保证恢复连接后第一时间拿到新证）。
func (n *Node) checkSelfCertRenew() {
	if !certsNeedRenew(n.Id()) {
		return
	}
	n.Log.Info("cert renew: requesting on connect",
		"cert_not_after", n.Id().Cert.NotAfter.Format(time.RFC3339), "want_ca", n.caNeedsRenew())
	n.requestCertRenew("on connect (renewal window)")
}

// requestCertRenew 向父发一次续签请求（按需顺带请求 CA 证书续签）。
//
// 为什么要由**子**来判 CA 证书的窗口、而不是父：父手上只有子的身份证书（mTLS 握手拿到的
// 就是叶子证书），并不知道子的 CA 证书什么时候过期。让子自报更简单，也不违反既有风格
// —— 父仍然不认子的"时间判断"，它只负责"你要我就签"，签发本身还要过"同一把密钥"那道校验
// （见 handleCertRenewReq）。
//
// 接收者 n 是本节点实例；没有上行（根）时什么都不做。
//
// 参数：
//
//	reason — 触发原因（原样带给父，只用于日志）
func (n *Node) requestCertRenew(reason string) {
	if n.up == nil {
		return
	}
	req := &pb.CertRenewReq{Reason: reason, WantCa: n.caNeedsRenew()}
	if req.WantCa && n.Id().CACert != nil {
		// 带上"当前这张 CA 证书"（DER），父据此确认要续的是**同一把密钥**。
		// 它是整条链上唯一能证明"只换证书、不换密钥"的东西，见 proto 里 CertRenewReq 的注释。
		req.CaCert = n.Id().CACert.Raw
	}
	n.up.sendCertRenewReq(req)
}

// caNeedsRenew 判断本节点自己的 CA 证书是否进入续签窗口。
//
// 接收者 n 是本节点实例。只有持有 CA 材料的节点（根 / 中继）才有 CA 证书，叶子恒为 false。
//
// 返回：
//
//	bool — 持有 CA 证书且它已进窗口时为 true
func (n *Node) caNeedsRenew() bool {
	id := n.Id()
	return id != nil && id.CACert != nil && needRenew(id.CACert)
}

// startCertRenewLoop 启动子节点本地的续签调度：每小时检查一次，进入窗口即主动请求续签
// （不依赖当前是否正连父；每次成功 Connect 也会顺带检查）。
//
// 接收者 n 是本节点实例；没有父（即本节点是根）时直接返回。
// **身份证书与自己的 CA 证书一起判**，所以中继的 CA 证书也能靠这条循环自动换新。
func (n *Node) startCertRenewLoop() {
	if n.up == nil {
		return
	}
	n.loop(time.Hour, 2*time.Minute, "cert-renew-check", func(context.Context) {
		if certsNeedRenew(n.Id()) {
			n.Log.Info("cert renew: requesting from parent",
				"cert_not_after", n.Id().Cert.NotAfter.Format(time.RFC3339), "want_ca", n.caNeedsRenew())
			n.requestCertRenew("local schedule (2/3 of lifetime)")
		}
	})
}

// ---------- 根的自签续期（根没有父，只能自己签自己） ----------

// applySelfRenew 把自签续期得到的材料落盘，并同步更新内存里的身份包。
//
// 调用方**必须先用 `identity.ValidateStartup` 校验过候选材料**再调它（见 loadIdentity / renewSelfCert）：
// 本函数只负责"写下去 + 换内存"，不做任何校验，以免把坏证书覆盖到好证书上。
//
// 落盘顺序是"先 CA、后身份"：两者是同一把密钥的两次表述，任一步崩溃都可恢复
// （旧身份证书能被新 CA 证书验通、新身份证书也能被旧 CA 证书验通，因为公钥没变），
// 所以这里不需要额外的事务语义。
//
// 参数：
//
//	cfg — 本节点配置；写回目标是 security.identity_cert_path 与 security.ca_cert_path
//	id  — 本节点身份包（会被就地更新 Cert / Chain / CACert / CAChain）
//	r   — 校验通过的候选材料；r.CAChain 为空表示本次没有轮换 CA 证书
//
// 返回：
//
//	error — 写盘失败时返回；此时内存保持不变
func applySelfRenew(cfg *config.Config, id *identity.Identity, r *selfRenewResult) error {
	if len(r.CAChain) > 0 {
		if cfg.Security.CACertPath == "" {
			return errors.New("本节点没有 security.ca_cert_path，无法把轮换后的 CA 证书写下去")
		}
		if err := identity.WriteCertChainFile(cfg.Security.CACertPath, r.CAChain); err != nil {
			return err
		}
		id.CACert, id.CAChain = r.CAChain[0], r.CAChain
	}
	if err := identity.WriteCertChainFile(cfg.Security.IdentityCertPath, r.Chain); err != nil {
		return err
	}
	id.Cert, id.Chain = r.Chain[0], r.Chain
	return nil
}

// certsNeedRenew 判断本节点是否有证书进了续签窗口 —— **身份证书与自己的 CA 证书都看**。
//
// 为什么必须一起看：CA 证书同样是启动强校验的硬门槛（`ValidateStartup` 里
// `id.CACert.NotAfter` 过期即 REFUSE TO START）。只盯身份证书就会出现
// "身份证书很新、CA 证书已过期、下次启动起不来"这种最难查的状态。
//
// 参数：
//
//	id — 本节点身份包；为 nil 时返回 false
//
// 返回：
//
//	bool — 身份证书或（存在的话）CA 证书任一进窗口即为 true
func certsNeedRenew(id *identity.Identity) bool {
	if id == nil {
		return false
	}
	if id.Cert != nil && needRenew(id.Cert) {
		return true
	}
	return id.CACert != nil && needRenew(id.CACert)
}

// certNotAfterDays 取某身份包身份证书的剩余有效天数。
//
// 参数：
//
//	id — 身份包；为 nil 或没有证书时返回 0
//
// 返回：
//
//	int32 — 剩余天数（向下取整）；已过期返回 -1
func certNotAfterDays(id *identity.Identity) int32 {
	if id == nil || id.Cert == nil {
		return 0
	}
	return daysUntil(id.Cert.NotAfter)
}

// caNotAfterDays 取某身份包 CA 证书的剩余有效天数。
//
// 参数：
//
//	id — 身份包；为 nil 或不持有 CA 证书（叶子）时返回 0
//
// 返回：
//
//	int32 — 剩余天数；不持有 CA 证书时返回 0，已过期返回 -1。
//	         0 只用来表示"没有 CA 证书"—— 因为刚签出来的 CA 证书剩余天数必然远大于 0。
func caNotAfterDays(id *identity.Identity) int32 {
	if id == nil || id.CACert == nil {
		return 0
	}
	return daysUntil(id.CACert.NotAfter)
}

// daysUntil 把一个到期时刻折算成"还剩几天"，并给"已过期"一个明确的负值。
//
// 参数：
//
//	notAfter — 证书的到期时刻
//
// 返回：
//
//	int32 — 剩余整天数（向下取整）；已过期返回 -1（不返回 0，避免与"没有这张证书"混淆）
func daysUntil(notAfter time.Time) int32 {
	d := int32(time.Until(notAfter).Hours() / 24)
	if d <= 0 {
		return -1
	}
	return d
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

// withCA 用一条新的 CA 证书链复制一份身份包（**不改原对象**）。
//
// 用途：CA 证书轮换时，拿"只把 CA 材料换掉"的副本来跑一遍启动强校验、
// 并用它作为后续重签身份证书的签发方（ReissueFor 的 owner）。
//
// 参数：
//
//	id     — 原身份包（提供 NodeID / 私钥 / 身份证书）
//	caChain — 新的 CA 证书链，caChain[0] 是新 CA 证书
//
// 返回：
//
//	*identity.Identity — 只把 CACert / CAChain 换掉的副本；caChain 为空时原样返回 id
func withCA(id *identity.Identity, caChain []*x509.Certificate) *identity.Identity {
	if len(caChain) == 0 {
		return id
	}
	return &identity.Identity{
		NodeID: id.NodeID, Key: id.Key, Cert: id.Cert, Chain: id.Chain,
		CAKey: id.CAKey, CACert: caChain[0], CAChain: caChain, RootPool: id.RootPool,
	}
}

// selfRenewResult 一次"自签续期"的产物：先 CA、后身份两步的结果。
//
// 两个字段都是"已经算出来、还没落盘"的候选值；校验通过后由 applySelfRenew 一起写下去。
type selfRenewResult struct {
	// Chain 新的身份证书链，chain[0] 是新身份证书
	Chain []*x509.Certificate
	// CAChain 新的 CA 证书链，caChain[0] 是新 CA 证书。
	// **nil 表示本次没有轮换 CA 证书**（CA 证书还没进窗口）。
	CAChain []*x509.Certificate
}

// reissueForSelf 用本节点 CA 重签自己的材料（**不落盘**）。
//
// 两步，顺序是硬的：
//  1. **先**看 CA 证书是否进窗口 → 是就用 ReissueCAFor 换一张（**同一把密钥、同一 CN**，
//     所以下级手里的旧 CA 证书仍然有效、信任锚完全不用动）；
//  2. **再**用（可能刚换过的）CA 证书重签身份证书 —— 否则身份证书链里引用的是旧 CA 证书，
//     虽然仍能验通，但"链里那张 CA 证书"与磁盘上的不是同一张，下次启动会绕远路。
//
// 参数：
//
//	id — 本节点身份包；id.Cert 提供身份名与公钥，CAKey/CACert/CAChain 提供签发材料
//
// 返回：
//
//	*selfRenewResult — 待落盘的（身份链, CA 链）
//	error            — 无 CA 材料 / 旧证书不是 Ed25519 / 重签后身份不符时返回
func reissueForSelf(id *identity.Identity) (*selfRenewResult, error) {
	if id == nil || id.Cert == nil {
		return nil, errors.New("identity certificate missing")
	}
	if id.CAKey == nil || id.CACert == nil {
		return nil, errors.New("no CA material to sign with（本节点不持 CA 私钥与 CA 证书）")
	}
	out := &selfRenewResult{}
	// ① 先轮换 CA 证书（只在它进了窗口时才动）
	owner := id
	if needRenew(id.CACert) {
		newCA, _, err := identity.ReissueCAFor(id.CACert, id)
		if err != nil {
			return nil, fmt.Errorf("轮换本节点 CA 证书失败: %w", err)
		}
		out.CAChain = append([]*x509.Certificate{newCA}, id.CAChain[1:]...)
		owner = withCA(id, out.CAChain)
	}
	// ② 再用（可能刚换过的）CA 证书重签身份证书
	pemBytes, err := identity.ReissueFor(id.Cert, owner)
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
	out.Chain = chain
	return out, nil
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
	res, err := reissueForSelf(cur)
	if err != nil {
		return err
	}
	// 先按"启动同一强度"校验**候选材料**再落盘：宁可续不上，也不能把坏证书写进去。
	// 候选要把 CA 与身份**一起**换掉再验 —— 只验身份证书会漏掉"新 CA 证书自己不过关"的情况。
	pub, err := identity.LoadPublicKeyFile(n.C().Security.IdentityPubKeyPath)
	if err != nil {
		return fmt.Errorf("load public key: %w", err)
	}
	if err := identity.ValidateStartup(withChain(withCA(cur, res.CAChain), res.Chain),
		identity.PoolCerts(n.rootsPool()), pub); err != nil {
		return fmt.Errorf("自签续期未通过启动强度校验: %w", err)
	}
	if err := applySelfRenew(n.C(), cur, res); err != nil {
		return err
	}
	n.certBox.Set(identity.TLSCertFrom(cur))
	// 这份文件是我们自己写的 → 重算监视基线，免得被当成"外部变更"再触发一轮重载
	n.refreshReloadBaseline()
	n.Log.Info("cert self-renew: applied", "reason", reason,
		"not_after", canonTime(res.Chain[0]), "fingerprint", certSha256(res.Chain[0]))
	n.noteCARotated(res.CAChain)
	return nil
}

// noteCARotated 记录"本节点这次有没有轮换自己的 CA 证书"，并打日志 + 记指标。
//
// **启动路径与运行期路径共用它**：启动时的自签续期（loadIdentity）也会轮换 CA 证书，
// 而它没有 Node 可用来打日志 —— 所以调用方把结果（identityBundle.caRotated）带出来再调本函数。
// 不这么做就会出现"启动时换了 CA 证书、日志里一行都没有"可观测缺口（实测踩到过）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	caChain — 新轮换出来的 CA 证书链；为空表示本次没有轮换（记 skipped）
func (n *Node) noteCARotated(caChain []*x509.Certificate) {
	if len(caChain) == 0 {
		n.Metrics.Inc("ca_rotate_total", "result", "skipped")
		return
	}
	n.Metrics.Inc("ca_rotate_total", "result", "issued")
	n.Log.Warn("CA 证书已轮换（同一把密钥、只换证书）：下级手里的旧 CA 证书在其有效期内仍然有效，"+
		"不需要重新分发 trust/、也不需要下级重新入网",
		"ca_not_after", canonTime(caChain[0]), "ca_fingerprint", certSha256(caChain[0]))
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
// 没有父的就是根，只能自签。**身份证书与自己的 CA 证书一起判**（见 certsNeedRenew）。
//
// 接收者 n 是本节点实例。
func (n *Node) startSelfRenewLoop() {
	if !n.canSelfRenew() {
		return // 有父（走"父给子签"）或没有 CA 材料（无从自签）
	}
	n.loop(time.Hour, 2*time.Minute, "cert-self-renew", func(context.Context) {
		if !certsNeedRenew(n.Id()) {
			return
		}
		n.Log.Info("cert self-renew: certificate in renewal window",
			"cert_not_after", canonTime(n.Id().Cert),
			"ca_not_after", canonTime(n.Id().CACert))
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
	// numPtr 解析整数并写入 *int32。下发窗口用得到：那两个字段的"没配"与"显式 0"语义不同
	// （0 = 不限），所以必须走指针，不能落到上面那个把 0 当"没配"的 num 上。
	numPtr := func(d **int32) bool {
		v, err := strconv.Atoi(val)
		if err != nil {
			return false
		}
		x := int32(v)
		*d = &x
		return true
	}
	// bl 解析布尔（"true"/"1"/"on"… 由 strconv 定），成功则写入 d
	bl := func(d *bool) bool {
		v, err := strconv.ParseBool(val)
		if err != nil {
			return false
		}
		*d = v
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
	case "command.local_busy_backoff_max":
		return dur(&c.Command.LocalBusyBackoffMax)
	case "command.max_dispatch_inflight_per_child":
		return numPtr(&c.Command.MaxDispatchInflightPerChild)
	case "command.max_dispatch_inflight":
		return numPtr(&c.Command.MaxDispatchInflight)
	case "command.dispatch_window_adaptive":
		return bl(&c.Command.DispatchWindowAdaptive)
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
