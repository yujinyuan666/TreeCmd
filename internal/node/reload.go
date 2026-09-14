package node

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"treecmd/internal/config"
	"treecmd/internal/identity"
)

// 证书生命周期：外部脚本管理证书时，本节点负责"发现变了就把新证书/新信任锚吃进来"。
//
// 三条硬规则：
//  1. **fail-safe**：新证书/新密钥/新信任锚只要有一项校验不过，就**继续用旧的**并打日志 ——
//     绝不因为脚本投放了半个文件、或投放了别人的证书，把正在跑的节点弄挂。
//  2. **变更才动作**：轮询用"mtime + size + 内容 sha256"综合摘要判断，避免无谓的重连。
//  3. **生效范围明确**：信任锚与对端证书只影响"新连接"；只有**本节点自己的**身份证书/私钥
//     发生变化时才主动重连一次（尽快用新证书握手）。

// certReloadResult 一次重载的结论。
type certReloadResult int

// 一次重载的四种结论：无变化 / 成功 / 失败（旧材料继续用）/ 证书文件缺失。
const (
	reloadNoChange certReloadResult = iota
	reloadOK
	reloadFailed
	reloadMissing
)

// String 返回结论的可读名字，用于日志与指标标签。
//
// 接收者 r 是一次重载的结论。
//
// 返回：
//
//	string — "ok" / "failed" / "missing" / "nochange"
func (r certReloadResult) String() string {
	switch r {
	case reloadOK:
		return "ok"
	case reloadFailed:
		return "failed"
	case reloadMissing:
		return "missing"
	default:
		return "nochange"
	}
}

// reloadWatcher 证书/密钥变更监视器。
//
// 两级判据：
//  1. 稳态只算 PathStamp（stat：size+mtime）—— 微秒级、零读 IO；
//  2. stamp 变了才读内容做 PathDigest 二次确认 —— 避免"仅 touch 文件"造成无谓重载。
type reloadWatcher struct {
	paths  []string // 参与判定的路径（文件或目录）
	stamp  string   // 上次 stat 指纹
	digest string   // 上次内容摘要（用于二次确认与诊断）
}

// newReloadWatcher 由配置推导要监视的路径：显式给了就用显式的，否则自动覆盖全部身份材料与信任锚，
// 并记下初始的 stat 指纹与内容摘要作为变更判定基线。
//
// 参数：
//
//	cfg — 节点配置
//
// 返回：
//
//	*reloadWatcher — 已计算好基线的监视器
func newReloadWatcher(cfg *config.Config) *reloadWatcher {
	paths := append([]string(nil), cfg.Security.CertReload.Paths...)
	if len(paths) == 0 {
		// 自动口径：身份私钥 / 公钥 / 证书 + 本节点 CA 证书 / CA 私钥 + 全部信任锚（含目录）
		paths = []string{
			cfg.Security.IdentityKeyPath,
			cfg.Security.IdentityPubKeyPath,
			cfg.Security.IdentityCertPath,
			cfg.Security.CACertPath,
			cfg.Security.CAKeyPath,
		}
		paths = append(paths, cfg.Security.CACertPaths...)
	}
	w := &reloadWatcher{paths: paths}
	w.stamp, _ = identity.PathStamp(paths)
	w.digest, _ = identity.PathDigest(paths)
	return w
}

// changed 两级判定监视路径是否真的变了：先 stat（便宜），stamp 变了才读内容摘要二次确认。
//
// 接收者 w 是证书监视器。
//
// 返回：
//
//	bool   — 内容是否真的变了（只是 mtime 变化不算）
//	string — 当前内容摘要（供调用方更新基线）
func (w *reloadWatcher) changed() (bool, string) {
	st, err := identity.PathStamp(w.paths)
	if err != nil {
		return false, ""
	}
	if st == w.stamp {
		return false, w.digest // 绝大多数情况走这里：只做了 stat
	}
	d, err := identity.PathDigest(w.paths)
	if err != nil {
		return false, ""
	}
	w.stamp = st
	if d == w.digest {
		return false, d // 只是 mtime 变了（或 stat 抖动），内容没变
	}
	return true, d
}

// refreshReloadBaseline 在本节点自己改写了证书文件之后重算监视基线（stamp + digest）。
//
// 接收者 n 是本节点实例。
//
// 必须做：否则"启动时没有证书 → 入网写入 → 脚本删除"这条时间线上，
// 监视器看到的摘要是"缺少证书"，删除后又回到"缺少证书"，变化检测不到。
func (n *Node) refreshReloadBaseline() {
	if n.reloader == nil {
		return
	}
	if st, err := identity.PathStamp(n.reloader.paths); err == nil {
		n.reloader.stamp = st
	}
	if d, err := identity.PathDigest(n.reloader.paths); err == nil {
		n.reloader.digest = d
	}
}

// TriggerCertReload 由外部信号（SIGUSR1）触发一次"立即重载"检查。
//
// 接收者 n 是本节点实例。信号通道满时直接丢弃，不阻塞调用方。
//
// 参数：
//
//	reason — 触发原因（仅用于日志）
func (n *Node) TriggerCertReload(reason string) {
	select {
	case n.certSignal <- reason:
	default:
	}
}

// startCertReloadLoop 启动证书热重载：定时轮询兜底，同时响应信号立即生效。
//
// 接收者 n 是本节点实例。配置里关掉热重载时直接返回、不启动协程。
func (n *Node) startCertReloadLoop() {
	if !n.C().Security.CertReloadEnabled() {
		n.Log.Info("cert reload disabled by config")
		return
	}
	n.reloader = newReloadWatcher(n.C())
	interval := n.C().Security.ReloadInterval()
	n.Log.Info("cert reload armed", "interval", interval.String(), "paths", len(n.reloader.paths),
		"on_change", n.C().Security.ReloadOnChange())
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		// 抖动错峰：同机多节点时避免所有节点在同一毫秒一起 stat/读盘
		tk := time.NewTicker(jitteredInterval(interval))
		defer tk.Stop()
		for {
			select {
			case <-n.stopCh:
				return
			case <-tk.C:
				n.checkCertReload("poll")
				tk.Reset(jitteredInterval(interval))
			case reason := <-n.certSignal:
				n.Log.Info("cert reload: signal received", "reason", reason)
				n.checkCertReload("signal:" + reason)
			}
		}
	}()
}

// jitteredInterval 给轮询间隔叠加 ±20% 抖动：把同机多节点的轮询摊开，避免形成 IO 突发。
//
// 参数：
//
//	d — 基准间隔
//
// 返回：
//
//	time.Duration — 抖动后的间隔
func jitteredInterval(d time.Duration) time.Duration {
	spread := d / 5
	return jittered(d, spread)
}

// checkCertReload 摘要变了就重载一次证书。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	trigger — 触发来源（"poll" 或 "signal:xxx"，仅用于日志）
func (n *Node) checkCertReload(trigger string) {
	changed, digest := n.reloader.changed()
	if !changed {
		return
	}
	n.reloader.digest = digest
	n.Log.Info("cert reload: change detected", "trigger", trigger)
	// 结果由 reloadCerts 自己按 ok / failed / missing 记账，这里不再重复计数
	_ = n.reloadCerts(trigger)
}

// reloadCerts 重新加载全部身份材料并按结论记一次指标（实际动作见 reloadCertsInner）。
//
// 接收者 n 是本节点实例。返回 reloadOK 时新材料已生效；reloadFailed / reloadMissing 时旧材料仍在用（fail-safe）。
//
// 参数：
//
//	trigger — 触发来源（仅用于日志）
//
// 返回：
//
//	certReloadResult — 本次重载的结论
func (n *Node) reloadCerts(trigger string) certReloadResult {
	res := n.reloadCertsInner(trigger)
	if res != reloadNoChange {
		n.Metrics.Inc("cert_reload_total", "result", res.String())
	}
	return res
}

// reloadCertsInner 重载的实际实现：证书文件缺失时按入网配置决定自愈还是保留旧证书；
// 否则加载并强校验全部身份材料，通过后原子替换 id / 信任锚 / TLS 证书容器。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	trigger — 触发来源（仅用于日志）
//
// 返回：
//
//	certReloadResult — ok / failed / missing；failed 与 missing 都意味着继续用旧材料
func (n *Node) reloadCertsInner(trigger string) certReloadResult {
	cfg := n.C()
	old := n.Id()

	// 证书文件被删掉 → 视为"需要重新入网"（若开启了入网），而不是当成错误
	if !fileExists(cfg.Security.IdentityCertPath) {
		if cfg.Security.EnrollmentEnabled() && cfg.Role() != config.RoleRoot {
			n.Log.Warn("cert reload: certificate file removed → will re-enroll", "path", cfg.Security.IdentityCertPath)
			go n.ensureCertSoon("cert file removed", true)
			return reloadMissing
		}
		n.Log.Error("cert reload: certificate file missing and enrollment disabled → keep current certificate",
			"path", cfg.Security.IdentityCertPath)
		return reloadMissing
	}

	bundle, err := loadIdentityForReload(cfg)
	if err != nil {
		// 这一条最重要：坏的证书文件绝不能让在跑的节点挂掉
		n.Log.Error("cert reload: rejected new material, KEEPING current one (fail-safe)", "err", err)
		return reloadFailed
	}

	identityChanged := identityChanged(old, bundle.id)
	n.idPtr.Store(bundle.id)
	n.roots.Store(bundle.roots)
	n.certBox.Set(identity.TLSCertFrom(bundle.id))

	n.Log.Info("cert reload: applied",
		"trigger", trigger,
		"cert_not_after", canonTime(bundle.id.Cert),
		"cert_fingerprint", certSha256(bundle.id.Cert),
		"identity_changed", identityChanged,
		"trust_anchors", len(bundle.cs))

	// 生效策略：默认只在"本节点身份证书/私钥变了"时主动重连一次；lazy 则完全交给自然重连
	if identityChanged && cfg.Security.ReloadOnChange() == "reconnect" {
		if n.up != nil {
			go n.up.forceReconnect("cert-reloaded")
		}
	}

	// 换进来的证书若已进入续签窗口、而本节点又能自签（根），顺手续一张 —— 否则它会静静地在
	// 几天后过期。有父的节点不用管：父会在它 Connect / RESUME 时主动换发。
	if n.canSelfRenew() && needRenew(n.Id().Cert) {
		go func() {
			if err := n.renewSelfCert("reloaded certificate in renewal window"); err != nil {
				n.Log.Warn("cert self-renew after reload failed", "err", err)
			}
		}()
	}
	return reloadOK
}

// ensureCertSoon 在后台重试入网（用于"证书文件被删"后的自愈）；已有入网在进行中则直接返回。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	reason — 触发原因（仅用于日志）
//	force  — true 表示"文件才是权威"：即使内存里还有可用证书，也去把证书文件补回来
func (n *Node) ensureCertSoon(reason string, force bool) {
	if n.enrolling.Swap(true) {
		return
	}
	defer n.enrolling.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := n.ensureCertForce(ctx, force); err != nil {
		n.Log.Warn("re-enroll failed", "reason", reason, "err", err)
		return
	}
	n.finishEnroll(reason)
}

// identityChanged 判断"是否需要让现有连接重新握手"：证书指纹或公钥变了即为变。
//
// 参数：
//
//	old — 变更前的身份；nil 视为已变
//	cur — 变更后的身份；nil 视为已变
//
// 返回：
//
//	bool — 是否需要重连握手
func identityChanged(old, cur *identity.Identity) bool {
	if old == nil || cur == nil {
		return true
	}
	if old.Cert == nil || cur.Cert == nil {
		return true
	}
	if string(identity.Fingerprint(old.Cert)) != string(identity.Fingerprint(cur.Cert)) {
		return true
	}
	op := identity.PublicKeyOf(old.Key)
	cp := identity.PublicKeyOf(cur.Key)
	return !op.Equal(cp)
}

// loadIdentityForReload 重载专用的身份加载：证书必须存在且逐项校验通过（与启动同一强度），
// 不接受"待入网"这种状态。
//
// 参数：
//
//	cfg — 节点配置
//
// 返回：
//
//	*identityBundle — 校验通过的身份材料
//	error           — 缺可用证书或校验失败时返回（调用方应继续用旧材料）
func loadIdentityForReload(cfg *config.Config) (*identityBundle, error) {
	// selfRenew=false：热重载只负责"把外部投放的材料吃进来"，绝不自己写证书文件
	b, err := loadIdentity(cfg, false)
	if err != nil {
		return nil, err
	}
	if b.pending || b.id == nil || b.id.Cert == nil {
		return nil, fmt.Errorf("no usable certificate")
	}
	return b, nil
}

// canonTime 把证书的到期时间格式化成 RFC3339 字符串，便于写进日志。
//
// 参数：
//
//	c — 证书；nil 时返回空串
//
// 返回：
//
//	string — NotAfter 的 RFC3339 表示
func canonTime(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	return c.NotAfter.Format(time.RFC3339)
}

// certSha256 取证书 DER 的 sha256 前 6 字节，便于日志里区分"换了哪张证书"。
//
// 参数：
//
//	c — 证书；nil 时返回空串
//
// 返回：
//
//	string — 十六进制摘要前缀
func certSha256(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	sum := sha256.Sum256(c.Raw)
	return fmt.Sprintf("%x", sum[:6])
}

// 本文件没有别的地方引用 ed25519 与 os，下面两行空标识符引用用来保持这两个导入合法。
var _ = ed25519.PublicKeySize
var _ = os.Stat
