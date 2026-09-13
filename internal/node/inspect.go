package node

import (
	"context"
	"fmt"
	"time"

	"treecmd/internal/config"
	"treecmd/internal/identity"
)

// 部署前自检：给"手工写配置 + 启动"的用法提供一条**只读**的检查路径 ——
// 不监听端口、不建连接、不落盘（不会顺手建出 state.db）。

// CheckReport 自检结论。
type CheckReport struct {
	Role       string
	NodeID     string
	NodeIDFrom string // node.id 的来源：config / cert / state / generated（ADR-050）
	NodeName   string // 节点名（node.name，ADR-051）
	NodeRemark string // 节点备注（node.remark）
	Listen     string
	Parents    []string
	NodeCounts string

	IdentityReady   bool      // 私钥 + 公钥 + 证书是否齐备且校验通过
	PendingEnroll   bool      // 是否"密钥齐备但还没有证书"，等待运行期入网
	CertNotAfter    time.Time // 证书到期时间（pending 时为零值）
	CertFingerprint string    // 证书指纹（便于比对"换没换证"）
	CertSerialOK    bool      // 证书链/身份/有效期是否通过

	CanIssueChildCerts bool // 是否持有 CA 材料（有子节点才需要）
	// CertInRenewWindow 证书是否已进入续签窗口（剩余 < 生命期 1/3，含已过期）。
	// 根会**启动时自签续期**；有父的节点会向父申请换发。`-check` 只报告、不执行。
	CertInRenewWindow bool
	// CanSelfRenew 本节点能否自签续期（没有父 + 持有 CA 材料，即根）
	CanSelfRenew bool
	// SelfRenewNeeded 证书是否已进续签窗口、启动时会走自签续期（`-check` 里只做只读演练）
	SelfRenewNeeded bool
	// CertAfterSelfRenew 自签续期之后证书会变成的到期时间（仅在 SelfRenewNeeded 时有意义）
	CertAfterSelfRenew time.Time
	// SelfRenewErr 演练/续期过程中的错误（非空表示续不上，启动会因证书问题被拒）
	SelfRenewErr error

	TrustAnchorPaths []string
	TrustAnchors     int

	EnrollmentEnabled bool
	EnrollTokenSet    bool
	AllowIDs          []string

	CertReloadEnabled bool
	ReloadInterval    time.Duration
	ReloadPaths       []string
	// AppliedDefaults 程序按约定补全的配置项（手工部署时只写 node.id + parents[] 就会有一批）
	AppliedDefaults []string

	Warnings []string
}

// Check 只读自检。返回 error 表示"按当前配置这个节点启动不了"，原因可直接给人看。
//
// 不监听端口、不建连接、不落盘（不会顺手建出 state.db）。除了填结论，
// 还会把"能启动但多半不是你想要的"组合写进 Warnings。
//
// 参数：
//
//	cfg — 已加载的配置
//
// 返回：自检报告（身份状态、信任锚数量、入网开关、热重载路径、应用过的默认项等），
// 以及致命错误（配置 / 身份硬伤）。
func Check(cfg *config.Config) (*CheckReport, error) {
	rep := &CheckReport{
		Role:       string(cfg.Role()),
		NodeID:     cfg.Node.ID,
		NodeIDFrom: string(cfg.NodeIDSource),
		NodeName:   cfg.Node.Name,
		NodeRemark: cfg.Node.Remark,
		Listen:     cfg.Node.Listen,
		NodeCounts: fmt.Sprintf("父 %d 个 / 下游侧 %v", len(cfg.Parents), cfg.HasDownstream()),
	}
	for _, p := range cfg.Parents {
		rep.Parents = append(rep.Parents, p.ID+"@"+p.Addr)
	}
	rep.TrustAnchorPaths = append([]string(nil), cfg.Security.CACertPaths...)
	rep.EnrollmentEnabled = cfg.Security.EnrollmentEnabled()
	rep.AllowIDs = append([]string(nil), cfg.Security.Enrollment.AllowIDs...)
	if tok, err := cfg.Security.EnrollToken(); err == nil {
		rep.EnrollTokenSet = tok != ""
	}
	rep.CertReloadEnabled = cfg.Security.CertReloadEnabled()
	rep.ReloadInterval = cfg.Security.ReloadInterval()
	rep.AppliedDefaults = append([]string(nil), cfg.Defaults...)

	// 信任锚（含目录扫描）：这里单独数一遍，便于一眼看出"目录里到底认到了几张"
	if len(cfg.Security.CACertPaths) > 0 {
		if cs, err := identity.LoadOrScanTrustAnchors(cfg.Security.CACertPaths); err != nil {
			return rep, fmt.Errorf("信任锚加载失败: %w", err)
		} else {
			rep.TrustAnchors = len(cs)
		}
	}

	// selfRenew=false：`-check` 是只读自检，绝不落盘（要不要自续只报告，不执行）
	b, err := loadIdentity(cfg, false)
	if err != nil {
		return rep, err
	}
	rep.PendingEnroll = b.pending
	rep.IdentityReady = !b.pending
	rep.CertSerialOK = !b.pending && b.id != nil && b.id.Cert != nil
	// 自签续期是"只读演练"：b.id.Cert 此时已是**续期后**的证书，所以报告里给的是磁盘上那张的到期时间
	rep.SelfRenewNeeded = b.selfRenewNeeded
	rep.SelfRenewErr = b.selfRenewErr
	if b.id != nil {
		rep.CanIssueChildCerts = b.id.CAKey != nil && b.id.CACert != nil
		if b.id.Cert != nil {
			rep.CertNotAfter = b.id.Cert.NotAfter
			if b.selfRenewNeeded {
				rep.CertNotAfter = b.certBeforeNotAfter // 报告磁盘上那张（更诚实）
			}
			rep.CertAfterSelfRenew = b.certAfterSelfRenew
			rep.CertFingerprint = fmt.Sprintf("%x", identity.Fingerprint(b.id.Cert))[:16]
			rep.CertInRenewWindow = needRenew(b.id.Cert)
			// 根：没有父，只能自己签自己；有父的节点由父签发，所以不能自签
			rep.CanSelfRenew = cfg.Role() == config.RoleRoot && rep.CanIssueChildCerts
		}
	}

	w := newReloadWatcher(cfg)
	rep.ReloadPaths = w.paths

	// 一些"能启动但多半不是你想要的"的组合，提前说出来
	if b.pending {
		rep.Warnings = append(rep.Warnings, "证书尚未签发：将进入待入网状态，由父签发后再对外服务")
		if !rep.EnrollmentEnabled {
			rep.Warnings = append(rep.Warnings, "运行期入网已关闭，而证书又不存在 → 永远无法上线")
		}
		if !rep.EnrollTokenSet && len(rep.AllowIDs) == 0 {
			rep.Warnings = append(rep.Warnings, "既未配置 enrollment.token 也未配置 allow_ids：父端会拒绝一切入网")
		}
	}
	if cfg.HasDownstream() && !rep.CanIssueChildCerts {
		rep.Warnings = append(rep.Warnings, "本节点有子节点但不持 CA 材料：无法为子节点签发证书（子节点会入网失败）")
	}
	if cfg.Role() == config.RoleRoot && b.pending {
		rep.Warnings = append(rep.Warnings, "根节点没有父可签发，证书必须自带")
	}
	if rep.SelfRenewNeeded {
		if rep.SelfRenewErr != nil {
			rep.Warnings = append(rep.Warnings,
				"证书已进入续签窗口，但自签续期演练失败："+rep.SelfRenewErr.Error())
		} else {
			rep.Warnings = append(rep.Warnings, fmt.Sprintf(
				"证书已进入续签窗口（磁盘上那张有效至 %s）：启动时会自动自签续期到 %s；本次自检只演练、不落盘",
				rep.CertNotAfter.Format("2006-01-02"), rep.CertAfterSelfRenew.Format("2006-01-02")))
		}
	} else if rep.CertInRenewWindow && !rep.CanSelfRenew {
		rep.Warnings = append(rep.Warnings,
			"证书已进入续签窗口（剩余不足生命期 1/3）：启动后会向父申请换发")
	}
	if !rep.CertReloadEnabled {
		rep.Warnings = append(rep.Warnings, "证书热重载已关闭：外部脚本换证书后需要重启进程")
	}
	if rep.TrustAnchors == 0 && cfg.Role() != config.RoleRoot {
		rep.Warnings = append(rep.Warnings, "没有任何信任锚：无法校验父/对端身份")
	}
	return rep, nil
}

// EnsureCertificate 只做"确保有可用证书"：已有就直接返回，否则走一次运行期入网。
// 供 `-enroll` 子命令与"证书被删后的自愈"共用。
//
// 接收者 n 是本节点实例；带互斥，同一时刻只会有一个入网流程在跑。
//
// 参数：
//
//	ctx — 上下文
//
// 返回：拿到可用证书返回 nil，否则返回错误。
func (n *Node) EnsureCertificate(ctx context.Context) error { return n.ensureCertWithLock(ctx, true) }

// HasUsableCert 是否已持有可用证书（存在且未过期），是 hasUsableCert 的对外封装。
func (n *Node) HasUsableCert() bool { return n.hasUsableCert() }

// WatchInfo 当前监视的证书路径与摘要（诊断用），转发给 watchPathsDigest。
func (n *Node) WatchInfo() ([]string, string) { return n.watchPathsDigest() }
