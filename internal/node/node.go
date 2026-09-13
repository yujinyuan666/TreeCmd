// Package node 组装单进程双角色节点：下行侧 DownstreamHub（服务端）+ 上行侧 UpstreamLink（客户端）
// + TaskEngine（handle / waitChildren / terminal / 聚合）。
package node

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"treecmd/internal/aggregate"
	"treecmd/internal/config"
	"treecmd/internal/exec"
	"treecmd/internal/identity"
	"treecmd/internal/observability"
	"treecmd/internal/pb"
	"treecmd/internal/persist"
	"treecmd/internal/registry"
	"treecmd/internal/store"
)

// Node 一个节点进程。
type Node struct {
	Log *Logger
	// cfg 原子指针：SIGHUP 热更时整体替换（读侧一律走 C()），避免与运行中的协程竞态。
	cfg     atomic.Pointer[config.Config]
	cfgPath string
	// 身份材料与信任锚都是**可热替换**的：外部脚本换掉证书/密钥/CA 后靠原子指针整体切换，
	// 读侧一律走 Id() / rootsPool()，避免与运行中的协程竞态。
	idPtr atomic.Pointer[identity.Identity]
	roots atomic.Pointer[x509.CertPool]

	Reg     *registry.Table
	Store   *store.Store
	Exec    *exec.Registry
	Obj     *store.ObjectStore // 对象存储（>64MB 大结果，3.13 第三级）
	Metrics *observability.Registry

	// CUSTOM 聚合器按 commandID 记录（提交节点解析后写入；各跳从 Command.AggregateName 解析）
	customMu sync.RWMutex
	customs  map[string]aggregate.CustomAggregator

	// 可热替换的 TLS 证书容器（证书续签 / 外部脚本换证 / 入网签发后都靠它生效）
	certBox *identity.TLSContainer

	// 证书热重载：轮询兜底 + SIGUSR1 立即生效
	reloader   *reloadWatcher
	certSignal chan string
	// 入网互斥：同一时刻只允许一次入网流程
	enrolling atomic.Bool

	// 运行期入网：一次性挑战表（nodeID → challenge）
	enrollMu   sync.Mutex
	challenges map[string]enrollChallenge

	// 吊销列表（7.7）：版本号由"该子节点的直接父"维护、单调递增；只应用更高版本
	crlMu      sync.Mutex
	crlVersion uint64
	crlSet     map[string]bool

	selfPath    atomic.Value // string
	ancestors   atomic.Value // []string 祖先路径链（含父自身）
	ancestorIDs atomic.Value // []string 祖先 NodeID 链（含父自身；环检测 + health 默认白名单用）

	semLocal chan struct{}
	inflight *InflightTable

	up  *Upstream
	hub *Hub

	evMu   sync.Mutex
	events map[string]chan struct{}

	pendingMu sync.Mutex
	resending map[string]bool

	healthMuSelf  sync.Mutex
	healthMuLight sync.Mutex
	healthMuHeavy sync.Mutex

	stateMu sync.Mutex
	state   *persist.State

	startedAt   time.Time
	stopCh      chan struct{}
	fetchNotify chan struct{}
	wg          sync.WaitGroup
	stopped     atomic.Bool

	// 近 1h 终态滑动窗口（内存态、非持久化，见 4.6）
	termMu  sync.Mutex
	termWnd []termSample
	// 结果索引（内存缓存，可重建）+ 查询回程转发表 + 查询响应通道
	index     *resultIndex
	routes    *routeTable
	qmu       sync.Mutex
	queryCh   map[string]chan *pb.QueryResp
	querySess map[string]*querySession

	apiSrv *http.Server

	// 计数器（可观测性）
	statCmdTerminal map[string]int64
}

// termSample 近 1 小时终态窗口里的一条采样：发生时间 + 终态名。
type termSample struct {
	At     time.Time
	Status string
}

// New 装配节点，但不启动任何监听；等价于 NewWithPath(cfg, "", logger)。
//
// 参数：
//
//	cfg    — 本节点配置；Node.ID 决定本节点的身份
//	logger — 日志器；传 nil 时回退到 stdout 上的 TextHandler（Info 级）
//
// 返回：
//
//	*Node — 装配好、可直接 Start 的节点
//	error — 身份材料缺失/校验不过、账本或对象存储打不开时返回
func New(cfg *config.Config, logger *slog.Logger) (*Node, error) { return NewWithPath(cfg, "", logger) }

// NewWithPath 与 New 相同，额外记住配置文件路径，供 SIGHUP 热更时按路径重载。
//
// 参数：
//
//	cfg     — 本节点配置
//	cfgPath — 配置文件路径；空串表示不支持按路径热更
//	logger  — 日志器；传 nil 时回退到 stdout 上的 TextHandler（Info 级）
//
// 返回：
//
//	*Node — 装配好、可直接 Start 的节点（尚未监听）
//	error — 身份材料缺失/校验不过、账本或对象存储打不开时返回
func NewWithPath(cfg *config.Config, cfgPath string, logger *slog.Logger) (*Node, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	n := &Node{
		cfgPath: cfgPath,
		Log:     &Logger{logger.With("node", shortID(cfg.Node.ID))},
		Reg:     registry.New(cfg.Node.ID, "/", cfg.Node.Labels, cfg.Node.Capabilities),
		Exec:    exec.NewRegistry(), events: map[string]chan struct{}{},
		resending: map[string]bool{}, stopCh: make(chan struct{}), fetchNotify: make(chan struct{}, 1),
		certSignal: make(chan string, 4), challenges: map[string]enrollChallenge{},
		queryCh:   map[string]chan *pb.QueryResp{},
		querySess: map[string]*querySession{},
		startedAt: time.Now(), index: newResultIndex(), routes: newRouteTable(cfg.Query.QueryRouteTTL, int(cfg.Query.MaxQueryRoutes)),
		statCmdTerminal: map[string]int64{},
	}
	n.cfg.Store(cfg)
	n.crlSet = map[string]bool{}
	n.customs = map[string]aggregate.CustomAggregator{}
	n.querySess = map[string]*querySession{}
	n.Metrics = observability.New()
	n.selfPath.Store("/")
	n.ancestors.Store([]string(nil))
	n.ancestorIDs.Store([]string(nil))
	n.semLocal = make(chan struct{}, cfg.Command.MaxInflight)
	n.inflight = newInflightTable()

	// 身份材料
	st, err := loadIdentity(cfg)
	if err != nil {
		return nil, err
	}
	n.idPtr.Store(st.id)
	n.roots.Store(st.roots)
	n.certBox = identity.NewTLSContainer(identity.TLSCertFrom(n.Id()))

	db, err := store.Open(stateDBPath(cfg))
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	n.Store = db
	obj, err := store.NewObjectStore(cfg.Command.ObjectStoreDir)
	if err != nil {
		return nil, fmt.Errorf("open object store: %w", err)
	}
	n.Obj = obj

	// 状态文件
	loaded := persist.Load(cfg.Persist.StatePath)
	// node.id 的运行时归宿就是 state.dat（ADR-050）：只要磁盘上这份状态**没有记录本节点这次
	// 解析出来的 ID**，就必须在"上线前"落盘 —— 否则"新生成 ID → 30s 内崩溃"会换掉身份
	//（周期落盘默认 30s，而 state.dat 此前只在周期与优雅退出时写）。
	// 注意判据是"**磁盘上那份**里有没有这个 ID"，不能用 n.state.Self.ID（新建时已被赋好值，恒等）。
	idNotPersisted := loaded == nil || loaded.Self.ID != cfg.Node.ID
	n.state = loaded
	if n.state == nil || n.state.ConfigHash != cfg.ConfigHash() {
		// 状态缺失 / hash 不匹配 / 损坏 → 回退全量注册（自动降级，不阻塞启动）
		n.state = &persist.State{ConfigHash: cfg.ConfigHash(), Self: persist.Self{ID: cfg.Node.ID}}
	} else {
		n.Reg.Warm(n.state.KnownChildren)
		if n.state.Self.Path != "" {
			n.selfPath.Store(n.state.Self.Path)
			n.Reg.SetSelfPath(n.state.Self.Path)
		}
	}
	if idNotPersisted {
		n.state.Self.ID = cfg.Node.ID
		n.saveState()
	}
	return n, nil
}

// identityBundle 一次身份材料加载的结果。
type identityBundle struct {
	id    *identity.Identity
	roots *x509.CertPool
	cs    []*x509.Certificate // 信任锚原始证书（校验时复用）
	// pending = "密钥齐备但还没有证书"，等待运行期入网签发
	pending bool
}

// loadIdentity 加载本节点身份材料并做启动强校验。
//
// **硬约束：私钥与公钥都必须预置，程序绝不生成、也绝不代收；缺任何一个都拒绝启动。**
//
// 证书有两种合法来源：
//  1. **预置**（自带 / 外部脚本投放）→ 走完整强校验；
//  2. **暂缺**（非 root 且开启运行期入网）→ 允许以"待入网"状态启动，之后由 ensureCert 向父换取。
//
// 证书**存在却校验不过**（身份不符 / 链不通 / 格式坏）一律拒绝启动：那是人为错误，必须早暴露，
// 不能靠自动重入网把它掩盖过去。
//
// 参数：
//
//	cfg — 本节点配置；读 security.* 下的密钥 / 证书 / 信任锚路径
//
// 返回：
//
//	*identityBundle — 身份材料（私钥、证书链、信任锚池）；证书暂缺时为 pending = true
//	error           — 任一硬校验失败；错误文案以 "REFUSE TO START:" 开头
func loadIdentity(cfg *config.Config) (*identityBundle, error) {
	// 信任锚：每一项都可以是文件或目录（目录扫 *.crt/*.pem）
	var cs []*x509.Certificate
	if len(cfg.Security.CACertPaths) > 0 {
		var err error
		cs, err = identity.LoadOrScanTrustAnchors(cfg.Security.CACertPaths)
		if err != nil {
			return nil, fmt.Errorf("REFUSE TO START: %w", err)
		}
	}

	// ① 私钥：必须存在，且必须是 ed25519（绝不自动生成）
	priv, err := identity.LoadIdentityKey(cfg.Security.IdentityKeyPath)
	if err != nil {
		return nil, fmt.Errorf("REFUSE TO START: %w", err)
	}
	// ② 公钥：必须存在（绝不从私钥推导后落盘）
	pub, err := identity.LoadPublicKeyFile(cfg.Security.IdentityPubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("REFUSE TO START: identity public key %s: %w (公钥必须预置)", cfg.Security.IdentityPubKeyPath, err)
	}

	if cfg.Role() == config.RoleRoot {
		// 根：没有父可签发，证书必须自带；信任锚缺省就用它自己的 CA 证书
		id, err := loadRootIdentity(cfg, priv)
		if err != nil {
			return nil, err
		}
		anchors := cs
		if len(anchors) == 0 {
			anchors = []*x509.Certificate{id.CACert}
		}
		if err := identity.ValidateStartup(id, anchors, pub); err != nil {
			return nil, fmt.Errorf("REFUSE TO START: startup identity validation failed: %w", err)
		}
		return &identityBundle{id: id, roots: identity.NewPool(anchors...), cs: anchors}, nil
	}

	if !fileExists(cfg.Security.IdentityCertPath) {
		if !cfg.Security.EnrollmentEnabled() {
			return nil, fmt.Errorf("REFUSE TO START: 证书 %s 不存在，且未开启运行期入网（security.enrollment.enabled=false）",
				cfg.Security.IdentityCertPath)
		}
		if len(cs) == 0 {
			return nil, fmt.Errorf("REFUSE TO START: 待入网但没有任何信任锚（security.ca_cert_paths），无法校验父的身份")
		}
		// 待入网状态：先带密钥起来，等 ensureCert 拿到证书再对外服务
		return &identityBundle{
			id:      &identity.Identity{NodeID: cfg.Node.ID, Key: priv},
			roots:   identity.NewPool(cs...),
			cs:      cs,
			pending: true,
		}, nil
	}

	id, err := loadNodeIdentity(cfg, priv)
	if err != nil {
		return nil, err
	}
	if err := identity.ValidateStartup(id, cs, pub); err != nil {
		return nil, fmt.Errorf("REFUSE TO START: startup identity validation failed: %w", err)
	}
	return &identityBundle{id: id, roots: identity.NewPool(cs...), cs: cs}, nil
}

// loadNodeIdentity 加载"预置证书"的非根节点身份材料。
// 有子节点的节点（根 / 中继）必须同时具备 CA 私钥与 CA 证书 —— 否则签不出子节点证书。
//
// 参数：
//
//	cfg — 本节点配置
//	key — 已由 loadIdentity 读到的 ed25519 私钥（本函数不负责加载私钥）
//
// 返回：
//
//	*identity.Identity — 含自身证书链；有子节点时还含 CA 私钥与 CA 证书链
//	error              — 证书读不出，或"有子节点却缺 CA 材料"时返回
func loadNodeIdentity(cfg *config.Config, key ed25519.PrivateKey) (*identity.Identity, error) {
	chain, err := identity.LoadCertChainFile(cfg.Security.IdentityCertPath)
	if err != nil {
		return nil, fmt.Errorf("REFUSE TO START: identity certificate: %w", err)
	}
	id := &identity.Identity{NodeID: cfg.Node.ID, Key: key, Cert: chain[0], Chain: chain}
	hasChildren := cfg.HasDownstream()
	if cfg.Security.CAKeyPath != "" {
		// 文件"不存在"= 本节点不持 CA 材料（叶子就是这种）；文件存在却读不出来才拒绝启动
		caKey, err := identity.LoadIdentityKey(cfg.Security.CAKeyPath)
		switch {
		case err == nil:
			id.CAKey = caKey
		case errors.Is(err, os.ErrNotExist):
			// 交给下面的 hasChildren 判定
		default:
			return nil, fmt.Errorf("REFUSE TO START: %w", err)
		}
	}
	if caChain, err := identity.LoadCertChainFile(caCertPath(cfg)); err == nil && len(caChain) > 0 {
		id.CACert = caChain[0]
		id.CAChain = caChain
	} else if hasChildren {
		return nil, fmt.Errorf("REFUSE TO START: CA certificate %s missing (该节点有子节点，必须有 CA 材料；运行期入网签发的 CA 证书会写到这里): %v",
			caCertPath(cfg), err)
	}
	if hasChildren && id.CAKey == nil {
		return nil, fmt.Errorf("REFUSE TO START: CA private key missing：本节点有子节点，必须有一条 CA 私钥用于给子节点签发（用 `treecmd-node -genkey -keydir keys -with-ca` 生成，或由你的证书脚本提供）；当前指向 %s",
			cfg.Security.CAKeyPath)
	}
	return id, nil
}

// loadRootIdentity 加载根节点身份材料（证书自带，没有父可签发）。
//
// 参数：
//
//	cfg — 本节点配置
//	key — 已由 loadIdentity 读到的 ed25519 私钥
//
// 返回：
//
//	*identity.Identity — 含自身证书链、CA 私钥、CA 证书链与信任锚池
//	error              — 缺 CA 路径 / CA 私钥，或证书链读不出时返回
func loadRootIdentity(cfg *config.Config, key ed25519.PrivateKey) (*identity.Identity, error) {
	// 本节点自己的 CA 证书优先取自 security.ca_cert_path；缺失时回退到信任锚（根的自签 CA 两者同源）
	// 注意回退条件只判"未配置"，不判"文件不存在" —— 配了就必须存在（缺文件即拒绝启动）
	caPath := cfg.Security.CACertPath
	if caPath == "" {
		if len(cfg.Security.CACertPaths) == 0 {
			return nil, fmt.Errorf("REFUSE TO START: 根节点必须给出 security.ca_cert_path 或 security.ca_cert_paths")
		}
		caPath = cfg.Security.CACertPaths[0]
	}
	caChain, err := identity.LoadCertChainFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("REFUSE TO START: root CA certificate %s: %w", caPath, err)
	}
	idChain, err := identity.LoadCertChainFile(cfg.Security.IdentityCertPath)
	if err != nil {
		return nil, fmt.Errorf("REFUSE TO START: identity certificate %s: %w (根节点没有父可签发：证书必须自带，或放进 certs/ 由你的脚本投放)",
			cfg.Security.IdentityCertPath, err)
	}
	if cfg.Security.CAKeyPath == "" {
		return nil, fmt.Errorf("REFUSE TO START: 根节点必须预置 CA 私钥（security.ca_key_path）")
	}
	caKey, err := identity.LoadIdentityKey(cfg.Security.CAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("REFUSE TO START: %w", err)
	}
	pool := identity.NewPool(caChain...)
	return &identity.Identity{
		NodeID: cfg.Node.ID, Key: key, Cert: idChain[0], Chain: idChain,
		CAKey: caKey, CACert: caChain[0], CAChain: caChain, RootPool: pool,
	}, nil
}

// caCertPath 本节点自己的 CA 证书路径（运行期入网签发的 CA 证书也写在这里）。
func caCertPath(cfg *config.Config) string { return cfg.Security.CACertPath }

// stateDBPath bbolt 账本路径：与 state.dat 同目录（默认 <data_dir>/state.db）。
//
// 账本用 bbolt（需要固定文件），状态快照用 state.dat（原子写），两者刻意分开放：
// 前者是权威账本、只增不减；后者是可重建的运行态。
//
// 参数：
//
//	cfg — 本节点配置；Persist.StatePath 为空时退回 DataDir
//
// 返回：
//
//	string — 账本文件的绝对或相对路径
func stateDBPath(cfg *config.Config) string {
	if cfg.Persist.StatePath != "" {
		return filepath.Join(filepath.Dir(cfg.Persist.StatePath), "state.db")
	}
	return filepath.Join(cfg.DataDir, "state.db")
}

// fileExists 判断路径是否存在（用于区分"证书暂缺 → 待入网"与"证书存在 → 必须校验通过"）。
//
// 参数：
//
//	p — 待检查的路径；空串直接返回 false
//
// 返回：
//
//	bool — os.Stat 成功即 true（不区分文件还是目录）
func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// C 取当前生效的配置（热更后即新值）。
func (n *Node) C() *config.Config { return n.cfg.Load() }

// Id 取当前生效的身份材料（证书热重载后即新值）。
func (n *Node) Id() *identity.Identity { return n.idPtr.Load() }

// rootsPool 当前信任锚池。
func (n *Node) rootsPool() *x509.CertPool { return n.roots.Load() }

// rootsFn 供 TLS 层"每次握手/每次拨号时求值"，从而让信任锚替换对新连接立即生效。
func (n *Node) rootsFn() func() *x509.CertPool { return n.rootsPool }

// SelfPath 本节点当前路径；尚未设置时回退到 "/"。
//
// 返回：
//
//	string — 已落盘的路径，或 "/"
func (n *Node) SelfPath() string {
	if v, ok := n.selfPath.Load().(string); ok && v != "" {
		return v
	}
	return "/"
}

// Ancestors 返回祖先路径链（含父自身的路径，不含本节点）；未设置时返回 nil。
//
// 返回：
//
//	[]string — 祖先路径列表
func (n *Node) Ancestors() []string {
	v, _ := n.ancestors.Load().([]string)
	return v
}

// AncestorIDs 返回祖先 NodeID 链（含父自身；用于环检测与 health 默认白名单）。
//
// 返回：
//
//	[]string — 祖先 NodeID 列表
func (n *Node) AncestorIDs() []string {
	v, _ := n.ancestorIDs.Load().([]string)
	return v
}

// Role 返回本节点形态（由配置推导：根 / 中继 / 叶子）。
//
// 返回：
//
//	config.Role — 当前生效配置下的角色
func (n *Node) Role() config.Role { return n.C().Role() }

// OnlineChildren 返回当前已连上的直接子节点数（等待收敛用）。
//
// 返回：
//
//	int — 已建连的子节点数；下行 hub 尚未启动时为 0
func (n *Node) OnlineChildren() int {
	if n.hub == nil {
		return 0
	}
	return n.hub.ConnCount()
}

// RegisteredChildren 返回注册表中已知的直接子节点数（含当前没连上的）。
func (n *Node) RegisteredChildren() int { return n.Reg.Len() }

// IDPrefix 返回节点 ID 的前 8 位，便于日志 / CLI 展示。
func (n *Node) IDPrefix() string { return shortID(n.C().Node.ID) }

// Start 启动全部子系统。
//
// 若本节点还**没有可用证书**（非 root + 开启运行期入网），则以"待入网"状态启动：
// 下行监听推迟到入网成功之后（没有证书就没法跟人握手），上行会话照常起，
// 由它先向父换取证书。这样"子先起、父后起""脚本还没来得及投放证书"都能自愈。
//
// 参数：
//
//	ctx — 调用方上下文；当前实现未使用它（进程生命周期由 Stop 控制）
//
// 返回：
//
//	error — 下行监听 / API 启动失败时返回
func (n *Node) Start(ctx context.Context) error {
	pending := !n.hasUsableCert()
	if pending {
		n.Log.Warn("no usable certificate: starting in ENROLLMENT mode",
			"cert_path", n.C().Security.IdentityCertPath,
			"enrollment_enabled", n.C().Security.EnrollmentEnabled(),
			"downstream_deferred", n.C().HasDownstream())
	}
	if !pending {
		if err := n.startHub(); err != nil {
			return err
		}
	}
	if n.C().HasAPI() {
		if err := n.StartAPI(); err != nil {
			return err
		}
	}
	if n.C().HasUpstream() {
		n.ensureStartedUpstream()
	}
	n.registerMetrics()
	n.startBackgroundLoops()
	// 建立会话后重新激活本地未终态指令（6.4），并周期兜底
	go func() {
		select {
		case <-n.stopCh:
			return
		case <-time.After(1500 * time.Millisecond):
		}
		n.reactivatePending()
	}()
	return nil
}

// registerCustom 记录"某条指令用哪个 CUSTOM 聚合器"（本地提交的指令才会走到这里）。
//
// 参数：
//
//	cmdID — 指令 ID
//	a     — 该指令要用的自定义聚合器实现
func (n *Node) registerCustom(cmdID string, a aggregate.CustomAggregator) {
	n.customMu.Lock()
	defer n.customMu.Unlock()
	if n.customs == nil {
		n.customs = map[string]aggregate.CustomAggregator{}
	}
	n.customs[cmdID] = a
}

// customFor 取该指令的 CUSTOM 聚合器：本地提交的用注册表，其他跳从 Command.AggregateName 解析。
//
// 参数：
//
//	c — 指令体；聚合策略不是 AGGREGATE_CUSTOM 时直接返回 nil
//
// 返回：
//
//	aggregate.CustomAggregator — 找到的聚合器；未注册且按名字也查不到时为 nil
func (n *Node) customFor(c *pb.Command) aggregate.CustomAggregator {
	if c == nil || c.Aggregate == nil || *c.Aggregate != pb.AggregateStrategy_AGGREGATE_CUSTOM {
		return nil
	}
	n.customMu.RLock()
	a, ok := n.customs[c.Id]
	n.customMu.RUnlock()
	if ok {
		return a
	}
	if a2, ok := aggregate.LookupCustom(c.AggregateName); ok {
		return a2
	}
	return nil
}

// dropCustom 删除某条指令的 CUSTOM 聚合器记录，避免注册表无限增长。
//
// 参数：
//
//	cmdID — 指令 ID；不存在时静默忽略
func (n *Node) dropCustom(cmdID string) {
	n.customMu.Lock()
	delete(n.customs, cmdID)
	n.customMu.Unlock()
}

// registerMetrics 注册 9.3 里的关键指标。
//
// 接收者 n 是本节点实例。这里注册的 gauge 都不缓存值：抓取时现场读账本 / 计数器再求值，
// 所以指标反映的是"抓取那一刻"的实际情况。
func (n *Node) registerMetrics() {
	m := n.Metrics
	m.Help("node_up", "本节点是否在运行")
	m.SetGauge("node_up", func() float64 { return 1 })
	m.Help("children_count", "直接子节点数（已连上）")
	m.SetGauge("children_count", func() float64 { return float64(n.childOnline()) })
	m.Help("children_known", "注册表中已知的直接子节点数")
	m.SetGauge("children_known", func() float64 { return float64(n.Reg.Len()) })
	m.Help("command_inflight", "本节点正在执行的本地指令数")
	m.SetGauge("command_inflight", func() float64 { return float64(n.inflightCount()) })
	m.Help("command_pending_total", "未终态指令数（本地账本）")
	m.SetGauge("command_pending_total", func() float64 {
		c := 0
		_ = n.Store.View(func(tx *store.Tx) error {
			for _, l := range tx.ScanLocal() {
				switch l.LocalState {
				case pb.LocalExecState_LOCAL_STATE_COMPLETED, pb.LocalExecState_LOCAL_STATE_SELF_FAILED,
					pb.LocalExecState_LOCAL_STATE_SELF_CANCELLED:
				default:
					c++
				}
			}
			return nil
		})
		return float64(c)
	})
	m.Help("partial_total", "处于 PARTIAL 的指令数（过渡态，不计入终态分布）")
	m.SetGauge("partial_total", func() float64 {
		c := 0
		_ = n.Store.View(func(tx *store.Tx) error {
			for _, rec := range tx.ScanCommands() {
				if rec.Status == pb.CommandStatus_COMMAND_STATUS_PARTIAL {
					c++
				}
			}
			return nil
		})
		return float64(c)
	})
	m.Help("pending_result_backlog", "待上报 / 待补报的结果条数")
	m.SetGauge("pending_result_backlog", func() float64 { return float64(n.pendingCount()) })
	m.Help("retention_floor", "指令日志的保留水位下界")
	m.SetGauge("retention_floor", func() float64 {
		v := int64(0)
		_ = n.Store.View(func(tx *store.Tx) error { v = tx.MinUnfinishedSeq(); return nil })
		return float64(v)
	})
	m.Help("result_index_entries", "本节点结果索引条数（内存）")
	m.SetGauge("result_index_entries", func() float64 { return float64(n.index.len()) })
	m.Help("clock_offset_ms", "与父节点的时钟偏移 EWMA（毫秒）")
	m.SetGauge("clock_offset_ms", func() float64 {
		if n.up == nil {
			return 0
		}
		return float64(n.up.offsetMSValue())
	})
	m.Help("command_terminal_total", "指令终态计数（按 status）")
	m.SetLabeled("command_terminal_total", func() map[string]float64 {
		n.termMu.Lock()
		defer n.termMu.Unlock()
		out := map[string]float64{}
		for k, v := range n.statCmdTerminal {
			out["status="+k] = float64(v)
		}
		return out
	})
	m.Help("fail_rate_1h", "近 1 小时指令失败率")
	m.SetGauge("fail_rate_1h", func() float64 { return n.failRate1h() })
	m.Help("cert_not_after_days", "本节点身份证书剩余有效天数（负值=已过期）")
	m.SetGauge("cert_not_after_days", func() float64 {
		id := n.Id()
		if id == nil || id.Cert == nil {
			return -1
		}
		return time.Until(id.Cert.NotAfter).Hours() / 24
	})
	m.Help("cert_reload_total", "证书热重载次数（result=ok|failed|nochange|missing）")
	m.Help("enroll_total", "运行期入网计数（result=issued|denied|installed）")
	m.Help("trust_anchor_count", "当前加载到的信任锚证书数量")
	m.SetGauge("trust_anchor_count", func() float64 { return float64(len(identity.PoolCerts(n.rootsPool()))) })
	m.Help("enrollment_pending", "是否处于待入网状态（1=还没有可用证书）")
	m.SetGauge("enrollment_pending", func() float64 {
		if n.hasUsableCert() {
			return 0
		}
		return 1
	})
	m.Help("pending_result_fail_total", "待上报重发失败次数")
	m.Help("result_stored_total", "结果落库条数")
	m.SetGauge("result_stored_total", func() float64 {
		c := 0
		_ = n.Store.View(func(tx *store.Tx) error { c = len(tx.ScanResults()); return nil })
		return float64(c)
	})
}

// backgroundContext 返回后台任务用的上下文。
//
// 返回：
//
//	context.Context — 固定为 context.Background()，不带取消与超时
func (n *Node) backgroundContext() context.Context { return context.Background() }

// Stop 优雅停止本节点：关停 API / 上行链路 / 下行监听，等全部后台协程退出，
// 再落一次状态快照并关闭账本。
//
// 接收者 n 是本节点实例。重复调用安全：靠 stopped 原子标志保证只真正执行一次。
func (n *Node) Stop() {
	if n.stopped.Swap(true) {
		return
	}
	close(n.stopCh)
	n.stopAPI()
	if n.up != nil {
		n.up.stop()
	}
	if n.hub != nil {
		n.hub.stop()
	}
	n.wg.Wait()
	n.saveState()
	_ = n.Store.Close()
}

// startBackgroundLoops 启动本节点全部后台周期任务（租约回收、待上报重发、结果索引补发、
// 证书续签 / 热重载、状态落盘、档案清理等）。
//
// 接收者 n 是本节点实例。启动哪些任务取决于本节点有没有下行 hub（有子节点）与上行 up（有父节点）。
func (n *Node) startBackgroundLoops() {
	// 租约过期扫描（服务端视角，LeaseTTL/3）
	if n.hub != nil {
		n.loop(n.C().Command.LeaseTTL/3, 0, "lease-reclaim", n.reclaimExpiredLeases)
		n.loop(5*time.Minute, 0, "eviction-scan", n.scanEvictions)
		n.loop(10*time.Minute, 0, "cmdlog-cleanup", n.cleanupCommandLog)
		n.loop(30*time.Minute, 3*time.Second, "evicted-cleanup", n.cleanupEvicted)
	}
	// pending_result 周期重发（3.11 触发点 2）
	if n.up != nil {
		n.loop(30*time.Second, time.Second, "pending-resend", n.resendPending)
	}
	// 结果索引待重发队列（链路通后补发）
	if n.up != nil {
		n.loop(30*time.Second, 2*time.Second, "result-index-resend", func(context.Context) { n.resendResultIndexes() })
	}
	// 证书续签：子节点本地调度（生命期 2/3 处主动发起；父若有 CA 材料才会真的签发）
	n.startCertRenewLoop()
	// 证书热重载：轮询兜底 + SIGUSR1 立即生效（外部脚本换证后无需重启）
	n.startCertReloadLoop()
	// state.dat 周期落盘
	n.loop(n.C().Persist.Interval, time.Second, "persist", func(context.Context) { n.saveState() })
	// results 档案清理 + 索引回收 + 周期重推（3.14）
	n.loop(30*time.Minute, 5*time.Second, "results-cleanup", func(context.Context) { n.cleanupResults() })
	n.loop(n.C().Command.IndexRepushInterval, 10*time.Second, "index-repush", func(context.Context) { n.repushIndexes() })
}

// loop 起一个后台周期协程：每 every 调用一次 fn，随 stopCh 关闭退出；协程计入 wg，供 Stop 等待。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	every  — 触发间隔；<= 0 时本函数直接返回，不启动任何协程
//	jitter — 抖动幅度上限，交给 jittered 打散触发时刻；0 表示不抖动
//	name   — 任务名（如 "persist" / "lease-reclaim"），仅用于 debug 日志，不参与调度
//	fn     — 每次触发调用的函数；串行执行，由 ticker 控制节奏
func (n *Node) loop(every, jitter time.Duration, name string, fn func(context.Context)) {
	if every <= 0 {
		return
	}
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		t := time.NewTicker(jittered(every, jitter))
		defer t.Stop()
		// 只是 debug 级：用 -log-level debug 启动时，可以一眼看到都起了哪些后台任务、各自的真实节奏
		n.Log.Debug("background task armed", "task", name, "every", every.String(), "jitter", jitter.String())
		for {
			select {
			case <-n.stopCh:
				return
			case <-t.C:
				fn(context.Background())
			}
		}
	}()
}

// jittered 给周期 d 叠加 ±20% 的随机偏移，防止多个节点同时触发形成同步风暴。
//
// 参数：
//
//	d     — 基准周期
//	limit — 抖动**幅度上限**：<= 0 表示不抖动、原样返回 d；
//	        否则实际幅度取「d 的 20%」与 limit 里更小的那个
//
// 返回：
//
//	time.Duration — 抖动后的周期；d 太小（20% 不足 1ns）时原样返回 d
//
// 调用方给的上限若比 20% 更紧（例如 30s 的周期只允许 ±1s），就以调用方为准 ——
// 这样"周期节奏"仍由调用方说了算，抖动只是在此基础上把多节点错开。
func jittered(d, limit time.Duration) time.Duration {
	if limit <= 0 {
		return d
	}
	// ±20% jitter（防同步风暴），但不超过调用方给的上限
	delta := int64(float64(d) * 0.2)
	if lim := int64(limit); delta > lim {
		delta = lim
	}
	if delta <= 0 {
		return d
	}
	off := time.Duration(randInt63n(2*delta+1)) - time.Duration(delta)
	return d + off
}

// saveState 把当前运行态快照原子写入 state.dat：自身（含 NodeID 与路径）、祖先链、
// 上行会话与水位、已知子节点列表、配置 hash 等。
//
// 接收者 n 是本节点实例；写盘前会在 stateMu 保护下把 n.state 各字段刷新为最新值。
//
// 注意：调用点有三处 —— 启动装配阶段（把解析出的 NodeID 落盘，见 NewWithPath）、
// 周期任务（persist，默认 30s）、以及 Stop() 退出前。三处都写同一份快照，
// 所以**没有"强制/非强制"之分**（原先的 force 参数已被删除：它在实现里从未被使用）。
func (n *Node) saveState() {
	n.stateMu.Lock()
	defer n.stateMu.Unlock()
	s := n.state
	s.SavedAt = time.Now().UTC().Format(time.RFC3339Nano)
	s.ConfigHash = n.C().ConfigHash()
	s.Self = persist.Self{ID: n.C().Node.ID, Path: n.SelfPath(), Ancestors: n.Ancestors()}
	if n.up != nil {
		s.Session = n.up.sessionSnapshot()
		s.Watermarks.LastCmdSeq = n.up.lastCmdSeq()
	}
	_ = n.Store.View(func(tx *store.Tx) error {
		s.Watermarks.NextCmdSeq = tx.NextCmdSeq()
		s.Watermarks.RetentionFloor = tx.MinUnfinishedSeq()
		return nil
	})
	kc := []persist.KnownChild{}
	for _, c := range n.Reg.Snapshot() {
		kc = append(kc, persist.KnownChild{ID: c.NodeID, Path: c.Path,
			Name: c.Name, Remark: c.Remark, Caps: c.Caps, Labels: c.Labels})
	}
	s.KnownChildren = kc
	if err := persist.Save(n.C().Persist.StatePath, s); err != nil {
		n.Log.Warn("save state failed", "err", err)
	}
}

// ---------- 事件唤醒（waitChildren 用；tick 是兜底，事件是优化） ----------

// eventCh 取（必要时创建）该指令的事件通道，waitChildren 靠它被"子节点已上报"唤醒。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	chan struct{} — 容量 1 的只写信号通道；发信号请用 signal，避免阻塞
func (n *Node) eventCh(cmdID string) chan struct{} {
	n.evMu.Lock()
	defer n.evMu.Unlock()
	ch, ok := n.events[cmdID]
	if !ok {
		ch = make(chan struct{}, 1)
		n.events[cmdID] = ch
	}
	return ch
}

// signal 向该指令的事件通道发一次非阻塞信号（通道满就丢弃），唤醒正在等待的 waitChildren。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID；该指令还没建过事件通道时直接返回（说明当前没人在等）
func (n *Node) signal(cmdID string) {
	n.evMu.Lock()
	ch, ok := n.events[cmdID]
	n.evMu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

// signalFetch 催上行拉取循环立刻拉一次（CommandNotify 通知到达后的落地动作）。
//
// 接收者 n 是本节点实例。信号通道带缓冲，满了就丢弃，不阻塞调用方。
func (n *Node) signalFetch() {
	select {
	case n.fetchNotify <- struct{}{}:
	default:
	}
}

// dropEvent 删除该指令的事件通道（waitChildren 退出时调用，避免 events 表无限增长）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	cmdID — 指令 ID；不存在时静默忽略
func (n *Node) dropEvent(cmdID string) {
	n.evMu.Lock()
	delete(n.events, cmdID)
	n.evMu.Unlock()
}

// ---------- 近 1h 终态窗口 ----------

// recordTerminal 记一次终态：写进近 1 小时的滑动窗口，并累加按状态分组的计数器。
//
// 接收者 n 是本节点实例；窗口是纯内存态，不持久化（重启后重新统计）。
//
// 参数：
//
//	status — 终态名（如 "FAILED" / "COMPLETED"），同时用作计数器的分组标签
func (n *Node) recordTerminal(status string) {
	n.termMu.Lock()
	defer n.termMu.Unlock()
	now := time.Now()
	n.termWnd = append(n.termWnd, termSample{At: now, Status: status})
	cut := now.Add(-time.Hour)
	i := 0
	for i < len(n.termWnd) && n.termWnd[i].At.Before(cut) {
		i++
	}
	if i > 0 {
		n.termWnd = append([]termSample(nil), n.termWnd[i:]...)
	}
	n.statCmdTerminal[status]++
}

// failRate1h 统计近 1 小时滑动窗口内 FAILED / TIMEOUT 占全部终态的比例。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	float64 — 失败率（0 ~ 1）；窗口内没有任何终态时返回 0
func (n *Node) failRate1h() float64 {
	n.termMu.Lock()
	defer n.termMu.Unlock()
	total, bad := 0, 0
	cut := time.Now().Add(-time.Hour)
	for _, s := range n.termWnd {
		if s.At.Before(cut) {
			continue
		}
		total++
		if s.Status == "FAILED" || s.Status == "TIMEOUT" {
			bad++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(bad) / float64(total)
}

// ---------- 本地并发信号量 ----------

// acquireLocal 尝试占用一个本地执行名额（名额总数 = command.max_inflight 决定的 semLocal 容量）。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	bool — true 表示占到名额（用完必须调 releaseLocal）；false 表示名额已满
func (n *Node) acquireLocal() bool {
	select {
	case n.semLocal <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseLocal 归还一个本地执行名额（不阻塞；没有可归还的就直接返回）。
//
// 接收者 n 是本节点实例。
func (n *Node) releaseLocal() {
	select {
	case <-n.semLocal:
	default:
	}
}

// ---------- Inflight：进程内单飞表 ----------

// InflightTable 同一 commandID 同时只允许一个执行在跑；同时存 CancelFunc 与 cancelRequested 标志。
type InflightTable struct {
	mu sync.Mutex
	m  map[string]*inflightEntry
}

// inflightEntry 单条"正在跑"的指令记录：取消函数、生效 attempt、进程内取消标志。
type inflightEntry struct {
	cancel    context.CancelFunc
	attempt   uint64
	cancelled atomic.Bool
}

// newInflightTable 建一张空的进程内单飞表。
//
// 返回：
//
//	*InflightTable — 内部 map 已初始化，可直接 Enter
func newInflightTable() *InflightTable { return &InflightTable{m: map[string]*inflightEntry{}} }

// Enter 抢某条指令的执行权（同一 commandID 同时只允许一个执行在跑）。
//
// 接收者 t 是进程内单飞表（并发安全）。
//
// 参数：
//
//	id      — 指令 ID
//	attempt — 本次是第几次尝试（从 1 开始）
//	cancel  — 用于中断本次执行的取消函数，在 Leave 前一直由表持有
//
// 返回：
//
//	bool — true 表示抢到（表中原本没有该 ID）；false 表示已有执行在跑
func (t *InflightTable) Enter(id string, attempt uint64, cancel context.CancelFunc) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[id]; ok {
		_ = e
		return false
	}
	t.m[id] = &inflightEntry{cancel: cancel, attempt: attempt}
	return true
}

// Leave 释放某条指令的执行权。
//
// 接收者 t 是进程内单飞表（并发安全）。
//
// 参数：
//
//	id — 指令 ID；表中没有该 ID 时静默忽略
func (t *InflightTable) Leave(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, id)
}

// Attempt 返回该指令当前在跑的 attempt（供 InflightHint 回给父端）。
//
// 接收者 t 是进程内单飞表（并发安全）。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	uint64 — 当前在跑的 attempt；没在跑时返回 0
func (t *InflightTable) Attempt(id string) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[id]; ok {
		return e.attempt
	}
	return 0
}

// CancelRequested 返回该指令是否已被请求取消（进程内标志）。
// 判据必须用它，不能用账本里的状态快照 —— 账本可能落后于内存。
//
// 接收者 t 是进程内单飞表（并发安全）。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	bool — 已标记取消为 true；没在跑或未标记为 false
func (t *InflightTable) CancelRequested(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[id]; ok {
		return e.cancelled.Load()
	}
	return false
}

// Running 返回该指令当前是否在跑。
//
// 接收者 t 是进程内单飞表（并发安全）。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	bool — 表中存在该 ID 为 true
func (t *InflightTable) Running(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.m[id]
	return ok
}

// MarkCancelled 给在跑的该指令置取消标志；本函数不执行 cancel，由调用方接着调 cancel。
//
// 接收者 t 是进程内单飞表（并发安全）。
//
// 参数：
//
//	id — 指令 ID；没在跑时静默忽略
func (t *InflightTable) MarkCancelled(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.m[id]; ok {
		e.cancelled.Store(true)
	}
}

// ---------- 小工具 ----------

// shortID 截取 ID 的前 8 位用于日志展示；不足 8 位就原样返回。
//
// 参数：
//
//	id — 原始 ID
//
// 返回：
//
//	string — 截断后的短 ID
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// ErrNotFound 通用未找到。
var ErrNotFound = errors.New("NOT_FOUND")

// ErrTerminal 指令已终态。
var ErrTerminal = errors.New("ERR_COMMAND_TERMINAL")

// ErrRetryExhausted 重试次数用尽。
var ErrRetryExhausted = errors.New("ERR_RETRY_EXHAUSTED")

// sortedKeys 取 map 的全部键并升序排序（用于把 map 输出成稳定的顺序）。
//
// 参数：
//
//	m — 要取键的 map；nil 也安全
//
// 返回：
//
//	[]string — 升序排好的键；m 为空时返回长度 0 的切片
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
