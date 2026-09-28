// Package config 负责静态配置（node.yaml）的加载、校验与 config_hash 计算。
// 硬约束（6.1 / ADR-005）：node.yaml 由人编写，程序只读，绝不回写。
package config

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"treecmd/internal/buildinfo"
)

// 节点元信息（node.name / node.remark）的长度上限。
// 它们会随注册上行、并随健康响应逐跳回传，必须封顶，否则单条 remark
// 就能吃掉 health_response_max_bytes 的预算。
const (
	MaxNodeNameBytes   = 128
	MaxNodeRemarkBytes = 512
)

// ByteSize 支持 "1MB" / "256KB" / "3.5MB" / 纯字节数。
type ByteSize int64

// UnmarshalYAML 让配置里的 ByteSize 字段既能写 "1MB" 这种字符串，也能直接写纯数字。
//
// 它是 yaml.v3 的自定义解析钩子，由 yaml.Unmarshal 在解析到该类型字段时自动调用，不用手工调。
// 实现上先试着按字符串解（走 ParseByteSize 支持单位），失败再退回按整数解。
//
// 参数：
//
//	node — 该字段在 YAML 文档里对应的节点，值是字符串或数字
//
// 返回：
//
//	error — 按字符串、按整数都解析不出来时返回
func (b *ByteSize) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		var n int64
		if err2 := node.Decode(&n); err2 == nil {
			*b = ByteSize(n)
			return nil
		}
		return err
	}
	v, err := ParseByteSize(s)
	if err != nil {
		return err
	}
	*b = ByteSize(v)
	return nil
}

// ParseByteSize 把 "1MB" / "256KB" / "3.5MB" 这类带单位的体积文本换算成字节数。
//
// 大小写不敏感。单位后缀按 KB/MB/GB/K/M/G/B 的顺序逐个匹配（先长后短，
// 否则 "1MB" 会被 "B" 抢先匹配）；没有后缀时按字节算，允许小数。
//
// 参数：
//
//	s — 待解析的体积文本，如 "8MB"
//
// 返回：
//
//	int64 — 换算出的字节数（小数部分截断）
//	error — 数字部分解析不出来时返回
func ParseByteSize(s string) (int64, error) {
	t := strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for _, suf := range []struct {
		s string
		m int64
	}{{"KB", 1024}, {"MB", 1024 * 1024}, {"GB", 1024 * 1024 * 1024}, {"K", 1024}, {"M", 1024 * 1024}, {"G", 1024 * 1024 * 1024}, {"B", 1}} {
		if strings.HasSuffix(t, suf.s) {
			mult = suf.m
			t = strings.TrimSuffix(t, suf.s)
			break
		}
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size %q", s)
	}
	return int64(f * float64(mult)), nil
}

// Parent 一个上游父节点（有序，故障转移依次尝试）。
type Parent struct {
	ID   string `yaml:"id"`
	Addr string `yaml:"addr"`
}

// NodeSection 节点自身声明。
//
// 关于 node.id：**可以留空**。留空时由程序按 ADR-050 解析 ——
// 依次取"已签发证书的身份 → state.dat 的 self.id → 新生成 UUIDv7"，
// **绝不回写本文件**（`node.yaml` 对程序始终只读）。显式写上则以其为准。
type NodeSection struct {
	ID     string `yaml:"id"`
	Listen string `yaml:"listen"`
	Name   string `yaml:"name"`   // 节点名（人类可读，如 edge-sz-01）；用于标记这个 node 的身份
	Remark string `yaml:"remark"` // 节点备注（自由文本）；与 name 一起随注册上行、经 API 可见
}

// SecuritySection 身份材料 + 授权参数。
type SecuritySection struct {
	TrustedOrigins     []string `yaml:"trusted_origins"`
	HealthViewers      []string `yaml:"health_viewers"`
	IdentityKeyPath    string   `yaml:"identity_key_path"`
	IdentityPubKeyPath string   `yaml:"identity_pubkey_path"`
	IdentityCertPath   string   `yaml:"identity_cert_path"`
	CACertPaths        []string `yaml:"ca_cert_paths"` // 信任锚：**文件或目录**，目录下所有 *.crt/*.pem 都加载（可多个）
	CACertPath         string   `yaml:"ca_cert_path"`  // **本节点自己的 CA 证书**（有子节点时必需，区别于信任锚）
	CAKeyPath          string   `yaml:"ca_key_path"`   // 本节点自己的 CA 私钥（仅父 / 中继有）

	// 证书生命期（天）。默认值 = 本项目历史行为：身份证书 30、CA 证书 3650（10 年）。
	//
	// 两个都不进 config_hash：换生命期只影响"以后签出来的证书多久过期"，
	// 不影响拓扑 / 会话 / 身份 / 父列表，**不需要全量重注册**。
	//
	// 为什么 CA 证书也做成可配：CA 证书现在可以"只换证书、不换密钥"地在线轮换
	// （见 identity.ReissueCAFor），所以把 10 年改成 1 年这类收敛策略是安全的 ——
	// 下级不用重新分发 trust/。**默认值刻意不变**，避免存量节点的 CA 证书集体进续签窗口。
	IdentityCertDays int `yaml:"identity_cert_days"` // 默认 30
	CACertDays       int `yaml:"ca_cert_days"`       // 默认 3650

	// 证书热重载：证书由外部脚本管理时，靠它把变更吃进来（见 README「证书生命周期」）
	CertReload CertReloadSection `yaml:"cert_reload"`
	// 运行期入网签发：子节点没有自带证书时，用许可向父换取证书（父签发子）
	Enrollment EnrollmentSection `yaml:"enrollment"`
}

// CertReloadSection 证书/密钥文件变更检测与热重载。
type CertReloadSection struct {
	Enabled *bool `yaml:"enabled"` // 默认 true
	// 轮询间隔（零依赖兜底）。默认 30s；小于 5s 会被抬到 5s
	Interval time.Duration `yaml:"interval"`
	// 额外要监视的路径（文件或目录）；留空 = 自动（身份私钥/公钥/证书 + CA 证书/私钥 + 信任锚）
	Paths []string `yaml:"paths"`
	// 变更后如何让新证书生效：
	//   reconnect（默认）—— 只有"本节点身份证书 / 私钥"变了才主动重连（尽快用新证书握手）；其余变更等自然重连
	//   lazy           —— 一律只对新连接生效，不打断任何现有会话
	OnChange string `yaml:"on_change"`
}

// EnrollmentSection 运行期入网签发（父签发子；子节点私钥不出本机）。
//
// 两侧共用本段：对父是"**允许别人来入网**"，对子是"**我去换证**"。
//
// **入网认证只有一个口径：入网许可（Token / TokenPath，两端同值）** —— 它是唯一的授权判据，
// 父端没配它就拒绝一切入网。它承载的是"入网**引导凭据**"（见 identity.ParseBootstrap）：
// 文件里除 permit 外还可以内嵌父的 CA 证书链，于是子节点只拷一份文件就走完首跳。
//
// 这里**曾经**还有一个 `allow_ids` 白名单（"只允许这些 NodeID 入网"）**已删除**：
// NodeID 是公开信息（`/v1/tree` 就能读到），且与密钥对之间没有任何密码学绑定
// （`node.id` 还允许留空自动生成），所以白名单挡不住"自报一个名单里的 ID + 自建一对密钥"。
// 想限定"这一次准入发给谁"，正确做法是**每节点一枚一次性许可**，而不是给一份 ID 名单。
type EnrollmentSection struct {
	Enabled      *bool         `yaml:"enabled"`       // 默认 true
	Token        string        `yaml:"token"`         // 入网许可（父端校验；子端提交同一串）
	TokenPath    string        `yaml:"token_path"`    // 或者从文件读（优先于 token，便于脚本投放）
	ChallengeTTL time.Duration `yaml:"challenge_ttl"` // 一次性挑战有效期，默认 5m
}

// CertReloadEnabled 报告证书热重载是否开启（没配就当开启）。
//
// 接收者 s 是 security 段的配置。
//
// 返回：
//
//	bool — enabled 字段为 nil（配置里没写）时返回 true，否则返回配置的值
func (s *SecuritySection) CertReloadEnabled() bool {
	return s.CertReload.Enabled == nil || *s.CertReload.Enabled
}

// ReloadInterval 返回归一化后的证书轮询间隔。
//
// 接收者 s 是 security 段的配置；轮询是零依赖的兜底手段，不用 inotify。
//
// 返回：
//
//	time.Duration — 未配置或非正数时取 30s；值小于 5s 会被抬到 5s（避免把磁盘刷爆）
func (s *SecuritySection) ReloadInterval() time.Duration {
	d := s.CertReload.Interval
	if d <= 0 {
		d = 30 * time.Second
	}
	if d < 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// ReloadOnChange 返回归一化后的"证书变更如何生效"策略。
//
// 接收者 s 是 security 段的配置。
//
// 返回：
//
//	string — 只有显式写了 "lazy" 才返回 "lazy"，其余（含空值、拼错）一律返回 "reconnect"
func (s *SecuritySection) ReloadOnChange() string {
	if s.CertReload.OnChange == "lazy" {
		return "lazy"
	}
	return "reconnect"
}

// EnrollmentEnabled 报告运行期入网是否开启（没配就当开启）。
//
// 接收者 s 是 security 段的配置。
//
// 返回：
//
//	bool — enabled 字段为 nil（配置里没写）时返回 true，否则返回配置的值
func (s *SecuritySection) EnrollmentEnabled() bool {
	return s.Enrollment.Enabled == nil || *s.Enrollment.Enabled
}

// EnrollCredentialRaw 取"入网引导凭据"的**原始内容**（不做任何解析）。
//
// 接收者 s 是 security 段的配置。`token_path`（文件）优先于 `token`（直接写在配置里）——
// 优先文件是为了让脚本能投放与轮换它。**为什么不在这里解析**：凭据里既有许可、
// 又可能内嵌父的 CA 证书链，解析要碰 x509 —— 那属于 internal/identity 的职责
// （`identity.ParseBootstrap`，格式的权威定义也在那里）。配置层只负责"去哪拿"。
//
// 参数：无。
//
// 返回：
//
//	[]byte — 凭据的原始内容；两个来源都没配时返回空字节切片
//	error  — 配了 token_path 但文件读不到时返回
func (s *SecuritySection) EnrollCredentialRaw() ([]byte, error) {
	if s.Enrollment.TokenPath != "" {
		b, err := os.ReadFile(s.Enrollment.TokenPath)
		if err != nil {
			return nil, fmt.Errorf("read enrollment.token_path: %w", err)
		}
		return b, nil
	}
	return []byte(strings.TrimSpace(s.Enrollment.Token)), nil
}

// EnrollChallengeTTL 返回归一化后的一次性入网挑战有效期。
//
// 接收者 s 是 security 段的配置。
//
// 返回：
//
//	time.Duration — 未配置或非正数时取 5 分钟
func (s *SecuritySection) EnrollChallengeTTL() time.Duration {
	if s.Enrollment.ChallengeTTL <= 0 {
		return 5 * time.Minute
	}
	return s.Enrollment.ChallengeTTL
}

// CommandSection 节点本地运行参数（不进 config_hash，见 6.1 白名单）。
type CommandSection struct {
	LeaseTTL                 time.Duration     `yaml:"lease_ttl"`
	RenewAt                  time.Duration     `yaml:"renew_at"`
	MaxDeadline              time.Duration     `yaml:"max_deadline"`
	DefaultDeadlineByType    map[string]string `yaml:"default_deadline_by_type"`
	UnknownTypeDeadline      time.Duration     `yaml:"unknown_type_deadline"`
	AuditRetention           time.Duration     `yaml:"audit_retention"`
	EvictionTimeout          time.Duration     `yaml:"eviction_timeout"`
	EvictionArchiveRetention time.Duration     `yaml:"eviction_archive_retention"`
	StreamIdleTimeout        time.Duration     `yaml:"stream_idle_timeout"`
	ReserveForReport         time.Duration     `yaml:"reserve_for_report"`
	MaxPayload               ByteSize          `yaml:"max_payload"`
	MaxCommandBytes          ByteSize          `yaml:"max_command_bytes"`
	FetchResponseMaxBytes    ByteSize          `yaml:"fetch_response_max_bytes"`
	MaxChunkTotal            int32             `yaml:"max_chunk_total"`
	ChunkSize                ByteSize          `yaml:"chunk_size"`
	ChildStuckTimeout        time.Duration     `yaml:"child_stuck_timeout"`
	LeaseReclaimCap          int32             `yaml:"lease_reclaim_cap"`
	MaxRetryNodeCount        int32             `yaml:"max_retry_node_count"`
	LocalBusyBackoff         time.Duration     `yaml:"local_busy_backoff"`
	// ---- 下发背压：在途窗口与退避（见 README「下发即执行」）----
	//
	// **"在途"的定义（全仓库一致）**：Assignment 处于 LEASED，且租约仍在有效期内。
	// 两种都不算：PENDING（含退避中）—— 子还没拿到；LEASED 但租约已过期 —— 那是"父已经忘了"的
	// 僵尸租约，下一轮就会被回收成 PENDING，若把它算进窗口，一次父重启就能让窗口被占满、把自己锁死。
	//
	// 两个窗口都是 *int32，语义是：**没配 = 默认值，显式写 0 = 不限**。
	// 为什么不像其它字段那样"0 即默认"：这里 0 的"不限"是个**有用且必须能表达**的取值
	// （= 完全回到加这个功能之前的行为）。代价是多一层指针，换来的是配置里能一眼看懂。
	// 两个字段用同一套规则，运维只需要记一条。
	MaxDispatchInflightPerChild *int32 `yaml:"max_dispatch_inflight_per_child"` // 每个直接子的在途上限（默认 8）
	// MaxDispatchInflight 所有直接子的在途总数上限。**默认 0 = 不限** —— 这是刻意的：
	// 固定数字必然在某个扇出规模上开始咬人（per-child 窗口是 8 时，只要直接子超过 32 个，
	// 全局 256 就会顶住，把本来能并行的下发变成一波一波），而它想防的是"病态扇出"这种少见情况。
	// 建议要开就按 **总数 ≥ 单子窗口 × 直接子数** 配，否则先看
	// `dispatch_throttled_total{reason="total_window"}` 有没有涨。
	MaxDispatchInflight *int32 `yaml:"max_dispatch_inflight"` // 所有直接子的在途总数上限（默认 0 = 不限）
	// DispatchWindowAdaptive 打开后，per-child 窗口 = min(配置值, max(1, 全局窗口 / 在线子数))：
	// 子在线的多就收紧、子掉线就放宽。这是 taktuk 的 `-d` work-stealing 在 treecmd 里
	// **唯一合法的等价物** —— 任务本身不可再分配（整棵子树人人各执行一次），能借的只有
	// "自适应在途窗口"这个效果。注意它**只会收紧**，不会超过 max_dispatch_inflight_per_child。
	DispatchWindowAdaptive bool `yaml:"dispatch_window_adaptive"`
	// LocalBusyBackoffMax LocalBusy 指数退避的**封顶**（默认 60s）。
	// 退避时长 = min(local_busy_backoff << (streak-1), 这个值)；也就是说 local_busy_backoff
	// 就是**基数**，不需要再造一个 backoff_base 字段去和它指同一件事。
	LocalBusyBackoffMax  time.Duration `yaml:"local_busy_backoff_max"`
	PendingResendBatch   int32         `yaml:"pending_resend_batch"`
	MaxReportConcurrency int32         `yaml:"max_report_concurrency"`
	IndexRepushInterval  time.Duration `yaml:"index_repush_interval"`
	MaxInflight          int32         `yaml:"max_inflight"`
	TickInterval         time.Duration `yaml:"tick_interval"`
	ReconcileWindow      time.Duration `yaml:"reconcile_window"`
	// 对象存储目录（>64MB 的大结果落这里，见 3.13 第三级）
	ObjectStoreDir string `yaml:"object_store_dir"`
}

// 下发背压的默认窗口。**只在配置里没写这个键**时生效；显式写 0 一律表示"不限"。
const (
	dispatchDefaultPerChild int32 = 8 // 每个子的在途上限
	dispatchDefaultTotal    int32 = 0 // 全局在途上限：默认不限（理由见 MaxDispatchInflight 的注释）
)

// DispatchWindowPerChild 返回归一化后的"每个直接子的在途分派上限"。
//
// 接收者 c 是 command 段的配置。
//
// 返回：
//
//	int32 — 没配时取 8；**0 表示不限**（会原样返回，不会被默认值顶掉）
//
// 默认值 8 之所以敢给，是因为窗口是**跨指令**的：单条指令对每个子只有 1 个 Assignment
// （见 EnsureCreated），所以 8 对"一次提交一条指令"零影响，只在同一子同时积压 >8 条指令时才生效。
func (c *CommandSection) DispatchWindowPerChild() int32 {
	if c.MaxDispatchInflightPerChild == nil {
		return dispatchDefaultPerChild
	}
	return *c.MaxDispatchInflightPerChild
}

// DispatchWindowTotal 返回全局在途分派上限。
//
// 接收者 c 是 command 段的配置。
//
// 返回：
//
//	int32 — 没配时取 0，也就是**不限**（这是刻意的默认，见字段注释）；0 表示不限
func (c *CommandSection) DispatchWindowTotal() int32 {
	if c.MaxDispatchInflight == nil {
		return dispatchDefaultTotal
	}
	return *c.MaxDispatchInflight
}

// LocalBusyBackoffCap 返回 LocalBusy 指数退避的封顶时长。
//
// 接收者 c 是 command 段的配置。
//
// 返回：
//
//	time.Duration — 没配或非正数时取 60s；**小于基数（local_busy_backoff）时抬到基数** ——
//	                否则 streak=1 那一次退避会比不封顶还短，指数退避就名不副实了
func (c *CommandSection) LocalBusyBackoffCap() time.Duration {
	d := c.LocalBusyBackoffMax
	if d <= 0 {
		d = 60 * time.Second
	}
	if c.LocalBusyBackoff > 0 && d < c.LocalBusyBackoff {
		d = c.LocalBusyBackoff
	}
	return d
}

// int32Ptr 取一个 int32 的指针。
//
// 存在的唯一理由是配置里那几个 *int32 字段需要区分"没配"（nil）与"显式写了 0"，
// 构造默认值时用得上；没有它就得在调用处临时声明一个变量。
//
// 参数：
//
//	v — 要取地址的整数值
//
// 返回：
//
//	*int32 — 指向 v 的副本的指针
func int32Ptr(v int32) *int32 { return &v }

// HealthSection 健康检查参数。
type HealthSection struct {
	MaxHealthFanout  int32    `yaml:"max_health_fanout"`
	ResponseMaxBytes ByteSize `yaml:"health_response_max_bytes"`
	RateLimitPerSec  int32    `yaml:"rate_limit_per_sec"`
}

// QuerySection 结果查询参数。
type QuerySection struct {
	QueryViewers          []string      `yaml:"query_viewers"`
	QueryRouteTTL         time.Duration `yaml:"query_route_ttl"`
	MaxQueryRoutes        int32         `yaml:"max_query_routes"`
	QueryResponseMaxBytes ByteSize      `yaml:"query_response_max_bytes"`
	ReqAuthTTL            time.Duration `yaml:"req_auth_ttl"`
}

// RegistrationSection 注册参数。
type RegistrationSection struct {
	Backfill string `yaml:"backfill"` // NONE / SINCE / FROM_SEQ
}

// SelfUpdateSection 可执行文件一致性：父把自己那份镜像下发给子（见 README「可执行文件一致性」）。
//
// 背景：树是"父下发、子执行"的，子如果跑的是另一份镜像，行为就可能与父不一致，
// 而这类不一致的症状是"行为诡异"而不是"报错"，极难排查。所以每个节点启动时算一次自己
// 可执行文件的 sha256：父在注册应答里给一份、子自己算一份，子连上后的第一件事就是比对。
type SelfUpdateSection struct {
	Enabled *bool `yaml:"enabled"` // 默认 true
	// OnMismatch 子发现自己与父不一致时做什么：
	//   sync（默认）—— 立刻向父拉取可执行文件，校验通过后原地重启
	//   warn         —— 只记日志与指标、不动手（先观察一轮再打开同步时用）
	OnMismatch string `yaml:"on_mismatch"`
	// Serve 是否把本节点的可执行文件发给直接子（默认 true）。
	// 只有"有下级的节点"才可能真的对外提供；叶子开着也没人问。
	Serve *bool `yaml:"serve"`
	// ChunkSize 分片大小（默认 256KB）。上限 4MB —— 要留足余量，因为同一个 Connect 流上
	// 还跑着心跳与指令下发，消息体积不能贴到 gRPC 的 8MB 上限。
	ChunkSize ByteSize `yaml:"chunk_size"`
	// MaxBytes 单次同步的字节上限（默认 64MB）：请求方与提供方都按它截断。
	MaxBytes ByteSize `yaml:"max_bytes"`
	// SyncTimeout 一次同步的总时限（请求 → 收完最后一片），默认 60s。
	SyncTimeout time.Duration `yaml:"sync_timeout"`
	// MaxAttempts / AttemptWindow 同一个目标哈希在窗口内最多尝试几次（默认 3 次 / 1h）。
	// 这是**防重启循环唯一的闸门**：替换失败、目录只读、"exec 完还是对不上"都会落到这里。
	MaxAttempts   int           `yaml:"max_attempts"`
	AttemptWindow time.Duration `yaml:"attempt_window"`
	// Dir 暂存文件放哪（默认 = 可执行文件所在目录）。
	// 必须与被替换的文件在**同一个文件系统**上，否则 rename 退化成"复制"，就不再是原子的了。
	Dir string `yaml:"dir"`

	// PieceStore 是否启用**镜像分片缓存**（默认 true）：把收到的每一片（经片级 sha256 校验后）
	// 落在 <dir>/pieces/ 下，于是本节点**在还没收完、还没重启**的时候就能把这些片
	// 转发给自己的直接子 —— 收敛从"逐层串行"变成"流水线"。
	//
	// 关掉它就完全回到旧行为（必须整份收完 + 重启之后才能对子供片）。
	PieceStore *bool `yaml:"piece_store"`
	// MaxServeConcurrency 同时向几个子供片（默认 4）。中继可能一边向父拉、一边给多个孙推，
	// 不限并发会把它自己的带宽与内存吃光。
	MaxServeConcurrency int32 `yaml:"max_serve_concurrency"`
	// PieceStoreMaxBytes 片存总占用上限（默认 = max_bytes 的 2 倍）；超出按最近使用时间清理。
	// 片存是**可丢的缓存**：清掉只会让下次从 0 重来，不影响正确性。
	PieceStoreMaxBytes ByteSize `yaml:"piece_store_max_bytes"`
}

// ForgetSection 失效节点清理参数（`/v1/forget`；设计与取舍见 README 的「失效节点清理：`/v1/forget`」一节）。
//
// 背景：误启动的实例、注册失败但调过一元 RPC 的节点，会在父端留下再也回不来的记录
// （内存注册表 + state.dat.known_children + bbolt 的若干桶），需要一个显式命令把它们清掉。
// 这两个阈值决定"要多沉默才算失效"，是**误删防护**：正在滚动重启的子节点不该被清掉。
type ForgetSection struct {
	// Grace 孤立残留（从未进过注册表的垃圾）的最小沉默时长，默认 1h。
	// 防的是"刚重试注册、马上就会成功"的节点被误清。
	Grace time.Duration `yaml:"grace"`
	// DeadThreshold 长期离线真子的判定线，默认 24h（与 command.eviction_timeout 同值）。
	DeadThreshold time.Duration `yaml:"dead_threshold"`
}

// GraceDuration 返回归一化后的孤立残留沉默阈值。
//
// 接收者 s 是 forget 段的配置。
//
// 返回：
//
//	time.Duration — 未配置或非正数时取 1h
func (s *ForgetSection) GraceDuration() time.Duration {
	if s.Grace <= 0 {
		return time.Hour
	}
	return s.Grace
}

// DeadThresholdDuration 返回归一化后的"长期离线"阈值。
//
// 接收者 s 是 forget 段的配置。
//
// 返回：
//
//	time.Duration — 未配置或非正数时取 24h（与驱逐超时同值）
func (s *ForgetSection) DeadThresholdDuration() time.Duration {
	if s.DeadThreshold <= 0 {
		return 24 * time.Hour
	}
	return s.DeadThreshold
}

// SelfUpdateEnabled 报告可执行文件一致性检查是否开启（没配就当开启）。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	bool — enabled 字段为 nil（配置里没写）时返回 true，否则返回配置的值
func (s *SelfUpdateSection) SelfUpdateEnabled() bool {
	return s.Enabled == nil || *s.Enabled
}

// ServingChildren 报告本节点是否愿意把自己的可执行文件发给直接子（没配就当愿意）。
//
// 接收者 s 是 selfupdate 段的配置。真正的判定还在服务端：只有"持有 CA 材料、且对端确实是
// 自己签发的直接子"才会真的发出去，这里只是一个总开关。
//
// 返回：
//
//	bool — serve 字段为 nil（配置里没写）时返回 true，否则返回配置的值
func (s *SelfUpdateSection) ServingChildren() bool {
	return s.Serve == nil || *s.Serve
}

// EnforceSync 报告"发现不一致时要不要真的动手同步并重启"。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	bool — on_mismatch 不是 "warn" 时为 true；即只有显式写了 warn 才只告警
func (s *SelfUpdateSection) EnforceSync() bool {
	return s.OnMismatch != "warn"
}

// ChunkBytes 返回归一化后的分片大小（字节）。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	int — 未配置或非正数时取 256KB；超过 4MB 时被压到 4MB（给心跳与指令帧留出消息体积余量）
func (s *SelfUpdateSection) ChunkBytes() int {
	n := int64(s.ChunkSize)
	if n <= 0 {
		n = 256 * 1024
	}
	const maxChunk = 4 << 20
	if n > maxChunk {
		n = maxChunk
	}
	return int(n)
}

// MaxTransferBytes 返回归一化后的单次同步字节上限。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	int64 — 未配置或非正数时取 64MB
func (s *SelfUpdateSection) MaxTransferBytes() int64 {
	n := int64(s.MaxBytes)
	if n <= 0 {
		n = 64 << 20
	}
	return n
}

// Timeout 返回归一化后的一次同步总时限。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	time.Duration — 未配置或非正数时取 60s；小于 5s 会被抬到 5s（太短必然失败，等于关掉功能）
func (s *SelfUpdateSection) Timeout() time.Duration {
	d := s.SyncTimeout
	if d <= 0 {
		d = 60 * time.Second
	}
	if d < 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// AttemptLimit 返回归一化后的"同一目标哈希最多尝试几次"。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	int — 未配置或非正数时取 3
func (s *SelfUpdateSection) AttemptLimit() int {
	if s.MaxAttempts <= 0 {
		return 3
	}
	return s.MaxAttempts
}

// Window 返回归一化后的尝试计数窗口。
//
// 接收者 s 是 selfupdate 段的配置。窗口一过，计数清零（给"当时磁盘写满了、后来修好了"
// 这种场景留一条自愈的路）。
//
// 返回：
//
//	time.Duration — 未配置或非正数时取 1h
func (s *SelfUpdateSection) Window() time.Duration {
	if s.AttemptWindow <= 0 {
		return time.Hour
	}
	return s.AttemptWindow
}

// StagingDir 返回暂存新镜像用哪个目录。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 参数：
//
//	exePath — 本节点可执行文件的路径（已解析符号链接）
//
// 返回：
//
//	string — 配了 dir 就用它；否则用可执行文件所在目录（同目录才能保证 rename 是原子的）
func (s *SelfUpdateSection) StagingDir(exePath string) string {
	if s.Dir != "" {
		return s.Dir
	}
	if exePath == "" {
		return "."
	}
	return filepath.Dir(exePath)
}

// PieceStoreEnabled 报告镜像分片缓存是否开启（没配就当开启）。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	bool — piece_store 字段为 nil（配置里没写）时返回 true，否则返回配置的值
func (s *SelfUpdateSection) PieceStoreEnabled() bool {
	return s.PieceStore == nil || *s.PieceStore
}

// MaxServeConcurrencyN 返回归一化后的"同时向几个子供片"上限。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	int32 — 未配置或非正数时取 4
func (s *SelfUpdateSection) MaxServeConcurrencyN() int32 {
	if s.MaxServeConcurrency <= 0 {
		return 4
	}
	return s.MaxServeConcurrency
}

// PieceStoreBytes 返回归一化后的片存字节上限。
//
// 接收者 s 是 selfupdate 段的配置。
//
// 返回：
//
//	int64 — 未配置时取 max_bytes 的 2 倍（够放下"正在收的这份 + 上一份"）
func (s *SelfUpdateSection) PieceStoreBytes() int64 {
	if s.PieceStoreMaxBytes > 0 {
		return int64(s.PieceStoreMaxBytes)
	}
	return 2 * s.MaxTransferBytes()
}

// PersistSection 状态落盘参数。
type PersistSection struct {
	StatePath string        `yaml:"state_path"`
	Interval  time.Duration `yaml:"interval"`
}

// APISection 对外 HTTP 端点（只有中继 / 根才开）。
type APISection struct {
	HTTPAddr string         `yaml:"http_addr"`
	Auth     APIAuthSection `yaml:"auth"`
	TLS      APITLSSection  `yaml:"tls"`
}

// APITLSSection 对外 HTTP 端点的 TLS 配置（**默认明文**，与历史行为一致）。
//
// 【为什么要有它】HMAC 签名只解决"谁有权动手"，解决不了三个问题：
//
//  1. **没有保密性** —— 指令内容、结果、拓扑在链路上是明文；
//  2. **没有服务器认证** —— 客户端不知道自己连的是不是真节点，响应也可以被伪造 / 篡改
//     （签名只覆盖请求，响应是裸的）；
//  3. **挡不住链路内中继** —— 中间人可以把在途请求原样转发给别的节点再执行一次
//     （防重放的 nonce 表是**每节点**一份，跨节点不共享）。
//
// 这三条里有两条只能靠 TLS 解决。开了它之后，`api.auth` 的 HMAC 仍然照常工作（身份 +
// 请求完整性 + 防重放），两者是叠加而不是替代。
//
// 【热重载】证书 / 密钥 / 客户端 CA 每次握手前按文件 mtime 检查一次，变了就重新加载 ⇒
// 换证书不必重启进程（与 security.cert_reload 同一口径）。
type APITLSSection struct {
	CertPath string `yaml:"cert_path"` // 服务端证书（PEM，可含链）
	KeyPath  string `yaml:"key_path"`  // 服务端私钥（PEM，权限 600）
	// CAPath 校验**客户端**证书的 CA（文件或目录，目录扫 *.crt/*.pem）。client_auth 不为 off 时必需。
	CAPath string `yaml:"ca_path"`
	// ClientAuth 客户端证书策略：off（默认，不要求）| optional（要了就验）| require（必须有且必须验过）。
	ClientAuth string `yaml:"client_auth"`
	// TrustClientCert true = 出示了被 CAPath 验过的客户端证书即视为已认证（**免 HMAC**）。
	//
	// 默认 false（不隐式放宽）：证书再叠加 HMAC，两者都要。改成 true 的理由是" TLS 已经把
	// 客户端身份钉死了，再让运维机保管一份共享密钥是纯负担" —— 那是**显式**的取舍，不该是默认值。
	TrustClientCert bool `yaml:"trust_client_cert"`
	// Require true = 这个端点**只以 HTTPS 提供**：明文请求一律拒绝（**含回环来源**）。
	//
	// 为什么连回环也要管：TLS 终止型反向代理（代理对外 HTTPS、回源走明文 HTTP）会把远程请求
	// 以"看起来像本机"的明文请求递进来 —— 那正是"本地反代绕过"的另一个入口。
	Require bool `yaml:"require"`
	// MinVersion 最低 TLS 版本："1.2"（默认）或 "1.3"。
	MinVersion string `yaml:"min_version"`
}

// Enabled 报告是否配了可用的服务端 TLS 材料（证书与私钥都给了才算）。
//
// 接收者 t 是 api.tls 段的配置。
//
// 返回：
//
//	bool — cert_path 与 key_path 都非空时为 true；只写了一半时按"没开"处理（启动校验会报错，见 Validate）
func (t *APITLSSection) Enabled() bool {
	return t.CertPath != "" && t.KeyPath != ""
}

// ClientAuthType 把 client_auth 的写法映射成 crypto/tls 的策略常量。
//
// 接收者 t 是 api.tls 段的配置。
//
// 返回：
//
//	tls.ClientAuthType — off ⇒ NoClientCert；optional ⇒ VerifyClientCertIfGiven；
//	                     require ⇒ RequireAndVerifyClientCert；空串按 off 处理
func (t *APITLSSection) ClientAuthType() tls.ClientAuthType {
	switch strings.ToLower(strings.TrimSpace(t.ClientAuth)) {
	case "optional":
		return tls.VerifyClientCertIfGiven
	case "require":
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

// MinTLSVersion 把 min_version 的写法映射成 crypto/tls 的版本常量。
//
// 接收者 t 是 api.tls 段的配置。
//
// 返回：
//
//	uint16 — "1.3" ⇒ VersionTLS13；其余（含空串 / 未知写法）⇒ VersionTLS12
func (t *APITLSSection) MinTLSVersion() uint16 {
	if strings.TrimSpace(t.MinVersion) == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// APIAuthSection 对外 HTTP 端点的访问控制（只作用于**写操作**，见 internal/node/apiauth.go）。
//
// 【为什么要它】`api.http_addr` 可以写成 `0.0.0.0`，而写接口里有几个**不可逆**的运维动作：
// `POST /v1/crl` 吊销节点、`POST /v1/forget` 一条事务删注册表 / 水位 / 驱逐归档 / 结果副本、
// `POST /v1/commands` 让整棵子树执行指令。没有访问控制时，任何能连上这个端口的人都能执行它们。
//
// 【口径】两条规则，前一条命中就不再往下判：
//
//  1. **来自回环地址**（127.0.0.1 / ::1）的请求一律放行 —— 本机运维脚本、控制台代理、
//     `curl localhost:...` 全部零改动；
//  2. **其它来源的写请求必须带 HMAC 签名**，密钥就是本段配的共享密钥。
//     **没配密钥 ⇒ 非回环的写请求一律拒绝**（fail-closed，不是"没配就放行"）。
//
// 为什么不做成"一律要密钥"：本项目的 HTTP 端点没有 TLS（明文，除非配了 api.tls），共享密钥
// 只解决"谁有权动手"，解决不了窃听；而本机运维是绝对主路径，给它免签可以避免"把密钥投放到
// 每台机器"这种纯负担。要远程运维就配密钥（推荐 secret_path，权限 600）+ 用 scripts/api_call.py 签。
//
// 【回环免签为什么还要收紧】"来自回环"的判据是 **TCP 对端地址**，而它会被部署形态改写：
// API 端口前面一旦挂了反向代理 / 端口转发（nginx、ssh -L、frpc、`kubectl port-forward`…），
// 所有远程请求的对端都变成 127.0.0.1，第 1 条豁免就等于对全网放行。所以免签要同时满足：
//
//	· `loopback_bypass` 没被显式关掉；
//	· 请求**没有转发特征头**（带了 Forwarded / X-Forwarded-For / X-Real-IP / Via 的对端
//	  若不在 `trusted_proxies` 里，就不算"本机"—— 本机 curl 不会带这些头）；
//	· 剥掉可信代理跳之后得到的真实来源仍是回环（见 `trusted_proxies`）。
//
// 密钥**不进 config_hash**（`api.*` 本来就不在 6.1 白名单里），且请求时现读文件 ⇒
// 换密钥既不用重启、也不用 SIGHUP。
type APIAuthSection struct {
	Secret       string `yaml:"secret"`        // 共享密钥（与 secret_path 二选一）
	SecretPath   string `yaml:"secret_path"`   // 从文件读；**优先于 secret**（便于脚本投放与轮换）
	ProtectReads bool   `yaml:"protect_reads"` // true = 读接口（/v1/tree、/v1/health、结果查询、/metrics）也要签名

	// LoopbackBypass 回环免签开关：**nil（没写）= true**，保持历史行为；显式写 false 时
	// 回环来源也照常走签名（"本机"不再是一种授权）。
	//
	// 为什么用指针：**默认值必须是 true**（存量部署的 `curl localhost` 不能因为升级就 401），
	// 而 bool 的零值是 false —— 用 nil 表示"没写"才能把"没写"与"写了 false"区分开。
	LoopbackBypass *bool `yaml:"loopback_bypass"`

	// TrustedProxies 可信代理白名单（CIDR 或裸 IP）。**默认空 = 一个都不信**：此时任何
	// X-Forwarded-For / Forwarded 头都被忽略（既能防伪造，也能让"回环 + 转发头"这一
	// 反代特征直接失去免签资格）。
	//
	// 配了之后（如 `["127.0.0.1/32", "::1/128"]`）：只有**对端**落在白名单里，才按 RFC 7239
	// 从右往左剥掉可信跳，取第一个不可信的作为真实来源。于是"API 前面挂了本地反代"这种
	// 部署既能继续用，又不会把远程请求误判成本机请求。
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// LoopbackBypassEnabled 报告回环免签是否开启。
//
// 接收者 a 是 api.auth 段的配置。
//
// 返回：
//
//	bool — 没写（nil）或显式写 true 时为 true；显式写 false 时为 false
func (a *APIAuthSection) LoopbackBypassEnabled() bool {
	return a.LoopbackBypass == nil || *a.LoopbackBypass
}

// TrustsProxy 判断某个对端地址是否在可信代理白名单内。
//
// 接收者 a 是 api.auth 段的配置。**每次调用重新解析 CIDR**：白名单通常只有一两条，
// 这点开销可以忽略，换来的是不必在配置对象上维护"解析后的副本"（避免 SIGHUP 重载时的
// 状态同步问题）。
//
// 参数：
//
//	host — 裸主机（"127.0.0.1" / "::1"），带端口或方括号也认
//
// 返回：
//
//	bool — 命中白名单时 true；白名单为空、host 解析不出 IP、或 CIDR 写错时一律 false（宁严不宽）
func (a *APIAuthSection) TrustsProxy(host string) bool {
	ip := parseIPHost(host)
	if ip == nil {
		return false
	}
	for _, cidr := range a.TrustedProxies {
		_, netw, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			// 裸 IP 也接受：补成单地址网段（IPv4 /32、IPv6 /128）
			if single := net.ParseIP(strings.TrimSpace(cidr)); single != nil {
				if single.Equal(ip) {
					return true
				}
			}
			continue
		}
		if netw.Contains(ip) {
			return true
		}
	}
	return false
}

// parseIPHost 把一个主机字段解析成 IP（兼容带端口 / 带方括号的写法）。
//
// 参数：
//
//	host — 形如 "127.0.0.1"、"127.0.0.1:54321"、"[::1]:54321" 的字段
//
// 返回：
//
//	net.IP — 解析结果；解析不出来时返回 nil
func parseIPHost(host string) net.IP {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return net.ParseIP(host)
}

// Configured 报告是否配了共享密钥（两个来源有一个非空即算配了）。
//
// 接收者 a 是 api.auth 段的配置。
//
// 返回：
//
//	bool — secret 或 secret_path 非空时为 true
func (a *APIAuthSection) Configured() bool {
	return a.Secret != "" || a.SecretPath != ""
}

// SecretBytes 取共享密钥的原始内容（不做任何解析，去掉首尾空白）。
//
// 接收者 a 是 api.auth 段的配置。`secret_path`（文件）优先于 `secret`（直接写在配置里）——
// 优先文件是为了让脚本能投放与轮换它（权限 600，别进 shell 历史、也别进配置备份）。
//
// 参数：无。
//
// 返回：
//
//	[]byte — 密钥内容；两个来源都没配时返回 nil
//	error  — 配了 secret_path 但文件读不到时返回
func (a *APIAuthSection) SecretBytes() ([]byte, error) {
	if a.SecretPath != "" {
		b, err := os.ReadFile(a.SecretPath)
		if err != nil {
			return nil, fmt.Errorf("read api.auth.secret_path: %w", err)
		}
		return bytes.TrimSpace(b), nil
	}
	return []byte(strings.TrimSpace(a.Secret)), nil
}

// Config 完整配置。
type Config struct {
	Version      int                 `yaml:"version"`
	Node         NodeSection         `yaml:"node"`
	Parents      []Parent            `yaml:"parents"`
	Security     SecuritySection     `yaml:"security"`
	Command      CommandSection      `yaml:"command"`
	Health       HealthSection       `yaml:"health"`
	Query        QuerySection        `yaml:"query"`
	Registration RegistrationSection `yaml:"registration"`
	SelfUpdate   SelfUpdateSection   `yaml:"selfupdate"`
	Forget       ForgetSection       `yaml:"forget"`
	Persist      PersistSection      `yaml:"persist"`
	API          APISection          `yaml:"api"`
	DataDir      string              `yaml:"data_dir"`

	// NodeIDSource / NodeIDWarning / NodeIDStatePath 是 node.id 的**解析结论**（ADR-050），
	// 由 Load 填充，供启动日志展示；不参与 config_hash、也不落盘。
	NodeIDSource    NodeIDSource `yaml:"-"` // config | cert | state | generated
	NodeIDWarning   string       `yaml:"-"`
	NodeIDStatePath string       `yaml:"-"`

	// Build 本节点**可执行文件**的身份快照（启动时算一次，见 README「可执行文件一致性」）。
	// 它和上面三个字段是同一类东西：**程序填的运行时字段** —— 不来自 node.yaml、不进
	// config_hash、也不落盘（yaml:"-"）。所以"把哈希放进运行时配置"并不违反"绝不回写
	// node.yaml"，只是让"我是哪份镜像"在配置对象上顺手可取。
	Build buildinfo.Info `yaml:"-"`
}

// Role 节点形态（根 / 中继 / 叶）。
type Role string

const (
	RoleRoot  Role = "root"
	RoleRelay Role = "relay"
	RoleLeaf  Role = "leaf"
)

// Role 由配置推导节点形态：无父即 Root；有父且有 listen 即 Relay；有父且无 listen 即 Leaf。
//
// 接收者 c 是完整配置。listen 只有空白字符也算"没有监听"。
//
// 返回：
//
//	Role — root / relay / leaf 三者之一
func (c *Config) Role() Role {
	if len(c.Parents) == 0 {
		return RoleRoot
	}
	if strings.TrimSpace(c.Node.Listen) == "" {
		return RoleLeaf
	}
	return RoleRelay
}

// HasDownstream 报告本节点是否有下级；判定只看 Role，形态不是 leaf 就为 true。
//
// 返回：
//
//	bool — 形态不是 leaf 时为 true
func (c *Config) HasDownstream() bool { return c.Role() != RoleLeaf }

// HasUpstream 报告本节点是否有上级父节点；判定只看 Role，形态不是 root 就为 true。
//
// 返回：
//
//	bool — 形态不是 root 时为 true
func (c *Config) HasUpstream() bool { return c.Role() != RoleRoot }

// HasAPI 报告本节点是否配了对外 HTTP 端点；判定只看 api.http_addr 是否非空。
//
// 返回：
//
//	bool — api.http_addr 非空时为 true
func (c *Config) HasAPI() bool { return c.API.HTTPAddr != "" }

// Load 读取 node.yaml，补全默认值、解析 node.id、校验，返回可用的配置。
//
// 处理顺序：读文件 → YAML 反序列化 → applyDefaults（补默认值并把相对路径解析成绝对路径）
// → node.id 解析 → Validate → 配置文件权限告警。
//
// 全程对 node.yaml **只读，绝不回写**（硬约束 6.1 / ADR-005）。配置文件对同组 / 其他人
// 开放了权限位时（perm & 0o077 != 0），只在标准错误打印一行告警，不阻断启动。
//
// 参数：
//
//	path — node.yaml 的路径；相对路径的基准是它所在目录
//
// 返回：
//
//	*Config — 补全并校验后的配置（路径字段已全部是绝对路径）
//	error   — 文件读不到 / YAML 语法错 / 校验不过时返回；文案可直接给人看
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.applyDefaults(filepath.Dir(path))
	// node.id 解析（ADR-050）：文件里没写就依次看 证书身份 → state.dat → 新生成。
	// 全程**只读**，绝不回写 node.yaml；生成的 ID 由节点启动时落进 state.dat。
	if strings.TrimSpace(c.Node.ID) == "" {
		res := resolveNodeID(path, c)
		c.Node.ID = res.NodeID
		c.NodeIDSource = res.Source
		c.NodeIDWarning = res.Warning
		c.NodeIDStatePath = res.StatePath
	} else {
		c.NodeIDSource = IDFromConfig
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	// 权限校验（6.4：校验 + 权限 0600）
	if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
		// 仅告警（不阻断），保持自用环境的可用性
		fmt.Fprintf(os.Stderr, "[warn] %s 权限为 %o，建议 0600\n", path, fi.Mode().Perm())
	}
	return c, nil
}

// applyDefaults 就地补全配置里的默认值，并把相对路径解析成绝对路径。
//
// 这是"手工部署只写 node.id 与 parents[] 也能跑起来"的实现处：凡是没有显式配置的
// 运行参数、身份材料路径、持久化路径，都在这里按约定补齐。补齐了哪些，看
// examples/child.yaml 的"约定与默认值"一节 —— 那里是给人读的权威清单。
//
// 几处约定路径只在文件/目录确实存在时才补：信任锚目录 trust/、入网许可 enroll.token。
// 路径解析的基准是 baseDir（即 node.yaml 所在目录）：data_dir 相对它解析，
// 其余相对路径也都相对它解析；空串与绝对路径原样不动。
//
// 参数：
//
//	baseDir — 配置文件所在目录，作为所有相对路径的解析基准
//
// 无返回值：所有修改都直接写回接收者 c。
func (c *Config) applyDefaults(baseDir string) {
	cd := &c.Command
	def := func(d *time.Duration, v time.Duration) {
		if *d == 0 {
			*d = v
		}
	}
	def(&cd.LeaseTTL, 90*time.Second)
	def(&cd.RenewAt, 30*time.Second)
	def(&cd.MaxDeadline, 24*time.Hour)
	def(&cd.UnknownTypeDeadline, 15*time.Minute)
	def(&cd.AuditRetention, 7*24*time.Hour)
	def(&cd.EvictionTimeout, 24*time.Hour)
	def(&cd.EvictionArchiveRetention, 30*24*time.Hour)
	def(&cd.StreamIdleTimeout, 180*time.Second)
	def(&cd.ReserveForReport, 5*time.Second)
	def(&cd.ChildStuckTimeout, 5*time.Minute)
	def(&cd.LocalBusyBackoff, 3*time.Second)
	def(&cd.LocalBusyBackoffMax, 60*time.Second)
	// 下发背压：两个窗口是 *int32，**不能用上面的 def()** —— def 把 0 当"没配"，
	// 而这里的 0 是"不限"这个有意义的取值。所以只在指针为 nil 时补默认值。
	if cd.MaxDispatchInflightPerChild == nil {
		cd.MaxDispatchInflightPerChild = int32Ptr(dispatchDefaultPerChild)
	}
	if cd.MaxDispatchInflight == nil {
		cd.MaxDispatchInflight = int32Ptr(dispatchDefaultTotal)
	}
	def(&cd.IndexRepushInterval, 10*time.Minute)
	if cd.MaxPayload == 0 {
		cd.MaxPayload = ByteSize(1 << 20)
	}
	if cd.MaxCommandBytes == 0 {
		cd.MaxCommandBytes = ByteSize(3 << 20)
	}
	if cd.FetchResponseMaxBytes == 0 {
		cd.FetchResponseMaxBytes = ByteSize(3*1024*1024 + 512*1024)
	}
	if cd.MaxChunkTotal == 0 {
		cd.MaxChunkTotal = 300
	}
	if cd.ChunkSize == 0 {
		cd.ChunkSize = ByteSize(256 * 1024)
	}
	if cd.LeaseReclaimCap == 0 {
		cd.LeaseReclaimCap = 3
	}
	if cd.MaxRetryNodeCount == 0 {
		cd.MaxRetryNodeCount = 3
	}
	if cd.PendingResendBatch == 0 {
		cd.PendingResendBatch = 32
	}
	if cd.MaxReportConcurrency == 0 {
		cd.MaxReportConcurrency = 8
	}
	if cd.MaxInflight == 0 {
		cd.MaxInflight = 64
	}
	// 证书生命期：默认值 = 历史行为（身份 30 天 / CA 10 年）
	if c.Security.IdentityCertDays <= 0 {
		c.Security.IdentityCertDays = 30
	}
	if c.Security.CACertDays <= 0 {
		c.Security.CACertDays = 3650
	}
	// 镜像分片缓存：并发与容量都给默认值（piece_store 是 *bool，nil 即开启）
	if c.SelfUpdate.MaxServeConcurrency <= 0 {
		c.SelfUpdate.MaxServeConcurrency = 4
	}
	if cd.TickInterval == 0 {
		t := cd.ChildStuckTimeout
		if cd.LeaseTTL < t {
			t = cd.LeaseTTL
		}
		cd.TickInterval = t / 4
		if cd.TickInterval < 200*time.Millisecond {
			cd.TickInterval = 200 * time.Millisecond
		}
	}
	if cd.ReconcileWindow == 0 {
		cd.ReconcileWindow = 3 * cd.RenewAt
	}
	if cd.ObjectStoreDir == "" {
		cd.ObjectStoreDir = filepath.Join(c.DataDir, "objects")
	}
	if len(cd.DefaultDeadlineByType) == 0 {
		cd.DefaultDeadlineByType = map[string]string{
			"noop": "1m", "echo": "1m", "probe": "5m", "shell": "1h", "batch": "6h",
			// script 是"执行外部脚本"的指令类型（internal/exec/script）：脚本可能跑很久，
			// 所以兜底给 1h，而不是落到 unknown_type_deadline 的 15m。
			"script": "1h",
		}
	}
	if c.Health.MaxHealthFanout == 0 {
		c.Health.MaxHealthFanout = 32
	}
	if c.Health.ResponseMaxBytes == 0 {
		c.Health.ResponseMaxBytes = ByteSize(1 << 20)
	}
	if c.Health.RateLimitPerSec == 0 {
		c.Health.RateLimitPerSec = 10
	}
	if c.Query.QueryRouteTTL == 0 {
		c.Query.QueryRouteTTL = 10 * time.Second
	}
	if c.Query.MaxQueryRoutes == 0 {
		c.Query.MaxQueryRoutes = 1024
	}
	if c.Query.QueryResponseMaxBytes == 0 {
		c.Query.QueryResponseMaxBytes = ByteSize(8 << 20)
	}
	if c.Query.ReqAuthTTL == 0 {
		c.Query.ReqAuthTTL = 60 * time.Second
	}
	if c.Persist.Interval == 0 {
		c.Persist.Interval = 30 * time.Second
	}
	if c.Registration.Backfill == "" {
		c.Registration.Backfill = "NONE"
	}
	// ---- 可执行文件一致性（selfupdate）：默认"发现不一致就同步并原地重启" ----
	su := &c.SelfUpdate
	if su.OnMismatch == "" {
		su.OnMismatch = "sync"
	}
	if su.ChunkSize == 0 {
		su.ChunkSize = ByteSize(256 * 1024)
	}
	if su.MaxBytes == 0 {
		su.MaxBytes = ByteSize(64 << 20)
	}
	def(&su.SyncTimeout, 60*time.Second)
	def(&su.AttemptWindow, time.Hour)
	if su.MaxAttempts == 0 {
		su.MaxAttempts = 3
	}
	if c.DataDir == "" {
		c.DataDir = "."
	}
	if !filepath.IsAbs(c.DataDir) {
		c.DataDir = filepath.Join(baseDir, c.DataDir)
	}
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(baseDir, p)
	}
	if c.Command.ObjectStoreDir != "" && !filepath.IsAbs(c.Command.ObjectStoreDir) {
		c.Command.ObjectStoreDir = filepath.Join(c.DataDir, c.Command.ObjectStoreDir)
	}
	// ---- 手工部署的约定路径：只写 node.id + parents[] 也能起来 ----
	sec := &c.Security
	if sec.IdentityKeyPath == "" {
		sec.IdentityKeyPath = "keys/id_ed25519"
	}
	if sec.IdentityPubKeyPath == "" {
		// 公钥与私钥成对预置；未显式配置时按 <私钥>.pub 推导（**不做推导生成，缺失即拒绝启动**）
		sec.IdentityPubKeyPath = sec.IdentityKeyPath + ".pub"
	}
	if sec.IdentityCertPath == "" {
		sec.IdentityCertPath = "certs/node.crt"
	}
	if sec.CAKeyPath == "" {
		sec.CAKeyPath = "keys/ca"
	}
	if len(sec.CACertPaths) == 0 {
		// 信任锚：约定目录 trust/（放**父节点的** CA 证书链即可，不需要放根的；
		// 而且只在首次入网时用得着 —— 入网成功后信任锚会从自己的证书链自举）
		dir := filepath.Join(baseDir, "trust")
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			sec.CACertPaths = []string{"trust"}
		}
	}
	if sec.Enrollment.Token == "" && sec.Enrollment.TokenPath == "" {
		// 入网许可：约定文件 enroll.token（脚本投放，权限 600）
		tp := filepath.Join(baseDir, "enroll.token")
		if _, err := os.Stat(tp); err == nil {
			sec.Enrollment.TokenPath = "enroll.token"
		}
	}
	if c.HasAPI() && c.API.Auth.Secret == "" && c.API.Auth.SecretPath == "" {
		// 对外 HTTP 的共享密钥：约定文件 api.secret（脚本投放，权限 600）。
		// **只在文件确实存在时才补** —— 没有它时写接口退化成"只接受本机请求"（见 APIAuthSection），
		// 那是合法状态，不是配置错误。
		tp := filepath.Join(baseDir, "api.secret")
		if _, err := os.Stat(tp); err == nil {
			c.API.Auth.SecretPath = "api.secret"
		}
	}
	if c.Persist.StatePath == "" {
		c.Persist.StatePath = "state.dat"
	}

	c.Security.IdentityKeyPath = resolve(c.Security.IdentityKeyPath)
	c.Security.IdentityPubKeyPath = resolve(c.Security.IdentityPubKeyPath)
	c.Security.IdentityCertPath = resolve(c.Security.IdentityCertPath)
	c.Security.CAKeyPath = resolve(c.Security.CAKeyPath)
	if c.Security.CACertPath == "" {
		// 兼容旧产物：缺省按 <身份证书>.ca 推导；推荐在 node.yaml 里显式写 security.ca_cert_path
		if c.Security.IdentityCertPath != "" {
			c.Security.CACertPath = c.Security.IdentityCertPath + ".ca"
		}
	}
	c.Security.CACertPath = resolve(c.Security.CACertPath)
	for i := range c.Security.CACertPaths {
		c.Security.CACertPaths[i] = resolve(c.Security.CACertPaths[i])
	}
	for i := range c.Security.CertReload.Paths {
		c.Security.CertReload.Paths[i] = resolve(c.Security.CertReload.Paths[i])
	}
	c.Security.Enrollment.TokenPath = resolve(c.Security.Enrollment.TokenPath)
	c.API.Auth.SecretPath = resolve(c.API.Auth.SecretPath)
	c.SelfUpdate.Dir = resolve(c.SelfUpdate.Dir)
	c.Persist.StatePath = resolve(c.Persist.StatePath)
}

// Validate 校验配置是否可启动（含 3.4 的租约硬约束：renew_at×3 ≤ lease_ttl）。
//
// 接收者 c 应已过 applyDefaults。检查项包括：node.id 是否已确定、name/remark 的长度上限
// 与是否含换行、形态与 listen/parents 是否搭配、parents 每项是否 id 与 addr 都非空、
// 租约约束（只有 relay/root 查）、registration.backfill 取值、**配了的**信任锚路径是否真实存在、
// 身份材料路径是否给出、cert_reload.on_change 取值、enrollment.token_path 是否真实存在。
//
// 注意：这里**故意不**因为"证书不存在 + 没配入网凭据"就拒绝启动 ——
// 配置层看不到"证书文件在不在"，而这个结论要由启动强校验给出（它才能同时掌握
// "有没有证书 / 有没有锚 / 能不能自举"），文案也更可操作（"待入网但没有任何信任锚"等）。
//
// 返回：
//
//	error — 任一约束不满足时返回；nil 表示校验通过
func (c *Config) Validate() error {
	if c.Node.ID == "" {
		return errors.New("node.id 未能确定：配置里没写、证书尚未签发、state.dat 也没有记录（生成 UUIDv7 也失败了）。" +
			"根节点请先自带证书；子节点可留空等程序生成后写入 state.dat（ADR-050）")
	}
	// 元信息会随注册上行、并随健康响应逐跳回传，所以必须有长度上限，
	// 否则单条 remark 就能把 health_response_max_bytes 的预算吃掉。
	if n := len(c.Node.Name); n > MaxNodeNameBytes {
		return fmt.Errorf("node.name too long: %d > %d bytes", n, MaxNodeNameBytes)
	}
	if n := len(c.Node.Remark); n > MaxNodeRemarkBytes {
		return fmt.Errorf("node.remark too long: %d > %d bytes", n, MaxNodeRemarkBytes)
	}
	if strings.ContainsAny(c.Node.Name, "\r\n") || strings.ContainsAny(c.Node.Remark, "\r\n") {
		return errors.New("node.name / node.remark 不能包含换行")
	}
	if c.Role() == RoleRelay && c.Node.Listen == "" {
		return errors.New("relay requires node.listen")
	}
	if c.Role() != RoleRoot && len(c.Parents) == 0 {
		return errors.New("non-root node requires parents[]")
	}
	if c.Role() == RoleRelay || c.Role() == RoleRoot {
		if c.Command.RenewAt*3 > c.Command.LeaseTTL {
			return fmt.Errorf("lease constraint violated: renew_at(%s)×3 > lease_ttl(%s)", c.Command.RenewAt, c.Command.LeaseTTL)
		}
	}
	for _, p := range c.Parents {
		if p.ID == "" || p.Addr == "" {
			return errors.New("parents[] entries require id and addr")
		}
	}
	if c.Registration.Backfill != "NONE" && c.Registration.Backfill != "SINCE" && c.Registration.Backfill != "FROM_SEQ" {
		return fmt.Errorf("invalid registration.backfill %q", c.Registration.Backfill)
	}
	// 信任锚（security.ca_cert_paths）：**不再要求非根节点必须配**。
	//
	// 它的口径不是"树的根"，而是"我信谁" —— 也就是**我的父**：把父的 `certs/node.crt.ca`
	// 整份文件（内容含父 CA 一路到根）指向它即可，不需要从根拷任何东西。
	// 而且它只在**首次入网**（手上还没有证书）时必需：入网成功后信任锚可以从**自己的证书链**
	// 自举出来（见 identity.ChainAnchors），那时这一项可以整段删掉。
	//
	// 这里只校验"配了的路径必须存在"。"到底够不够启动"由启动强校验判定 —— 只有它同时掌握
	// "有没有锚"与"能不能从证书链自举"两件事（要 stat 证书文件），放在两处判必然各说一套。
	for _, p := range c.Security.CACertPaths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("security.ca_cert_paths: %s: %w（信任锚必须存在：给文件就放父的 CA 证书链；给目录时会扫其中的 *.crt/*.pem）", p, err)
		}
	}
	if c.Security.IdentityKeyPath == "" || c.Security.IdentityPubKeyPath == "" {
		return errors.New("security.identity_key_path / identity_pubkey_path are required (节点必须带自己的私钥与公钥启动)")
	}
	if c.Security.IdentityCertPath == "" {
		return errors.New("security.identity_cert_path is required（即使证书尚未签发，也要给出它将写入的路径）")
	}
	switch c.Security.CertReload.OnChange {
	case "", "reconnect", "lazy":
	default:
		return fmt.Errorf("invalid security.cert_reload.on_change %q (reconnect|lazy)", c.Security.CertReload.OnChange)
	}
	switch c.SelfUpdate.OnMismatch {
	case "", "sync", "warn":
	default:
		return fmt.Errorf("invalid selfupdate.on_mismatch %q (sync|warn)", c.SelfUpdate.OnMismatch)
	}
	if c.SelfUpdate.MaxBytes < 0 || c.SelfUpdate.ChunkSize < 0 || c.SelfUpdate.MaxAttempts < 0 {
		return errors.New("selfupdate 的 max_bytes / chunk_size / max_attempts 不能为负数")
	}
	if c.Security.Enrollment.TokenPath != "" {
		if _, err := os.Stat(c.Security.Enrollment.TokenPath); err != nil {
			return fmt.Errorf("security.enrollment.token_path: %w", err)
		}
	}
	// 对外 HTTP 的共享密钥：同样只校验"配了路径就必须能读到"。**没配是合法状态**
	// （写接口退化成只接受本机请求），所以这里绝不能写成"没配就拒绝启动"。
	if c.API.Auth.SecretPath != "" {
		if _, err := os.Stat(c.API.Auth.SecretPath); err != nil {
			return fmt.Errorf("api.auth.secret_path: %w（配了就要能读到：脚本投放、权限 600）", err)
		}
	}
	// 可信代理白名单：写错的 CIDR 必须**启动时就暴露**，不能等到"某个请求突然被当成远程"
	// 才被发现 —— 那时它要么静默拒绝合法的本机运维，要么（更糟）把远程请求当本机放行。
	for _, p := range c.API.Auth.TrustedProxies {
		s := strings.TrimSpace(p)
		if _, _, err := net.ParseCIDR(s); err != nil && net.ParseIP(s) == nil {
			return fmt.Errorf("api.auth.trusted_proxies: %q 不是合法的 CIDR 或 IP（例：127.0.0.1/32、::1/128）", p)
		}
	}
	// 对外 HTTP 的 TLS：只写一半（有证书没密钥）是配置错误，必须拒绝启动 ——
	// 否则它会静默退化成明文，而 operator 以为自己已经开了 HTTPS。
	if c.API.TLS.CertPath != "" && c.API.TLS.KeyPath == "" {
		return errors.New("api.tls: 写了 cert_path 就必须写 key_path")
	}
	if c.API.TLS.KeyPath != "" && c.API.TLS.CertPath == "" {
		return errors.New("api.tls: 写了 key_path 就必须写 cert_path")
	}
	if c.API.TLS.Enabled() {
		for _, p := range []string{c.API.TLS.CertPath, c.API.TLS.KeyPath} {
			if _, err := os.Stat(p); err != nil {
				return fmt.Errorf("api.tls: %w（证书 / 密钥必须存在且可读；密钥建议 600）", err)
			}
		}
		switch strings.ToLower(strings.TrimSpace(c.API.TLS.ClientAuth)) {
		case "", "off", "optional", "require":
		default:
			return fmt.Errorf("invalid api.tls.client_auth %q (off|optional|require)", c.API.TLS.ClientAuth)
		}
		if c.API.TLS.ClientAuthType() != tls.NoClientCert {
			if c.API.TLS.CAPath == "" {
				return errors.New("api.tls: client_auth 不是 off 时必须配 ca_path（拿什么验客户端证书？）")
			}
			if _, err := os.Stat(c.API.TLS.CAPath); err != nil {
				return fmt.Errorf("api.tls.ca_path: %w（客户端 CA，文件或目录）", err)
			}
		}
		switch strings.TrimSpace(c.API.TLS.MinVersion) {
		case "", "1.2", "1.3":
		default:
			return fmt.Errorf("invalid api.tls.min_version %q (1.2|1.3)", c.API.TLS.MinVersion)
		}
	}
	// require 但没开 TLS ⇒ 所有请求（含本机）都会被拒，端点等于自杀。这种配置必须在启动时拦下。
	if c.API.TLS.Require && !c.API.TLS.Enabled() {
		return errors.New("api.tls.require: true 但没配 cert_path / key_path —— 那会让所有请求都被拒（端点等于关闭）")
	}
	// 注意：**不在这里**因为"证书不存在 + 没配凭据"就拒绝启动 ——
	// 配置层看不到"证书文件在不在"，而无证书时到底算不算错由启动强校验判定
	// （它会给出"待入网但没有任何信任锚"或"没有入网许可"这类可操作的结论）。
	// 这里只负责"配了路径就必须存在"。
	return nil
}

// ConfigHash 计算配置指纹，只覆盖影响拓扑 / 会话 / 证书 / 父列表 / 监听地址的关键字段（6.1 白名单）。
// 明确不进 hash：security.viewers.*、query.query_viewers、command.*、health.*、persist.*、version。
//
// 接收者 c 是完整配置。做法是把白名单字段按固定顺序拼成一段文本再取 SHA-256。
// 入网策略只把"开关"写进去，**凭据（token/token_path）不进** —— 换许可不该触发全量重注册。
//
// 返回：
//
//	string — "sha256:" 前缀的十六进制摘要
func (c *Config) ConfigHash() string {
	var sb strings.Builder
	sb.WriteString("node.id=" + c.Node.ID + "\n")
	sb.WriteString("node.listen=" + c.Node.Listen + "\n")
	for _, p := range c.Parents {
		sb.WriteString("parents=" + p.ID + "@" + p.Addr + "\n")
	}
	sb.WriteString("security.identity_key_path=" + c.Security.IdentityKeyPath + "\n")
	sb.WriteString("security.identity_pubkey_path=" + c.Security.IdentityPubKeyPath + "\n")
	sb.WriteString("security.identity_cert_path=" + c.Security.IdentityCertPath + "\n")
	sb.WriteString("security.ca_cert_paths=" + strings.Join(c.Security.CACertPaths, ",") + "\n")
	sb.WriteString("security.ca_key_path=" + c.Security.CAKeyPath + "\n")
	sb.WriteString("security.ca_cert_path=" + c.Security.CACertPath + "\n")
	// 入网策略：只有"开/关"进 hash。
	//
	// ⚠️ 这一行**曾经**还会拼上 allow_ids 列表；该字段已随"入网认证只留许可一个口径"删除
	// ⇒ config_hash 变了一次：升级后**首次启动会触发一次全量重注册**（一次性、可预期，
	// 与当年删掉 node.labels / node.capabilities 时同一类副作用）。
	if c.Security.EnrollmentEnabled() {
		sb.WriteString("security.enrollment=on\n")
	} else {
		sb.WriteString("security.enrollment=off\n")
	}
	sb.WriteString("registration.backfill=" + c.Registration.Backfill + "\n")
	sum := sha256.Sum256([]byte(sb.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DeadlineForType 按指令类型给出兜底 Deadline。
//
// 接收者 c 是完整配置。查 command.default_deadline_by_type 里该类型的字符串值：
// 能解析成正的时长就用它，否则（没配、格式错、非正数）退回 command.unknown_type_deadline。
//
// 参数：
//
//	t — 指令类型名，如 "probe" / "shell" / "batch"
//
// 返回：
//
//	time.Duration — 该类型的兜底时限；未知类型返回 unknown_type_deadline
func (c *Config) DeadlineForType(t string) time.Duration {
	if s, ok := c.Command.DefaultDeadlineByType[t]; ok {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			return d
		}
	}
	return c.Command.UnknownTypeDeadline
}
