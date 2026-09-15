// Package config 负责静态配置（node.yaml）的加载、校验与 config_hash 计算。
// 硬约束（6.1 / ADR-005）：node.yaml 由人编写，程序只读，绝不回写。
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
type EnrollmentSection struct {
	Enabled      *bool         `yaml:"enabled"`       // 默认 true
	Token        string        `yaml:"token"`         // 入网许可（父端校验；子端提交同一串）
	TokenPath    string        `yaml:"token_path"`    // 或者从文件读（优先于 token，便于脚本投放）
	AllowIDs     []string      `yaml:"allow_ids"`     // 父端白名单：只允许这些 NodeID 入网；留空 = 只校验 token
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

// EnrollToken 取入网许可串，token_path（文件）优先于 token（直接写在配置里）。
//
// 接收者 s 是 security 段的配置。从文件读时会去掉首尾空白与换行，
// 因为脚本投放的 token 文件常带一个结尾换行。优先文件是为了方便脚本轮换许可。
//
// 返回：
//
//	string — 入网许可；两个来源都没配时返回空串
//	error  — 配了 token_path 但文件读不到时返回
func (s *SecuritySection) EnrollToken() (string, error) {
	if s.Enrollment.TokenPath != "" {
		b, err := os.ReadFile(s.Enrollment.TokenPath)
		if err != nil {
			return "", fmt.Errorf("read enrollment.token_path: %w", err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(s.Enrollment.Token), nil
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
	PendingResendBatch       int32             `yaml:"pending_resend_batch"`
	MaxReportConcurrency     int32             `yaml:"max_report_concurrency"`
	IndexRepushInterval      time.Duration     `yaml:"index_repush_interval"`
	MaxInflight              int32             `yaml:"max_inflight"`
	TickInterval             time.Duration     `yaml:"tick_interval"`
	ReconcileWindow          time.Duration     `yaml:"reconcile_window"`
	// 对象存储目录（>64MB 的大结果落这里，见 3.13 第三级）
	ObjectStoreDir string `yaml:"object_store_dir"`
}

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
}

// ForgetSection 失效节点清理参数（`/v1/forget`，见 docs/失效节点清理与版本一致性设计.md）。
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

// PersistSection 状态落盘参数。
type PersistSection struct {
	StatePath string        `yaml:"state_path"`
	Interval  time.Duration `yaml:"interval"`
}

// APISection 对外 HTTP 端点（只有中继 / 根才开）。
type APISection struct {
	HTTPAddr string `yaml:"http_addr"`
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
		// 信任锚：约定目录 trust/（你的证书脚本往这里投 CA 即可，换 CA 也不用改配置）
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
	c.SelfUpdate.Dir = resolve(c.SelfUpdate.Dir)
	c.Persist.StatePath = resolve(c.Persist.StatePath)
}

// Validate 校验配置是否可启动（含 3.4 的租约硬约束：renew_at×3 ≤ lease_ttl）。
//
// 接收者 c 应已过 applyDefaults。检查项包括：node.id 是否已确定、name/remark 的长度上限
// 与是否含换行、形态与 listen/parents 是否搭配、parents 每项是否 id 与 addr 都非空、
// 租约约束（只有 relay/root 查）、registration.backfill 取值、非根节点是否配了信任锚且锚文件真实存在、
// 身份材料路径是否给出、cert_reload.on_change 取值、enrollment.token_path 是否真实存在。
//
// 注意：这里**故意不**因为"证书不存在 + 没配入网 token"就拒绝启动 ——
// 父端可能只配了 allow_ids 白名单（那种模式不需要 token），子端无从得知。
// 于是它会先以"待入网"状态起来，运行期再由父端明确拒绝（ERR_ENROLL_BAD_PERMIT /
// ERR_ENROLL_NOT_ALLOWED，日志里写着原因）。
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
	if len(c.Security.CACertPaths) == 0 && c.Role() != RoleRoot {
		return errors.New("security.ca_cert_paths is required for non-root nodes（用于校验父与对端）")
	}
	for _, p := range c.Security.CACertPaths {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("security.ca_cert_paths: %s: %w（信任锚必须存在；给目录时会扫其中的 *.crt/*.pem）", p, err)
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
	// 注意：**不在这里**因为"证书不存在 + 没配 token"就拒绝启动 ——
	// 父端可能只配了 allow_ids 白名单（那种模式不需要 token），子端无从得知。
	// 于是它会先以"待入网"状态起来，运行期再由父端明确拒绝（ERR_ENROLL_*）。
	return nil
}

// ConfigHash 计算配置指纹，只覆盖影响拓扑 / 会话 / 证书 / 父列表 / 监听地址的关键字段（6.1 白名单）。
// 明确不进 hash：security.viewers.*、query.query_viewers、command.*、health.*、persist.*、version。
//
// 接收者 c 是完整配置。做法是把白名单字段按固定顺序拼成一段文本再取 SHA-256；
// allow_ids 会先排序，保证同一份配置每次算出的哈希一致。
// 入网策略只把"开关 + allow_ids 列表"写进去，凭据 token 不进 —— 换 token 不该触发全量重注册。
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
	// 入网策略：允许列表进 hash（改了要重注册），但**凭据（token）不进** —— 换 token 不该触发全量重注册
	if c.Security.EnrollmentEnabled() {
		allow := append([]string(nil), c.Security.Enrollment.AllowIDs...)
		sortStrings(allow)
		sb.WriteString("security.enrollment=on:" + strings.Join(allow, ",") + "\n")
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

// sortStrings 就地按字典序升序排列字符串切片（插入排序）。
//
// 这里用它是为了让 allow_ids 的拼接顺序稳定：`enrollment.allow_ids` 是个字符串列表，
// 用户手写顺序不该影响 ConfigHash。待排序的都是几十个元素的小切片，所以用最朴素的插入排序即可。
//
// 参数：
//
//	s — 待排序的切片；直接原地修改，不返回新切片
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
