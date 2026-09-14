// Package registry 维护直接子节点表、路径路由、祖先链与环检测。
//
// **不做任何 Target 筛选**（见 README「实现说明」）：父节点下发的任务，子节点收到即执行；
// 因此这里只有"哪些是我的直接子节点"这一件事，没有按路径 / 标签剪枝的逻辑。
package registry

import (
	"sort"
	"strings"
	"sync"
	"time"

	"treecmd/internal/identity"
	"treecmd/internal/persist"
)

// Child 一个直接子节点。
type Child struct {
	NodeID       string
	Path         string
	Name         string // 节点名（人类可读，注册时上报；仅展示用途）
	Remark       string // 节点备注（注册时上报；仅展示用途）
	Labels       map[string]string
	Caps         []string
	ListenAddr   string
	Confirmed    bool // 是否真的连上过（warm 预热不算）
	RegisteredAt time.Time
	LastEpoch    uint64
	// BuildHash 该子节点**可执行文件**的哈希（注册时上报；见 README「可执行文件一致性」）。
	// 仅展示用途：父端拿它和 n.Build().Hash 一比，就能在 /v1/tree 里看出"谁跑的还是旧镜像"。
	BuildHash string
}

// Table 直接子节点表。
type Table struct {
	mu       sync.RWMutex
	selfID   string
	selfPath string
	labels   map[string]string
	caps     []string
	children map[string]*Child
}

// New 构造一张空的直接子节点表，并把本节点信息记进去。
//
// 参数：
//
//	selfID   — 本节点 NodeID
//	selfPath — 本节点路径；根节点通常是 "/"
//	labels   — 本节点标签
//	caps     — 本节点能力列表
//
// 返回：
//
//	*Table — 子节点为空的表，可直接使用
func New(selfID, selfPath string, labels map[string]string, caps []string) *Table {
	return &Table{
		selfID: selfID, selfPath: selfPath,
		labels: labels, caps: caps,
		children: map[string]*Child{},
	}
}

// SelfID 返回本节点 NodeID（构造后不再变化，故未加锁）。
func (t *Table) SelfID() string { return t.selfID }

// SelfPath 返回本节点当前路径。
//
// 接收者 t 是本节点的直接子节点表。路径可能被 SetSelfPath 改过，故这里加读锁。
//
// 返回：
//
//	string — 本节点路径
func (t *Table) SelfPath() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.selfPath
}

// SetSelfPath 设置本节点路径（注册收到 RegisterAck 后调用）。
//
// 接收者 t 是本节点的直接子节点表。
//
// 参数：
//
//	p — 新的路径
func (t *Table) SetSelfPath(p string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.selfPath = p
}

// SetLabels 更新本节点标签。
//
// 接收者 t 是本节点的直接子节点表。
//
// 参数：
//
//	l — 新的标签表
func (t *Table) SetLabels(l map[string]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.labels = l
}

// Labels 返回本节点标签。
//
// 接收者 t 是本节点的直接子节点表。直接返回内部 map 引用，调用方不应修改它。
//
// 返回：
//
//	map[string]string — 本节点标签
func (t *Table) Labels() map[string]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.labels
}

// Caps 返回本节点能力列表的一份拷贝。
//
// 接收者 t 是本节点的直接子节点表。
//
// 返回：
//
//	[]string — 能力列表副本；改它不会影响表内数据
func (t *Table) Caps() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]string(nil), t.caps...)
}

// Upsert 插入或更新一个直接子节点（按 NodeID 去重）。
//
// 接收者 t 是本节点的直接子节点表。
// 已存在时是"合并更新"：Path / Labels / Caps / Confirmed / RegisteredAt / LastEpoch 直接覆盖，
// 而 Name / Remark / ListenAddr / BuildHash 只在本次非空时才覆盖 —— 避免旧版本客户端或未配置
// 名字的节点把表里已有的人类可读信息擦掉。
//
// 参数：
//
//	c — 待写入的子节点；以 c.NodeID 为 key，首次插入时直接存指针
func (t *Table) Upsert(c *Child) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.children[c.NodeID]; ok {
		old.Path = c.Path
		old.Labels = c.Labels
		old.Caps = c.Caps
		// 元信息按"上报了才覆盖"处理：旧版本客户端 / 未配置 name 的节点不应该把已有名字擦掉
		if c.Name != "" {
			old.Name = c.Name
		}
		if c.Remark != "" {
			old.Remark = c.Remark
		}
		if c.ListenAddr != "" {
			old.ListenAddr = c.ListenAddr
		}
		// 可执行文件哈希同理，但**必须覆盖**：子节点自同步换版后重新注册时，
		// 正是靠这次覆盖把"我跑的还是旧镜像"改成"我跟上了"（否则 /v1/tree 会一直显示旧值、
		// lagging_children 永远归不了零 —— 这是端到端测试抓出来的）。
		if c.BuildHash != "" {
			old.BuildHash = c.BuildHash
		}
		old.Confirmed = c.Confirmed
		old.RegisteredAt = c.RegisteredAt
		old.LastEpoch = c.LastEpoch
		return
	}
	t.children[c.NodeID] = c
}

// Remove 按 NodeID 移除一个直接子节点（连接断开确认离线 / 驱逐时调用）。
//
// 接收者 t 是本节点的直接子节点表。
//
// 参数：
//
//	id — 要移除的子节点 NodeID；不存在时什么都不做
func (t *Table) Remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.children, id)
}

// Get 按 NodeID 取一个直接子节点。
//
// 接收者 t 是本节点的直接子节点表。
//
// 参数：
//
//	id — 子节点 NodeID
//
// 返回：
//
//	*Child — 命中的子节点（表内指针，不要改它的字段）
//	bool   — false 表示表里没有这个 NodeID
func (t *Table) Get(id string) (*Child, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c, ok := t.children[id]
	return c, ok
}

// Snapshot 返回全部直接子节点的快照，按 NodeID 升序（保证遍历顺序确定）。
//
// 接收者 t 是本节点的直接子节点表。
//
// 返回：
//
//	[]*Child — 结构体逐个复制后的新切片；元素指针是新指针，但 Labels / Caps 仍与表内共享底层数据
func (t *Table) Snapshot() []*Child {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Child, 0, len(t.children))
	for _, c := range t.children {
		cp := *c
		out = append(out, &cp)
	}
	sort.SliceStable(out, func(i, j int) bool { return identity.NodeIDLess(out[i].NodeID, out[j].NodeID) })
	return out
}

// Len 返回直接子节点数量（含仅预热、尚未确认的）。
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.children)
}

// Warm 用持久化文件 state.dat 里的静态快照预热子节点表。
//
// 接收者 t 是本节点的直接子节点表。
// 预热出来的子节点一律 Confirmed=false（只是"可能还在"，并未真的连上），摘要也未知；
// 表里已经存在的 NodeID 不覆盖。
//
// 参数：
//
//	known — 持久化记录里已知的子节点列表
func (t *Table) Warm(known []persist.KnownChild) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, kc := range known {
		if _, ok := t.children[kc.ID]; ok {
			continue
		}
		t.children[kc.ID] = &Child{
			NodeID: kc.ID, Path: kc.Path, Caps: kc.Caps, Labels: kc.Labels,
			Name: kc.Name, Remark: kc.Remark,
			Confirmed: false,
		}
	}
}

// Ancestors 返回某条路径的祖先链（不含自身本身），供 RegisterAck 下发给子节点做环检测。
//
// 例如 "/a/b/c" 返回 ["/a", "/a/b"]。
//
// 参数：
//
//	path — 绝对路径
//
// 返回：
//
//	[]string — 从根到父的各级路径；根路径 "/" 或空串返回 nil
func Ancestors(path string) []string {
	if path == "/" || path == "" {
		return nil
	}
	segs := Segments(path)
	var out []string
	for i := 0; i < len(segs); i++ {
		out = append(out, Join("/", segs[:i+1]...))
	}
	return out
}

// Segments 把路径切成段：先去掉首尾斜杠，再按 "/" 拆分。
//
// 参数：
//
//	p — 路径
//
// 返回：
//
//	[]string — 各段名字；空串或根路径返回 nil
func Segments(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// Join 把父路径与若干子段拼成一条路径。
//
// 参数：
//
//	parent — 父路径
//	segs   — 一级或多级子段；空段会被跳过
//
// 返回：
//
//	string — 拼接结果；无子段时返回规范化后的 parent，全空时返回 "/"
func Join(parent string, segs ...string) string {
	if len(segs) == 0 {
		if parent == "" {
			return "/"
		}
		return parent
	}
	base := strings.TrimRight(parent, "/")
	out := base
	for _, s := range segs {
		if s == "" {
			continue
		}
		out += "/" + strings.Trim(s, "/")
	}
	if out == "" {
		return "/"
	}
	return out
}

// IsAncestor 判断 a 是否是 b 的祖先（把"与 b 相等"也算祖先）。
//
// 特判：根路径 "/" 视为所有路径的祖先。
//
// 参数：
//
//	a — 候选祖先路径
//	b — 待判断的路径
//
// 返回：
//
//	bool — true 表示 a 是 b 的祖先或与 b 相同
func IsAncestor(a, b string) bool {
	if a == "/" {
		return true
	}
	a = strings.TrimRight(a, "/")
	if a == b {
		return true
	}
	return strings.HasPrefix(b, a+"/")
}

// Remaining 去掉前缀后返回剩余路径（路径前缀路由用）。
//
// 参数：
//
//	full   — 完整路径
//	prefix — 要抹掉的前缀；为 "/" 时不抹
//
// 返回：
//
//	string — 剩余路径；full 不以 prefix 开头时原样返回 full
func Remaining(full, prefix string) string {
	if prefix == "/" {
		return full
	}
	p := strings.TrimRight(prefix, "/")
	if !strings.HasPrefix(full, p) {
		return full
	}
	return full[len(p):]
}

// FirstSegment 取剩余路径的首段（路由下一跳用）。
//
// 参数：
//
//	remaining — 剩余路径
//
// 返回：
//
//	string — 首段名字；路径为空时返回 ""
func FirstSegment(remaining string) string {
	segs := Segments(remaining)
	if len(segs) == 0 {
		return ""
	}
	return segs[0]
}

// ContainsNode 判断祖先链里是否已经包含某个 NodeID（注册时做环检测）。
//
// 参数：
//
//	ancestorIDs — 祖先的 NodeID 列表
//	id          — 待查 NodeID
//
// 返回：
//
//	bool — true 表示链里出现过 id
func ContainsNode(ancestorIDs []string, id string) bool {
	for _, a := range ancestorIDs {
		if a == id {
			return true
		}
	}
	return false
}
