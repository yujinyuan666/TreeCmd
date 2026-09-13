// Package observability 提供最小可用的指标注册表 + Prometheus 文本导出（零外部依赖）。
// 指标口径见方案 9.3 / 13.4。
package observability

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry 计数器 + 表函数（gauge 在抓取时实时求值，不做后台采集）。
//
// 字段说明：counters 是"计数器 key → 计数值指针"（值用 atomic 读写）；
// gauges 是"指标名 → 无标签取值函数"；labeled 是"指标名 → 带标签取值函数"；
// help 是"指标名 → # HELP 说明文字"。整个结构可以被多个 goroutine 并发使用。
type Registry struct {
	mu       sync.RWMutex
	counters map[string]*int64
	gauges   map[string]func() float64
	labeled  map[string]func() map[string]float64
	help     map[string]string
}

// New 创建一个空的指标注册表。
//
// 返回：
//
//	*Registry — 四张内部表都已初始化的注册表，可以并发使用
func New() *Registry {
	return &Registry{
		counters: map[string]*int64{}, gauges: map[string]func() float64{},
		labeled: map[string]func() map[string]float64{}, help: map[string]string{},
	}
}

// Help 给某个指标名登记一行说明，导出时写成 # HELP 行。
//
// 接收者 r 是指标注册表；内部有读写锁，可以并发调用。
//
// 参数：
//
//	name — 指标名，要与计数 / gauge 用的名字完全一致才会生效
//	text — 说明文字；同一个名字重复设置会覆盖上一次
func (r *Registry) Help(name, text string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.help[name] = text
}

// counterKey 把指标名和标签拼成内部 map 用的 key。
//
// 没有标签时直接用指标名；有标签时拼成 "指标名|值1,值2,..."。
// 这里只做拼接、不排序也不去重，所以标签顺序不同会被当成两个不同的计数器。
//
// 参数：
//
//	name   — 指标名
//	labels — 扁平的"键、值"交替序列，如 "status","COMPLETED"
//
// 返回：
//
//	string — 供内部 map 使用的 key
func counterKey(name string, labels []string) string {
	if len(labels) == 0 {
		return name
	}
	return name + "|" + strings.Join(labels, ",")
}

// Inc 把计数器加 1。
//
// 接收者 r 是指标注册表。
//
// 参数：
//
//	name   — 指标名；不存在时会自动创建
//	labels — 扁平的"键、值"交替序列，如 "status","COMPLETED"；要么不传，要么成对传
func (r *Registry) Inc(name string, labels ...string) { r.Add(name, 1, labels...) }

// Add 把计数器累加 delta，计数器不存在时会自动创建。
//
// 接收者 r 是指标注册表。计数值用 atomic 读写，所以对同一个 key 的并发累加不会丢更新；
// 创建动作走写锁的二次检查，避免并发创建时把已累加的值覆盖掉。
//
// 参数：
//
//	name   — 指标名
//	delta  — 增量，可以为负
//	labels — 扁平的"键、值"交替序列；要么不传，要么成对传
func (r *Registry) Add(name string, delta int64, labels ...string) {
	key := counterKey(name, labels)
	r.mu.RLock()
	p, ok := r.counters[key]
	r.mu.RUnlock()
	if !ok {
		r.mu.Lock()
		if p, ok = r.counters[key]; !ok {
			var v int64
			p = &v
			r.counters[key] = p
		}
		r.mu.Unlock()
	}
	atomic.AddInt64(p, delta)
}

// SetGauge 注册一个无标签的 gauge（瞬时值）。
//
// 接收者 r 是指标注册表。gauge 不是被推着更新的，而是每次抓取时调用 f 现算，
// 所以 f 必须快速、不阻塞、并发安全。
//
// 参数：
//
//	name — 指标名
//	f    — 取值函数；调用 WriteText 抓取时会被调用，返回值就是当前值
func (r *Registry) SetGauge(name string, f func() float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = f
}

// SetLabeled 注册一个带标签的 gauge。
//
// 接收者 r 是指标注册表。和无标签 gauge 一样，取值函数是抓取时才调用的。
//
// 参数：
//
//	name — 指标名
//	f    — 取值函数，返回"标签组合 → 当前值"的 map；map 的 key 是已拼好的标签原文，
//	       例如 "status=RUNNING"（导出时会被放进大括号里，形如 name{status=RUNNING} 3）
func (r *Registry) SetLabeled(name string, f func() map[string]float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.labeled[name] = f
}

// WriteText 把所有指标写成 Prometheus 文本格式，可直接由 /metrics 端点返回。
//
// 接收者 r 是指标注册表。输出顺序是稳定的：先计数器、再无标签 gauge、最后带标签 gauge，
// 每段内部按名字排序，这样两次抓取的结果可以直接 diff。
//
// 参数：
//
//	w — 输出目标；写入失败会被忽略（fmt.Fprintf 的返回值没有检查）
func (r *Registry) WriteText(w io.Writer) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var keys []string
	for k := range r.counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	for _, k := range keys {
		name, labels := splitKey(k)
		if !seen[name] {
			if h, ok := r.help[name]; ok {
				fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, h, name)
			} else {
				fmt.Fprintf(w, "# TYPE %s counter\n", name)
			}
			seen[name] = true
		}
		fmt.Fprintf(w, "%s%s %d\n", name, labels, atomic.LoadInt64(r.counters[k]))
	}
	var gnames []string
	for k := range r.gauges {
		gnames = append(gnames, k)
	}
	sort.Strings(gnames)
	for _, name := range gnames {
		if h, ok := r.help[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n", name, h)
		}
		fmt.Fprintf(w, "# TYPE %s gauge\n%s %g\n", name, name, r.gauges[name]())
	}
	var lnames []string
	for k := range r.labeled {
		lnames = append(lnames, k)
	}
	sort.Strings(lnames)
	for _, name := range lnames {
		if h, ok := r.help[name]; ok {
			fmt.Fprintf(w, "# HELP %s %s\n", name, h)
		}
		fmt.Fprintf(w, "# TYPE %s gauge\n", name)
		m := r.labeled[name]()
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			fmt.Fprintf(w, "%s{%s} %g\n", name, k, m[k])
		}
	}
}

// splitKey 把 counterKey 拼出来的内部 key 拆回指标名和 Prometheus 标签串。
//
// 没有 "|" 时标签串是空串；有标签时把 "值1,值2,..." 每两个一组渲染成 {k1="v1",k2="v2"}。
// 注意循环条件是 j+1 < len(parts)，所以标签个数是奇数时，最后落单的那个会被丢掉。
//
// 参数：
//
//	k — counterKey 产生的内部 key
//
// 返回：
//
//	string — 指标名
//	string — 可直接拼在指标名后面的标签串，如 {status="COMPLETED"}；无标签时是空串
func splitKey(k string) (string, string) {
	i := strings.IndexByte(k, '|')
	if i < 0 {
		return k, ""
	}
	name, rest := k[:i], k[i+1:]
	parts := strings.Split(rest, ",")
	var sb strings.Builder
	sb.WriteByte('{')
	for j := 0; j+1 < len(parts); j += 2 {
		if j > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, "%s=%q", parts[j], parts[j+1])
	}
	sb.WriteByte('}')
	return name, sb.String()
}
