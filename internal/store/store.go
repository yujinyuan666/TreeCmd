// Package store 封装 bbolt，提供方案 6.7 / 10 章列出的全部子库：
//
//	meta            next_cmd_seq 权威值（只增不减）
//	commands        CommandRecord（服务端视角：LocalSeq / 指令体 / 指令级 Status）
//	cmdlog          seq → commandID 的指令日志（按 cmd_seq 组织，供保留水位裁剪）
//	assignments     AssignmentRecord（父为每个直接子各一条）
//	assign_child    childID → commandID 索引（FetchCommands 用）
//	child_reports   子报告权威副本（ADR-048：父端权威结果持久化）
//	local_state     LocalCommandRecord（客户端视角：本地三态 + 自身结果 + 未终态指令体）
//	pending_result  待上报 / 待补报的 Report（除 Sig）
//	results         结果档案（发起节点自留）
//	child_watermark ChildWatermark（FetchedCmdSeq / LastSeenAt / LastEpoch）
//
// 所有跨表写入都在**同一个事务**里完成（EnsureCreated / terminal / 接受子报告 / finalize）。
//
// bbolt 是一个嵌入式单文件键值库：文件里分若干"桶"（bucket，相当于一张表），
// 桶内部是"键 → 值"的有序映射，键和值都是 []byte。所有读写都必须在一个事务里进行：
// Update 是读写事务（结束即提交，回调返回 error 则回滚），View 是只读事务。
// 桶里的键按字节序排列，所以带相同前缀的键是连续存放的，可以用游标（cursor，指向某个键位置的指针）做前缀扫描。
package store

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	"treecmd/internal/pb"
)

var (
	bMeta      = []byte("meta")
	bCommands  = []byte("commands")
	bCmdLog    = []byte("cmdlog")
	bAssign    = []byte("assignments")
	bAssignIdx = []byte("assign_child")
	bChildRep  = []byte("child_reports")
	bLocal     = []byte("local_state")
	bPending   = []byte("pending_result")
	bResults   = []byte("results")
	bWatermark = []byte("child_watermark")
	bEvicted   = []byte("evicted_children")
	bCRL       = []byte("crl")
	bPendIndex = []byte("pending_index")
	keyNextSeq = []byte("next_cmd_seq")
	allBuckets = [][]byte{bMeta, bCommands, bCmdLog, bAssign, bAssignIdx, bChildRep, bLocal, bPending, bResults, bWatermark, bEvicted, bCRL, bPendIndex}
)

// Store bbolt 封装。
type Store struct {
	db   *bolt.DB
	path string
}

// Open 打开（或创建）数据库文件，并确保 13 个桶都已建好。
//
// 参数：
//
//	path — 数据库文件路径；其父目录不存在时会先递归创建
//
// 返回：
//
//	*Store — 数据库句柄，之后用 Update / View 开事务
//	error  — 建目录、打开文件或建桶失败时返回
func Open(path string) (*Store, error) {
	if err := mkdir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

// Path 返回数据库文件路径。
func (s *Store) Path() string { return s.path }

// Tx 一次事务的上下文。Now 为事务时间（同一事务内一致，见 1.1 约束五）。
//
// Tx 只是对 bbolt 事务的薄封装，事务内的读写要等事务提交才真正落盘。
type Tx struct {
	tx  *bolt.Tx
	Now time.Time
}

// Update 开启一次读写事务并执行 fn，fn 正常返回即提交，返回 error 则回滚。
//
// 参数：
//
//	fn — 事务回调；入参是本项目封装后的事务上下文 *Tx
//
// 返回：
//
//	error — fn 返回的错误，或提交失败的错误
func (s *Store) Update(fn func(*Tx) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return fn(&Tx{tx: tx, Now: time.Now()})
	})
}

// View 开启一次只读事务并执行 fn（不产生任何写入）。
//
// 参数：
//
//	fn — 事务回调；入参是本项目封装后的事务上下文 *Tx
//
// 返回：
//
//	error — fn 返回的错误
func (s *Store) View(fn func(*Tx) error) error {
	return s.db.View(func(tx *bolt.Tx) error {
		return fn(&Tx{tx: tx, Now: time.Now()})
	})
}

// ---------- 通用编解码 ----------

// putProto 把一条 protobuf 消息序列化后写入桶里的指定键。
//
// 参数：
//
//	b   — 目标桶（相当于一张表）
//	key — 键，字节切片
//	m   — 要写入的 protobuf 消息
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func putProto(b *bolt.Bucket, key []byte, m proto.Message) error {
	v, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	return b.Put(key, v)
}

// getProto 从桶里按键读出一条 protobuf 消息；键不存在时返回 (零值, false, nil)。
//
// 类型参数 T 是目标消息类型（需实现 proto.Message），out 既是解码目标也是返回值。
//
// 参数：
//
//	b   — 目标桶
//	key — 键
//	out — 解码目标对象，命中时内容会被覆盖
//
// 返回：
//
//	T     — 与 out 相同的对象；未命中或出错时为零值
//	bool  — 键是否存在
//	error — 反序列化失败时返回
func getProto[T proto.Message](b *bolt.Bucket, key []byte, out T) (T, bool, error) {
	var zero T
	v := b.Get(key)
	if v == nil {
		return zero, false, nil
	}
	if err := proto.Unmarshal(v, out); err != nil {
		return zero, false, err
	}
	return out, true, nil
}

// k 把多段字符串用 '/' 连接成一个复合键，例如 k(cmdID, childID)。
//
// 参数：
//
//	parts — 依次拼接的键片段
//
// 返回：
//
//	[]byte — 拼接结果；无入参时返回空切片
func k(parts ...string) []byte {
	out := []byte{}
	for i, p := range parts {
		if i > 0 {
			out = append(out, '/')
		}
		out = append(out, p...)
	}
	return out
}

// ---------- meta ----------

// NextCmdSeq 读取 meta 桶里权威的 next_cmd_seq，即"最后已分配出去的 seq"。
//
// 返回：
//
//	int64 — 已分配的最大序号；键不存在或长度不是 8 字节时返回 0
func (t *Tx) NextCmdSeq() int64 {
	v := t.tx.Bucket(bMeta).Get(keyNextSeq)
	if len(v) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(v))
}

// AllocLocalSeq 读取 next_cmd_seq、加一后写回，并返回本次分配到的 LocalSeq。
//
// "读-改-写"整个过程在同一个 bbolt 写事务内完成，因此并发调用不会拿到重复序号。
// 创建事务与 EnsureCreated 共用同一个计数器。
//
// 返回：
//
//	int64 — 本次分配到的 LocalSeq
//	error — 写回失败时返回
func (t *Tx) AllocLocalSeq() (int64, error) {
	b := t.tx.Bucket(bMeta)
	next := t.NextCmdSeq() + 1
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(next))
	if err := b.Put(keyNextSeq, buf[:]); err != nil {
		return 0, err
	}
	return next, nil
}

// SetNextCmdSeq 把 next_cmd_seq 抬高到 v，仅在启动恢复兜底时使用。
//
// 只增不减：v 不大于当前值时直接返回 nil，不做写入。
//
// 参数：
//
//	v — 期望的序号下界
//
// 返回：
//
//	error — 写入失败时返回
func (t *Tx) SetNextCmdSeq(v int64) error {
	if v <= t.NextCmdSeq() {
		return nil
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	return t.tx.Bucket(bMeta).Put(keyNextSeq, buf[:])
}

// ---------- commands + cmdlog ----------

// PutCommand 写入（或覆盖）一条指令记录，并把它登记进指令日志 cmdlog。
//
// 两处写入在同一事务内完成：commands 桶存完整记录（键为 CommandId），
// cmdlog 桶存 "LocalSeq → CommandId"（键为 8 字节大端 seq），供按序号顺序回放与裁剪。
//
// 参数：
//
//	rec — 指令记录；以 CommandId 作为 commands 桶的键，重复写入即覆盖
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutCommand(rec *pb.CommandRecord) error {
	if err := putProto(t.tx.Bucket(bCommands), []byte(rec.CommandId), rec); err != nil {
		return err
	}
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], uint64(rec.LocalSeq))
	return t.tx.Bucket(bCmdLog).Put(seq[:], []byte(rec.CommandId))
}

// GetCommand 按 commandID 读出一条指令记录。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	*pb.CommandRecord — 命中的记录；未命中或反序列化失败时为 nil
//	bool             — 是否命中
func (t *Tx) GetCommand(id string) (*pb.CommandRecord, bool) {
	rec, ok, err := getProto(t.tx.Bucket(bCommands), []byte(id), &pb.CommandRecord{})
	if err != nil {
		return nil, false
	}
	return rec, ok
}

// DeleteCommand 删除指令记录，同时删掉它在 cmdlog 里对应的序号条目。
//
// 保留水位裁剪 / 审计期结束后调用。记录不存在时只做一次无效删除。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	error — 删除 commands 桶条目失败时返回
func (t *Tx) DeleteCommand(id string) error {
	rec, ok := t.GetCommand(id)
	if ok {
		var seq [8]byte
		binary.BigEndian.PutUint64(seq[:], uint64(rec.LocalSeq))
		_ = t.tx.Bucket(bCmdLog).Delete(seq[:])
	}
	return t.tx.Bucket(bCommands).Delete([]byte(id))
}

// CmdLogAfter 从 cmdlog 里顺序取出 seq > since 的条目，返回 (seq 列表, commandID 列表)。
//
// 实现上把 since+1 编码成 8 字节大端作起点，用游标 Seek 到该位置再连续 Next；
// 因为键按字节序排列、且大端编码的字节序等于数值序，所以结果天然按 seq 升序。
//
// 参数：
//
//	since — 下界（不含）；返回的 seq 都严格大于它
//	limit — 最多返回条数；<= 0 表示不限制
//
// 返回：
//
//	[]int64  — 命中的 seq，升序
//	[]string — 与 seq 一一对应的 commandID
func (t *Tx) CmdLogAfter(since int64, limit int) ([]int64, []string) {
	var seqs []int64
	var ids []string
	c := t.tx.Bucket(bCmdLog).Cursor()
	start := make([]byte, 8)
	binary.BigEndian.PutUint64(start, uint64(since+1))
	for k, v := c.Seek(start); k != nil; k, v = c.Next() {
		if len(k) != 8 {
			continue
		}
		seqs = append(seqs, int64(binary.BigEndian.Uint64(k)))
		ids = append(ids, string(v))
		if limit > 0 && len(seqs) >= limit {
			break
		}
	}
	return seqs, ids
}

// MaxLoggedSeq 返回 cmdlog 里的最大 seq，即游标 Last 指向的键。
//
// 返回：
//
//	int64 — 最大 seq；日志为空或键长度不是 8 字节时返回 0
func (t *Tx) MaxLoggedSeq() int64 {
	k, _ := t.tx.Bucket(bCmdLog).Cursor().Last()
	if len(k) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(k))
}

// LastAllocatedSeq 返回"最后已分配的 seq"（即 next_cmd_seq），用于 RegisterAck 的 start_cmd_seq。
func (t *Tx) LastAllocatedSeq() int64 { return t.NextCmdSeq() }

// ---------- assignments ----------

// PutAssignment 写入一条 Assignment 记录，并维护 assign_child 索引。
//
// assignments 桶的键是 "commandID/childID"；assign_child 桶存反向索引 "childID/commandID"，
// 让"某个子节点名下有哪些指令"也能按前缀连续扫出来。
//
// 参数：
//
//	a — 分配记录；两处键都取自它的 CommandId / ChildId 字段
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutAssignment(a *pb.AssignmentRecord) error {
	if err := putProto(t.tx.Bucket(bAssign), k(a.CommandId, a.ChildId), a); err != nil {
		return err
	}
	return t.tx.Bucket(bAssignIdx).Put(k(a.ChildId, a.CommandId), []byte(a.CommandId))
}

// GetAssignment 读出一条 (指令, 子节点) 的 Assignment。
//
// 参数：
//
//	cmdID   — 指令 ID
//	childID — 子节点 ID
//
// 返回：
//
//	*pb.AssignmentRecord — 命中的记录；未命中或反序列化失败时为 nil
//	bool                 — 是否命中
func (t *Tx) GetAssignment(cmdID, childID string) (*pb.AssignmentRecord, bool) {
	a, ok, err := getProto(t.tx.Bucket(bAssign), k(cmdID, childID), &pb.AssignmentRecord{})
	if err != nil {
		return nil, false
	}
	return a, ok
}

// AssignmentsOfCommand 返回某条指令下的全部 Assignment（含从未投递出去的）。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	[]*pb.AssignmentRecord — 键前缀为 "cmdID/" 的记录；反序列化失败的条目会被跳过
func (t *Tx) AssignmentsOfCommand(cmdID string) []*pb.AssignmentRecord {
	var out []*pb.AssignmentRecord
	c := t.tx.Bucket(bAssign).Cursor()
	prefix := []byte(cmdID + "/")
	for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
		a := &pb.AssignmentRecord{}
		if err := proto.Unmarshal(v, a); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// CommandIDsOfChild 返回挂在某个子节点名下的全部 commandID（供 FetchCommands 用）。
//
// 走的是 assign_child 反向索引，键前缀为 "childID/"。
//
// 参数：
//
//	childID — 子节点 ID
//
// 返回：
//
//	[]string — 命中的 commandID
func (t *Tx) CommandIDsOfChild(childID string) []string {
	var out []string
	c := t.tx.Bucket(bAssignIdx).Cursor()
	prefix := []byte(childID + "/")
	for k, v := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, v = c.Next() {
		out = append(out, string(v))
	}
	return out
}

// DeleteAssignmentsOfCommand 删除某条指令的全部 Assignment，索引条目一并删除。
//
// 先取出记录再逐条删，避免边遍历游标边修改桶。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	error — 任意一次删除失败时返回，后续条目不再删除
func (t *Tx) DeleteAssignmentsOfCommand(cmdID string) error {
	for _, a := range t.AssignmentsOfCommand(cmdID) {
		if err := t.tx.Bucket(bAssign).Delete(k(a.CommandId, a.ChildId)); err != nil {
			return err
		}
		if err := t.tx.Bucket(bAssignIdx).Delete(k(a.ChildId, a.CommandId)); err != nil {
			return err
		}
	}
	return nil
}

// ScanAssignments 返回 assignments 桶的全量快照。
//
// 调用方拿到的是一份拷贝，迭代之后可以另行写入，避免边遍历边改桶。
//
// 返回：
//
//	[]*pb.AssignmentRecord — 所有记录；反序列化失败的条目会被跳过
func (t *Tx) ScanAssignments() []*pb.AssignmentRecord {
	var out []*pb.AssignmentRecord
	_ = t.tx.Bucket(bAssign).ForEach(func(_, v []byte) error {
		a := &pb.AssignmentRecord{}
		if err := proto.Unmarshal(v, a); err == nil {
			out = append(out, a)
		}
		return nil
	})
	return out
}

// MinUnfinishedSeq 返回所有未终态 Assignment 里最小的 LocalSeq，即 retention_floor 的第二项。
//
// 没有未终态 Assignment 时返回 MaxLoggedSeq()。
//
// 返回：
//
//	int64 — 最小未完成序号；无未完成项时退化为指令日志的最大 seq
func (t *Tx) MinUnfinishedSeq() int64 {
	min := int64(-1)
	c := t.tx.Bucket(bAssign).Cursor()
	for k, v := c.First(); k != nil; k, v = c.Next() {
		a := &pb.AssignmentRecord{}
		if err := proto.Unmarshal(v, a); err != nil {
			continue
		}
		if isTerminalAssign(a.Status) {
			continue
		}
		if min < 0 || a.LocalSeq < min {
			min = a.LocalSeq
		}
	}
	if min < 0 {
		return t.MaxLoggedSeq()
	}
	return min
}

// isTerminalAssign 判断一个分配状态是否已经终结（完成 / 失败 / 超时 / 已取消）。
//
// 参数：
//
//	s — 分配状态枚举值
//
// 返回：
//
//	bool — 属于终态时为 true
func isTerminalAssign(s pb.AssignStatus) bool {
	switch s {
	case pb.AssignStatus_ASSIGN_STATUS_DONE, pb.AssignStatus_ASSIGN_STATUS_FAILED,
		pb.AssignStatus_ASSIGN_STATUS_TIMEOUT, pb.AssignStatus_ASSIGN_STATUS_CANCELLED:
		return true
	}
	return false
}

// ---------- child_reports ----------

// PutChildReport 写入子报告的权威副本（ADR-048：父端权威结果持久化）。
//
// 参数：
//
//	r — 子报告记录；以 "CommandId/ChildId" 作为键
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutChildReport(r *pb.ChildReportRecord) error {
	return putProto(t.tx.Bucket(bChildRep), k(r.CommandId, r.ChildId), r)
}

// GetChildReport 读取一条子报告权威副本。
//
// 参数：
//
//	cmdID   — 指令 ID
//	childID — 子节点 ID
//
// 返回：
//
//	*pb.ChildReportRecord — 命中的记录；未命中或反序列化失败时为 nil
//	bool                  — 是否命中
func (t *Tx) GetChildReport(cmdID, childID string) (*pb.ChildReportRecord, bool) {
	r, ok, err := getProto(t.tx.Bucket(bChildRep), k(cmdID, childID), &pb.ChildReportRecord{})
	if err != nil {
		return nil, false
	}
	return r, ok
}

// DeleteChildReportsOfCommand 删除某条指令下的全部子报告。
//
// 先把待删键拷一份出来，再统一删除，避免边遍历游标边改桶。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	error — 任意一次删除失败时返回
func (t *Tx) DeleteChildReportsOfCommand(cmdID string) error {
	c := t.tx.Bucket(bChildRep).Cursor()
	prefix := []byte(cmdID + "/")
	var keys [][]byte
	for k, _ := c.Seek(prefix); k != nil && hasPrefix(k, prefix); k, _ = c.Next() {
		keys = append(keys, append([]byte(nil), k...))
	}
	for _, kk := range keys {
		if err := t.tx.Bucket(bChildRep).Delete(kk); err != nil {
			return err
		}
	}
	return nil
}

// ---------- local_state ----------

// PutLocal 写入一条客户端视角的记录（本地三态 + 自身结果 + 未终态指令体）。
//
// 参数：
//
//	r — 本地指令记录；以 CommandId 作为键，重复写入即覆盖
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutLocal(r *pb.LocalCommandRecord) error {
	return putProto(t.tx.Bucket(bLocal), []byte(r.CommandId), r)
}

// GetLocal 读取一条客户端视角记录。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	*pb.LocalCommandRecord — 命中的记录；未命中或反序列化失败时为 nil
//	bool                   — 是否命中
func (t *Tx) GetLocal(id string) (*pb.LocalCommandRecord, bool) {
	r, ok, err := getProto(t.tx.Bucket(bLocal), []byte(id), &pb.LocalCommandRecord{})
	if err != nil {
		return nil, false
	}
	return r, ok
}

// ScanLocal 遍历本地账本，返回全部记录（reactivatePending 用）。
//
// 返回：
//
//	[]*pb.LocalCommandRecord — 所有记录；反序列化失败的条目会被跳过
func (t *Tx) ScanLocal() []*pb.LocalCommandRecord {
	var out []*pb.LocalCommandRecord
	_ = t.tx.Bucket(bLocal).ForEach(func(_, v []byte) error {
		r := &pb.LocalCommandRecord{}
		if err := proto.Unmarshal(v, r); err == nil {
			out = append(out, r)
		}
		return nil
	})
	return out
}

// DeleteLocal 删除一条本地账本记录。
func (t *Tx) DeleteLocal(id string) error { return t.tx.Bucket(bLocal).Delete([]byte(id)) }

// ---------- pending_result ----------

// PutPending 写入一条待上报条目。
//
// 参数：
//
//	r — 待上报记录；以 CommandId 作为键，重复写入即覆盖
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutPending(r *pb.PendingResultRecord) error {
	return putProto(t.tx.Bucket(bPending), []byte(r.CommandId), r)
}

// GetPending 读取一条待上报条目（reportUpstream 的唯一数据源）。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	*pb.PendingResultRecord — 命中的记录；未命中或反序列化失败时为 nil
//	bool                    — 是否命中
func (t *Tx) GetPending(id string) (*pb.PendingResultRecord, bool) {
	r, ok, err := getProto(t.tx.Bucket(bPending), []byte(id), &pb.PendingResultRecord{})
	if err != nil {
		return nil, false
	}
	return r, ok
}

// DeletePending 删除一条待上报条目（收到 ok=true 后才调用，独立事务）。
func (t *Tx) DeletePending(id string) error { return t.tx.Bucket(bPending).Delete([]byte(id)) }

// ScanPending 扫描待上报队列，按 commandID 升序返回，最多 limit 条。
//
// 参数：
//
//	limit — 最多返回条数；<= 0 表示不限制
//
// 返回：
//
//	[]*pb.PendingResultRecord — 排序并截断后的待上报记录
func (t *Tx) ScanPending(limit int) []*pb.PendingResultRecord {
	var out []*pb.PendingResultRecord
	_ = t.tx.Bucket(bPending).ForEach(func(_, v []byte) error {
		r := &pb.PendingResultRecord{}
		if err := proto.Unmarshal(v, r); err == nil {
			out = append(out, r)
		}
		return nil
	})
	sortPending(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// sortPending 就地把切片按 CommandId 升序排序（简单的插入排序）。
//
// 参数：
//
//	l — 待排序的记录切片，原地修改
func sortPending(l []*pb.PendingResultRecord) {
	for i := 1; i < len(l); i++ {
		for j := i; j > 0 && l[j].CommandId < l[j-1].CommandId; j-- {
			l[j], l[j-1] = l[j-1], l[j]
		}
	}
}

// ---------- results ----------

// PutResult 写入结果档案（按 commandID upsert，幂等）。
//
// 参数：
//
//	r — 结果记录；以 CommandId 作为键，重复写入即覆盖
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutResult(r *pb.ResultRecord) error {
	return putProto(t.tx.Bucket(bResults), []byte(r.CommandId), r)
}

// GetResult 读取一条结果档案。
//
// 参数：
//
//	id — 指令 ID
//
// 返回：
//
//	*pb.ResultRecord — 命中的记录；未命中或反序列化失败时为 nil
//	bool             — 是否命中
func (t *Tx) GetResult(id string) (*pb.ResultRecord, bool) {
	r, ok, err := getProto(t.tx.Bucket(bResults), []byte(id), &pb.ResultRecord{})
	if err != nil {
		return nil, false
	}
	return r, ok
}

// ScanResults 遍历结果档案，返回全部记录。
//
// 返回：
//
//	[]*pb.ResultRecord — 所有记录；反序列化失败的条目会被跳过
func (t *Tx) ScanResults() []*pb.ResultRecord {
	var out []*pb.ResultRecord
	_ = t.tx.Bucket(bResults).ForEach(func(_, v []byte) error {
		r := &pb.ResultRecord{}
		if err := proto.Unmarshal(v, r); err == nil {
			out = append(out, r)
		}
		return nil
	})
	return out
}

// DeleteResult 删除一条结果档案。
func (t *Tx) DeleteResult(id string) error { return t.tx.Bucket(bResults).Delete([]byte(id)) }

// ---------- child_watermark ----------

// PutWatermark 写入子节点水位（注册时立即写；上行帧到达时刷新 LastSeenAt）。
//
// 参数：
//
//	w — 子水位记录；以 ChildId 作为键，重复写入即覆盖
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutWatermark(w *pb.ChildWatermark) error {
	return putProto(t.tx.Bucket(bWatermark), []byte(w.ChildId), w)
}

// GetWatermark 读取一个子节点水位。
//
// 参数：
//
//	childID — 子节点 ID
//
// 返回：
//
//	*pb.ChildWatermark — 命中的记录；未命中或反序列化失败时为 nil
//	bool               — 是否命中
func (t *Tx) GetWatermark(childID string) (*pb.ChildWatermark, bool) {
	w, ok, err := getProto(t.tx.Bucket(bWatermark), []byte(childID), &pb.ChildWatermark{})
	if err != nil {
		return nil, false
	}
	return w, ok
}

// ScanWatermarks 遍历子水位，返回全部记录。
//
// 返回：
//
//	[]*pb.ChildWatermark — 所有记录；反序列化失败的条目会被跳过
func (t *Tx) ScanWatermarks() []*pb.ChildWatermark {
	var out []*pb.ChildWatermark
	_ = t.tx.Bucket(bWatermark).ForEach(func(_, v []byte) error {
		w := &pb.ChildWatermark{}
		if err := proto.Unmarshal(v, w); err == nil {
			out = append(out, w)
		}
		return nil
	})
	return out
}

// ---------- CRL（吊销列表，7.7） ----------

var (
	keyCRLVersion = []byte("crl_version")
	keyCRLGuids   = []byte("crl_guids")
)

// PutCRL 把吊销列表（版本号 + 被吊销节点 ID 列表）落盘。
//
// 本函数自身不比较版本，直接覆盖；"只应用更高版本"由调用方保证（版本号单调递增）。
//
// 参数：
//
//	version — CRL 版本号，以 8 字节大端存入 crl_version 键
//	guids   — 被吊销的节点 ID；用换行符拼接后存入 crl_guids 键
//
// 返回：
//
//	error — 任意一次写入失败时返回
func (t *Tx) PutCRL(version uint64, guids []string) error {
	b := t.tx.Bucket(bCRL)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], version)
	if err := b.Put(keyCRLVersion, buf[:]); err != nil {
		return err
	}
	return b.Put(keyCRLGuids, []byte(strings.Join(guids, "\n")))
}

// GetCRL 读取当前 CRL。
//
// 返回：
//
//	uint64   — 版本号；键缺失或长度不是 8 字节时为 0
//	[]string — 被吊销的节点 ID；值按换行切分并丢掉空项，无数据时为 nil
func (t *Tx) GetCRL() (uint64, []string) {
	b := t.tx.Bucket(bCRL)
	v := b.Get(keyCRLVersion)
	var ver uint64
	if len(v) == 8 {
		ver = binary.BigEndian.Uint64(v)
	}
	raw := string(b.Get(keyCRLGuids))
	var guids []string
	for _, g := range strings.Split(raw, "\n") {
		if g != "" {
			guids = append(guids, g)
		}
	}
	return ver, guids
}

// ---------- 结果索引待重发队列（3.14） ----------

// PutPendingIndex 入队一条待重发的索引。
//
// 参数：
//
//	cmdID   — 指令 ID，作为键
//	payload — 已由调用方序列化好的字节内容，原样存入
//
// 返回：
//
//	error — 写入失败时返回
func (t *Tx) PutPendingIndex(cmdID string, payload []byte) error {
	return t.tx.Bucket(bPendIndex).Put([]byte(cmdID), payload)
}

// DeletePendingIndex 把一条索引出队。
//
// 参数：
//
//	cmdID — 指令 ID
//
// 返回：
//
//	error — 删除失败时返回
func (t *Tx) DeletePendingIndex(cmdID string) error {
	return t.tx.Bucket(bPendIndex).Delete([]byte(cmdID))
}

// ScanPendingIndex 取出待重发队列，返回 "commandID → 内容" 的映射。
//
// 值会先拷贝一份再返回，避免指向 bbolt 内部缓冲区。limit > 0 时按键升序只取前 limit 条。
//
// 参数：
//
//	limit — 最多返回条数；<= 0 表示不限制
//
// 返回：
//
//	map[string][]byte — 键为 commandID，值为对应内容（副本）
func (t *Tx) ScanPendingIndex(limit int) map[string][]byte {
	out := map[string][]byte{}
	_ = t.tx.Bucket(bPendIndex).ForEach(func(k, v []byte) error {
		cp := make([]byte, len(v))
		copy(cp, v)
		out[string(k)] = cp
		return nil
	})
	if limit > 0 && len(out) > limit {
		trimmed := map[string][]byte{}
		keys := make([]string, 0, len(out))
		for k := range out {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[:limit] {
			trimmed[k] = out[k]
		}
		return trimmed
	}
	return out
}

// ---------- 被驱逐子节点的指令体归档（3.7） ----------

// PutEvicted 归档一条被驱逐子节点的指令体。key = childID + "/" + commandID。
//
// 参数：
//
//	e — 归档条目；键取自它的 ChildId / CommandId 字段
//
// 返回：
//
//	error — 序列化失败或写入失败时返回
func (t *Tx) PutEvicted(e *pb.EvictedEntry) error {
	return putProto(t.tx.Bucket(bEvicted), k(e.ChildId, e.CommandId), e)
}

// GetEvicted 读取一条归档条目。
//
// 参数：
//
//	childID — 子节点 ID
//	cmdID   — 指令 ID
//
// 返回：
//
//	*pb.EvictedEntry — 命中的条目；未命中或反序列化失败时为 nil
//	bool             — 是否命中
func (t *Tx) GetEvicted(childID, cmdID string) (*pb.EvictedEntry, bool) {
	e, ok, err := getProto(t.tx.Bucket(bEvicted), k(childID, cmdID), &pb.EvictedEntry{})
	if err != nil {
		return nil, false
	}
	return e, ok
}

// DeleteEvicted 清除一条归档条目（该子节点回来对账成功后调用）。
//
// 参数：
//
//	childID — 子节点 ID
//	cmdID   — 指令 ID
//
// 返回：
//
//	error — 删除失败时返回
func (t *Tx) DeleteEvicted(childID, cmdID string) error {
	return t.tx.Bucket(bEvicted).Delete(k(childID, cmdID))
}

// ScanEvicted 遍历归档，返回全部条目。
//
// 返回：
//
//	[]*pb.EvictedEntry — 所有归档条目；反序列化失败的条目会被跳过
func (t *Tx) ScanEvicted() []*pb.EvictedEntry {
	var out []*pb.EvictedEntry
	_ = t.tx.Bucket(bEvicted).ForEach(func(_, v []byte) error {
		e := &pb.EvictedEntry{}
		if err := proto.Unmarshal(v, e); err == nil {
			out = append(out, e)
		}
		return nil
	})
	return out
}

// DeleteWatermark 删除一条子水位（驱逐条目超过归档保留期后回收）。
//
// 参数：
//
//	childID — 子节点 ID
//
// 返回：
//
//	error — 删除失败时返回
func (t *Tx) DeleteWatermark(childID string) error {
	return t.tx.Bucket(bWatermark).Delete([]byte(childID))
}

// ScanCommands 遍历指令记录，返回全部记录（指标 / 清理用）。
//
// 返回：
//
//	[]*pb.CommandRecord — 所有指令记录；反序列化失败的条目会被跳过
func (t *Tx) ScanCommands() []*pb.CommandRecord {
	var out []*pb.CommandRecord
	_ = t.tx.Bucket(bCommands).ForEach(func(_, v []byte) error {
		r := &pb.CommandRecord{}
		if err := proto.Unmarshal(v, r); err == nil {
			out = append(out, r)
		}
		return nil
	})
	return out
}

// ---------- 工具 ----------

// hasPrefix 判断字节切片 b 是否以 prefix 开头（等同于 bytes.HasPrefix）。
//
// 参数：
//
//	b      — 待检查的字节切片
//	prefix — 前缀
//
// 返回：
//
//	bool — 以 prefix 开头时为 true
func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// mkdir 递归创建目录；dir 为空或 "." 时什么也不做。
//
// 参数：
//
//	dir — 目录路径
//
// 返回：
//
//	error — 创建失败时返回
func mkdir(dir string) error {
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}
