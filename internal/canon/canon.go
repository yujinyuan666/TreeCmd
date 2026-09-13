// Package canon 提供"确定性编码"工具：所有摘要 / 签名一律对 canonical 编码取，
// 并按方案 7.5 的规则对 repeated 结构显式排序（按 NodeID 的 16 字节大端升序）。
package canon

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"treecmd/internal/identity"
	"treecmd/internal/pb"
)

// Deterministic 是 protobuf 的确定性序列化（字段按序号、无 map 序随机化）。
var Deterministic = proto.MarshalOptions{Deterministic: true}

// Bytes 把 protobuf 消息序列化成确定性的（canonical）字节串。
//
// 参数：
//
//	m — 任意 protobuf 消息；传 nil 接口时直接返回 nil 字节 + nil 错误，不报错
//
// 返回：
//
//	[]byte — canonical 编码结果；m 为 nil 时是 nil
//	error  — 编码失败时返回，正常路径不会出现
func Bytes(m proto.Message) ([]byte, error) { return Deterministic.Marshal(m) }

// Digest 先做 canonical 编码，再对编码字节取 SHA-256 摘要。
//
// 摘要一律取 canonical 字节，是为了让同一份语义内容在任何节点上算出同一个值。
//
// 参数：
//
//	m — 任意 protobuf 消息；序列化规则同 Bytes
//
// 返回：
//
//	[]byte — 32 字节 SHA-256 摘要
//	error  — canonical 编码失败时返回
func Digest(m proto.Message) ([]byte, error) {
	b, err := Bytes(m)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// DigestBytes 把任意多段字节按"长度前缀"拼接后取 SHA-256 摘要。
//
// 每段先写 8 字节大端长度、再写内容。加长度前缀是为了让分段边界参与摘要：
// 否则 ["ab","c"] 与 ["a","bc"] 拼出来一样，摘要会撞上。
//
// 参数：
//
//	b — 若干段待摘要的字节；一段都不传时等价于对空输入取摘要
//
// 返回：
//
//	[]byte — 32 字节 SHA-256 摘要
func DigestBytes(b ...[]byte) []byte {
	h := sha256.New()
	for _, x := range b {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(x)))
		h.Write(l[:])
		h.Write(x)
	}
	return h.Sum(nil)
}

// SortAttests 就地递归排序证明列表：先把每个节点的 Descendants 排好，再排本层。
//
// 排序键是 NodeID 的 16 字节大端值（identity.NodeIDLess），不是十六进制字符串字典序 ——
// 两者在大小写、前导零下结果可能不同。必须先递归再排本层，整棵树才会全有序。
//
// 参数：
//
//	list — 待排序的证明列表；会被原地修改，调用方持有的 slice 内容随之改变
func SortAttests(list []*pb.ChildAttest) {
	for _, a := range list {
		if len(a.Descendants) > 0 {
			SortAttests(a.Descendants)
		}
	}
	sort.SliceStable(list, func(i, j int) bool { return identity.NodeIDLess(list[i].NodeId, list[j].NodeId) })
}

// TS 把 time.Time 转成 protobuf 的 Timestamp，零值转成 nil。
//
// 之所以要特判零值：timestamppb.New 不做范围校验，直接把零值时间写成纪元前很久的秒数，
// 那是个不合法的 Timestamp。这里用 nil 表示"没有这个时间"。
//
// 参数：
//
//	t — 任意时间；IsZero() 为 true 时返回 nil
//
// 返回：
//
//	*timestamppb.Timestamp — 转换结果；t 为零值时是 nil
func TS(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// Time 把 protobuf 的 Timestamp 转回 time.Time，nil 转成 time.Time 的零值。
//
// 参数：
//
//	ts — 待转换的时间戳；nil 时返回 time.Time{}
//
// 返回：
//
//	time.Time — 转换结果，时区是 UTC（AsTime 内部固定转 UTC）
//
// 注意：这里不做合法性校验，超范围的秒数会被 time.Unix 静默归一化。
func Time(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// Writer 用于非 proto 内容的确定性拼接（定长/长度前缀，见 7.5 的"降级"约定）。
//
// 字段 b 是已拼好的缓冲区。各写入方法都返回 Writer 自身，所以可以链式写：
// w.Str("a").I64(1).DigestOf()。它没有加锁，一个 Writer 只给一个 goroutine 用。
type Writer struct{ b []byte }

// NewWriter 创建一个空的拼接器。
//
// 返回：
//
//	*Writer — 内部缓冲区为空的新实例，可以直接开始链式写入
func NewWriter() *Writer { return &Writer{} }

// Str 写入一个字符串：先写 8 字节大端长度，再写它的 UTF-8 字节。
//
// 接收者 w 是累加中的缓冲区。
//
// 参数：
//
//	s — 要写入的字符串；空串也会写入一个长度为 0 的前缀
//
// 返回：
//
//	*Writer — w 本身，便于链式调用
func (w *Writer) Str(s string) *Writer { return w.Bytes([]byte(s)) }

// Bytes 写入一段字节串：先写 8 字节大端长度，再写内容。
//
// 接收者 w 是累加中的缓冲区。
//
// 参数：
//
//	b — 要写入的字节；nil 与空切片都只写一个长度为 0 的前缀
//
// 返回：
//
//	*Writer — w 本身，便于链式调用
func (w *Writer) Bytes(b []byte) *Writer {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(len(b)))
	w.b = append(w.b, l[:]...)
	w.b = append(w.b, b...)
	return w
}

// I64 写入一个定长有符号整数：8 字节大端补码，不写长度前缀。
//
// 接收者 w 是累加中的缓冲区。这里是"定长"写法 —— 长度天然是 8，所以不需要前缀。
//
// 参数：
//
//	v — 要写入的整数；按 uint64 的补码形式落盘，负数也能原样往返
//
// 返回：
//
//	*Writer — w 本身，便于链式调用
func (w *Writer) I64(v int64) *Writer {
	var l [8]byte
	binary.BigEndian.PutUint64(l[:], uint64(v))
	w.b = append(w.b, l[:]...)
	return w
}

// U64 写入一个定长无符号整数：8 字节大端，不写长度前缀。
//
// 接收者 w 是累加中的缓冲区。
//
// 参数：
//
//	v — 要写入的整数；内部转成 int64 后走 I64 的编码，位模式不变
//
// 返回：
//
//	*Writer — w 本身，便于链式调用
func (w *Writer) U64(v uint64) *Writer { return w.I64(int64(v)) }

// Bool 写入一个布尔值：true 写 1 字节 0x01，false 写 0x00。
//
// 接收者 w 是累加中的缓冲区。
//
// 参数：
//
//	v — 要写入的布尔值
//
// 返回：
//
//	*Writer — w 本身，便于链式调用
func (w *Writer) Bool(v bool) *Writer {
	if v {
		w.b = append(w.b, 1)
	} else {
		w.b = append(w.b, 0)
	}
	return w
}

// Out 返回当前已拼接的字节。
//
// 接收者 w 是累加中的缓冲区。
//
// 返回：
//
//	[]byte — 内部缓冲区本身（没有拷贝）；之后再调用写入方法会一并改变它
func (w *Writer) Out() []byte { return w.b }

// DigestOf 对当前已拼接的全部内容取 SHA-256 摘要。
//
// 接收者 w 是累加中的缓冲区。
//
// 返回：
//
//	[]byte — 32 字节 SHA-256 摘要；一段都没写过时就是空输入的摘要
func (w *Writer) DigestOf() []byte {
	sum := sha256.Sum256(w.b)
	return sum[:]
}
