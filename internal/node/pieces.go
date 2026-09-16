package node

// 镜像分片的本地缓存 —— "边收边转发"的地基（见 docs/四项外部经验借鉴方案.md §4）。
//
// 为什么需要它：没有片存时，子节点必须把整份镜像**收完 → 校验 → rename → exec 重启**
// 之后才可能给它的直接子供片（serveBinary 读的是"本节点启动时那份磁盘文件"）。
// 于是收敛是**逐层串行**的：总时间 ≈ 层数 × 单层时间。
// 有了片存，中继在**还没收完、还没重启**的时候就能把已经收到并验证过的片转发给下级，
// 收敛从"逐层串行"变成"流水线"。
//
// 三条硬约束（都是**安全边界**，不是性能优化）：
//
//  1. **只有通过片级 sha256 校验的片才允许入存。** 分片帧上的 crc32 只能查传输损坏，
//     拿它当"可信"会让中继把内容未经验证的片转发出去。所以入存的前提是先拿到父的
//     BinaryManifest（片级 sha256 清单）。
//  2. **只按清单里的片号取片**（Get 只接受 index），绝不接受任意 offset ——
//     否则片存就是一个任意文件读取的口子。
//  3. 目录权限 0700、按目标哈希分目录：不同镜像的片绝不混放。
//
// 落盘布局（都在 <selfupdate 暂存目录>/pieces/ 下）：
//
//	<hash 前 12 位>/manifest          清单本身（proto 序列化），供本节点再向下转发
//	<hash 前 12 位>/piece-<零填充序号> 单片内容
//
// 片存是**可丢的缓存**：删掉只会让下次从 0 重来，不影响正确性，也不参与
// state.dat 的自更新尝试计数（防重启循环那套逻辑与它无关）。

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"treecmd/internal/pb"
)

// piecesDirName 片存在暂存目录下的子目录名。
const piecesDirName = "pieces"

// pieceProgressOf 取本节点片存的进度快照（供 TreeSnapshot；节点未启用片存时返回 nil）。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	[]pieceProgress — 进度列表；片存未启用时返回 nil
func (n *Node) pieceProgress() []pieceProgress {
	return n.pieces.Summary()
}

// pieceStore 某节点上的镜像分片缓存。
//
// **必须按节点隔离**：片存根目录里带本节点的**完整** ID（见 pieceStoreDir）。原因不是洁癖 ——
// `selfupdate.dir` 缺省取"可执行文件所在目录"，而多个节点的可执行文件**完全可以同处一目录**
// （测试里都在 `.selfupdate/bin`，生产里都可能在 `/usr/local/bin`）。若只按目标哈希分目录，
// A 节点下载的片会被 B 节点当成"我已经有了"。这是端到端测试抓出来的真实故障。
//
// 字段说明：
//
//	dir       — 片存根目录（<selfupdate 暂存目录>/pieces/<本节点 ID 短形式>）
//	maxBytes  — 整个片存的字节上限，超过就按最近使用时间清理（<=0 表示不限制）
//	mu        — 保护 manifests
//	manifests — 目标哈希 → 清单的内存缓存。丢了不要紧：可以从磁盘上那份 manifest 重新读，
//	            也可以（在本节点自己就是标准答案时）从本地镜像现算
type pieceStore struct {
	dir      string
	maxBytes int64

	mu        sync.Mutex
	manifests map[string]*pb.BinaryManifest
}

// pieceStoreDir 算出某个节点的片存根目录。
//
// ⚠️ **必须用完整的 NodeID，不能用它的前缀。** NodeID 是 UUIDv7（时间有序）——开头若干位是
// 毫秒时间戳，**同一秒内启动的节点前缀完全相同**。用 `nodeID[:8]` 当目录名会让同批启动的节点
// 共用一个片存：A 下载到一半的片被 B 当成"我已经有了"，于是 B 拿着 `from_index=已有片数`
// 去申请，父端从那里开始发，B 端立刻报"第 N 片 sha256 校验不过"。
// 这是端到端测试抓出来的真实故障（leaf1 收敛、relay 失败，两个日志里的短 ID 一模一样）。
//
// 对比：片目录用的是**镜像内容哈希**的前 12 位（见 shortHashDir）——内容哈希不按时间排序，
// 取前缀当唯一键是安全的；而且万一真撞了，片级与整份 sha256 都会当场失败（fail-closed）。
//
// 参数：
//
//	stagingDir — selfupdate 的暂存目录（通常 = 可执行文件所在目录 or selfupdate.dir）
//	nodeID     — 本节点 NodeID（完整）
//
// 返回：
//
//	string — <stagingDir>/pieces/<完整 NodeID>
func pieceStoreDir(stagingDir, nodeID string) string {
	seg := nodeID
	if seg == "" {
		seg = "unknown-node"
	}
	return filepath.Join(stagingDir, piecesDirName, seg)
}

// newPieceStore 建一个片存并把根目录准备好（权限 0700）。
//
// 参数：
//
//	dir      — 片存根目录；空串表示不启用（返回 nil）
//	maxBytes — 字节上限，<=0 表示不限制
//
// 返回：
//
//	*pieceStore — 可用的片存；dir 为空时返回 nil（调用方需判空）
//	error       — 建目录失败时返回
func newPieceStore(dir string, maxBytes int64) (*pieceStore, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("建片存目录 %s: %w", dir, err)
	}
	return &pieceStore{dir: dir, maxBytes: maxBytes, manifests: map[string]*pb.BinaryManifest{}}, nil
}

// shortHashDir 取哈希用于目录名的短形式（去掉 "sha256:" 前缀后前 12 位）。
//
// 参数：
//
//	hash — "sha256:xxxx…" 形式的哈希
//
// 返回：
//
//	string — 目录名；哈希为空或过短时返回 "unknown"
func shortHashDir(hash string) string {
	s := hash
	if i := indexOfColon(s); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 12 {
		s = s[:12]
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// dirFor 返回某个目标哈希对应的片目录（不建目录）。
//
// 接收者 s 是片存。
//
// 参数：
//
//	hash — 目标镜像的整份哈希
//
// 返回：
//
//	string — 该哈希的片目录绝对路径；片存未启用（s 为 nil）时返回空串
func (s *pieceStore) dirFor(hash string) string {
	if s == nil {
		return ""
	}
	return filepath.Join(s.dir, shortHashDir(hash))
}

// PutManifest 记住某份镜像的片清单（先内存、再尽力落盘）。
//
// 落盘的意义：本节点重启后仍能把它转发给下级（不必重新读一遍自己的镜像算哈希）。
// 落盘失败不算错——内存里还有，只是重启后要重算。
//
// 接收者 s 是片存。
//
// 参数：
//
//	hash — 目标镜像的整份哈希
//	m    — 清单
//
// 返回：
//
//	error — 建目录失败时返回；写文件失败只记在返回值里但不影响内存缓存
func (s *pieceStore) PutManifest(hash string, m *pb.BinaryManifest) error {
	if s == nil || m == nil {
		return nil
	}
	s.mu.Lock()
	s.manifests[hash] = m
	s.mu.Unlock()
	dir := s.dirFor(hash)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := proto.Marshal(m)
	if err != nil {
		return fmt.Errorf("序列化清单: %w", err)
	}
	return writeFileAtomic(filepath.Join(dir, "manifest"), b, 0o600)
}

// Manifest 取某份镜像的片清单：先查内存，再读磁盘，都没有就返回 nil。
//
// 接收者 s 是片存。
//
// 参数：
//
//	hash — 目标镜像的整份哈希
//
// 返回：
//
//	*pb.BinaryManifest — 清单；取不到时返回 nil（调用方应回退到"自己现算"或老流程）
func (s *pieceStore) Manifest(hash string) *pb.BinaryManifest {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	m := s.manifests[hash]
	s.mu.Unlock()
	if m != nil {
		return m
	}
	b, err := os.ReadFile(filepath.Join(s.dirFor(hash), "manifest"))
	if err != nil {
		return nil
	}
	out := &pb.BinaryManifest{}
	if err := proto.Unmarshal(b, out); err != nil {
		return nil
	}
	s.mu.Lock()
	s.manifests[hash] = out
	s.mu.Unlock()
	return out
}

// pieceFileName 某一片在片目录里的文件名（序号零填充，便于排序与肉眼核对）。
//
// 参数：
//
//	index — 片号
//
// 返回：
//
//	string — 文件名，如 "piece-0007"
func pieceFileName(index int32) string {
	return fmt.Sprintf("piece-%08d", index)
}

// Put 把**已经通过 sha256 校验**的一片落盘（原子写：临时文件 + rename）。
//
// 接收者 s 是片存。调用方必须在调用前完成校验 —— 本函数不做任何校验。
//
// 参数：
//
//	hash  — 目标镜像的整份哈希
//	index — 片号
//	data  — 片内容（已校验）
//
// 返回：
//
//	error — 建目录或写盘失败时返回
func (s *pieceStore) Put(hash string, index int32, data []byte) error {
	if s == nil {
		return nil
	}
	dir := s.dirFor(hash)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, pieceFileName(index)), data, 0o600)
}

// Get 按**片号**取一片。
//
// 接收者 s 是片存。这是片存唯一的读取入口，**故意不接受 offset**：
// 只按清单里的片号取，才不会被当成任意文件读取的口子用（见文件头第 2 条）。
//
// 参数：
//
//	hash  — 目标镜像的整份哈希
//	index — 片号
//
// 返回：
//
//	[]byte — 片内容
//	bool   — 没这一片时为 false
func (s *pieceStore) Get(hash string, index int32) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(s.dirFor(hash), pieceFileName(index)))
	if err != nil {
		return nil, false
	}
	return b, true
}

// Have 报告某份镜像的片是否已经**集齐**。
//
// 接收者 s 是片存。
//
// 参数：
//
//	hash  — 目标镜像的整份哈希
//	total — 总片数
//
// 返回：
//
//	bool — total > 0 且 0..total-1 每一片都在时为 true
func (s *pieceStore) Have(hash string, total int32) bool {
	if s == nil || total <= 0 {
		return false
	}
	return s.Prefix(hash) >= total
}

// Prefix 返回从第 0 片起**连续存在**的片数 —— 断点续传的起点。
//
// 接收者 s 是片存。只算"从 0 开始的连续前缀"：中间缺一片的话，后面那些片对拼装没用，
// 所以不能简单用"有几片"来当续传起点。
//
// 参数：
//
//	hash — 目标镜像的整份哈希
//
// 返回：
//
//	int32 — 连续前缀长度（0 表示一片都没有 / 第 0 片就缺）
func (s *pieceStore) Prefix(hash string) int32 {
	if s == nil {
		return 0
	}
	entries, err := os.ReadDir(s.dirFor(hash))
	if err != nil {
		return 0
	}
	have := map[int32]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "piece-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "piece-"))
		if err != nil {
			continue
		}
		have[int32(n)] = true
	}
	var n int32
	for have[n] {
		n++
	}
	return n
}

// Assemble 把片存里的 0..total-1 逐片写进 dst，同时喂给 h（供调用方做整份校验）。
//
// 接收者 s 是片存。调用方必须先确认 Have(hash, total) 为真，否则会返回缺片错误。
//
// 之所以"最后统一拼装"而不是"边收边追加到暂存文件"：断点续传时前半段只存在于片存里，
// 暂存文件里没有，追加会得到一个内容错位的文件。统一拼装让两条路径（全新下载 / 续传）
// 走同一段代码，也就不会有"续传后文件不对"这种最难查的问题。
//
// 参数：
//
//	hash   — 目标镜像的整份哈希
//	total  — 总片数
//	dst    — 目标写入器（暂存文件）
//	digest — 边写边喂的哈希器（调用方用来做整份 sha256 校验）
//
// 返回：
//
//	int64 — 写出的字节数
//	error — 缺片 / 读片失败 / 写失败时返回
func (s *pieceStore) Assemble(hash string, total int32, dst io.Writer, digest hash.Hash) (int64, error) {
	var n int64
	for i := int32(0); i < total; i++ {
		b, ok := s.Get(hash, i)
		if !ok {
			return n, fmt.Errorf("拼装缺片: hash=%s index=%d", shortHashDir(hash), i)
		}
		if digest != nil {
			digest.Write(b)
		}
		w, err := dst.Write(b)
		n += int64(w)
		if err != nil {
			return n, fmt.Errorf("写暂存文件失败（片 %d）: %w", i, err)
		}
	}
	return n, nil
}

// Evict 按"最近使用时间"清理片存，把总占用压到 maxBytes 以内。
//
// 接收者 s 是片存。maxBytes <= 0 时什么都不做。清理是**尽力而为**：
// 删不掉的文件（权限等）跳过，绝不因为清理失败影响正在进行的同步。
//
// 返回：
//
//	int — 删掉的文件数（仅用于日志）
func (s *pieceStore) Evict() int {
	if s == nil || s.maxBytes <= 0 {
		return 0
	}
	type item struct {
		path string
		size int64
		at   time.Time
	}
	var all []item
	var total int64
	_ = filepath.Walk(s.dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.IsDir() {
			return nil
		}
		all = append(all, item{path: p, size: fi.Size(), at: fi.ModTime()})
		total += fi.Size()
		return nil
	})
	if total <= s.maxBytes {
		return 0
	}
	// 最旧的先删
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	removed := 0
	for _, it := range all {
		if total <= s.maxBytes {
			break
		}
		if err := os.Remove(it.path); err != nil {
			continue
		}
		total -= it.size
		removed++
	}
	return removed
}

// pieceProgressOf 取本节点片存的进度快照（供 TreeSnapshot；节点未启用片存时返回 nil）。
//
// pieceProgress 片存里某一份镜像的进度快照（供 /v1/tree 展示"流水线跑到哪了"）。
type pieceProgress struct {
	// Hash 目标镜像的整份哈希
	Hash string `json:"hash"`
	// Have 从第 0 片起**连续存在**的片数（断点续传的起点就是它）
	Have int32 `json:"have"`
	// Total 清单里的总片数；0 = 还没有清单（此时 Have 仍然有效，只是没有分母）
	Total int32 `json:"total"`
	// Bytes 该目标哈希占用的片存字节数
	Bytes int64 `json:"bytes"`
	// Ready 片已集齐（可以对外供片、也可以拼装成完整镜像）
	Ready bool `json:"ready"`
}

// Summary 汇总片存里每一份镜像的进度（只读，供 /v1/tree 与日志展示）。
//
// 接收者 s 是片存。
//
// 返回：
//
//	[]pieceProgress — 按哈希排序的进度列表；片存未启用或为空时返回 nil
func (s *pieceStore) Summary() []pieceProgress {
	if s == nil {
		return nil
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var out []pieceProgress
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(s.dir, e.Name())
		p := pieceProgress{}
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var bytesOnDisk int64
		for _, f := range files {
			if f.IsDir() {
				continue
			}
			info, err := f.Info()
			if err != nil {
				continue
			}
			bytesOnDisk += info.Size()
			if f.Name() == "manifest" {
				if m := s.ManifestByDir(dir); m != nil {
					p.Hash, p.Total = m.GetHash(), int32(len(m.GetPieceSha256()))
				}
			}
		}
		p.Bytes = bytesOnDisk
		// 目录名是哈希的短形式，拿不到清单时至少把它当标识，别让这一项看起来像空的
		if p.Hash == "" {
			p.Hash = e.Name()
		}
		p.Have = s.Prefix(p.Hash)
		p.Ready = p.Total > 0 && p.Have >= p.Total
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out
}

// ManifestByDir 从某个片目录直接读清单（Summary 用：它手上只有目录名这个短哈希，
// 而内存 / 磁盘的清单键是完整的 "sha256:…" 哈希，对不上）。
//
// 接收者 s 是片存。
//
// 参数：
//
//	dir — 片目录的绝对路径
//
// 返回：
//
//	*pb.BinaryManifest — 清单；读不到或解析失败时返回 nil
func (s *pieceStore) ManifestByDir(dir string) *pb.BinaryManifest {
	if s == nil {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifest"))
	if err != nil {
		return nil
	}
	m := &pb.BinaryManifest{}
	if err := proto.Unmarshal(b, m); err != nil {
		return nil
	}
	return m
}

// writeFileAtomic 原子写一个小文件：同目录临时文件 → sync → rename。
//
// 参数：
//
//	path — 目标路径
//	data — 内容
//	mode — 权限位
//
// 返回：
//
//	error — 建目录 / 建临时文件 / 写 / rename 失败时返回
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// pieceDigest 计算一片的 sha256（与父端清单里的 piece_sha256 同一口径）。
//
// 参数：
//
//	data — 片内容
//
// 返回：
//
//	[]byte — 32 字节摘要
func pieceDigest(data []byte) []byte {
	d := sha256.Sum256(data)
	return d[:]
}
