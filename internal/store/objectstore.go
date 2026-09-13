// 对象存储：本地文件系统实现（对应方案 3.13 / 3.14 的第三级"退化对象存储引用"）。
//
// 目录结构：<dir>/<sha256 前 2 位>/<sha256 全量>
// 写入走"临时文件 → fsync → rename"，读取时校验摘要，get 不到或摘要不符即报错。
//
// 也就是说每个对象的内容决定了它的路径（按摘要寻址），同一份内容无论写多少次都落在同一个文件里；
// 前 2 位做一级子目录，是为了避免所有文件挤在同一个目录里。
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ObjectStore 本地文件系统对象存储。
type ObjectStore struct {
	dir string
}

// NewObjectStore 打开（或创建）对象存储目录。
//
// 参数：
//
//	dir — 对象存储根目录；传空字符串视为配置错误
//
// 返回：
//
//	*ObjectStore — 句柄，后续用它 Put / Get 对象
//	error        — dir 为空或建目录失败时返回
func NewObjectStore(dir string) (*ObjectStore, error) {
	if dir == "" {
		return nil, errors.New("object store dir is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &ObjectStore{dir: dir}, nil
}

// Dir 返回对象存储根目录。
func (o *ObjectStore) Dir() string { return o.dir }

// Put 把一个对象写入文件系统，返回它的引用路径和摘要。
//
// 流程：算 sha256 → 拼出相对路径 ref（前 2 位 / 全量摘要）→ 若已存在则直接返回 →
// 否则先写临时文件并 fsync，再 rename 到目标路径。rename 是原子的，
// 所以读到的文件要么不存在、要么内容完整，不会看到半截数据。
// 因为路径由内容摘要决定，相同内容重复写入是幂等的。
//
// 参数：
//
//	b — 对象内容（本项目里是超过 64MB 的大结果等二进制数据）
//
// 返回：
//
//	string — 引用路径 ref，形如 "ab/abcdef...（64 位十六进制）"，可作为 Get / Has 的入参
//	[]byte — 内容摘要（sha256 原始字节，32 字节）
//	error  — 建目录、写文件、fsync 或 rename 失败时返回
func (o *ObjectStore) Put(b []byte) (string, []byte, error) {
	sum := sha256.Sum256(b)
	hexSum := hex.EncodeToString(sum[:])
	ref := hexSum[:2] + "/" + hexSum
	dst := filepath.Join(o.dir, ref)
	if _, err := os.Stat(dst); err == nil {
		return ref, sum[:], nil // 已存在，内容一致（按摘要寻址天然幂等）
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return "", nil, err
	}
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", nil, err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return "", nil, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		return "", nil, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return "", nil, err
	}
	return ref, sum[:], nil
}

// Get 按引用路径取回对象，并重新计算摘要与路径中的摘要比对。
//
// 参数：
//
//	ref — Put 返回的引用路径，形如 "ab/abcdef..."
//
// 返回：
//
//	[]byte — 对象内容
//	error  — ref 非法（为空或含 ".."）、文件读不到、或摘要对不上时返回
func (o *ObjectStore) Get(ref string) ([]byte, error) {
	if ref == "" || strings.Contains(ref, "..") {
		return nil, fmt.Errorf("invalid object ref %q", ref)
	}
	b, err := os.ReadFile(filepath.Join(o.dir, ref))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if want := filepath.Base(ref); want != hex.EncodeToString(sum[:]) {
		return nil, fmt.Errorf("object %s digest mismatch", ref)
	}
	return b, nil
}

// Has 判断给定引用路径对应的对象文件是否存在。
//
// 参数：
//
//	ref — 引用路径；为空时直接返回 false
//
// 返回：
//
//	bool — 文件存在为 true
func (o *ObjectStore) Has(ref string) bool {
	if ref == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(o.dir, ref))
	return err == nil
}

// Cleanup 按"最近访问时间"回收对象，删除 mtime 早于保留期的文件。
//
// 说明：这里只是按文件修改时间粗略判断，并没有真正读取访问时间。
//
// 参数：
//
//	retentionSeconds — 保留期（秒）；<= 0 时不做任何回收，直接返回 0
//
// 返回：
//
//	int — 实际删除成功的文件个数
func (o *ObjectStore) Cleanup(retentionSeconds int64) int {
	if retentionSeconds <= 0 {
		return 0
	}
	now := time.Now().Unix()
	removed := 0
	_ = filepath.Walk(o.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		if now-info.ModTime().Unix() > retentionSeconds {
			if os.Remove(path) == nil {
				removed++
			}
		}
		return nil
	})
	return removed
}
