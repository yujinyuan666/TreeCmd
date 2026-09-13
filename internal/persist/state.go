// Package persist 负责运行时状态文件 state.dat 的读写。
// 硬约束（6.1 / 6.3）：只有程序写它；写临时文件 → fsync → rename 覆盖，保证原子。
package persist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// KnownChild 只留静态信息（id / path / name / remark / caps / labels），
// 供启动预热注册表并标记为未确认（6.2）。凡"会变的事实"一律以 bbolt 为准：
// LastSeenAt / last_epoch / status 都不在这里。
type KnownChild struct {
	ID         string            `json:"id"`
	Path       string            `json:"path"`
	Name       string            `json:"name,omitempty"`   // 节点名（ADR-051；旧快照无此字段 → 空值，向后兼容）
	Remark     string            `json:"remark,omitempty"` // 节点备注（ADR-051）
	Caps       []string          `json:"caps,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	TagSummary []string          `json:"tag_summary,omitempty"`
}

// Self 本节点静态身份快照。
type Self struct {
	ID        string   `json:"id"`
	Path      string   `json:"path"`
	Ancestors []string `json:"ancestors"`
}

// Session 会话信息（epoch 只随"本节点新建会话"变，故放这里）。
type Session struct {
	ParentID  string `json:"parent_id"`
	SessionID string `json:"session_id"`
	Epoch     uint64 `json:"epoch"`
	MsgSeq    uint64 `json:"msg_seq"`
}

// Watermarks 水位观测快照（retention_floor 与 next_cmd_seq 均为快照，权威值在 bbolt）。
type Watermarks struct {
	LastCmdSeq     int64 `json:"last_cmd_seq"`
	NextCmdSeq     int64 `json:"next_cmd_seq"`
	RetentionFloor int64 `json:"retention_floor"`
}

// State state.dat 的内容。
type State struct {
	SavedAt            string       `json:"saved_at"`
	ConfigHash         string       `json:"config_hash"`
	Self               Self         `json:"self"`
	Session            Session      `json:"session"`
	Watermarks         Watermarks   `json:"watermarks"`
	ClockOffsetMS      int64        `json:"clock_offset_ms"`
	OffsetCalibratedAt string       `json:"offset_calibrated_at"`
	KnownChildren      []KnownChild `json:"known_children"`
}

// Load 读取 state.dat 并解析成 State。
//
// 文件不存在、或内容是坏 JSON 时都返回 nil（调用方据此回退到全量注册），不报错、不 panic。
//
// 参数：
//
//	path — state.dat 的路径
//
// 返回：
//
//	*State — 解析出的状态；读不到或解析失败时为 nil
func Load(path string) *State {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	s := &State{}
	if err := json.Unmarshal(b, s); err != nil {
		return nil
	}
	return s
}

// Save 原子地把 State 写进 state.dat。
//
// "原子"指三步：先写 path+".tmp" 并 fsync 强制刷盘 → 再 rename 覆盖到目标路径。
// 这样即使进程在写一半时崩溃，目标文件要么还是旧的完整内容、要么是新的完整内容，
// 不会留下半截文件。另外：SavedAt 为空时自动填当前 UTC 时间；父目录不存在会自动创建；
// 临时文件权限为 0600。
//
// 参数：
//
//	path — state.dat 的路径
//	s    — 要写入的状态；SavedAt 为空时会被就地填上当前时间（会修改入参）
//
// 返回：
//
//	error — 建目录 / 序列化 / 写文件 / fsync / rename 任一步失败时返回
func Save(path string, s *State) error {
	if s.SavedAt == "" {
		s.SavedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename state: %w", err)
	}
	return nil
}
