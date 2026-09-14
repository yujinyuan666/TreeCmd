package node

// 可执行文件一致性：启动时算自己的哈希、连上后第一件事与父比对、不一致就拉取并原地重启。
//
// 与《架构方案》里其它机制的关系：这是一条**独立的辅助链路**，不参与指令分发、聚合、
// 背书链与租约的任何判定。它只回答一个问题 —— "我跑的是不是父在跑的那一份" —— 并在此之上
// 做一件很硬的事：不一致就换镜像重启。之所以值得这么做：树是"父下发、子执行"的，
// 子与父行为不一致的症状是"行为诡异"而不是"报错"，是最难排查的一类故障。
//
// 三条设计约束（决定了代码为什么长这样）：
//  1. **方向单向**：父永远是标准答案。子向父对齐 ⇒ 升级天然自上而下（根先换、逐层收敛），
//     而"把根换回旧版"就等于整棵树回滚，不需要逐台登录。
//  2. **一致路径零成本**：启动算一次哈希，之后每次注册只比一个字符串；不一致才动网络。
//  3. **fail-safe**：拉取 / 落盘 / 替换任一步失败，都保留当前镜像继续服务，绝不因为
//     "想升级"把在跑的节点弄挂。唯一的例外是"替换成功"这一条路径 —— 它必然重启。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"treecmd/internal/buildinfo"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/persist"
)

// initBuildInfo 计算本节点可执行文件的哈希，并把它放进**运行时配置**（cfg.Build）。
//
// 这是"启动时先算自己那份镜像的哈希"的落点。算不出来**不算致命**：只记 ERROR 与指标，
// 之后所有一致性判定都自动降级为"不做判定"（宁可不管，也不能因为读不到自己的文件就拒绝启动）。
//
// 若入口（`-check` / `-enroll`）已经算过并填进配置，这里直接采用，不重复读盘。
//
// 接收者 n 是刚装配好、尚未启动的节点。配置里的 Build 字段是 yaml:"-" 的运行时字段，
// 不来自 node.yaml、不进 config_hash、也不落盘 —— 所以"把哈希放进配置"并不违反
// "绝不回写 node.yaml"（ADR-005）。
func (n *Node) initBuildInfo() {
	cfg := n.C()
	if cfg.Build.Path != "" {
		n.selfBuild = cfg.Build
		return
	}
	info, err := buildinfo.Compute()
	n.selfBuild = info
	cfg.Build = info
	if err != nil {
		n.Log.Error("算不出本节点可执行文件的哈希：可执行文件一致性检查将不生效", "err", err, "path", info.Path)
		n.Metrics.Inc("selfupdate_total", "result", "self_unknown")
		return
	}
	n.Log.Info("本节点可执行文件", "hash", info.Short(), "bytes", info.Size,
		"version", info.Version, "path", info.Path)
}

// Build 返回本节点可执行文件的身份快照。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	buildinfo.Info — **启动那一刻**算出来的快照；磁盘上的文件后来被换掉也不会改变它
//	                 （所以要对外发文件之前必须用 buildinfo.SameAsDisk 复验）
func (n *Node) Build() buildinfo.Info { return n.selfBuild }

// buildForAck 组装注册应答里那三项：父自己那份镜像的哈希 / 字节数 / 签名。
//
// 签名绑住 (父 NodeID, 哈希, 字节数) 三样东西，子端用父的证书公钥离线验签。
// 为什么在 mTLS 之上还要签名：注册应答里没有整体签名，而"子据此换掉自己的可执行文件"
// 这件事值得一次显式的承诺 —— 代价只有一次 Ed25519 签名。
//
// 接收者 n 是本节点（父）。
//
// 返回：
//
//	string — 哈希；算不出来时为空串（子端据此跳过检查）
//	int64  — 字节数
//	[]byte — 身份密钥对 (NodeID, 哈希, 字节数) 的签名；没有哈希时为 nil
func (n *Node) buildForAck() (string, int64, []byte) {
	info := n.Build()
	if !info.Known() {
		return "", 0, nil
	}
	sig := identity.Sign(n.Id().Key, buildinfo.SigPayload(n.C().Node.ID, info.Hash, info.Size))
	return info.Hash, info.Size, sig
}

// ---------- 子端：连上后的第一件事 ----------

// checkParentBuild 在注册应答之后、起心跳与拉取循环之前，比对两边的可执行文件哈希。
//
// 这个位置就是"子节点连上来之后的第一件事"的字面落点：此刻本节点还**没有执行过**
// 父下发的任何指令（工作队列的拉取循环尚未启动），所以"镜像不对就先别干活"成立。
//
// 三种结局：
//   - 一致：记一条 debug 日志，顺手清掉上次同步的尝试痕迹（说明那次同步确实成功了）；
//   - 不一致 + on_mismatch=sync：向父拉取、校验、原地重启 —— **成功路径本函数不会返回**；
//   - 不一致 + on_mismatch=warn（或开关关掉、或已被防循环锁扣住）：只记日志与指标，继续服务。
//
// 接收者 n 是本节点（子）。本函数只应在上行会话刚注册成功时被调用一次。
//
// 参数：
//
//	u      — 本节点当前的上行侧（从中取父的身份与公钥，用于验签）
//	frames — 本次会话的唯一读协程吐出的帧通道；同步阶段由本函数消费（见 pullBinary）
//	ack    — 父的注册应答，其中 server_binary_* 三项是本函数要看的东西
func (n *Node) checkParentBuild(u *Upstream, frames <-chan recvResult, ack *pb.RegisterAck) {
	cfg := n.C()
	mine := n.Build()
	parentHash := ack.GetServerBinaryHash()
	if parentHash == "" {
		// 父是旧版本（或父算不出自己的哈希）：没有可比的东西，静默跳过
		n.Log.Debug("父未在注册应答里给出可执行文件哈希，跳过一致性检查")
		n.Metrics.Inc("selfupdate_total", "result", "unknown")
		return
	}
	if !mine.Known() {
		n.Log.Error("本节点算不出自己的可执行文件哈希，无法与父比对", "path", mine.Path)
		n.Metrics.Inc("selfupdate_total", "result", "self_unknown")
		return
	}
	if mine.Hash == parentHash {
		n.Log.Debug("可执行文件与父一致", "hash", mine.Short())
		n.Metrics.Inc("selfupdate_total", "result", "match")
		n.clearSelfUpdateStamp(mine.Hash)
		return
	}

	n.Metrics.Inc("selfupdate_total", "result", "mismatch")
	pid, _ := u.parentIdentity()
	n.Log.Warn("可执行文件与父不一致",
		"self", mine.Short(), "self_path", mine.Path,
		"parent", shortHash(parentHash), "parent_id", shortID(pid))

	if !cfg.SelfUpdate.SelfUpdateEnabled() {
		n.Log.Warn("selfupdate 已关闭，只报不做（可执行文件版本不一致）")
		n.Metrics.Inc("selfupdate_total", "result", "disabled")
		return
	}
	if !cfg.SelfUpdate.EnforceSync() {
		n.Log.Warn("selfupdate.on_mismatch=warn：只告警、不重启（要看效果先观察一轮时用）")
		n.Metrics.Inc("selfupdate_total", "result", "warned")
		return
	}

	// 验父的承诺：必须能对上 (父 ID, 哈希, 大小)。宁可不升级，也不接受一个来路不明的镜像。
	if err := n.verifyParentBuild(u, ack); err != nil {
		n.Log.Error("父给的镜像承诺验不过，放弃本次自同步", "err", err)
		n.Metrics.Inc("selfupdate_total", "result", "bad_sig")
		return
	}
	if !n.selfUpdateAllowed(parentHash) {
		n.Metrics.Inc("selfupdate_total", "result", "locked")
		return
	}
	n.syncAndRestart(u, frames, parentHash, ack.GetServerBinarySize())
}

// verifyParentBuild 校验父在注册应答里对"镜像哈希 + 大小"给出的身份密钥签名。
//
// 接收者 n 是本节点（子）。
//
// 参数：
//
//	u   — 上行侧：提供父的 NodeID 与证书公钥（握手时已从对端证书取得）
//	ack — 注册应答，含 server_binary_hash / server_binary_size / server_binary_sig
//
// 返回：
//
//	error — 拿不到父公钥 / 签名缺失 / 验签不通过时返回
func (n *Node) verifyParentBuild(u *Upstream, ack *pb.RegisterAck) error {
	pid, ppub := u.parentIdentity()
	if pid == "" || len(ppub) == 0 {
		return errors.New("拿不到父的身份公钥（握手信息缺失）")
	}
	sig := ack.GetServerBinarySig()
	if len(sig) == 0 {
		return errors.New("父没有对镜像哈希签名")
	}
	payload := buildinfo.SigPayload(pid, ack.GetServerBinaryHash(), ack.GetServerBinarySize())
	if !identity.Verify(ppub, payload, sig) {
		return fmt.Errorf("签名不验证：父 %s 对 %s 的承诺对不上", shortID(pid), shortHash(ack.GetServerBinaryHash()))
	}
	return nil
}

// selfUpdateAllowed 判断"现在还能不能再试一次同步"，并把这次尝试记进盘上的痕迹。
//
// 这是**防重启循环的唯一闸门**。为什么必须有它：镜像被 exec 替换后进程内的状态全丢，
// 一旦出现"换完还是对不上"（只读目录、rename 失败、被别的东西又换回来…），
// 就会变成"连上 → 拉取 → 重启 → 连上"的死循环。所以：
//   - 计数**先落盘再动作**（中途崩溃也算一次）；
//   - 同一个目标哈希在一个时间窗口内最多 AttemptLimit 次，超了就锁住并告警；
//   - 窗口一过计数清零（给"当时磁盘满了、后来修好了"留一条自愈的路）。
//
// 接收者 n 是本节点（子）。
//
// 参数：
//
//	target — 本次要追的目标哈希（= 父的镜像）
//
// 返回：
//
//	bool — true 表示允许发起本次尝试（且计数已 +1 落盘）；false 表示已锁住，不要动
func (n *Node) selfUpdateAllowed(target string) bool {
	su := &n.C().SelfUpdate
	limit, window := su.AttemptLimit(), su.Window()
	now := time.Now()
	n.stateMu.Lock()
	st := &n.state.SelfUpdate
	stale := true
	if st.TargetHash == target && st.Attempts > 0 && st.FirstAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, st.FirstAt); err == nil {
			stale = now.Sub(t) > window
		}
	}
	if stale {
		// 换了目标、或窗口过了：重新开一轮
		st.TargetHash = target
		st.Attempts = 0
		st.FirstAt = now.UTC().Format(time.RFC3339Nano)
	}
	if st.Attempts >= limit {
		// 窗口内已经用满：**计数保持不动**（不清零、不推进），所以本窗口内的后续调用
		// 都会被挡在这里；等窗口过去，上面那段 stale 判定才会重新开一轮。
		first := st.FirstAt
		unlock := "?"
		if t, err := time.Parse(time.RFC3339Nano, first); err == nil {
			unlock = t.Add(window).Format("15:04:05")
		}
		n.stateMu.Unlock()
		n.Log.Error("同一个目标镜像已尝试太多次，本窗口内不再自同步（防重启循环）",
			"target", shortHash(target), "attempts", limit, "window", window.String(),
			"first_at", first, "retry_after", unlock)
		return false
	}
	st.Attempts++
	st.LastAt = now.UTC().Format(time.RFC3339Nano)
	attempt := st.Attempts
	n.stateMu.Unlock()
	n.saveState()
	n.Log.Info("开始自同步（镜像与父不一致）", "attempt", attempt, "limit", limit,
		"target", shortHash(target), "state", n.C().Persist.StatePath)
	return true
}

// clearSelfUpdateStamp 清掉盘上的同步尝试痕迹。
//
// 接收者 n 是本节点（子）。只在"本节点当前哈希 == 父的哈希"时被调用 ——
// 它同时承担两个语义：① 上一次自同步确实成功了（换了镜像、重启后终于对上了）；
// ② 本节点本来就和父一致，没有欠账。没有痕迹时什么都不做（不会每次都写盘）。
//
// 参数：
//
//	mineHash — 本节点当前的镜像哈希（仅用于日志）
func (n *Node) clearSelfUpdateStamp(mineHash string) {
	n.stateMu.Lock()
	st := &n.state.SelfUpdate
	pending := st.Attempts > 0 || st.TargetHash != ""
	if !pending {
		n.stateMu.Unlock()
		return
	}
	target, attempts := st.TargetHash, st.Attempts
	*st = persistSelfUpdateZero
	n.stateMu.Unlock()
	n.saveState()
	n.Log.Info("自同步成功：本节点已是父那一份镜像（尝试痕迹已清零）",
		"hash", shortHash(mineHash), "was_target", shortHash(target), "attempts", attempts)
	n.Metrics.Inc("selfupdate_total", "result", "settled")
}

// ---------- 子端：拉取 ----------

// syncAndRestart 向父拉取它的可执行文件，校验通过就替换并原地重启。
//
// 接收者 n 是本节点（子）。任何一步失败都**不阻断**当前进程：打出 ERROR、记一条指标，
// 然后带着旧镜像继续服务（父端会因为"少了一个可用版本"而在 /v1/tree 里看得见）。
//
// 参数：
//
//	u        — 上行侧（用于把 BinaryReq 送出去）
//	frames   — 本次会话的帧通道
//	wantHash — 目标哈希（父的镜像）
//	wantSize — 目标字节数（0 = 父没给，以收到的实际字节数为准）
//
// 注意：替换成功后本函数**不会返回**（进程镜像已被 exec 替换）。
func (n *Node) syncAndRestart(u *Upstream, frames <-chan recvResult, wantHash string, wantSize int64) {
	timeout := n.C().SelfUpdate.Timeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	staged, err := n.pullBinary(u, ctx, frames, wantHash, wantSize)
	if err != nil {
		n.Log.Error("拉取父的可执行文件失败：继续用当前镜像服务", "err", err,
			"target", shortHash(wantHash), "timeout", timeout.String())
		n.Metrics.Inc("selfupdate_total", "result", "pull_failed")
		return
	}
	defer os.Remove(staged.tmp) // 成功路径下 tmp 已被 rename 走，这次删除是空操作
	if err := staged.commit(); err != nil {
		n.Log.Error("替换可执行文件失败：继续用当前镜像服务", "err", err, "path", staged.target)
		n.Metrics.Inc("selfupdate_total", "result", "install_failed")
		return
	}
	n.Metrics.Inc("selfupdate_total", "result", "synced")
	n.Log.Warn("可执行文件已替换为新镜像，准备原地重启（连接会短暂中断，之后自动重连）",
		"hash", shortHash(wantHash), "bytes", staged.size, "path", staged.target,
		"prev", staged.target+prevSuffix)
	// 重启前把状态刷到盘上：这一次重启要让"已经试过几次"跨过 exec 活下来
	n.saveState()
	if err := restartSelf(staged.target); err != nil {
		n.Log.Error("原地重启失败（syscall.Exec 返回了）", "err", err, "path", staged.target)
	}
}

// pullBinary 就地向父申请它的可执行文件，边收边写暂存文件，收完做整份校验。
//
// 收帧循环与正常阶段共用同一个读协程（frames）：非分片帧照常分发给 dispatch，
// 所以拉取期间心跳回应、终态通知都不会被丢掉。超时、拒绝、校验失败都返回错误。
//
// 接收者 n 是本节点（子）。
//
// 参数：
//
//	u        — 上行侧（BinaryReq 从它发）
//	ctx      — 本次拉取的上下文（带 selfupdate.sync_timeout 的总时限）
//	frames   — 本次会话的帧通道
//	wantHash — 目标哈希；每一片都要与它一致（父中途换镜像会立刻被挡住）
//	wantSize — 目标字节数（0 表示未知，以实收为准）
//
// 返回：
//
//	*stagedBinary — 已落盘并校验通过的暂存镜像（尚未替换到目标位置）
//	error         — 申请失败 / 被拒 / 超时 / crc 或 sha256 校验不过时返回
func (n *Node) pullBinary(u *Upstream, ctx context.Context,
	frames <-chan recvResult, wantHash string, wantSize int64) (*stagedBinary, error) {

	cfg := n.C().SelfUpdate
	info := n.Build()
	if info.Path == "" {
		return nil, errors.New("不知道自己的可执行文件路径")
	}
	dir := cfg.StagingDir(info.Path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("建暂存目录 %s: %w", dir, err)
	}
	target := info.Path
	tmp := filepath.Join(dir, "."+filepath.Base(target)+stagingSuffix)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return nil, fmt.Errorf("开暂存文件 %s: %w", tmp, err)
	}
	// 函数退出时若还没交出去（出错路径），把半截文件清掉
	keep := false
	defer func() {
		if !keep {
			f.Close()
			os.Remove(tmp)
		}
	}()

	if err := u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: n.C().Node.ID,
		Frame: &pb.UpFrame_BinaryReq{BinaryReq: &pb.BinaryReq{
			WantHash: wantHash, MaxBytes: cfg.MaxTransferBytes(),
		}}}); err != nil {
		return nil, fmt.Errorf("发申请帧: %w", err)
	}
	n.Log.Info("已向父申请它的可执行文件", "want", shortHash(wantHash), "staging", tmp)

	h := sha256.New()
	var written int64
	nextIndex := int32(0)
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("等待父的可执行文件超时: %w", ctx.Err())
		case r := <-frames:
			if r.err != nil {
				return nil, fmt.Errorf("读流结束: %w", r.err)
			}
			chunk := r.f.GetBinaryChunk()
			if chunk == nil {
				// 不是分片：照常处理（心跳回应 / 终态 / 配置下发…），别把它们丢了
				if err := u.dispatch(r.f); err != nil {
					n.Log.Warn("拉取期间处理下行帧失败", "err", err)
				}
				continue
			}
			if chunk.GetReason() != "" {
				return nil, fmt.Errorf("父拒绝/终止: %s", chunk.GetReason())
			}
			if chunk.GetHash() != wantHash {
				return nil, fmt.Errorf("父中途换了镜像：%s != %s", shortHash(chunk.GetHash()), shortHash(wantHash))
			}
			if wantSize > 0 && chunk.GetSize() != wantSize {
				return nil, fmt.Errorf("父报的字节数变了：%d != %d", chunk.GetSize(), wantSize)
			}
			if chunk.GetIndex() != nextIndex || chunk.GetOffset() != written {
				return nil, fmt.Errorf("分片顺序不对：index=%d(want %d) offset=%d(want %d)",
					chunk.GetIndex(), nextIndex, chunk.GetOffset(), written)
			}
			payload := chunk.GetPayload()
			if crc32.ChecksumIEEE(payload) != chunk.GetCrc32() {
				return nil, fmt.Errorf("第 %d 片 crc32 校验不过", chunk.GetIndex())
			}
			if int64(len(payload)) > cfg.MaxTransferBytes() {
				return nil, errors.New("单片超过配置的字节上限")
			}
			if _, err := f.Write(payload); err != nil {
				return nil, fmt.Errorf("写暂存文件: %w", err)
			}
			h.Write(payload)
			written += int64(len(payload))
			if written > cfg.MaxTransferBytes() {
				return nil, fmt.Errorf("收到的字节数超过 selfupdate.max_bytes(%d)", cfg.MaxTransferBytes())
			}
			nextIndex++
			if !chunk.GetFinal() {
				continue
			}
			// ---- 最后一片：整份校验 ----
			got := buildinfo.HashPrefix + hex.EncodeToString(h.Sum(nil))
			if got != wantHash {
				return nil, fmt.Errorf("整份哈希对不上：实收 %s，期望 %s", shortHash(got), shortHash(wantHash))
			}
			if wantSize > 0 && written != wantSize {
				return nil, fmt.Errorf("整份字节数对不上：实收 %d，期望 %d", written, wantSize)
			}
			if err := f.Sync(); err != nil {
				return nil, fmt.Errorf("刷盘: %w", err)
			}
			if err := f.Close(); err != nil {
				return nil, fmt.Errorf("关闭暂存文件: %w", err)
			}
			keep = true
			n.Log.Info("父的可执行文件已收齐并校验通过",
				"bytes", written, "chunks", nextIndex, "hash", shortHash(got))
			return &stagedBinary{tmp: tmp, target: target, mode: n.execMode(), size: written, hash: got}, nil
		}
	}
}

// stagedBinary 一份已经收齐、校验通过、尚未替换到位的镜像。
type stagedBinary struct {
	tmp    string      // 暂存文件（与目标同目录，保证 rename 是原子的）
	target string      // 目标位置（本进程正在跑的那个文件）
	mode   os.FileMode // 要设成的权限位（沿用原文件的）
	size   int64       // 字节数
	hash   string      // 哈希
}

// commit 把暂存镜像原子地换到目标位置，并给上一版留一份旁支（`<exe>.prev`）。
//
// 三步：把当前文件硬链接成 `<exe>.prev`（留退路，失败不致命）→ chmod → rename 覆盖。
// rename 是原子的，所以崩溃在中间也只会是"要么旧、要么新"，不会出现半个可执行文件。
//
// 接收者 b 是收齐并校验通过的暂存镜像。
//
// 返回：
//
//	error — chmod 或 rename 失败时返回（此时目标位置仍是旧镜像，进程照常跑）
func (b *stagedBinary) commit() error {
	prev := b.target + prevSuffix
	_ = os.Remove(prev)
	if err := os.Link(b.target, prev); err != nil {
		// 留退路失败不致命：最多是这次升级没有可回滚的旧版
		fmt.Fprintf(os.Stderr, "[warn] 无法保留上一版镜像 %s: %v\n", prev, err)
	}
	if err := os.Chmod(b.tmp, b.mode); err != nil {
		return fmt.Errorf("chmod %s: %w", b.tmp, err)
	}
	if err := os.Rename(b.tmp, b.target); err != nil {
		return fmt.Errorf("替换 %s: %w", b.target, err)
	}
	syncDir(filepath.Dir(b.target))
	return nil
}

// execMode 返回"要设给新镜像"的权限位。
//
// 接收者 n 是本节点实例。优先沿用目标文件当前的权限（人工部署时可能是 0750 / 0755），
// 拿不到就退到 0755（可执行 + 可读）。
//
// 返回：
//
//	os.FileMode — 权限位
func (n *Node) execMode() os.FileMode {
	if fi, err := os.Stat(n.Build().Path); err == nil {
		return fi.Mode().Perm()
	}
	return 0o755
}

// restartSelf 用 syscall.Exec 把当前进程**原地替换**成刚换好的那份镜像。
//
// 为什么是 exec 而不是"退出再等谁拉起"：本项目的手工部署形态是 `nohup ... &` + pidfile，
// 背后没有 systemd / supervisor 可以依赖 —— 退出就是真的没了。exec 的好处是
// **PID 不变、打开的文件描述符与环境原样保留**，启动脚本、pidfile、日志重定向全都还成立
// （监听套接字会随 exec 关闭，接着由新镜像重新 bind）。
//
// 代价是进程内状态全丢（内存账本、在跑的本地指令、结果索引缓存），这一条框架本来就扛得住：
// 账本停在 SELF_RUNNING 的指令会在下次启动时走 Executor.OnRestart，
// 未上报的结果在 pending_result 里等着重发，子节点断线后会自动重连。
//
// 参数：
//
//	target — 刚替换好的可执行文件绝对路径
//
// 返回：
//
//	error — 只在**失败**时返回；成功时本函数不会返回（进程镜像已被替换）
func restartSelf(target string) error {
	argv := os.Args
	if len(argv) == 0 {
		argv = []string{target}
	}
	// 仅 unix 可用：darwin / linux 都支持 syscall.Exec（本项目的部署形态本就没有 Windows）
	return syscall.Exec(target, argv, os.Environ())
}

// ---------- 父端：把镜像发下去 ----------

// canServeBinary 判定"这个孩子的申请接不接"。
//
// 门槛只有一条但是硬的：**对端必须由本节点自己的 CA 签发**（也就是"我的直接子"）——
// 用对端叶子证书验自己 CA 证书的签名即可，不需要查注册表（刚入网还没注册的也能拿）。
// 另外还看 selfupdate.serve 开关与"本节点到底有没有 CA 材料"。
//
// 接收者 n 是本节点（父）。
//
// 参数：
//
//	cc — 发起申请的子连接
//
// 返回：
//
//	error — 不接时返回（文案就是回给对端的 ERR_BINARY_* 原因）
func (n *Node) canServeBinary(cc *childConn) error {
	if !n.C().SelfUpdate.ServingChildren() {
		return errors.New("ERR_BINARY_SERVE_OFF")
	}
	if cc == nil || cc.leaf == nil {
		return errors.New("ERR_BINARY_NO_CERT")
	}
	ca := n.Id().CACert
	if ca == nil {
		// 叶子没有 CA 材料，本来也不会有子来申请
		return errors.New("ERR_BINARY_NO_CA")
	}
	if err := cc.leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("ERR_BINARY_NOT_DIRECT_CHILD: %w", err)
	}
	return nil
}

// serveBinary 响应一个子的 BinaryReq：校验申请、复验本地镜像、然后分片推过去。
//
// 三处安全检查：
//  1. 申请里的 want_hash 必须与**本节点现在的**镜像哈希逐字节相同（避免"申请到一份已经变了的镜像"）；
//  2. 发之前用 buildinfo.SameAsDisk 复验磁盘文件仍是启动时那一份 —— 哈希是启动时算的，
//     中途被人换掉的话，发出去的就是"内容与承诺不符"的东西，宁可不发；
//  3. 大小上限取 min(申请方给的, 本节点 selfupdate.max_bytes)。
//
// 推分片用 cc.sendThrottled：先等发送缓冲回落到一半以下再压下一片，给同一时刻的心跳、
// 终态这类必经帧留出位置（否则几十 MB 的分片会把缓冲占满，把续租响应挤掉）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。本函数由 dispatch 起在独立协程里跑，不阻塞读循环。
//
// 参数：
//
//	cc  — 发起申请的子连接
//	req — 申请内容（want_hash / max_bytes）
func (h *Hub) serveBinary(cc *childConn, req *pb.BinaryReq) {
	n := h.n
	if err := n.canServeBinary(cc); err != nil {
		n.Log.Warn("拒绝子的可执行文件申请", "child", shortID(cc.nodeID), "err", err)
		n.Metrics.Inc("selfupdate_serve_total", "result", "rejected")
		h.sendBinaryChunk(cc, &pb.BinaryChunk{Final: true, Reason: err.Error()})
		return
	}
	info := n.Build()
	if !info.Known() {
		h.sendBinaryErr(cc, "ERR_BINARY_SELF_UNKNOWN")
		return
	}
	if req.GetWantHash() != info.Hash {
		n.Log.Warn("子申请的是另一份镜像，拒绝", "child", shortID(cc.nodeID),
			"want", shortHash(req.GetWantHash()), "have", info.Short())
		n.Metrics.Inc("selfupdate_serve_total", "result", "rejected")
		h.sendBinaryChunk(cc, &pb.BinaryChunk{Hash: info.Hash, Size: info.Size,
			Final: true, Reason: "ERR_BINARY_HASH_MISMATCH"})
		return
	}
	ok, err := buildinfo.SameAsDisk(info)
	if err != nil || !ok {
		n.Log.Error("本地可执行文件已被替换 / 读不到，拒绝外发（重启本节点后才会重新对外提供）",
			"path", info.Path, "err", err)
		n.Metrics.Inc("selfupdate_serve_total", "result", "rejected")
		h.sendBinaryChunk(cc, &pb.BinaryChunk{Hash: info.Hash, Size: info.Size,
			Final: true, Reason: "ERR_BINARY_LOCAL_CHANGED"})
		return
	}
	maxBytes := n.C().SelfUpdate.MaxTransferBytes()
	if req.GetMaxBytes() > 0 && req.GetMaxBytes() < maxBytes {
		maxBytes = req.GetMaxBytes()
	}
	if info.Size > maxBytes {
		h.sendBinaryChunk(cc, &pb.BinaryChunk{Hash: info.Hash, Size: info.Size,
			Final: true, Reason: "ERR_BINARY_TOO_LARGE"})
		return
	}

	f, err := os.Open(info.Path)
	if err != nil {
		h.sendBinaryErr(cc, "ERR_BINARY_OPEN_FAILED")
		return
	}
	defer f.Close()

	ctx, cancel := context.WithTimeout(context.Background(), n.C().SelfUpdate.Timeout())
	defer cancel()

	chunkSize := n.C().SelfUpdate.ChunkBytes()
	total := int32((info.Size + int64(chunkSize) - 1) / int64(chunkSize))
	if total == 0 {
		total = 1 // 空文件也给一片（子端据此判定收齐）
	}
	n.Log.Info("开始向子推送本节点的可执行文件", "child", shortID(cc.nodeID),
		"hash", info.Short(), "bytes", info.Size, "chunks", total)
	buf := make([]byte, chunkSize)
	var off int64
	for i := int32(0); i < total; i++ {
		want := int64(chunkSize)
		if rest := info.Size - off; rest < want {
			want = rest
		}
		payload := buf[:want]
		if want > 0 {
			if _, err := io.ReadFull(f, payload); err != nil {
				n.Log.Error("读本节点可执行文件失败，中断推送", "err", err, "offset", off)
				h.sendBinaryChunk(cc, &pb.BinaryChunk{Final: true, Reason: "ERR_BINARY_READ_FAILED"})
				n.Metrics.Inc("selfupdate_serve_total", "result", "error")
				return
			}
		}
		chunk := &pb.BinaryChunk{
			Hash: info.Hash, Size: info.Size, Index: i, Total: total, Offset: off,
			Payload: append([]byte(nil), payload...), Crc32: crc32.ChecksumIEEE(payload),
			Final: i == total-1,
		}
		if err := cc.sendThrottled(ctx, &pb.DownFrame{ProtoVersion: protoVersion,
			Frame: &pb.DownFrame_BinaryChunk{BinaryChunk: chunk}}); err != nil {
			n.Log.Warn("推送可执行文件分片失败", "child", shortID(cc.nodeID), "err", err, "index", i)
			n.Metrics.Inc("selfupdate_serve_total", "result", "error")
			return
		}
		off += int64(len(payload))
	}
	n.Log.Info("可执行文件推送完成", "child", shortID(cc.nodeID), "hash", info.Short(), "bytes", off)
	n.Metrics.Inc("selfupdate_serve_total", "result", "sent")
}

// sendBinaryErr 只发一个"出错终止片"（带原因、无载荷）。
//
// 接收者 h 是下行侧（服务端）的连接管理器；子端收到后会把这次同步判为失败并继续服务。
//
// 参数：
//
//	cc     — 目标子连接
//	reason — 错误码（ERR_BINARY_*），会原样出现在子端的日志里
func (h *Hub) sendBinaryErr(cc *childConn, reason string) {
	h.n.Metrics.Inc("selfupdate_serve_total", "result", "rejected")
	h.sendBinaryChunk(cc, &pb.BinaryChunk{Final: true, Reason: reason})
}

// sendBinaryChunk 把一帧分片放进发送缓冲（不阻塞、不等待；失败只记日志）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。它给"终止片"这类小帧用：
// 数据分片走 cc.sendThrottled，不带限速就用这个。
//
// 参数：
//
//	cc    — 目标子连接
//	chunk — 待发送的分片
func (h *Hub) sendBinaryChunk(cc *childConn, chunk *pb.BinaryChunk) {
	if cc == nil {
		return
	}
	if err := cc.send(&pb.DownFrame{ProtoVersion: protoVersion,
		Frame: &pb.DownFrame_BinaryChunk{BinaryChunk: chunk}}); err != nil {
		h.n.Log.Warn("发送分片帧失败", "child", shortID(cc.nodeID), "err", err)
	}
}

// ---------- 小工具 ----------

// 与镜像文件配套的两个后缀：暂存文件（写到一半）与上一版留档。
const (
	stagingSuffix = ".staging"
	prevSuffix    = ".prev"
)

// persistSelfUpdateZero 是"没有欠账"的痕迹零值（清零时整体赋值）。
var persistSelfUpdateZero = persist.SelfUpdate{}

// shortHash 把一个哈希压成 12 位短形式，用于日志与展示。
//
// 参数：
//
//	h — "sha256:xxxx…" 形式的哈希
//
// 返回：
//
//	string — 去掉前缀后取前 12 位；空值返回 "?"
func shortHash(h string) string {
	if h == "" {
		return "?"
	}
	s := h
	if i := indexOfColon(s); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}

// indexOfColon 返回字符串里第一个冒号的下标，没有则返回 -1。
//
// 参数：
//
//	s — 待查找的字符串
//
// 返回：
//
//	int — 冒号下标；不存在时为 -1
func indexOfColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

// syncDir 对目录做一次 fsync，保证"重命名"这个动作本身落到了盘上。
//
// 少了它，rename 之后紧接着掉电，目录项可能还停在旧名字上 —— 那就会出现
// "文件内容已经是新的，但按路径打开还是旧的"这种最难查的状态。
//
// 参数：
//
//	dir — 要 fsync 的目录路径；打不开或 fsync 失败都只忽略（尽力而为）
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}
