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
	"bytes"
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

// fetchManifest 向父申请"这份镜像由哪些片组成、每片 sha256 是多少"，拿不到就返回 nil。
//
// 返回 nil 是**正常情况**，不是错误：父可能是旧版本（不认识 BinaryManifestReq 帧），
// 也可能显式关掉了片存。此时调用方回退到老流程（只靠 crc32 + 整份 sha256），
// 行为与加片存之前逐字节一致 —— "拿不到清单就不工作"是绝对不行的。
//
// 超时是**独立预算**（整份同步预算的 1/3，至少 5s）：不能让"等一份永远不会来的清单"
// 把整次同步耗光。
//
// 接收者 n 是本节点（子）。等待期间非清单帧照常分发给 dispatch，所以心跳回应、
// 终态通知都不会被丢掉。
//
// 参数：
//
//	u        — 上行侧（清单请求从它发）
//	ctx      — 本次同步的上下文
//	frames   — 本次会话的帧通道
//	wantHash — 目标哈希
//
// 返回：
//
//	*pb.BinaryManifest — 可用的清单（已存进片存）；拿不到或不可用时返回 nil
func (n *Node) fetchManifest(u *Upstream, ctx context.Context,
	frames <-chan recvResult, wantHash string) *pb.BinaryManifest {
	if n.pieces == nil {
		return nil // 本节点没启用片存：问了也没地方放，直接走老流程
	}
	if err := u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: n.C().Node.ID,
		Frame: &pb.UpFrame_BinaryManifestReq{BinaryManifestReq: &pb.BinaryManifestReq{
			WantHash: wantHash,
		}}}); err != nil {
		n.Log.Warn("申请镜像清单失败，回退到旧流程", "err", err)
		return nil
	}
	budget := n.C().SelfUpdate.Timeout() / 3
	if budget < 5*time.Second {
		budget = 5 * time.Second
	}
	mctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	for {
		select {
		case <-mctx.Done():
			n.Log.Info("父未回镜像清单（旧版本父？），回退到 crc32 + 整份 sha256 的旧流程",
				"budget", budget.String())
			return nil
		case r := <-frames:
			if r.err != nil {
				return nil
			}
			m := r.f.GetBinaryManifest()
			if m == nil {
				// 不是清单帧：照常处理（心跳回应 / 终态 / 配置下发…），别把它们丢了
				if err := u.dispatch(r.f); err != nil {
					n.Log.Warn("等清单期间处理下行帧失败", "err", err)
				}
				continue
			}
			if m.GetReason() != "" {
				n.Log.Info("父不提供镜像清单，回退旧流程", "reason", m.GetReason())
				return nil
			}
			// 清单本身必须自洽：哈希要对得上、片数非空、片大小为正
			if m.GetHash() != wantHash || len(m.GetPieceSha256()) == 0 || m.GetChunkSize() <= 0 {
				n.Log.Warn("父给的清单不可用，回退旧流程",
					"hash_match", m.GetHash() == wantHash,
					"pieces", len(m.GetPieceSha256()), "chunk", m.GetChunkSize())
				return nil
			}
			if err := n.pieces.PutManifest(wantHash, m); err != nil {
				n.Log.Warn("清单落盘失败（不影响本次同步）", "err", err)
			}
			n.Log.Info("已拿到镜像清单（片级 sha256）",
				"pieces", len(m.GetPieceSha256()), "chunk", m.GetChunkSize())
			return m
		}
	}
}

// pullBinary 就地向父申请它的可执行文件，边收边写暂存文件，收完做整份校验。
//
// 两条路径，取决于能不能拿到片清单：
//
//	**清单路径**（父支持且本节点启用了片存）—— 每片先过 sha256 再落片存，最后统一拼装。
//	  好处有三：① 片级校验从 crc32 升级为 sha256，"这一片确实属于那份镜像"可证；
//	  ② 已经验证过的片可以立刻转发给本节点的直接子（边收边转发，见 pieces.go）；
//	  ③ 断点续传 —— 续传时前半段只存在于片存里，所以**最后统一拼装**（往里追加会错位）。
//
//	**旧路径**（拿不到清单）—— 与加片存之前逐字节一致：按 crc32 校验、直接追加进暂存文件、
//	  只有整份 sha256 兜底，不落片存、不支持续传。
//
// 收帧循环与正常阶段共用同一个读协程（frames）：非分片帧照常分发给 dispatch。
// 超时、拒绝、校验失败都返回错误。
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
	_ = os.Remove(tmp) // 清掉上一次失败的残留（下面用 O_TRUNC 建新文件）
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

	// ① 先要清单（片级 sha256）。拿不到就退回旧路径。
	manifest := n.fetchManifest(u, ctx, frames, wantHash)
	pieceHashes := manifest.GetPieceSha256()
	useStore := len(pieceHashes) > 0 && n.pieces != nil

	// ② 断点续传：片存里"从第 0 片起连续存在"的片数就是本次的起点。
	// 只有拿到清单才敢续 —— 没有清单时既不知道父的片大小、也无法校验已有片。
	fromIndex := int64(0)
	if useStore {
		fromIndex = int64(n.pieces.Prefix(wantHash))
		if fromIndex > int64(len(pieceHashes)) {
			fromIndex = 0 // 片存与清单对不上（父换了 chunk_size？）→ 老老实实从头来
		}
	}

	// ③ 片已经集齐（上一次同步在"拼装 / 替换"之前中断了）：一片都不用再要，直接拼装。
	// 这一支必须显式处理 —— 否则会带着 from_index = 总片数 去申请，父端把它当成越界 clamp 回 0
	// 从头重发，子端立刻报"分片顺序不对"。这是端到端测试抓出来的第二种故障。
	if useStore && fromIndex >= int64(len(pieceHashes)) {
		n.Log.Info("片存已集齐，直接拼装（不必再向父申请）",
			"hash", shortHash(wantHash), "pieces", len(pieceHashes))
		st, err := n.assembleFromStore(f, tmp, target, wantHash, wantSize, pieceHashes)
		if err != nil {
			return nil, err
		}
		keep = true
		return st, nil
	}

	if err := u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: n.C().Node.ID,
		Frame: &pb.UpFrame_BinaryReq{BinaryReq: &pb.BinaryReq{
			WantHash: wantHash, MaxBytes: cfg.MaxTransferBytes(), FromIndex: fromIndex,
		}}}); err != nil {
		return nil, fmt.Errorf("发申请帧: %w", err)
	}
	n.Log.Info("已向父申请它的可执行文件", "want", shortHash(wantHash), "staging", tmp,
		"manifest", useStore, "from_piece", fromIndex)

	h := sha256.New()
	// 续传时"已收字节数"从片边界起算：它同时是下一片必须落到的 offset
	written := fromIndex * manifest.GetChunkSize()
	nextIndex := int32(fromIndex)
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
			if useStore {
				// 片级 sha256：这是"片可以对外转发"的唯一依据（crc32 只查传输损坏）
				idx := int(chunk.GetIndex())
				if idx < 0 || idx >= len(pieceHashes) {
					return nil, fmt.Errorf("父给了清单外的片号 %d（清单共 %d 片）", idx, len(pieceHashes))
				}
				if !bytes.Equal(pieceDigest(payload), pieceHashes[idx]) {
					n.Metrics.Inc("selfupdate_pieces_received_total", "result", "rejected")
					return nil, fmt.Errorf("第 %d 片 sha256 校验不过（内容非本镜像的一片）", idx)
				}
				if err := n.pieces.Put(wantHash, chunk.GetIndex(), payload); err != nil {
					n.Metrics.Inc("selfupdate_pieces_received_total", "result", "rejected")
					return nil, fmt.Errorf("写片存: %w", err)
				}
				n.Metrics.Inc("selfupdate_pieces_received_total", "result", "ok")
			} else {
				if _, err := f.Write(payload); err != nil {
					return nil, fmt.Errorf("写暂存文件: %w", err)
				}
				h.Write(payload)
			}
			written += int64(len(payload))
			if written > cfg.MaxTransferBytes() {
				return nil, fmt.Errorf("收到的字节数超过 selfupdate.max_bytes(%d)", cfg.MaxTransferBytes())
			}
			nextIndex++
			if !chunk.GetFinal() {
				continue
			}
			// ---- 最后一片：整份校验 ----
			if useStore {
				// 统一拼装（见 assembleFromStore 的注释：续传时前半段只存在于片存里）
				st, err := n.assembleFromStore(f, tmp, target, wantHash, wantSize, pieceHashes)
				if err != nil {
					return nil, err
				}
				keep = true
				if rm := n.pieces.Evict(); rm > 0 {
					n.Log.Info("片存已按上限清理", "removed", rm)
				}
				return st, nil
			}
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
				"bytes", written, "chunks", nextIndex, "hash", shortHash(got),
				"piece_store", useStore, "resumed_from", fromIndex)
			if n.pieces != nil {
				if rm := n.pieces.Evict(); rm > 0 {
					n.Log.Info("片存已按上限清理", "removed", rm)
				}
			}
			return &stagedBinary{tmp: tmp, target: target, mode: n.execMode(), size: written, hash: got}, nil
		}
	}
}

// assembleFromStore 把片存里已集齐的片拼装进暂存文件、做整份校验，返回可替换的暂存镜像。
//
// 两个调用点共用它（这也是它被抽出来的原因）：
//
//  1. 正常收完最后一片之后；
//  2. 启动时发现片已经齐了 —— 上一次同步在"拼装 / 替换"之前中断了。
//
// **为什么要"统一拼装"而不是"边收边追加"**：断点续传时前半段只存在于片存里、暂存文件里没有，
// 往暂存文件追加会得到一个内容错位的文件。统一拼装让两条路径走同一段代码，
// 也就不会有"续传之后文件不对"这种最难查的问题。
//
// 接收者 n 是本节点（子）。返回后 **f 已被关闭**，调用方不要再碰它。
//
// 参数：
//
//	f           — 已打开的暂存文件（写满即用）
//	tmp         — 暂存文件路径
//	target      — 目标位置（本进程正在跑的那个文件）
//	wantHash    — 期望的整份哈希
//	wantSize    — 期望的字节数（0 = 未知）
//	pieceHashes — 清单里的片级 sha256（它的长度就是总片数）
//
// 返回：
//
//	*stagedBinary — 已校验通过、可替换的暂存镜像
//	error — 片不齐 / 哈希不符 / 字节数不符 / 刷盘失败时返回
func (n *Node) assembleFromStore(f *os.File, tmp, target, wantHash string,
	wantSize int64, pieceHashes [][]byte) (*stagedBinary, error) {
	total := int32(len(pieceHashes))
	if !n.pieces.Have(wantHash, total) {
		return nil, errors.New("片存不齐，无法拼装（父少发了片？）")
	}
	h := sha256.New()
	written, err := n.pieces.Assemble(wantHash, total, f, h)
	if err != nil {
		return nil, err
	}
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
	n.Log.Info("已从片存拼装出完整镜像并校验通过",
		"bytes", written, "chunks", total, "hash", shortHash(got))
	return &stagedBinary{tmp: tmp, target: target, mode: n.execMode(), size: written, hash: got}, nil
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

// manifestFor 取某份镜像的片清单：**优先**用片存里那份（继承自父、或上次下载时留下的），
// 没有就从本节点自己的可执行文件现算。
//
// 为什么需要"现算"这条兜底：本节点跑的可能不是从父那儿下载来的那份镜像（根节点就是最典型的例子
// —— 它没有父），此时它手上没有任何外部清单，但它**就是标准答案**，有资格自己算一份给下级用。
//
// 接收者 h 是下行侧（服务端）的连接管理器（`h.n` 是父）。
//
// 参数：
//
//	hash — 目标镜像的整份哈希
//
// 返回：
//
//	*pb.BinaryManifest — 可用的清单；没有片存且又算不出来（读不到文件 / 磁盘文件已被换掉）时返回 nil
func (h *Hub) manifestFor(hash string) *pb.BinaryManifest {
	n := h.n
	if n.pieces != nil {
		if m := n.pieces.Manifest(hash); m != nil {
			return m
		}
	}
	info := n.Build()
	if !info.Known() || info.Hash != hash {
		return nil // 申请的不是"我跑的那份"，我没有它的清单
	}
	// 现算之前必须确认磁盘文件仍是启动时那一份：否则算出来的片级哈希对应的是另一份内容，
	// 子每片都能"校验通过"、最后整份对不上，会得到一条很难懂的错误。
	if ok, err := buildinfo.SameAsDisk(info); err != nil || !ok {
		n.Log.Error("本地可执行文件已被替换 / 读不到，无法为它生成镜像清单",
			"path", info.Path, "err", err)
		return nil
	}
	chunkSize := int64(n.C().SelfUpdate.ChunkBytes())
	if chunkSize <= 0 {
		return nil
	}
	m, err := buildManifest(info, chunkSize)
	if err != nil {
		n.Log.Warn("生成本节点镜像清单失败", "err", err)
		return nil
	}
	if n.pieces != nil {
		if err := n.pieces.PutManifest(hash, m); err != nil {
			n.Log.Warn("清单落盘失败（不影响本次供片）", "err", err)
		}
	}
	n.Log.Info("已为本节点镜像生成片清单", "hash", info.Short(), "pieces", len(m.PieceSha256), "chunk", chunkSize)
	return m
}

// buildManifest 读一份镜像文件、按 chunkSize 切片并算出片级 sha256 清单。
//
// 参数：
//
//	info      — 镜像身份快照（提供路径、哈希、字节数）
//	chunkSize — 片大小（必须与推片时用的一致）
//
// 返回：
//
//	*pb.BinaryManifest — 清单（piece_sha256 的顺序与片号一致）
//	error — 打开文件失败 / 读失败时返回
func buildManifest(info buildinfo.Info, chunkSize int64) (*pb.BinaryManifest, error) {
	if chunkSize <= 0 {
		return nil, errors.New("chunk size 必须为正")
	}
	f, err := os.Open(info.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := &pb.BinaryManifest{Hash: info.Hash, Size: info.Size, ChunkSize: chunkSize}
	buf := make([]byte, chunkSize)
	for {
		n, err := io.ReadFull(f, buf)
		if n > 0 {
			m.PieceSha256 = append(m.PieceSha256, pieceDigest(buf[:n]))
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	return m, nil
}

// serveManifest 响应一个子的 BinaryManifestReq：把清单发过去（子据此做片级 sha256 校验）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。本函数由 dispatch 起在独立协程里跑
// （本节点没继承到清单时要从自己的镜像现算，那是几十 MB 的哈希，绝不能压在读循环上）。
//
// 参数：
//
//	cc  — 发起申请的子连接
//	req — 申请内容（want_hash）
func (h *Hub) serveManifest(cc *childConn, req *pb.BinaryManifestReq) {
	n := h.n
	send := func(reason string) {
		_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_BinaryManifest{
			BinaryManifest: &pb.BinaryManifest{Reason: reason}}})
	}
	if err := n.canServeBinary(cc); err != nil {
		n.Log.Warn("拒绝子的镜像清单申请", "child", shortID(cc.nodeID), "err", err)
		n.Metrics.Inc("selfupdate_serve_total", "result", "rejected")
		send(err.Error())
		return
	}
	if req.GetWantHash() == "" {
		send("ERR_BINARY_MANIFEST_NO_HASH")
		return
	}
	m := h.manifestFor(req.GetWantHash())
	if m == nil {
		// 子会据此回退到"crc32 + 整份 sha256"的旧流程，所以这不是错误，只是一条 info
		n.Log.Info("没有该镜像的清单，子将走旧流程", "child", shortID(cc.nodeID),
			"want", shortHash(req.GetWantHash()))
		send("ERR_BINARY_NO_MANIFEST")
		return
	}
	if m.GetHash() != req.GetWantHash() {
		send("ERR_BINARY_HASH_MISMATCH")
		return
	}
	_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion,
		Frame: &pb.DownFrame_BinaryManifest{BinaryManifest: m}})
	n.Log.Info("已下发镜像清单", "child", shortID(cc.nodeID),
		"hash", shortHash(m.GetHash()), "pieces", len(m.GetPieceSha256()))
}

// serveBinary 响应一个子的 BinaryReq：校验申请、复验本地镜像（或从片存取片），然后分片推过去。
//
// **供片来源二选一**（这是"边收边转发"的落点）：
//
//   - **片存**：里面每一片都有 sha256 背书，所以**不需要**"磁盘文件仍是启动时那份"这个前提。
//     于是中继还没收完、还没重启，就已经能把已收到的片转发给它的直接子 —— 收敛从
//     "逐层串行"变成"流水线"。
//   - **本节点自己的可执行文件**（老路径）：发之前必须用 buildinfo.SameAsDisk 复验
//     磁盘文件仍是启动时那一份 —— 哈希是启动时算的，中途被人换掉的话，发出去的就是
//     "内容与承诺不符"的东西，宁可不发。
//
// 三处安全检查（与前两条并列的第三条）：
//
//  3. 申请里的 want_hash 必须与**本节点现在的**镜像哈希逐字节相同（避免"申请到一份已经变了的镜像"）；
//     大小上限取 min(申请方给的, 本节点 selfupdate.max_bytes)。
//
// 推分片用 cc.sendThrottled：先等发送缓冲回落到一半以下再压下一片，给同一时刻的心跳、
// 终态这类必经帧留出位置（否则几十 MB 的分片会把缓冲占满，把续租响应挤掉）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。本函数由 dispatch 起在独立协程里跑，不阻塞读循环。
//
// 参数：
//
//	cc  — 发起申请的子连接
//	req — 申请内容（want_hash / max_bytes / from_index）
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
	maxBytes := n.C().SelfUpdate.MaxTransferBytes()
	if req.GetMaxBytes() > 0 && req.GetMaxBytes() < maxBytes {
		maxBytes = req.GetMaxBytes()
	}
	if info.Size > maxBytes {
		h.sendBinaryChunk(cc, &pb.BinaryChunk{Hash: info.Hash, Size: info.Size,
			Final: true, Reason: "ERR_BINARY_TOO_LARGE"})
		return
	}

	// 片大小以**清单**为准（子存的那些片是按清单的片边界切出来的）；没有清单就用本地配置。
	// 两者不一致会导致"片号/偏移对不上"或"拼装出来字节错位"，所以这里必须统一口径。
	chunkSize := int64(n.C().SelfUpdate.ChunkBytes())
	if m := h.manifestFor(info.Hash); m != nil && m.GetChunkSize() > 0 {
		chunkSize = m.GetChunkSize()
	}
	if chunkSize <= 0 {
		h.sendBinaryErr(cc, "ERR_BINARY_BAD_CHUNK_SIZE")
		return
	}
	total := int32((info.Size + chunkSize - 1) / chunkSize)
	if total == 0 {
		total = 1 // 空文件也给一片（子端据此判定收齐）
	}
	fromIndex := int32(req.GetFromIndex())
	if fromIndex < 0 || fromIndex >= total {
		fromIndex = 0
	}

	// 供片并发闸门：中继可能一边向父拉、一边给多个孙推，不限并发会把它自己的带宽吃光。
	// 这里用"等一会儿再放弃"而不是"立刻拒绝"——子端一次失败就要等下一轮重连才重试，
	// 太容易把收敛拖慢。等到超时再拒，至少给了它一个排队的机会。
	ctx, cancel := context.WithTimeout(context.Background(), n.C().SelfUpdate.Timeout())
	defer cancel()
	if n.serveSem != nil {
		select {
		case n.serveSem <- struct{}{}:
			defer func() { <-n.serveSem }()
		case <-ctx.Done():
			n.Log.Warn("供片并发已满，拒绝本次申请", "child", shortID(cc.nodeID))
			n.Metrics.Inc("selfupdate_serve_total", "result", "busy")
			h.sendBinaryChunk(cc, &pb.BinaryChunk{Hash: info.Hash, Size: info.Size,
				Final: true, Reason: "ERR_BINARY_BUSY"})
			return
		}
	}

	useStore := n.pieces != nil && n.pieces.Have(info.Hash, total)
	var f *os.File
	if !useStore {
		ok, err := buildinfo.SameAsDisk(info)
		if err != nil || !ok {
			n.Log.Error("本地可执行文件已被替换 / 读不到，拒绝外发（重启本节点后才会重新对外提供）",
				"path", info.Path, "err", err)
			n.Metrics.Inc("selfupdate_serve_total", "result", "rejected")
			h.sendBinaryChunk(cc, &pb.BinaryChunk{Hash: info.Hash, Size: info.Size,
				Final: true, Reason: "ERR_BINARY_LOCAL_CHANGED"})
			return
		}
		var oerr error
		f, oerr = os.Open(info.Path)
		if oerr != nil {
			h.sendBinaryErr(cc, "ERR_BINARY_OPEN_FAILED")
			return
		}
		defer f.Close()
	}

	n.Log.Info("开始向子推送本节点的可执行文件", "child", shortID(cc.nodeID),
		"hash", info.Short(), "bytes", info.Size, "chunks", total,
		"from", fromIndex, "source", map[bool]string{true: "piece-store", false: "disk"}[useStore])
	buf := make([]byte, chunkSize)
	off := int64(fromIndex) * chunkSize
	for i := fromIndex; i < total; i++ {
		var payload []byte
		if useStore {
			piece, ok := n.pieces.Get(info.Hash, i)
			if !ok {
				// 片存不齐（清理 / 单文件损坏）：明确报错，让子下一轮重来
				n.Log.Warn("片存缺片，中断推送", "index", i, "child", shortID(cc.nodeID))
				h.sendBinaryChunk(cc, &pb.BinaryChunk{Final: true, Reason: "ERR_BINARY_PIECE_MISSING"})
				n.Metrics.Inc("selfupdate_serve_total", "result", "error")
				return
			}
			payload = piece
		} else {
			want := chunkSize
			if rest := info.Size - off; rest < want {
				want = rest
			}
			if want < 0 {
				want = 0
			}
			payload = buf[:want]
			if want > 0 {
				if _, err := io.ReadFull(f, payload); err != nil {
					n.Log.Error("读本节点可执行文件失败，中断推送", "err", err, "offset", off)
					h.sendBinaryChunk(cc, &pb.BinaryChunk{Final: true, Reason: "ERR_BINARY_READ_FAILED"})
					n.Metrics.Inc("selfupdate_serve_total", "result", "error")
					return
				}
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
		n.Metrics.Inc("selfupdate_serve_pieces_total", "source",
			map[bool]string{true: "piece-store", false: "disk"}[useStore])
		off += int64(len(payload))
	}
	n.Log.Info("可执行文件推送完成", "child", shortID(cc.nodeID), "hash", info.Short(),
		"bytes", off, "from", fromIndex, "source", map[bool]string{true: "piece-store", false: "disk"}[useStore])
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
