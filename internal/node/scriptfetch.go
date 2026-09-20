package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"hash/crc32"

	"treecmd/internal/exec/script"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
)

// fetchScript 向父索取一个脚本的完整内容，阻塞直到收齐（或失败）。
//
// 这是 script 执行器在"本地没有 / 哈希不符"时走的路径（见 script.go 的 EnsureScript）。
//
// 为什么不直接把分片塞进一个带缓冲 channel：片数事先不知道，而**送方绝对不能阻塞** ——
// 送方是会话的读循环（`u.dispatch`），它一停，心跳、终态通知、指令下发全跟着停。
// 所以这里用"按 index 存片的表 + 一次性唤醒"：送方永不阻塞、也永不丢片，
// 等待方在片齐或出现终止原因时才被唤醒（与 queryDataBuf 同一思路）。
//
// 分片**允许乱序到达**（按 index 归位，比"严格顺序消费"更稳）：每片落地前先验 crc32，
// 收齐后再验总字节数与**整份 sha256 是否与父声明的一致**（见 scriptBuf.result），
// 最后验**父对这份脚本的身份背书**（见 verifyScriptSig）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	ctx     — 执行上下文；到点就放弃这次索取（上游还等着这条指令的结果，不能一直挂着）
//	name    — 脚本文件名
//	wantSHA — 期望的哈希；父端也会拿它复核，不一致直接拒
//
// 返回：
//
//	[]byte — 收齐的脚本内容（调用方仍需自己复算 sha256）
//	error  — 发不出去 / 父拒绝（带原因）/ 片 crc32 不过 / 大小或哈希对不上 / 父的背书缺失或验不过 /
//	         ctx 到点 / 节点关闭时返回
func (u *Upstream) fetchScript(ctx context.Context, name, wantSHA string) ([]byte, error) {
	// 快照"发片那一刻的父"：签名要等收齐才验，而 u 上的 parentID/parentPub 是**当前会话**的。
	// 会话一结束 failScriptWaits 就让本次索取立刻失败，所以正常收不到跨会话的片；
	// 快照一下更稳 —— "签名者必须是我父"这条断言的依据，得是发片时的那个父。
	parentID, parentPub := u.parentIdentity()

	reqID, err := ulid()
	if err != nil {
		return nil, fmt.Errorf("生成脚本索取请求 ID 失败: %w", err)
	}
	buf := u.registerScriptBuf(reqID)
	defer u.dropScriptBuf(reqID)

	if err := u.send(&pb.UpFrame{ProtoVersion: protoVersion, NodeId: u.n.C().Node.ID,
		Frame: &pb.UpFrame_ScriptReq{ScriptReq: &pb.ScriptReq{
			ReqId: reqID, Name: name, WantSha256: wantSHA, MaxBytes: scriptMaxBytes,
		}}}); err != nil {
		return nil, fmt.Errorf("向父索取脚本 %s 失败: %w", name, err)
	}

	for {
		res := u.takeScriptBuf(reqID)
		switch {
		case res.reason != "":
			return nil, fmt.Errorf("索取脚本 %s 失败: %s", name, res.reason)
		case res.done:
			if err := verifyScriptSig(name, res, parentID, parentPub); err != nil {
				u.n.Metrics.Inc("script_verify_total", "result", "rejected")
				return nil, err
			}
			u.n.Metrics.Inc("script_verify_total", "result", "ok")
			u.n.Log.Info("脚本身份背书校验通过", "name", name, "signer", shortID(res.signerID),
				"sha256", shortHash(res.sha256), "bytes", len(res.data))
			return res.data, nil
		}
		select {
		case <-buf.notify:
		case <-ctx.Done():
			u.n.Metrics.Inc("script_fetch_total", "result", "timeout")
			return nil, fmt.Errorf("索取脚本 %s 超时: %w", name, ctx.Err())
		case <-u.done:
			return nil, errors.New("本节点正在关闭，脚本索取中断")
		}
	}
}

// verifyScriptSig 校验父对这份脚本的身份背书。
//
// 三道缺一不可：**签名得在**（父用身份私钥对 `(name, sha256)` 签过）、**签名者得是本节点本次的父**、
// 签名得能用**父的公钥**验通。父公钥来自 mTLS 对端叶证书（与 HopAttest 同一来源，握手时已由
// `expectNodeID` 核过身份）。
//
// 为什么"签名者 == 父"这一条明明已经被 mTLS 兜住了还要显式判：拓扑上换父、或片来自另一条连接时，
// 这里会立刻以明确的原因暴露出来，而不是靠"反正连的就是父"这种隐含假设。
//
// 注意签名**不负责防篡改**：内容对不对由 res.sha256（父声明的哈希）与复算值比对负责，
// 那道校验在 scriptBuf.result 里已经做过。
//
// 参数：
//
//	name      — 脚本文件名
//	res       — 收齐的结论（内容、父声明的哈希、签名者、签名）
//	parentID  — 本次索取开始时快照的父 NodeID
//	parentPub — 同一时刻快照的父 Ed25519 公钥
//
// 返回：
//
//	error — 背书缺失 / 签名者不是父 / 拿不到父公钥 / 验签不过时返回；文案可直接给人看
func verifyScriptSig(name string, res scriptResult, parentID string, parentPub ed25519.PublicKey) error {
	if res.signerID == "" || len(res.signature) == 0 {
		return fmt.Errorf("ERR_SCRIPT_SIG_MISSING: 父没有为脚本 %s 提供身份背书", name)
	}
	if parentID == "" || res.signerID != parentID {
		return fmt.Errorf("ERR_SCRIPT_SIG_SIGNER: 脚本 %s 的签名者是 %s，不是本节点本次的父 %s",
			name, res.signerID, parentID)
	}
	if len(parentPub) == 0 {
		return fmt.Errorf("ERR_SCRIPT_SIG_NO_PUBKEY: 还没拿到父 %s 的公钥，无法验证脚本 %s 的签名", parentID, name)
	}
	if !identity.Verify(parentPub, script.SignMessage(name, res.sha256), res.signature) {
		return fmt.Errorf("ERR_SCRIPT_SIG_INVALID: 脚本 %s 的身份背书验不过（内容 %s）",
			name, shortHash(res.sha256))
	}
	return nil
}

// routeScriptChunk 处理一片下行脚本帧（由 `Upstream.dispatch` 调用）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	c — 收到的脚本分片
//
// 返回：
//
//	error — 恒为 nil；这里不把校验失败当"帧处理失败"上抛，而是记进收片表让等待方看到
func (u *Upstream) routeScriptChunk(c *pb.ScriptChunk) error {
	u.deliverScriptChunk(c)
	return nil
}

// registerScriptBuf 为一次索取登记收片表。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	reqID — 本次索取的请求 ID
//
// 返回：
//
//	*scriptBuf — 该次索取的收片表（等待方持有它等唤醒）
func (u *Upstream) registerScriptBuf(reqID string) *scriptBuf {
	b := &scriptBuf{parts: map[int32][]byte{}, notify: make(chan struct{}, 1)}
	u.mu.Lock()
	u.scriptBufs[reqID] = b
	u.mu.Unlock()
	return b
}

// dropScriptBuf 注销收片表（索取结束，无论成败）。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	reqID — 本次索取的请求 ID
func (u *Upstream) dropScriptBuf(reqID string) {
	u.mu.Lock()
	delete(u.scriptBufs, reqID)
	u.mu.Unlock()
}

// deliverScriptChunk 把一片分片按 index 存进对应的收片表，并唤醒等待方。
//
// 校验在这里就地做完（crc32、总大小上限、片数上限），失败把原因写进收片表 ——
// 等待方下一次醒来就会看到错误，不需要另建一条错误通道。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	c — 收到的脚本分片
func (u *Upstream) deliverScriptChunk(c *pb.ScriptChunk) {
	u.mu.Lock()
	b := u.scriptBufs[c.GetReqId()]
	if b != nil {
		b.total = c.GetTotal()
		b.size = c.GetSize()
		b.sha256 = c.GetSha256()
		if r := c.GetReason(); r != "" {
			b.reason = r
		}
		if b.reason == "" {
			switch {
			case c.GetSize() > scriptMaxBytes:
				b.reason = fmt.Sprintf("脚本太大：父声明 %d 字节，上限 %d", c.GetSize(), scriptMaxBytes)
			case c.GetTotal() > maxScriptChunks:
				b.reason = fmt.Sprintf("分片过多：父声明 %d 片，上限 %d", c.GetTotal(), maxScriptChunks)
			case crc32.ChecksumIEEE(c.GetPayload()) != c.GetCrc32():
				b.reason = fmt.Sprintf("脚本第 %d 片 crc32 校验不过", c.GetIndex())
			case c.GetIndex() < 0 || (b.total > 0 && c.GetIndex() >= b.total):
				b.reason = fmt.Sprintf("分片号越界：index=%d total=%d", c.GetIndex(), b.total)
			default:
				b.parts[c.GetIndex()] = append([]byte(nil), c.GetPayload()...)
				// 背书只挂在最后一片上（见 proto 注释），这里照收；验签等收齐后由调用方做
				// （要对整份内容的哈希签，收齐之前无从验起）。
				if c.GetSignerId() != "" || len(c.GetSignature()) > 0 {
					b.signerID = c.GetSignerId()
					b.signature = append([]byte(nil), c.GetSignature()...)
				}
			}
		}
	}
	u.mu.Unlock()
	if b != nil {
		// 非阻塞唤醒：容量 1 的通道 + 等待方每次醒来都会把表读空，所以不会漏唤醒
		select {
		case b.notify <- struct{}{}:
		default:
		}
	}
}

// takeScriptBuf 尝试从收片表里取出完整结果。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	reqID — 本次索取的请求 ID
//
// 返回：
//
//	scriptResult — 本次索取的结论；还没收齐时 done 为 false
func (u *Upstream) takeScriptBuf(reqID string) scriptResult {
	u.mu.Lock()
	defer u.mu.Unlock()
	b := u.scriptBufs[reqID]
	if b == nil {
		return scriptResult{reason: "索取已被注销", done: true}
	}
	return b.result()
}

// failScriptWaits 让所有正在等脚本的索取立刻失败。
//
// 由会话结束时调用：不然等待方要一直等到指令自己的超时才醒 —— 明明已经知道不可能收到了。
//
// 接收者 u 是上行侧（客户端角色）的连接管理器。
//
// 参数：
//
//	reason — 写进收片表的原因（会出现在等待方的错误信息里）
func (u *Upstream) failScriptWaits(reason string) {
	u.mu.Lock()
	waits := make([]*scriptBuf, 0, len(u.scriptBufs))
	for _, b := range u.scriptBufs {
		if b.reason == "" {
			b.reason = reason
		}
		waits = append(waits, b)
	}
	u.mu.Unlock()
	for _, b := range waits {
		select {
		case b.notify <- struct{}{}:
		default:
		}
	}
}

// scriptBuf 收集一次脚本下发的多个分片（见 fetchScript 的说明）。
//
// 它由 `Upstream.mu` 保护 —— 字段虽小，但读写来自两个协程（会话读循环写、执行脚本的协程读）。
type scriptBuf struct {
	// total 父声明的总片数；0 = 还没收到任何片。
	total int32
	// size 父声明的整份字节数，收齐后用来校验长度。
	size int64
	// sha256 父声明的整份哈希（每片都带）。收齐后要拿它比对复算值，它也是父签名覆盖的那个值。
	sha256 string
	// parts 已收下的片，按 index 归位（因此允许乱序到达）。
	parts map[int32][]byte
	// signerID 父声明的签名者身份（只有最后一片带）。
	signerID string
	// signature 父对 (name, sha256) 的背书签名（只有最后一片带）。
	signature []byte
	// reason 非空 = 这次索取已经失败。
	reason string
	// notify 唤醒等待方；容量 1，用非阻塞发送。
	notify chan struct{}
}

// scriptResult 是一次脚本索取的结论：内容 + 父的背书，或失败原因。
//
// 单独有个类型是为了让"收片表算出的东西"能一次交给调用方 —— 验签要同时用到内容、哈希与签名，
// 分成几个 getter 取会把两次加锁之间的状态暴露出去。
type scriptResult struct {
	// data 收齐的脚本内容（仅在 done 且 reason 为空时有效）。
	data []byte
	// sha256 父声明的整份哈希（已用它比对过 data）。
	sha256 string
	// signerID 签名的声称者（父）NodeID。
	signerID string
	// signature 父对 (name, sha256) 的背书签名。
	signature []byte
	// reason 非空 = 这次索取已经失败。
	reason string
	// done 是否已经有结论（收齐或失败）。
	done bool
}

// result 判断这次索取有没有结论，并给出结果。
//
// 收齐时会顺手做两道**不需要父公钥**的校验：长度对不对、内容哈希与父声明的是否一致
// （后者正是签名覆盖的那个值，所以它不过就谈不上验签）。签名本身留给调用方验 ——
// 那需要父的公钥，收片表里没有（见 fetchScript）。
//
// 接收者 b 是收片表（调用方必须已持有 `Upstream.mu`）。
//
// 返回：
//
//	scriptResult — 收齐的内容与父的背书；还没齐时空结果（done=false）；失败时带 reason
func (b *scriptBuf) result() scriptResult {
	if b.reason != "" {
		return scriptResult{reason: b.reason, done: true}
	}
	if b.total <= 0 || int32(len(b.parts)) < b.total {
		return scriptResult{}
	}
	var out bytes.Buffer
	for i := int32(0); i < b.total; i++ {
		p, ok := b.parts[i]
		if !ok {
			return scriptResult{} // 理论上不会发生（上面已比对片数），保守处理
		}
		out.Write(p)
	}
	data := out.Bytes()
	if b.size > 0 && int64(len(data)) != b.size {
		return scriptResult{reason: fmt.Sprintf("脚本大小对不上：父声明 %d 字节，实收 %d 字节", b.size, len(data)), done: true}
	}
	if b.sha256 != "" {
		if got := hashBytes(data); got != b.sha256 {
			return scriptResult{reason: fmt.Sprintf("脚本内容与父声明的哈希不符：声明 %s，实收 %s", b.sha256, got), done: true}
		}
	}
	return scriptResult{
		data: data, sha256: b.sha256,
		signerID: b.signerID, signature: b.signature, done: true,
	}
}
