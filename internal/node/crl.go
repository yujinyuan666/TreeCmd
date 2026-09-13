package node

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
	"treecmd/internal/store"
)

// ---------- 吊销列表（CRL，7.7） ----------
//
// 口径：版本号由**该子节点的直接父**维护、单调递增；子只应用更高版本（防重放旧 CRL 回滚吊销状态）；
// 重连后发 CRLReq 取"当前版本全量"对齐（不依赖增量补齐）；DownFrame 由发送方身份密钥签名，
// 接收方按 4.5 四步校验 —— 否则中间人可篡改 CRL 把合法节点拉黑。

// loadCRL 从本地存储读出 CRL 版本与吊销 ID 集合，装进内存（启动时调用）。
//
// 接收者 n 是本节点实例。只加载不校验：数据本来就是本地落盘的；
// 版本号大于 0 时打一条 Info 日志。
func (n *Node) loadCRL() {
	var (
		ver   uint64
		guids []string
	)
	_ = n.Store.View(func(tx *store.Tx) error {
		ver, guids = tx.GetCRL()
		return nil
	})
	n.crlMu.Lock()
	if n.crlSet == nil {
		n.crlSet = map[string]bool{}
	}
	n.crlVersion = ver
	for _, g := range guids {
		n.crlSet[g] = true
	}
	n.crlMu.Unlock()
	if ver > 0 {
		n.Log.Info("CRL loaded", "version", ver, "revoked", len(guids))
	}
}

// isRevoked 该 NodeID 是否被吊销（服务端拦截器用）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	nodeID — 待判断的节点 ID
//
// 返回：在吊销集合里返回 true，否则 false。
func (n *Node) isRevoked(nodeID string) bool {
	n.crlMu.Lock()
	defer n.crlMu.Unlock()
	return n.crlSet[nodeID]
}

// crlSnapshot 返回当前 CRL 的版本号与吊销 ID 列表（加锁读取，列表已按字典序排序）。
//
// 接收者 n 是本节点实例。
//
// 返回：
//
//	版本号，以及排序后的吊销节点 ID 切片
func (n *Node) crlSnapshot() (uint64, []string) {
	n.crlMu.Lock()
	defer n.crlMu.Unlock()
	out := make([]string, 0, len(n.crlSet))
	for g := range n.crlSet {
		out = append(out, g)
	}
	sortStrings(out)
	return n.crlVersion, out
}

// Revoke 运维吊销某节点：写入本地 CRL 并推送给所有直接子。
//
// 接收者 n 是本节点实例；写入内存后版本号 +1，落盘，再打一条 AUDIT-REVOKE 日志。
//
// 参数：
//
//	nodeID — 要吊销的节点 ID；为空时返回 ERR_BAD_REQUEST
//
// 返回：落盘失败返回错误，否则 nil。
func (n *Node) Revoke(nodeID string) error {
	if nodeID == "" {
		return fmt.Errorf("ERR_BAD_REQUEST: empty node id")
	}
	n.crlMu.Lock()
	if n.crlSet == nil {
		n.crlSet = map[string]bool{}
	}
	n.crlSet[nodeID] = true
	n.crlVersion++
	ver := n.crlVersion
	guids := make([]string, 0, len(n.crlSet))
	for g := range n.crlSet {
		guids = append(guids, g)
	}
	n.crlMu.Unlock()
	sortStrings(guids)
	if err := n.Store.Update(func(tx *store.Tx) error { return tx.PutCRL(ver, guids) }); err != nil {
		return err
	}
	n.Log.Warn("AUDIT-REVOKE", "node", shortID(nodeID), "version", ver)
	if n.hub != nil {
		for _, c := range n.Reg.Snapshot() {
			n.pushCRL(c.NodeID)
		}
	}
	return nil
}

// crlPayload 拼接 CRL 的"待签名内容"：版本、签发者、吊销 ID 列表、签发时间。
//
// 参数：
//
//	rl — 吊销列表；Sig 字段本身不参与，签名与验签双方各算一次
//
// 返回：canon 编码后的字节串。
func (n *Node) crlPayload(rl *pb.RevocationList) []byte {
	w := canon.NewWriter().U64(rl.Version).Str(rl.SignerId)
	for _, g := range rl.Guids {
		w.Str(g)
	}
	if rl.IssuedAt != nil {
		w.I64(rl.IssuedAt.Seconds)
	}
	return w.Out()
}

// pushCRL 向某子推送当前 CRL（DownFrame；父无法对子发起 RPC）。
//
// 接收者 n 是本节点实例；用本节点身份密钥签好 Sig 后交给 hub 下发。
//
// 参数：
//
//	childID — 目标直接子节点 ID
//
// 当前 CRL 版本为 0（还没吊销过任何节点）时不推送。
func (n *Node) pushCRL(childID string) {
	ver, guids := n.crlSnapshot()
	if ver == 0 {
		return
	}
	rl := &pb.RevocationList{Version: ver, Guids: guids, SignerId: n.C().Node.ID, IssuedAt: canon.TS(time.Now())}
	rl.Sig = identity.Sign(n.Id().Key, n.crlPayload(rl))
	if n.hub != nil {
		n.hub.sendCRL(childID, rl)
	}
}

// applyCRL 收到 CRL：验签（父身份密钥）→ 只应用更高版本 → 落盘 + 下发给自己子树。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	fromID  — 发送方（直接父）的节点 ID，必须与 rl.SignerId 一致
//	fromPub — 发送方的 ed25519 公钥，用于验签
//	rl      — 收到的吊销列表
//
// 返回：身份 / 签名不符或落盘失败时返回错误；版本不高于本地时静默忽略并返回 nil。
func (n *Node) applyCRL(fromID string, fromPub ed25519.PublicKey, rl *pb.RevocationList) error {
	if rl.SignerId != fromID {
		return fmt.Errorf("ID_MISMATCH: CRL signer %s != peer %s", shortID(rl.SignerId), shortID(fromID))
	}
	if len(fromPub) == 0 || !identity.Verify(fromPub, n.crlPayload(rl), rl.Sig) {
		return fmt.Errorf("SIG_INVALID: CRL 验签失败")
	}
	n.crlMu.Lock()
	if rl.Version <= n.crlVersion {
		n.crlMu.Unlock()
		return nil // 只应用更高版本（防重放旧 CRL 回滚吊销状态）
	}
	set := map[string]bool{}
	for _, g := range rl.Guids {
		set[g] = true
	}
	n.crlVersion = rl.Version
	n.crlSet = set
	n.crlMu.Unlock()
	if err := n.Store.Update(func(tx *store.Tx) error { return tx.PutCRL(rl.Version, rl.Guids) }); err != nil {
		return err
	}
	n.Log.Warn("CRL updated", "version", rl.Version, "revoked", len(rl.Guids), "from", shortID(fromID))
	// 沿自己的下行流继续向下转发（子缓存并继续转发）
	if n.hub != nil {
		for _, c := range n.Reg.Snapshot() {
			n.pushCRL(c.NodeID)
		}
	}
	return nil
}

// sortStrings 对字符串切片做原地插入排序（升序），用于输出前得到稳定顺序。
//
// 参数：
//
//	s — 待排序切片，函数直接修改它并返回
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
