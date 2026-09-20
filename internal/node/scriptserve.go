package node

import (
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"time"

	"treecmd/internal/buildinfo"
	"treecmd/internal/exec/script"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
)

const (
	// scriptMaxBytes 单次脚本下发的大小上限（1MB）。
	//
	// 脚本是"小东西"：真需要几 MB 的资源请走别的渠道。给上限是为了让一个失控的脚本目录
	// 不会变成一条"任人取用的文件通道"。
	scriptMaxBytes int64 = 1 << 20

	// maxScriptChunks 单次脚本下发允许的最大片数（与 scriptMaxBytes / scriptChunkSize 匹配，
	// 留足余量）。收片方用它挡住"父声明一个天文数字的片数"这种打法。
	maxScriptChunks int32 = 4096

	// scriptChunkSize 脚本分片的片大小。
	//
	// 比 selfupdate 的默认片大小小一个量级：脚本本身就小（≤1MB），片太大最后一片会浪费得多。
	scriptChunkSize int64 = 64 << 10

	// scriptServeTimeout 一次脚本下发的总时限。
	scriptServeTimeout = 30 * time.Second
)

// canServeScript 判断能不能把本节点的脚本发给这条子连接。
//
// 口径与 canServeBinary 完全一致：**只对本节点 CA 签发的直接子开放**。
// cc.leaf 是 mTLS 握手拿到的对端叶子证书，用它验"是不是我签的"。
//
// 参数：
//
//	cc — 申请方的连接
//
// 返回：
//
//	error — 没有对端证书 / 本节点没有 CA / 对端不是本节点签发的直接子时返回
func (n *Node) canServeScript(cc *childConn) error {
	if cc == nil || cc.leaf == nil {
		return errors.New("ERR_SCRIPT_NO_CERT")
	}
	ca := n.Id().CACert
	if ca == nil {
		return errors.New("ERR_SCRIPT_NO_CA")
	}
	if err := cc.leaf.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("ERR_SCRIPT_NOT_DIRECT_CHILD: %w", err)
	}
	return nil
}

// serveScript 把本节点 script/ 目录里的一个脚本发给申请的直接子。
//
// 由 `Hub.dispatch` 起在独立协程里跑，不阻塞读循环。
//
// 它要顶住三类输入校验，缺一不可：
//
//  1. **名字白名单**（script.ValidName）—— 挡住 `../../keys/id_ed25519` 这种路径穿越；
//  2. **符号链接不能逃出脚本目录**（script.ResolveInDir）—— 名字合法但指向目录外的链接一样要拒，
//     否则身份私钥会被当成脚本发给全树；
//  3. **哈希必须与申请方期望的一致** —— 申请方拿到的哈希来自指令载荷（已被 origin 签名），
//     这里复核一遍，避免"申请到一份变了的内容"。
//
// 通过校验后，本节点还会用自己的**身份私钥**给这份脚本签一份背书（`script.SignMessage`），
// 附在最后一片上 —— 子端据此确认"这份字节确实是我父给的"。签名只做归因，不做防篡改
// （内容对不对由哈希比对负责，见 script 包文档）。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc  — 发起申请的子连接
//	req — 申请内容（req_id / name / want_sha256 / max_bytes）
func (h *Hub) serveScript(cc *childConn, req *pb.ScriptReq) {
	n := h.n
	reqID := req.GetReqId()

	// fail 回一片"出错终止片"（无载荷 + 原因），子端据此立刻结束这次索取
	fail := func(result, reason string) {
		n.Metrics.Inc("script_serve_total", "result", result)
		h.sendScriptChunk(cc, &pb.ScriptChunk{ReqId: reqID, Name: req.GetName(), Final: true, Reason: reason})
	}

	if err := n.canServeScript(cc); err != nil {
		n.Log.Warn("拒绝子的脚本申请", "child", shortID(cc.nodeID), "err", err)
		fail("rejected", err.Error())
		return
	}
	if err := script.ValidName(req.GetName()); err != nil {
		n.Log.Warn("拒绝非法脚本名", "child", shortID(cc.nodeID), "name", req.GetName(), "err", err)
		fail("rejected", "ERR_SCRIPT_BAD_NAME: "+err.Error())
		return
	}
	dir := n.scriptDir()
	path, err := script.ResolveInDir(dir, req.GetName())
	if err != nil {
		n.Log.Warn("申请方要的脚本本节点没有", "child", shortID(cc.nodeID), "name", req.GetName(), "err", err)
		fail("rejected", "ERR_SCRIPT_NOT_FOUND: "+err.Error())
		return
	}
	hash, size, _, err := buildinfo.HashFile(path)
	if err != nil {
		n.Log.Warn("读脚本失败，拒绝下发", "name", req.GetName(), "err", err)
		fail("error", "ERR_SCRIPT_READ_FAILED")
		return
	}
	if want := req.GetWantSha256(); want != "" && want != hash {
		n.Log.Warn("申请方要的是另一个版本的脚本，拒绝", "child", shortID(cc.nodeID),
			"name", req.GetName(), "want", shortHash(want), "have", shortHash(hash))
		fail("rejected", "ERR_SCRIPT_HASH_MISMATCH")
		return
	}
	maxBytes := scriptMaxBytes
	if mb := req.GetMaxBytes(); mb > 0 && mb < maxBytes {
		maxBytes = mb
	}
	if size > maxBytes {
		n.Log.Warn("脚本超过大小上限，拒绝下发", "name", req.GetName(), "bytes", size, "limit", maxBytes)
		fail("rejected", "ERR_SCRIPT_TOO_LARGE")
		return
	}

	f, err := os.Open(path)
	if err != nil {
		fail("error", "ERR_SCRIPT_OPEN_FAILED")
		return
	}
	defer f.Close()

	total := int32((size + scriptChunkSize - 1) / scriptChunkSize)
	if total == 0 {
		total = 1 // 空脚本也给一片：子端靠"收齐 total 片"判定结束
	}
	// 本节点的身份背书：对 (脚本名, 整份哈希) 签一次，只挂在最后一片上。
	//
	// 为什么现在签：签名覆盖的是**整份内容**的哈希，只有读完整个文件、算出 hash 之后才谈得上签；
	// 而子端也只有在收齐之后才能复算哈希去验 —— 所以两边都落在"最后一片"这个时刻上。
	signerID := n.Id().NodeID
	sig := identity.Sign(n.Id().Key, script.SignMessage(req.GetName(), hash))

	ctx, cancel := context.WithTimeout(context.Background(), scriptServeTimeout)
	defer cancel()

	n.Log.Info("开始向子下发脚本", "child", shortID(cc.nodeID), "name", req.GetName(),
		"sha256", shortHash(hash), "bytes", size, "chunks", total, "signer", shortID(signerID))
	buf := make([]byte, scriptChunkSize)
	off := int64(0)
	for i := int32(0); i < total; i++ {
		want := scriptChunkSize
		if rest := size - off; rest < want {
			want = rest
		}
		if want < 0 {
			want = 0
		}
		payload := buf[:want]
		if want > 0 {
			if _, err := io.ReadFull(f, payload); err != nil {
				n.Log.Error("读脚本失败，中断下发", "name", req.GetName(), "err", err, "offset", off)
				fail("error", "ERR_SCRIPT_READ_FAILED")
				return
			}
		}
		last := i == total-1
		chunk := &pb.ScriptChunk{
			ReqId: reqID, Name: req.GetName(), Sha256: hash, Size: size,
			Index: i, Total: total, Offset: off,
			Payload: append([]byte(nil), payload...), Crc32: crc32.ChecksumIEEE(payload),
			Final: last,
		}
		if last {
			chunk.SignerId = signerID
			chunk.Signature = sig
		}
		if err := cc.sendThrottled(ctx, &pb.DownFrame{ProtoVersion: protoVersion,
			Frame: &pb.DownFrame_ScriptChunk{ScriptChunk: chunk}}); err != nil {
			n.Log.Warn("下发脚本分片失败", "child", shortID(cc.nodeID), "err", err, "index", i)
			n.Metrics.Inc("script_serve_total", "result", "error")
			return
		}
		off += int64(len(payload))
	}
	n.Metrics.Inc("script_serve_total", "result", "sent")
	n.Log.Info("脚本下发完成", "child", shortID(cc.nodeID), "name", req.GetName(), "bytes", off)
}

// sendScriptChunk 发一片下行脚本帧。
//
// 只用于"出错终止片"这类单片消息 —— 正常分片走 sendThrottled 才有回压。
//
// 接收者 h 是下行侧（服务端）的连接管理器。
//
// 参数：
//
//	cc    — 目标子连接
//	chunk — 要发的那一片
func (h *Hub) sendScriptChunk(cc *childConn, chunk *pb.ScriptChunk) {
	if cc == nil {
		return
	}
	_ = cc.send(&pb.DownFrame{ProtoVersion: protoVersion, Frame: &pb.DownFrame_ScriptChunk{ScriptChunk: chunk}})
}
