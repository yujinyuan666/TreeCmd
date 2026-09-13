package node

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"treecmd/internal/canon"
	"treecmd/internal/identity"
	"treecmd/internal/pb"
)

// 跨跳请求的原始身份传递（ReqAuth，见 3.14 / ADR-048）。
//
// 为什么需要它：健康检查与结果查询都走 Connect 流**逐跳转发**，中间节点只看得见它的直接父 / 直接子。
// 请求里只有 reqID 与参数、没有"原始调用者是谁"，于是 `health_viewers` / `query_viewers` 非空时
// 中间节点**根本判不了**。修法是让请求携带一份"自包含、可离线验证的委托凭证"：
// 入口用自己的身份密钥签一份短时委托，任一跳用**预置的根证书**离线验链 + 验签即可拿到 ViewerID。
const (
	reqAuthKindHealth uint32 = 1
	reqAuthKindQuery  uint32 = 2
)

// reqAuthParams 计算委托凭证里绑定的"参数摘要"。
//
// 输入口径只绑定**跨跳不变的参数**（command_id / detail / Kind），
// 绝不含 depth / timeout_ms —— 它们逐跳递减，一绑上去每跳必然验签失败。
//
// 参数：
//
//	commandID — 指令 ID
//	detail    — 是否要明细
//	kind      — 委托用途（reqAuthKindHealth / reqAuthKindQuery）
//
// 返回：canon 编码后的摘要字节串。
func reqAuthParams(commandID string, detail bool, kind uint32) []byte {
	w := canon.NewWriter().Str(commandID).Bool(detail).U64(uint64(kind))
	return w.DigestOf()
}

// reqAuthPayload 拼接委托凭证的"待签名内容"（除 EntrySig 之外的全部字段）。
//
// 参数：
//
//	ra — 委托凭证；Viewer / Entry 的身份与证书、签发与过期时间、用途、参数摘要都会参与
//
// 返回：确定性编码（canon）后的字节串，签名方与验签方用它保证内容一致。
func reqAuthPayload(ra *pb.ReqAuth) []byte {
	w := canon.NewWriter()
	w.Str(ra.ViewerId).Bytes(ra.ViewerCertFp).Str(ra.EntryId).Bytes(ra.EntryCert)
	if ra.IssuedAt != nil {
		w.I64(ra.IssuedAt.Seconds).I64(int64(ra.IssuedAt.Nanos))
	}
	if ra.NotAfter != nil {
		w.I64(ra.NotAfter.Seconds).I64(int64(ra.NotAfter.Nanos))
	}
	w.U64(uint64(ra.Kind)).Bytes(ra.ParamsHash)
	return w.Out()
}

// makeReqAuth 入口生成委托凭证（一次生成，逐跳原样透传；转发者不得改写）。
//
// 接收者 n 是本节点实例。ViewerID 取入口自身身份：本实现的 HTTP 入口没有 mTLS，无法区分真实调用方。
//
// 参数：
//
//	commandID — 指令 ID
//	detail    — 是否要明细
//	kind      — 委托用途（reqAuthKindHealth / reqAuthKindQuery）
//
// 返回：已用本节点身份密钥签好 EntrySig 的 *pb.ReqAuth。
func (n *Node) makeReqAuth(commandID string, detail bool, kind uint32) *pb.ReqAuth {
	now := time.Now()
	ra := &pb.ReqAuth{
		ViewerId:     n.C().Node.ID, // 本实现的 HTTP 入口无 mTLS ⇒ 以入口自身身份代表调用方
		ViewerCertFp: identity.Fingerprint(n.Id().Cert),
		EntryId:      n.C().Node.ID,
		EntryCert:    chainPEM(n.Id().Chain),
		IssuedAt:     canon.TS(now),
		NotAfter:     canon.TS(now.Add(n.C().Query.ReqAuthTTL)),
		Kind:         kind,
		ParamsHash:   reqAuthParams(commandID, detail, kind),
	}
	ra.EntrySig = identity.Sign(n.Id().Key, reqAuthPayload(ra))
	return ra
}

// chainPEM 把证书链编码成 PEM 字节串（多个 CERTIFICATE 块依次拼接）。
//
// 参数：
//
//	chain — 证书链，chain[0] 是叶子 / 身份证书
//
// 返回：PEM 编码结果；链为空时返回 nil。
func chainPEM(chain []*x509.Certificate) []byte {
	var out []byte
	for _, c := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// verifyReqAuth 每跳离线验证委托凭证：**不需要回连入口**。
//
// 接收者 n 是本节点实例。用预置根证书验 EntryCert 链 + 验 EntrySig，
// 再依次检查 NotAfter / Kind / ParamsHash，任何一步不过都返回错误。
//
// 参数：
//
//	ra        — 委托凭证
//	commandID — 指令 ID（用于重算参数摘要）
//	detail    — 是否要明细（用于重算参数摘要）
//	kind      — 本跳期望的委托用途
//
// 返回：全部校验通过时返回原始调用者 ViewerID，否则返回错误。
func (n *Node) verifyReqAuth(ra *pb.ReqAuth, commandID string, detail bool, kind uint32) (string, error) {
	if ra == nil {
		return "", errors.New("ERR_UNAUTHORIZED_REQUEST: 缺少 ReqAuth 委托凭证")
	}
	chain, err := parsePEMChain(ra.EntryCert)
	if err != nil || len(chain) == 0 {
		return "", fmt.Errorf("CERT_UNTRUSTED: EntryCert 解析失败: %v", err)
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots: n.rootsPool(), Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return "", fmt.Errorf("CERT_UNTRUSTED: %w", err)
	}
	pub, ok := chain[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("CERT_UNTRUSTED: EntryCert 不是 ed25519")
	}
	if !identity.Verify(pub, reqAuthPayload(ra), ra.EntrySig) {
		return "", errors.New("SIG_INVALID: EntrySig 验签失败")
	}
	if ra.NotAfter != nil && time.Now().After(canon.Time(ra.NotAfter)) {
		return "", errors.New("ERR_UNAUTHORIZED_REQUEST: 委托已过期")
	}
	if ra.Kind != kind {
		return "", fmt.Errorf("ERR_UNAUTHORIZED_REQUEST: 委托用途不符（got %d want %d）", ra.Kind, kind)
	}
	if string(reqAuthParams(commandID, detail, kind)) != string(ra.ParamsHash) {
		return "", errors.New("ERR_UNAUTHORIZED_REQUEST: 参数摘要不匹配（委托被用于别的请求）")
	}
	return ra.ViewerId, nil
}

// auditReject 记录一次"被拒绝的请求"：拒绝类事件必须落审计日志并单独告警
// （它们是"有人在试探"的最早信号）。
//
// 接收者 n 是本节点实例；同时把 untrusted_origin_rejected_total 指标 +1。
//
// 参数：
//
//	kind   — 拒绝环节（如 query_req_auth / query_viewers）
//	viewer — 原始调用者 ID（未知时传空串）
//	cmdID  — 相关指令 ID（可为空）
//	err    — 拒绝原因
func (n *Node) auditReject(kind, viewer, cmdID string, err error) {
	n.Log.Warn("AUDIT-REJECT", "kind", kind, "viewer", shortID(viewer), "cmd", shortID(cmdID), "err", err)
	n.Metrics.Inc("untrusted_origin_rejected_total")
}

// checkReqAuth 查询请求的逐跳校验：验委托 + 按**自己的** query_viewers 决定是否服务 / 转发。
//
// 接收者 n 是本节点实例；验签失败或白名单不通过时都会走 auditReject 落审计。
//
// 参数：
//
//	req — 查询请求；其中 req.ReqAuth 是入口签发的委托凭证
//
// 返回：校验与白名单都通过返回 nil，否则返回错误。
func (n *Node) checkReqAuth(req *pb.QueryReq) error {
	viewer, err := n.verifyReqAuth(req.ReqAuth, req.CommandId, false, reqAuthKindQuery)
	if err != nil {
		n.auditReject("query_req_auth", "", req.CommandId, err)
		return err
	}
	if !n.allowedQueryViewer(viewer) {
		err := fmt.Errorf("ERR_UNAUTHORIZED_REQUEST: viewer %s 不在 query_viewers", shortID(viewer))
		n.auditReject("query_viewers", viewer, req.CommandId, err)
		return err
	}
	return nil
}

// checkHealthReqAuth 健康 / 轨迹请求的逐跳校验：验委托 + 按本节点自己的 health_viewers 决定是否服务。
//
// 接收者 n 是本节点实例；默认白名单只允许直接父与 root（root 走祖先链判断）。
//
// 参数：
//
//	req — 健康请求；其中 req.ReqAuth 是入口签发的委托凭证
//
// 返回：校验与白名单都通过返回 nil，否则返回错误。
func (n *Node) checkHealthReqAuth(req *pb.HealthReq) error {
	viewer, err := n.verifyReqAuth(req.ReqAuth, req.CommandId, req.Detail, reqAuthKindHealth)
	if err != nil {
		n.auditReject("health_req_auth", "", req.CommandId, err)
		return err
	}
	if !n.allowedHealthViewer(viewer) {
		err := fmt.Errorf("ERR_UNAUTHORIZED_REQUEST: viewer %s 不在 health_viewers（默认只允许直接父与 root）", shortID(viewer))
		n.auditReject("health_viewers", viewer, req.CommandId, err)
		return err
	}
	return nil
}

// isAncestorID 判断某 NodeID 是否在本节点的祖先链上（默认白名单里的 root 走这条）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	nodeID — 待判断的节点 ID
//
// 返回：在祖先链上返回 true，否则 false。
func (n *Node) isAncestorID(nodeID string) bool {
	for _, a := range n.AncestorIDs() {
		if a == nodeID {
			return true
		}
	}
	return false
}
