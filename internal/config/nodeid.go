package config

// node.id 的解析（ADR-050）。
//
// 目标：`node.id` 不必由人预先编好（新节点上线不用先手工编个 UUID 再去签发证书），
// 同时**绝不给 ADR-005 开口子** —— 程序对 `node.yaml` 始终只读。
//
// 于是 ID 的"运行时归宿"是 state.dat（`self.id`），而**证书一旦签发就成为权威来源**：
//
//	1. `node.yaml` 里的 `node.id` —— 显式指定，最高优先；程序**永不改写它**
//	2. 已签发证书的身份（CN 优先、SAN URI 兜底）—— 证书就是身份，与它对齐才可能过硬校验
//	3. state.dat 的 `self.id` —— "还没证书"那段窗口里的身份锚点（跨重启稳定）
//	4. 都没有 → 生成 UUIDv7（**只存在于内存**；节点启动会把 `self.id` 落进 state.dat，从此稳定）
//
// 本文件只做"读 + 决定"，**不写任何文件**：state.dat 由 internal/node 在启动时统一落盘
// （且必须在"上线前"落，否则首启 30s 内崩溃会换掉身份）。

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"treecmd/internal/identity"
)

// NodeIDSource 说明本次 node.id 是从哪来的。
type NodeIDSource string

const (
	// IDFromConfig 由 node.yaml 显式指定。
	IDFromConfig NodeIDSource = "config"
	// IDFromCert 取自已签发证书的身份。
	IDFromCert NodeIDSource = "cert"
	// IDFromState 取自 state.dat 的 self.id。
	IDFromState NodeIDSource = "state"
	// IDFromGenerated 本次新生成（尚未落盘；节点启动会写进 state.dat）。
	IDFromGenerated NodeIDSource = "generated"
)

// NodeIDResolve 解析结论。
type NodeIDResolve struct {
	NodeID string
	Source NodeIDSource
	// 以下为诊断信息（供启动日志 / `-check` 提示，不参与任何判定）
	StatePath string // 本节点 state.dat 的实际路径
	CertID    string // 证书身份（证书不存在时为空）
	StateID   string // state.dat 里记录的 id（不存在时为空）
	Warning   string // 证书与 state.dat 身份不一致等需要提醒的情况
}

// 最小化读取 state.dat：只取 self.id（不 import persist，避免与它的读写语义耦合）。
type stateIDProbe struct {
	Self struct {
		ID string `json:"id"`
	} `json:"self"`
}

// resolveNodeID 解析本节点的 NodeID，并说明这个 ID 是从哪来的。cfg 必须已经过 applyDefaults（路径已是绝对路径）。
//
// 优先级从高到低（ADR-050）：
//
//  1. node.yaml 里显式写了 node.id
//  2. 已签发证书的身份（CN 优先、SAN URI 兜底）—— 证书就是身份，与它对齐才过得了启动强校验
//  3. state.dat 里记录的 self.id —— "还没证书"那段窗口里的身份锚点
//  4. 都没有则新生成 UUIDv7（只存在于内存，尚未落盘）
//
// 本函数**只读不写**：state.dat 由 internal/node 在启动时统一落盘。
// 若证书与 state.dat 身份不一致，以证书为准并把差异写进 Warning（state.dat 会在启动时被更正）。
//
// 参数：
//
//	cfgPath — node.yaml 的路径；仅作为相对路径的兜底解析基准
//	c       — 已过 applyDefaults 的配置
//
// 返回：
//
//	NodeIDResolve — 解析结论；NodeID 为空表示连 UUIDv7 都没生成出来（CSPRNG 不可用），交给 Validate 报错
func resolveNodeID(cfgPath string, c *Config) NodeIDResolve {
	res := NodeIDResolve{StatePath: c.Persist.StatePath}

	// 1) 显式写定
	if id := strings.TrimSpace(c.Node.ID); id != "" {
		res.NodeID, res.Source = id, IDFromConfig
		return res
	}

	// 2) 已签发证书的身份
	if certID, ok := certIdentityOf(cfgPath, c.Security.IdentityCertPath); ok {
		res.CertID = certID
		// 3) state.dat（只用于比对 + 提示，不覆盖证书）
		if st := readStateNodeID(c.Persist.StatePath); st != "" {
			res.StateID = st
			if st != certID {
				res.Warning = fmt.Sprintf(
					"state.dat 记录的 node.id（%s）与证书身份（%s）不一致；以证书为准（否则必然过不了启动强校验）。"+
						"state.dat 会在启动时被更正。", st, certID)
			}
		}
		res.NodeID, res.Source = certID, IDFromCert
		return res
	}

	// 4) state.dat
	if st := readStateNodeID(c.Persist.StatePath); st != "" {
		res.StateID = st
		res.NodeID, res.Source = st, IDFromState
		return res
	}

	// 5) 新生成（内存态）
	id, err := identity.NewNodeID()
	if err != nil {
		// 走到这里说明 CSPRNG 都不可用；让上层拿到一个空 ID，由 Validate 报错
		return res
	}
	res.NodeID, res.Source = id, IDFromGenerated
	return res
}

// readStateNodeID 从 state.dat 里只读出 self.id。
//
// 刻意用一个最小化的结构体来解析（而不是 import persist），避免和 persist 包的读写语义耦合；
// 文件不存在、JSON 损坏、字段为空这三种情况一律当作"没有"返回空串，不报错。
//
// 参数：
//
//	path — state.dat 的路径
//
// 返回：
//
//	string — 文件里的 self.id；读不到或解析不出时为空串
func readStateNodeID(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var p stateIDProbe
	if err := json.Unmarshal(b, &p); err != nil {
		return ""
	}
	return strings.TrimSpace(p.Self.ID)
}

// certIdentityOf 读已有证书并取其身份（CN 优先、SAN URI 兜底）。
// 返回 ok=false 表示"没有可用证书"（文件不存在 / 解析不出 / 空链）。
//
// 实现上只取该文件里第一段类型为 CERTIFICATE 的 PEM 块来解析；
// 解析出来的身份为空也按"没有"处理。
//
// 参数：
//
//	cfgPath  — node.yaml 的路径；certPath 是相对路径时以它所在目录为基准
//	certPath — 身份证书路径；为空时兜底用 "certs/node.crt"（与 applyDefaults 的约定一致）
//
// 返回：
//
//	string — 证书里的 NodeID
//	bool   — true 表示确实取到了可用身份
func certIdentityOf(cfgPath, certPath string) (string, bool) {
	full := strings.TrimSpace(certPath)
	if full == "" {
		full = "certs/node.crt" // 与 applyDefaults 的约定一致（调用点已过 defaults，这里只是兜底）
	}
	if !filepath.IsAbs(full) {
		full = filepath.Join(filepath.Dir(cfgPath), full)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", false
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return "", false
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return "", false
		}
		if id := identity.NodeIDFromCert(c); id != "" {
			return id, true
		}
		return "", false
	}
}
