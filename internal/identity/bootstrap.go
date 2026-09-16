// Package identity —— 入网引导凭据（bootstrap credential）。
//
// 部署一个子节点需要两样"从父那里拿来的东西"：
//  1. **许可**（permit）：证明"父授权我进来" —— 唯一能回答"父要不要收我"的凭据；
//  2. **父的 CA 证书链**：首跳时必须能把父的服务端证书验到某个锚（否则谁都能冒充父发证书）。
//
// 这两样都由父产出、都要拷给子节点。它们**职责不同、不能互相替代**（许可管授权、CA 管身份），
// 但可以装进**同一份文件** —— 于是"部署一个子节点"从"拷两个东西"变成"拷一份凭据"。
// 本文件就是那份文件的格式定义与解析器，**格式的权威定义只在这里**（脚本产出、程序解析）。
//
// 格式（纯文本，UTF-8；行序无关）：
//
//	# 以 # 开头的行与空行：注释，忽略
//	permit=<入网许可串>          # 必需；值取本行 '=' 之后去掉首尾空白的内容
//	-----BEGIN CERTIFICATE-----  # 可选、可多段：父的 CA 证书链（PEM），
//	...                          # 内容含父 CA 一路到根
//	-----END CERTIFICATE-----
//
// 兼容：整个文件只有一行普通文本时（历史上 enroll.token 就是"一行裸许可串"），
// 那一行被当成 permit。**未知的 key=value 行会直接报错**，不会静默忽略 ——
// 一个拼错的 `permt=` 必须当场暴露，否则表现成"许可莫名其妙不对"，极难查。
package identity

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Bootstrap 一份入网引导凭据的解析结果。
type Bootstrap struct {
	// Permit 入网许可串。空串表示"这份凭据没提供许可"—— 父端据此拒绝一切入网，
	// 子端据此提前失败（父端一定会拒）。
	Permit string
	// Anchors 凭据里内嵌的信任锚（父的 CA 证书链，含父 CA 一路到根）。
	// 为空表示"这份凭据没带锚"—— 此时信任锚只能来自 security.ca_cert_paths
	// 或本节点自己的证书链（见 ChainAnchors）。
	Anchors []*x509.Certificate
}

// kvLine 匹配"看起来像个配置键"的行（`key=value`，key 是标识符）。
// 用它把"未知键"与"裸许可串"区分开：`permt=xxx` 报错，`7f3a9c…` 当许可。
var kvLine = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// ParseBootstrap 解析一份入网引导凭据 —— 该格式**唯一**的解析入口（格式见包注释）。
//
// 参数：
//
//	data — 凭据文件内容；也接受"直接写在配置里的许可串"（裸串形态）
//
// 返回：
//
//	*Bootstrap — 解析出的许可与锚。两者都可以为空（空凭据是合法输入，
//	             够不够用由调用方按角色判定：父端没许可就拒绝一切入网，子端没许可就提前失败）
//	error — 未知键 / permit 重复 / PEM 块不完整或不是 CERTIFICATE / 证书解析失败 /
//	        出现多行裸文本时返回（一律 fail-fast，不静默忽略）
func ParseBootstrap(data []byte) (*Bootstrap, error) {
	out := &Bootstrap{}
	permitSet := false
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(strings.TrimRight(lines[i], "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// PEM 证书块：从 BEGIN 行累积到 END 行，整块交给 pem.Decode
		if strings.HasPrefix(trimmed, "-----BEGIN") {
			blob, closed := "", false
			for ; i < len(lines); i++ {
				l := strings.TrimRight(lines[i], "\r")
				blob += l + "\n"
				if strings.HasPrefix(strings.TrimSpace(l), "-----END") {
					closed = true
					break
				}
			}
			if !closed {
				return nil, errors.New("引导凭据里的 PEM 块没有结束行（-----END CERTIFICATE-----）")
			}
			block, _ := pem.Decode([]byte(blob))
			if block == nil || block.Type != "CERTIFICATE" {
				return nil, errors.New("引导凭据里的 PEM 块不是 CERTIFICATE")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("引导凭据里的证书无法解析: %w", err)
			}
			out.Anchors = append(out.Anchors, cert)
			continue
		}
		if kvLine.MatchString(trimmed) {
			k, v, _ := strings.Cut(trimmed, "=")
			if k != "permit" {
				return nil, fmt.Errorf("引导凭据里有未知的键 %q（只支持 permit；证书请用 PEM 块）", k)
			}
			if permitSet {
				return nil, errors.New("引导凭据里 permit 出现了多次")
			}
			out.Permit = strings.TrimSpace(v)
			permitSet = true
			continue
		}
		// 普通文本行：兼容"一行裸许可串"的历史形态
		if permitSet {
			return nil, errors.New("引导凭据里出现了多余的文本行（裸文本只允许作为唯一一行许可）")
		}
		out.Permit = trimmed
		permitSet = true
	}
	return out, nil
}

// CredentialEmpty 报告一份凭据是否"什么都没有"（既无许可也无锚）。
//
// 接收者 b 是解析结果；b 为 nil 时视为空。
//
// 返回：
//
//	bool — Permit 为空且 Anchors 为空时为 true
func (b *Bootstrap) CredentialEmpty() bool {
	return b == nil || (b.Permit == "" && len(b.Anchors) == 0)
}
