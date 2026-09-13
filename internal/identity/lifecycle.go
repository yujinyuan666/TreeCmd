// Package identity —— 证书生命周期与运行期入网签发。
//
// 本文件解决两件部署期问题（见 README「证书生命周期」）：
//  1. **证书与密钥由外部脚本管理**：程序只负责"发现文件变了就把新证书/新信任锚吃进来"，
//     所以需要「文件变更摘要 + 目录信任锚 + 可热替换的 TLS 材料」这三样原语。
//  2. **子节点没有自带证书**：靠「运行期入网」向父换取 —— 父只签**公钥**，
//     私钥全程留在子机本地，程序既不生成也不接收任何私钥。
package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// 入网握手的身份标记
// ---------------------------------------------------------------------------

// EnrollSNIPrefix 入网握手专用的 SNI 标记。
//
// 为什么用 SNI 而不是 ALPN：ALPN 一旦协商成非 "h2" 的值，gRPC 的 HTTP/2 传输层会直接拒收
// （它要求协商结果就是 h2）。SNI 是 ClientHello 里本就可自由设置的字段，而我们全程用
// "信任锚 + 身份断言"做证书校验（不做主机名校验），所以拿它当携带标记的成本最低。
const EnrollSNIPrefix = "enroll."

// EnrollServerName 构造入网握手用的 SNI：EnrollSNIPrefix + 父 NodeID，便于父端审计"谁在申请入网"。
func EnrollServerName(parentNodeID string) string { return EnrollSNIPrefix + parentNodeID }

// IsEnrollServerName 判断一个 SNI 是否表示入网握手（是否以 EnrollSNIPrefix 开头）。
func IsEnrollServerName(name string) bool { return strings.HasPrefix(name, EnrollSNIPrefix) }

// POPMessage 拼出"私钥持有证明"（Proof of Possession）的待签内容。
//
// 内容按 nonce \0 parentNodeID \0 nodeID 拼接，用 0 字节做分隔以免相邻字段黏连产生歧义。
// 同时绑定这三者是为了防重放（nonce）、防跨父重放（父 NodeID）、防冒用身份（子 NodeID）：
// 光有一个入网 token 不足以让别人替你申请证书，攻击者还必须持有对应的私钥。
//
// 参数：
//
//	nonce — 服务端下发的一次性随机数，用于防重放
//	parentNodeID — 目标父节点的 NodeID，用于防跨父重放
//	nodeID — 申请入网的子节点 NodeID，用于防冒用身份
//
// 返回：
//
//	[]byte — 子节点应当用自己私钥签名的字节串
func POPMessage(nonce []byte, parentNodeID, nodeID string) []byte {
	buf := make([]byte, 0, len(nonce)+len(parentNodeID)+len(nodeID)+32)
	buf = append(buf, nonce...)
	buf = append(buf, 0)
	buf = append(buf, parentNodeID...)
	buf = append(buf, 0)
	buf = append(buf, nodeID...)
	return buf
}

// ---------------------------------------------------------------------------
// 信任锚：文件 + 目录
// ---------------------------------------------------------------------------

// certFileExts 目录扫描接受的后缀（大小写不敏感）。
var certFileExts = []string{".crt", ".pem", ".cer", ".cert"}

// LoadOrScanTrustAnchors 加载信任锚列表，每一项既可以是文件，也可以是目录。
//
// 目录会扫出其中所有证书文件（后缀见 certFileExts）并按路径排序以保证结果确定。
// 支持目录是为了配合"证书脚本往固定目录投放"的用法：换 CA 时脚本只要替换目录里的文件，
// 配置文件一行都不用改。任一项加载失败即整体报错，不会静默跳过。
//
// 参数：
//
//	paths — 信任锚路径列表，元素可以是文件也可以是目录
//
// 返回：
//
//	[]*x509.Certificate — 加载到的全部信任锚证书（文件内的整条链都会纳入）
//	error — 路径不存在 / 证书解析失败 / 目录里没有证书 / 最终一个锚都没加载到时返回
func LoadOrScanTrustAnchors(paths []string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("trust anchor %s: %w", p, err)
		}
		if !st.IsDir() {
			chain, err := LoadCertChainFile(p)
			if err != nil {
				return nil, fmt.Errorf("trust anchor %s: %w", p, err)
			}
			out = append(out, chain...)
			continue
		}
		files, err := scanCertDir(p)
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("trust anchor dir %s: 目录里没有证书文件（支持 %s）", p, strings.Join(certFileExts, "/"))
		}
		for _, f := range files {
			chain, err := LoadCertChainFile(f)
			if err != nil {
				return nil, fmt.Errorf("trust anchor %s: %w", f, err)
			}
			out = append(out, chain...)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no trust anchor loaded")
	}
	return out, nil
}

// scanCertDir 列出目录下所有证书文件（按后缀匹配，后缀见 certFileExts），结果按路径排序。
//
// 只处理普通文件，子目录会被跳过。目录不可读时报错。
//
// 参数：
//
//	dir — 要扫描的目录
//
// 返回：
//
//	[]string — 证书文件的完整路径（已排序；没有匹配文件时为空切片）
//	error — 目录不可读时返回
func scanCertDir(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read trust anchor dir %s: %w", dir, err)
	}
	var files []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		for _, want := range certFileExts {
			if ext == want {
				files = append(files, filepath.Join(dir, e.Name()))
				break
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

// ---------------------------------------------------------------------------
// 变更检测：路径摘要
// ---------------------------------------------------------------------------

// PathStamp 计算一组路径的轻量指纹：只看 size + mtime，不读文件内容。
//
// 为什么要两套：证书轮询是"每节点、每间隔"都要跑的稳态开销。直接用内容摘要，等于每次轮询
// 都把全部证书/密钥重新读一遍 —— 节点一多（同机上百个进程/实例）就会形成读 IO 突发，
// 把正常业务也拖慢。所以稳态只做 stat（微秒级），stat 说变了才去读内容做二次确认。
// 目录只记其中各文件的名字 + 大小 + mtime，不递归；文件不存在会以 MISSING 计入指纹，
// 保证"从无到有"这类变化也能被检测到。
//
// 参数：
//
//	paths — 要纳入指纹的路径（文件或目录）；内部先排序，空字符串会被跳过
//
// 返回：
//
//	string — 十六进制 SHA-256 指纹
//	error — 目录遍历失败时返回（单个文件缺失不算错误，会记入指纹）
func PathStamp(paths []string) (string, error) {
	h := sha256.New()
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	for _, p := range sorted {
		if p == "" {
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(h, "MISSING\t%s\n", p)
			continue
		}
		if !st.IsDir() {
			fmt.Fprintf(h, "FILE\t%s\t%d\t%d\n", p, st.Size(), st.ModTime().UnixNano())
			continue
		}
		fmt.Fprintf(h, "DIR\t%s\n", p)
		ents, err := os.ReadDir(p)
		if err != nil {
			fmt.Fprintf(h, "DIRERR\t%s\n", p)
			continue
		}
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			fp := filepath.Join(p, n)
			if fst, err := os.Stat(fp); err == nil {
				fmt.Fprintf(h, "\t%s\t%d\t%d\n", n, fst.Size(), fst.ModTime().UnixNano())
			} else {
				fmt.Fprintf(h, "\t%s\tGONE\n", n)
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// PathDigest 计算一组路径（文件或目录）的"内容 + 元信息"摘要，用于发现变更。
//
// 取 mtime 与 size 做快速判据、内容 sha256 做最终判据：只看 mtime 会被"脚本整体重写但
// 内容相同"误触发，只看内容又要在每次轮询读全量文件 —— 两者结合最稳。
// 目录按名字排序后逐个纳入，保证结果与遍历顺序无关。它是 PathStamp 报变之后才跑的二次确认。
//
// 参数：
//
//	paths — 要纳入摘要的路径（文件或目录）；内部先排序，空字符串会被跳过
//
// 返回：
//
//	string — 十六进制 SHA-256 摘要
//	error — 文件读取或目录遍历失败时返回（单个文件缺失不算错误，会记入 MISSING）
func PathDigest(paths []string) (string, error) {
	h := sha256.New()
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	for _, p := range sorted {
		if p == "" {
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			// 文件"不存在"也是一种状态（例如证书尚未签发 → 入网后出现），必须进摘要，
			// 否则"从无到有"这个变化检测不到。
			fmt.Fprintf(h, "MISSING\t%s\n", p)
			continue
		}
		if !st.IsDir() {
			if err := hashFileInto(h, p); err != nil {
				return "", err
			}
			continue
		}
		files, err := os.ReadDir(p)
		if err != nil {
			return "", fmt.Errorf("read dir %s: %w", p, err)
		}
		names := make([]string, 0, len(files))
		for _, e := range files {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		fmt.Fprintf(h, "DIR\t%s\n", p)
		for _, n := range names {
			if err := hashFileInto(h, filepath.Join(p, n)); err != nil {
				return "", err
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashFileInto 读取单个文件的内容，把"路径 + 内容 SHA-256"这一行写进哈希器 h。
//
// 参数：
//
//	h — 接收写入的哈希器（只要求实现 Write 方法）
//	p — 要读取的文件路径
//
// 返回：
//
//	error — 文件读不到时返回
func hashFileInto(h interface{ Write([]byte) (int, error) }, p string) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("read %s: %w", p, err)
	}
	sum := sha256.Sum256(b)
	fmt.Fprintf(h, "FILE\t%s\t%s\n", p, hex.EncodeToString(sum[:]))
	return nil
}

// ---------------------------------------------------------------------------
// 运行期入网：父侧签发
// ---------------------------------------------------------------------------

// Issued 一次入网签发的结果。
type Issued struct {
	CertChain   []byte // 身份证书链（PEM 串接，到根）
	CACertChain []byte // CA 证书链（仅在申请方提交了 CA 公钥时非空）
	NotAfter    time.Time
}

// IssueForPubkeys 用本节点 CA 材料为给定的公钥签发身份证书与（可选的）CA 证书。
//
// 接收者 id 是父节点的身份包，必须持有 CA 私钥与 CA 证书。与 IssueChild 的关键区别：
// 这里不生成任何密钥。调用方（父）只拿到公钥，私钥始终由申请方自己持有 —— 这正是
// "运行期入网"能守住"程序绝不生成/接收私钥"的前提。caPub 为空时不签发 CA 证书；
// CA 证书的 CN 沿用 "<nodeID>-ca" 约定（启动校验会检查 CN 是否含 NodeID）。
//
// 参数：
//
//	childNodeID — 申请入网的子节点 NodeID（不能为空）
//	idPub — 子节点的身份公钥，必填，且必须是 Ed25519 公钥
//	caPub — 子节点的 CA 公钥；长度 0 表示该子节点不需要 CA 证书
//
// 返回：
//
//	*Issued — 身份证书链与（可选）CA 证书链（均为 PEM 字节）以及到期时间
//	error — 本节点无 CA 材料 / NodeID 为空 / 公钥非法 / 证书签发失败时返回
func (id *Identity) IssueForPubkeys(childNodeID string, idPub, caPub ed25519.PublicKey) (*Issued, error) {
	if id == nil || id.CAKey == nil || id.CACert == nil {
		return nil, errors.New("this node has no CA material to sign with（有子节点才需要 security.ca_key_path + security.ca_cert_path）")
	}
	if childNodeID == "" {
		return nil, errors.New("child node id is empty")
	}
	if len(idPub) != ed25519.PublicKeySize {
		return nil, errors.New("identity public key is not ed25519")
	}
	now := time.Now().Add(-time.Minute)

	idCert, err := issueCert(childNodeID, idPub, id.CACert, id.CAKey, false, now)
	if err != nil {
		return nil, err
	}
	out := &Issued{NotAfter: idCert.NotAfter}
	out.CertChain = appendPEM(nil, idCert)
	for _, c := range id.CAChain {
		out.CertChain = appendPEM(out.CertChain, c)
	}

	if len(caPub) > 0 {
		if len(caPub) != ed25519.PublicKeySize {
			return nil, errors.New("CA public key is not ed25519")
		}
		// CA 证书的 CN 必须含 nodeID（启动校验会检查），沿用 " <nodeID>-ca " 约定
		caCert, err := issueCert(childNodeID+"-ca", caPub, id.CACert, id.CAKey, true, now)
		if err != nil {
			return nil, err
		}
		out.CACertChain = appendPEM(nil, caCert)
		for _, c := range id.CAChain {
			out.CACertChain = appendPEM(out.CACertChain, c)
		}
	}
	return out, nil
}

// appendPEM 把一张证书编码成 PEM 并追加到 dst 末尾。
//
// 参数：
//
//	dst — 已积累的 PEM 字节（可为 nil）
//	c — 要追加的证书
//
// 返回：
//
//	[]byte — 追加之后的字节切片
func appendPEM(dst []byte, c *x509.Certificate) []byte {
	return append(dst, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
}

// ---------------------------------------------------------------------------
// 运行期入网：入网握手用的 TLS
// ---------------------------------------------------------------------------

// NewEnrollClientTLSConfig 构造入网握手用的客户端 TLS 配置。
//
// 两个要点：
//  1. **不提供客户端证书** —— 因为此刻还没有证书，这正是要申请的东西；
//  2. **仍然严格校验服务端** —— 服务端证书必须能验到信任锚，且身份必须等于 parentNodeID，
//     否则任何人都能冒充父给你发证书。
//
// SNI 设成 EnrollServerName(parentNodeID)，服务端据此把这条连接认作入网握手。
//
// 参数：
//
//	roots — 信任锚池（父那条链的根 CA）
//	parentNodeID — 目标父节点的 NodeID，同时用作 SNI 与对端身份断言
//
// 返回：
//
//	*tls.Config — 入网握手用的客户端 TLS 配置（最低 TLS 1.3）
func NewEnrollClientTLSConfig(roots *x509.CertPool, parentNodeID string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, // 不用系统根，改用下面的锚链校验
		MinVersion:         tls.VersionTLS13,
		ServerName:         EnrollServerName(parentNodeID),
		// 同样要求对端身份就是配置里的那个父 —— 否则任何人都能冒充父给你发证书
		VerifyPeerCertificate: ChainVerifier(roots, parentNodeID, 0),
	}
}
