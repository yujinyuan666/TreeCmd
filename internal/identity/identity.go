// Package identity 实现 NodeID（UUIDv7）、Ed25519 身份密钥、与系统树同构的 PKI
// （双密钥：身份密钥 / CA 密钥）、证书签发与链校验、启动强校验、mTLS 配置。
//
// 与方案的差异（有意为之，见 README.md「实现说明」）：
//  9. 方案 7.7 的「CA 密钥按需生成 → 向父重签自身证书为 CA:TRUE」在本实现中改为
//     「为有子节点的节点额外签发一张独立的 CA 证书（CA:TRUE，含 CA 公钥）」。
//     理由：方案的写法让"身份密钥"与"CA 密钥"落在同一张证书上，而子节点证书由
//     CA 密钥签发、其公钥却不在父的身份证书里，链无法校验。独立 CA 证书既满足
//     "双密钥互相隔离"，又让标准 x509 链校验成立（PKI 与树同构不变）。
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// UUIDv7（时间有序，见 7.1）
// ---------------------------------------------------------------------------

// NewNodeID 生成一个新的节点身份标识，返回 8-4-4-4-12 形式的 UUIDv7 字符串。
//
// UUIDv7 的前 48 位是毫秒时间戳，所以按 16 字节二进制值排序就等价于按"创建时间先后"排序，
// 这让树里的节点能有一个确定且随时间的排序（见 NodeIDLess）。
//
// 返回：
//
//	string — 新生成的 NodeID（UUIDv7 文本）
//	error  — 系统随机源读取失败时返回
func NewNodeID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC4122
	return FormatUUID(b), nil
}

// FormatUUID 把 16 字节 UUID 编码成 8-4-4-4-12 的十六进制字符串。
func FormatUUID(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ParseUUID 把 UUID 字符串解析成 16 字节；先去掉首尾空白与全部连字符，长度不是 32 个十六进制字符就报错。
func ParseUUID(s string) ([16]byte, error) {
	var out [16]byte
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return out, fmt.Errorf("invalid uuid %q", s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, err
	}
	copy(out[:], b)
	return out, nil
}

// NodeIDLess 判断 NodeID a 是否应排在 b 之前：按 16 字节二进制值大端升序比较（见 7.5）。
//
// 关键约束：绝不能改用十六进制字符串字典序 —— 跨字节、大小写、前导零下两者并不等价。
// 两个 ID 都解析失败时退化成普通字符串比较，保证排序仍然是全序（不会出现 A<B 且 B<A）。
//
// 参数：
//
//	a — 参与比较的 NodeID（UUID 字符串）
//	b — 参与比较的 NodeID（UUID 字符串）
//
// 返回：
//
//	bool — a 严格小于 b 时为 true
func NodeIDLess(a, b string) bool {
	ab, err1 := ParseUUID(a)
	bb, err2 := ParseUUID(b)
	if err1 != nil || err2 != nil {
		return a < b
	}
	for i := 0; i < 16; i++ {
		if ab[i] != bb[i] {
			return ab[i] < bb[i]
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// 身份密钥（Ed25519）
// ---------------------------------------------------------------------------

// LoadIdentityKey 从 PEM 文件读取本节点的身份私钥。
//
// 文件不存在即报错，绝不自动生成 —— 私钥必须由部署期（你的部署脚本 / -genkey）预置，
// 缺失的节点不允许启动；否则每次启动都会变成"新身份"，已有的背书链全部作废。
//
// 参数：
//
//	path — 身份私钥文件路径（PEM，支持 PKCS#8 或裸 seed 编码）
//
// 返回：
//
//	ed25519.PrivateKey — 解析出的身份私钥
//	error — 路径为空 / 文件读不到 / PEM 解析失败时返回
func LoadIdentityKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("identity private key path is empty")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity private key %s: %w (私钥必须预置，程序绝不生成)", path, err)
	}
	key, err := parseEd25519PrivatePEM(b)
	if err != nil {
		return nil, fmt.Errorf("parse identity key %s: %w", path, err)
	}
	return key, nil
}

// GenerateKeyPair 用系统 CSPRNG 生成一对 Ed25519 密钥。
//
// 仅部署期使用（-genkey 以及本节点 CA 密钥的生成）；身份密钥绝不从 NodeID 派生。
//
// 返回：
//
//	ed25519.PublicKey — 生成的公钥
//	ed25519.PrivateKey — 生成的私钥
//	error — 随机源读取失败时返回
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// WritePublicKeyFile 把 Ed25519 公钥以 PEM(PKIX) 格式落盘，文件权限 0644（公钥不是秘密）。
//
// 参数：
//
//	path — 目标文件路径；父目录不存在时会以 0700 权限创建
//	pub — 要写入的 Ed25519 公钥
//
// 返回：
//
//	error — 序列化失败 / 建目录失败 / 写文件失败时返回
func WritePublicKeyFile(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	blk := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, blk, 0o644)
}

// PublicKeyOf 从私钥取出它对应的公钥。
func PublicKeyOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// WriteKeyFile 把 Ed25519 私钥以 PEM(PKCS#8) 落盘，文件权限 0600（私钥必须只有属主可读）。
//
// 参数：
//
//	path — 目标文件路径；父目录不存在时会以 0700 权限创建
//	priv — 要写入的 Ed25519 私钥
//
// 返回：
//
//	error — 序列化失败 / 建目录失败 / 写文件失败时返回
func WriteKeyFile(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	blk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, blk, 0o600)
}

// parseEd25519PrivatePEM 把 PEM 内容解析成 Ed25519 私钥，依次兼容三种编码。
//
// 尝试顺序：PKCS#8（Go 的标准导出格式）→ 裸 32 字节 seed → 裸 64 字节私钥。
//
// 参数：
//
//	b — PEM 文件内容
//
// 返回：
//
//	ed25519.PrivateKey — 解析出的私钥
//	error — 不是 PEM / 不是 Ed25519 密钥 / 编码不支持时返回
func parseEd25519PrivatePEM(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		if ed, ok := k.(ed25519.PrivateKey); ok {
			return ed, nil
		}
		return nil, errors.New("not an ed25519 key")
	}
	// 兼容裸 32 字节 seed
	if len(blk.Bytes) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(blk.Bytes), nil
	}
	if len(blk.Bytes) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(blk.Bytes), nil
	}
	return nil, errors.New("unsupported key encoding")
}

// LoadPublicKeyFile 从文件读取 Ed25519 公钥。
//
// 依次兼容三种编码：PEM(PKIX) 公钥 → PEM 证书（取证书里的公钥）→ 裸 32 字节公钥。
//
// 参数：
//
//	path — 公钥文件路径
//
// 返回：
//
//	ed25519.PublicKey — 解析出的公钥
//	error — 文件读不到 / 不是 PEM / 编码不支持时返回
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not PEM")
	}
	if pk, err := x509.ParsePKIXPublicKey(blk.Bytes); err == nil {
		if ed, ok := pk.(ed25519.PublicKey); ok {
			return ed, nil
		}
		return nil, errors.New("not an ed25519 public key")
	}
	if cert, err := x509.ParseCertificate(blk.Bytes); err == nil {
		if ed, ok := cert.PublicKey.(ed25519.PublicKey); ok {
			return ed, nil
		}
	}
	if len(blk.Bytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(blk.Bytes), nil
	}
	return nil, errors.New("unsupported public key encoding")
}

// WriteCertFile 把若干张 DER 证书按给定顺序拼成 PEM 证书链写盘，权限 0644。
//
// 参数：
//
//	path — 目标文件路径；父目录不存在时会以 0700 权限创建
//	chainDER — DER 证书字节的切片，切片顺序即链顺序（自身证书在前、根证书在后）
//
// 返回：
//
//	error — 建目录失败 / 写文件失败时返回
func WriteCertFile(path string, chainDER [][]byte) error {
	var buf []byte
	for _, der := range chainDER {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, buf, 0o644)
}

// LoadCertChainFile 读取一个 PEM 文件里的全部证书，按出现顺序返回证书链。
//
// 不是 CERTIFICATE 类型的 PEM 块（例如夹带的私钥）会被跳过；文件里一张证书都没有时返回错误。
//
// 参数：
//
//	path — 证书链文件路径
//
// 返回：
//
//	[]*x509.Certificate — 解析出的证书链，顺序与文件里 PEM 块的先后一致
//	error — 文件读不到 / 某张证书解析失败 / 文件里没有证书时返回
func LoadCertChainFile(path string) ([]*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate in %s", path)
	}
	return out, nil
}

// WriteFamily 一次性写出一个节点的 CA 私钥文件与 CA 证书链文件。
//
// 只是把 WriteKeyFile 与 WriteCertFile 组合起来，方便"CA 密钥和 CA 证书成对落盘"。
//
// 参数：
//
//	keyPath — CA 私钥文件路径
//	key — 要写入的 CA 私钥
//	caCertPath — CA 证书链文件路径
//	caChainDER — CA 证书链的 DER 字节切片（自身 CA 证书在前、上级在后）
//
// 返回：
//
//	error — 任一文件写失败时返回（先写私钥，私钥失败就不会再写证书）
func WriteFamily(keyPath string, key ed25519.PrivateKey, caCertPath string, caChainDER [][]byte) error {
	if err := WriteKeyFile(keyPath, key); err != nil {
		return err
	}
	return WriteCertFile(caCertPath, caChainDER)
}

// Sign 用身份私钥对消息签名；所有 *.Sig 一律用身份密钥，绝不用 CA 密钥（见 7.5）。
func Sign(priv ed25519.PrivateKey, msg []byte) []byte { return ed25519.Sign(priv, msg) }

// Verify 校验签名，长度不合法直接判失败，否则交给 ed25519.Verify。
//
// 参数：
//
//	pub — 签名者的公钥
//	msg — 被签名的原始消息
//	sig — 签名值
//
// 返回：
//
//	bool — 公钥与签名长度合法且签名有效时为 true
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// Fingerprint 计算证书指纹：对证书的 DER 原始字节求 SHA-256。
//
// 参数：
//
//	c — 目标证书
//
// 返回：
//
//	[]byte — 32 字节的 SHA-256 摘要
func Fingerprint(c *x509.Certificate) []byte {
	sum := sha256.Sum256(c.Raw)
	return sum[:]
}

// NodeIDFromCert 从证书里提取它所代表的 NodeID：优先取 Subject.CommonName，
// CN 为空时从 SAN 的 spiffe:// URI 末段兜底，两者都取不到返回空字符串。
//
// 启动强校验会用它断言"证书身份 == 配置里的 NodeID"（见 7.7）。
//
// 参数：
//
//	c — 待检查的证书
//
// 返回：
//
//	string — 证书里的身份字符串；无法识别时为空串
func NodeIDFromCert(c *x509.Certificate) string {
	if c.Subject.CommonName != "" {
		return c.Subject.CommonName
	}
	for _, u := range c.URIs {
		if strings.HasPrefix(u.String(), "spiffe://") {
			if i := strings.LastIndex(u.String(), "/"); i >= 0 {
				return u.String()[i+1:]
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// PKI：根 CA / 节点身份证书 / 节点 CA 证书
// ---------------------------------------------------------------------------

// Identity 一个节点的身份材料。
type Identity struct {
	NodeID   string
	Key      ed25519.PrivateKey
	Cert     *x509.Certificate
	Chain    []*x509.Certificate // [自身证书, 上级CA证书...]
	CAKey    ed25519.PrivateKey  // 仅"有子节点"的节点持有
	CACert   *x509.Certificate
	CAChain  []*x509.Certificate // [自身CA证书, 上级CA证书...]
	RootPool *x509.CertPool
}

// serial 生成一个随机的 128 位证书序列号。
//
// 返回：
//
//	*big.Int — 序列号
//	error — 随机源读取失败时返回
func serial() (*big.Int, error) {
	lim := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, lim)
}

// GenerateRoot 生成树根的整套身份材料：自签的根 CA 证书 + 根自己的身份证书（见 7.9）。
//
// 根是信任锚，它的 CA 证书自签（自己签自己）、有效期 10 年；根的身份证书由这张 CA 签出、
// 有效期 30 天。函数不写任何文件，落盘由调用方统一处理。
//
// 参数：
//
//	nodeID — 根节点的身份标识
//
// 返回：
//
//	*Identity — 含根身份密钥、根 CA 密钥、两份证书链与信任锚池
//	error — 密钥生成 / 证书创建或解析失败时返回
func GenerateRoot(nodeID string) (*Identity, error) {
	_, caKey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now().Add(-time.Minute)
	caTmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: nodeID + "-root-ca", Organization: []string{"treecmd"}},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	_, rootKey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	idCert, err := issueCert(nodeID, rootKey.Public().(ed25519.PublicKey), caCert, caKey, false, now)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &Identity{
		NodeID: nodeID, Key: rootKey, Cert: idCert, Chain: []*x509.Certificate{idCert, caCert},
		CAKey: caKey, CACert: caCert, CAChain: []*x509.Certificate{caCert}, RootPool: pool,
	}, nil
}

// IssueChild 用本节点的 CA 密钥为子节点签发一套身份材料，子节点的私钥在本机（本进程）生成。
//
// 接收者 id 是父节点的身份包，必须持有 CA 私钥与 CA 证书；没有 CA 材料的叶子节点调用会直接报错。
// withCA 为 true 时额外签发该子节点的 CA 证书（只有还会带下级的中继 / 根需要，叶子不要）。
// 证书链一律带全到根，否则 mTLS 握手时无法完成链校验。
//
// 参数：
//
//	childNodeID — 子节点的身份标识
//	withCA — 是否同时为该子节点签发 CA 证书（它将成为可继续签发下一级的节点）
//
// 返回：
//
//	*Identity — 子节点的身份包（含新生成的私钥与到根的证书链）
//	error — 本节点无 CA 材料 / 密钥生成失败 / 证书签发失败时返回
func (id *Identity) IssueChild(childNodeID string, withCA bool) (*Identity, error) {
	if id.CAKey == nil || id.CACert == nil {
		return nil, errors.New("this node has no CA key (leaf must not sign children)")
	}
	_, childKey, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	now := time.Now().Add(-time.Minute)
	childCert, err := issueCert(childNodeID, childKey.Public().(ed25519.PublicKey), id.CACert, id.CAKey, false, now)
	if err != nil {
		return nil, err
	}
	out := &Identity{
		NodeID: childNodeID,
		Key:    childKey,
		Cert:   childCert,
		Chain:  append([]*x509.Certificate{childCert}, id.CAChain...),
	}
	if withCA {
		_, childCAKey, err := GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		childCACert, err := issueCert(childNodeID+"-ca", childCAKey.Public().(ed25519.PublicKey), id.CACert, id.CAKey, true, now)
		if err != nil {
			return nil, err
		}
		out.CAKey = childCAKey
		out.CACert = childCACert
		out.CAChain = append([]*x509.Certificate{childCACert}, id.CAChain...)
	}
	return out, nil
}

// issueCert 用父证书与父私钥签发一张证书，是本包里唯一的底层签发原语。
//
// isCA 为 true 时签出 CA 证书（IsCA + keyUsage certSign），否则签普通身份证书；
// 两种证书都写入 SAN "spiffe://treecmd/node/<cn>"，有效期 30 天（见 7.7）。
// NotBefore 取 now，调用方传入的 now 通常已往前放宽 1 分钟以吸收机器间时钟偏差。
//
// 参数：
//
//	cn — 证书的 Subject.CommonName，也就是这张证书代表的身份名
//	pub — 被签发者的公钥
//	parent — 签发者（父）的证书
//	parentKey — 签发者（父）的私钥，用于给新证书签名
//	isCA — 是否签成 CA 证书
//	now — 生效时间基准；NotAfter 固定为 now 之后 30 天
//
// 返回：
//
//	*x509.Certificate — 签发好的证书
//	error — 序列号生成 / 证书创建失败 / 结果解析失败时返回
func issueCert(cn string, pub ed25519.PublicKey, parent *x509.Certificate, parentKey ed25519.PrivateKey, isCA bool, now time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	sanURI, _ := url.Parse("spiffe://treecmd/node/" + cn)
	// 有效期：身份证书短、CA 证书长。
	//
	// 身份证书走"运行期续签"（父给子重签 / 根自签重签），30 天 + 生命期 2/3 处换发，
	// 换证只影响自己，代价小。
	// CA 证书则是**全树信任锚链的一环**：换 CA 意味着所有下级节点都要重新分发 trust/，
	// 所以给它长有效期（10 年），让它稳定；否则有下级的节点（中继）会陷入
	// "CA 证书 30 天到期、而续签只换身份证书链"的死角（启动强校验会因 CA 过期拒绝启动）。
	notAfter := now.AddDate(0, 0, 30)
	if isCA {
		notAfter = now.AddDate(10, 0, 0)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"treecmd"}},
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{sanURI},
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
		tmpl.Subject.CommonName = cn
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ReissueFor 用本节点的 CA 材料为"同一身份（同一 NodeID、同一公钥）"重签一张新证书，
// 并把新证书 + 到根的 CA 链拼成 PEM 字节返回（见 7.7 续签）。
//
// 关键：只换证书、不换密钥 —— 沿用 existing 里的公钥与身份名，所以已有的背书链、
// origin 验签、CRL 条目全部照旧。调用方（通常是本机自己向父申请）需持有 CA 材料。
//
// 参数：
//
//	existing — 待续签的旧证书（从它取公钥与身份名）
//	owner — 用于签发的 CA 材料持有者（父 / 上级节点）的身份包，须含 CA 私钥与 CA 证书
//
// 返回：
//
//	[]byte — 新证书 + owner.CAChain 拼接成的 PEM 字节
//	error — owner 无 CA 材料 / 旧证书不是 Ed25519 / 签发失败时返回
func ReissueFor(existing *x509.Certificate, owner *Identity) ([]byte, error) {
	if owner == nil || owner.CAKey == nil || owner.CACert == nil {
		return nil, errors.New("this node has no CA material to sign with")
	}
	pub, ok := existing.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("existing certificate is not ed25519")
	}
	now := time.Now().Add(-time.Minute)
	cert, err := issueCert(NodeIDFromCert(existing), pub, owner.CACert, owner.CAKey, false, now)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	for _, c := range owner.CAChain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out, nil
}

// ParseChainPEM 把 PEM 串接的证书内容解析成证书链，跳过不是 CERTIFICATE 的块。
//
// 参数：
//
//	b — PEM 字节内容（通常来自网络或文件）
//
// 返回：
//
//	[]*x509.Certificate — 解析出的证书链，顺序与 PEM 块先后一致
//	error — 某张证书解析失败 / 内容里一张证书都没有时返回
func ParseChainPEM(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate in PEM")
	}
	return out, nil
}

// WriteCertChainFile 原子地写证书链：先写临时文件并 fsync，再 rename 覆盖目标路径。
//
// 续签换发时用，避免别处读到"写了一半"的证书链。文件权限沿用 WriteCertFile 的 0644。
//
// 参数：
//
//	path — 目标文件路径
//	chain — 证书链（切片顺序即写入顺序）
//
// 返回：
//
//	error — 写临时文件失败 / rename 失败时返回
func WriteCertChainFile(path string, chain []*x509.Certificate) error {
	var der [][]byte
	for _, c := range chain {
		der = append(der, c.Raw)
	}
	tmp := path + ".tmp"
	if err := WriteCertFile(tmp, der); err != nil {
		return err
	}
	if f, err := os.Open(tmp); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	return os.Rename(tmp, path)
}

// TLSCertFrom 由身份包构造可用于 mTLS 的 tls.Certificate（私钥 + 整条证书链）。
func TLSCertFrom(id *Identity) tls.Certificate { return certFromIdentity(id) }

// TLSContainer 可热替换的证书容器：mTLS 的证书经回调读取，续签后无需重建 tls.Config。
type TLSContainer struct {
	mu   sync.RWMutex
	cert tls.Certificate
}

// NewTLSContainer 用一个初始证书构造可热替换的证书容器。
func NewTLSContainer(c tls.Certificate) *TLSContainer { return &TLSContainer{cert: c} }

// Set 替换容器里的证书。
//
// 接收者 t 是存放本节点当前证书的并发安全容器，内部用写锁保护，可随时调用。
//
// 参数：
//
//	c — 新证书（通常是续签成功后从新证书链重新构造的 tls.Certificate）
func (t *TLSContainer) Set(c tls.Certificate) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cert = c
}

// current 在读锁保护下取一份当前证书的拷贝，并返回它的指针。
//
// 接收者 t 是存放本节点当前证书的并发安全容器。
//
// 拷贝是为了让调用方拿到之后可以脱离锁安全使用，不会被并发的 Set 修改。
//
// 返回：
//
//	*tls.Certificate — 当前证书的副本指针
func (t *TLSContainer) current() *tls.Certificate {
	t.mu.RLock()
	defer t.mu.RUnlock()
	c := t.cert
	return &c
}

// Get 是 tls.Config.GetCertificate 的回调，服务端握手时返回容器里的当前证书。
func (t *TLSContainer) Get(*tls.ClientHelloInfo) (*tls.Certificate, error) { return t.current(), nil }

// GetClient 是 tls.Config.GetClientCertificate 的回调，客户端握手时返回容器里的当前证书。
func (t *TLSContainer) GetClient(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return t.current(), nil
}

// ---------------------------------------------------------------------------
// 启动强校验（7.9）
// ---------------------------------------------------------------------------

// ValidateStartup 执行启动强校验，任一条不满足就直接返回错误（调用方必须 fatal，不得放行）。
//
// 校验链条：私钥必须是 Ed25519 → 预置公钥必须与私钥一致 → 证书身份必须等于 NodeID →
// 身份证书能验到 caCerts 里的某个信任锚 → 有效期未超出 7 天续签宽限 →
// 私钥 ↔ 证书公钥 ↔ 预置公钥两两一致。若节点还持有 CA 材料，则对 CA 证书再做一遍：
// IsCA 为真、keyUsage 含 certSign、有效期、CN 含 NodeID、且能验到信任锚。
// 有效期允许"过期不超过 7 天"（续签宽限）；是否只放行续签帧由应用层决定，这里只做判定。
//
// 参数：
//
//	id — 本节点的身份包（私钥、证书、证书链、可选的 CA 材料）
//	caCerts — 启动时配置的信任锚证书列表（id.Cert 必须能验到其中之一）
//	pubFromFile — 启动时必须预置的公钥文件内容（文件缺失 / 解析失败由调用方先行拦截）
//
// 返回：
//
//	error — 任一条校验不通过时返回对应原因；全部通过返回 nil
func ValidateStartup(id *Identity, caCerts []*x509.Certificate, pubFromFile ed25519.PublicKey) error {
	if id == nil || id.Key == nil || id.Cert == nil {
		return errors.New("identity incomplete")
	}
	if len(id.Key.Public().(ed25519.PublicKey)) != ed25519.PublicKeySize {
		return errors.New("identity key not ed25519")
	}
	// ① 公钥必须预置：文件缺失 / 解析失败在调用方已拦；这里校验三者一致
	if pubFromFile == nil {
		return errors.New("public key missing: 节点必须带自己的公钥启动")
	}
	if len(pubFromFile) != ed25519.PublicKeySize {
		return errors.New("public key is not ed25519")
	}
	if !pubFromFile.Equal(PublicKeyOf(id.Key)) {
		return errors.New("public key does not match private key")
	}
	if got := NodeIDFromCert(id.Cert); got != id.NodeID {
		return fmt.Errorf("cert identity %q != node id %q", got, id.NodeID)
	}
	// 有效期（续签宽限：允许过期 ≤7 天，但仅放行续签类帧 —— 本实现只做校验放行，见 README）
	if time.Now().After(id.Cert.NotAfter.Add(7 * 24 * time.Hour)) {
		return fmt.Errorf("certificate expired at %s", id.Cert.NotAfter)
	}
	pool := x509.NewCertPool()
	for _, c := range caCerts {
		pool.AddCert(c)
	}
	inters := x509.NewCertPool()
	for _, c := range id.Chain[1:] {
		inters.AddCert(c)
	}
	if _, err := id.Cert.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("certificate chain does not verify to any trust anchor: %w", err)
	}
	pub := PublicKeyOf(id.Key)
	certPub, ok := id.Cert.PublicKey.(ed25519.PublicKey)
	if !ok || !certPub.Equal(pub) {
		return errors.New("identity key does not match certificate")
	}
	if !certPub.Equal(pubFromFile) {
		return errors.New("public key does not match certificate")
	}
	if id.CAKey != nil {
		if id.CACert == nil {
			return errors.New("CA key present but CA cert missing")
		}
		caPub := PublicKeyOf(id.CAKey)
		certCAPub, ok := id.CACert.PublicKey.(ed25519.PublicKey)
		if !ok || !certCAPub.Equal(caPub) {
			return errors.New("CA key does not match CA certificate")
		}
		// CA 证书本身也是信任链的一环，必须与身份证书同等强度地校验：
		if !id.CACert.IsCA {
			return errors.New("CA certificate is not a CA (basicConstraints CA:FALSE)")
		}
		if id.CACert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("CA certificate lacks keyUsage certSign")
		}
		if time.Now().After(id.CACert.NotAfter.Add(7 * 24 * time.Hour)) {
			return fmt.Errorf("CA certificate expired at %s", id.CACert.NotAfter)
		}
		if !strings.Contains(id.CACert.Subject.CommonName, id.NodeID) {
			return fmt.Errorf("CA certificate CN %q does not contain node id", id.CACert.Subject.CommonName)
		}
		caInter := x509.NewCertPool()
		for _, c := range id.CAChain[1:] {
			caInter.AddCert(c)
		}
		if _, err := id.CACert.Verify(x509.VerifyOptions{
			Roots: pool, Intermediates: caInter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return fmt.Errorf("CA certificate chain does not verify to any trust anchor: %w", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// mTLS 配置
// ---------------------------------------------------------------------------

// ServerTLSConfig 构造服务端 mTLS 配置：默认要求并校验客户端证书（多信任锚逐个尝试，见 4.5）。
//
// rootsFn 每次握手时求值 ⇒ 信任锚被外部脚本替换后，新连接立刻用新锚（不必重建 gRPC server，
// 也就不会打断现有会话）。证书本身经 TLSContainer 回调读取，同样支持热替换。
//
// enrollEnabled 为 true 时，SNI 带 EnrollSNIPrefix 的握手放宽为"不要求客户端证书"——
// 因为入网时子节点本来就还没有证书；这条路径的鉴权完全由 Enroll RPC 自己承担
// （一次性 nonce + 私钥持有证明 + 入网许可）。其余连接一律严格 mTLS。
//
// 参数：
//
//	box — 本节点的证书容器（可热替换，握手时按需取用）
//	rootsFn — 返回当前信任锚池的函数，每次握手都会重新调用
//	enrollEnabled — 是否开启"入网握手"这条放宽路径
//
// 返回：
//
//	*tls.Config — 服务端 TLS 配置（最低 TLS 1.3，只协商 h2）
func ServerTLSConfig(box *TLSContainer, rootsFn func() *x509.CertPool, enrollEnabled bool) *tls.Config {
	strict := func() *tls.Config {
		roots := rootsFn()
		return &tls.Config{
			GetCertificate:        box.Get,
			ClientAuth:            tls.RequireAndVerifyClientCert,
			ClientCAs:             roots,
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{"h2"},
			VerifyPeerCertificate: ChainVerifier(roots, "", renewalGrace),
		}
	}
	cfg := strict()
	if enrollEnabled {
		cfg.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if IsEnrollServerName(chi.ServerName) {
				roots := rootsFn()
				return &tls.Config{
					GetCertificate: box.Get,
					// 有证书就收下（便于审计"谁在申请入网"），没有也放行
					ClientAuth: tls.RequestClientCert,
					ClientCAs:  roots,
					MinVersion: tls.VersionTLS13,
					NextProtos: []string{"h2"},
				}, nil
			}
			return strict(), nil
		}
	}
	return cfg
}

// renewalGrace 续签宽限窗口：TLS 层接受"过期 ≤7 天"的证书（否则连不上、也就没机会续签），
// 但标记为 renewal-only，由应用层拦截器只放行续签相关帧（见 7.7 第 3 条）。
const renewalGrace = 7 * 24 * time.Hour

// PeerExpired 判断对端证书是否已过期（应用层据此只放行续签 / 注册类帧）。
//
// 参数：
//
//	c — 对端证书；传 nil 时直接返回 false
//
// 返回：
//
//	bool — 证书非空且当前时间已超过 NotAfter 时为 true
func PeerExpired(c *x509.Certificate) bool {
	return c != nil && time.Now().After(c.NotAfter)
}

// ClientTLSConfig 构造客户端 mTLS 配置：跳过标准校验（CA 由父签发、不在系统根里），
// 改由 VerifyPeerCertificate 按信任锚池逐个尝试，并可选断言对端 NodeID（见 4.5 / 7.7）。
//
// 同样支持续签宽限窗口。rootsFn 每次建连时求值 ⇒ 信任锚热替换对下一次拨号立即生效。
//
// 参数：
//
//	box — 本节点的证书容器（可热替换）
//	rootsFn — 返回当前信任锚池的函数，每次建连调用一次
//	expectNodeID — 期望的对端 NodeID；非空时必须与对端证书身份一致
//
// 返回：
//
//	*tls.Config — 客户端 TLS 配置（最低 TLS 1.3）
func ClientTLSConfig(box *TLSContainer, rootsFn func() *x509.CertPool, expectNodeID string) *tls.Config {
	return &tls.Config{
		GetClientCertificate:  box.GetClient,
		InsecureSkipVerify:    true,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: ChainVerifier(rootsFn(), expectNodeID, renewalGrace),
	}
}

// ChainVerifier 构造一个证书校验回调：逐锚尝试验链 + 可选 NodeID 一致性 + 续签宽限。
//
// 回调先按标准方式验证书链；若失败，但在该证书过期后的 grace 窗口内、且签名链本身可信，
// 就放行（renewal-only 的判定留给应用层拦截器，见 7.7 第 3 条）。
// expectNodeID 非空时还会断言对端身份，防止"链可信但身份不是我要找的那个节点"。
//
// 参数：
//
//	roots — 信任锚池（根 CA 集合）
//	expectNodeID — 期望的对端 NodeID；留空表示不校验身份
//	grace — 续签宽限窗口；0 表示不启用宽限（过期即拒绝）
//
// 返回：
//
//	func([][]byte, [][]*x509.Certificate) error — 可直接赋给 tls.Config.VerifyPeerCertificate 的回调
func ChainVerifier(roots *x509.CertPool, expectNodeID string, grace time.Duration) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("no peer certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		inters := x509.NewCertPool()
		for _, rc := range rawCerts[1:] {
			if c, err := x509.ParseCertificate(rc); err == nil {
				inters.AddCert(c)
			}
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			// 续签宽限窗口：证书"刚好过期"时仍允许握手（只有 TLS 层放行，应用层才可能换发新证）
			if grace > 0 && time.Now().Before(leaf.NotAfter.Add(grace)) && chainTrusts(roots, inters, leaf) {
				// 通过（renewal-only 的判定在应用层拦截器里做）
			} else {
				return fmt.Errorf("peer chain untrusted: %w", err)
			}
		}
		if expectNodeID != "" {
			if got := NodeIDFromCert(leaf); got != expectNodeID {
				return fmt.Errorf("peer identity %q != expected %q", got, expectNodeID)
			}
		}
		return nil
	}
}

// chainTrusts 忽略有效期、只验证书签名链是否可信（续签宽限窗口专用）。
//
// 先正常 Verify；失败则手工比对 issuer/subject 并逐级 CheckSignatureFrom，
// 覆盖"证书刚好过期导致 Verify 失败"的情形。只认签名，不看时间。
//
// 参数：
//
//	roots — 信任锚池
//	inters — 中间证书池（对端发来的链里除叶子以外的部分）
//	leaf — 待验证的对端叶子证书
//
// 返回：
//
//	bool — 签名链能连到某个信任锚时为 true
func chainTrusts(roots, inters *x509.CertPool, leaf *x509.Certificate) bool {
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	_, err := leaf.Verify(opts)
	if err == nil {
		return true
	}
	// 去掉有效期约束后再验一次（直接按 subject/issuer 逐张比对签名）
	for _, root := range poolSubjects(roots) {
		if bytesEqual(leaf.RawIssuer, root.RawSubject) {
			return leaf.CheckSignatureFrom(root) == nil
		}
	}
	for _, ic := range poolSubjects(inters) {
		if bytesEqual(leaf.RawIssuer, ic.RawSubject) && leaf.CheckSignatureFrom(ic) == nil {
			if bytesEqual(ic.RawIssuer, ic.RawSubject) {
				return true
			}
			for _, root := range poolSubjects(roots) {
				if bytesEqual(ic.RawIssuer, root.RawSubject) && ic.CheckSignatureFrom(root) == nil {
					return true
				}
			}
		}
	}
	return false
}

// bytesEqual 按字节逐个比较两个切片，用转成 string 的方式实现比较。
func bytesEqual(a, b []byte) bool { return string(a) == string(b) }

// poolSubjects 取出某信任锚池里登记过的全部证书（依赖 NewPool 建立的旁路索引）。
//
// 参数：
//
//	p — 信任锚池
//
// 返回：
//
//	[]*x509.Certificate — 池里登记的证书；没登记过则为 nil
func poolSubjects(p *x509.CertPool) []*x509.Certificate { return poolCertIndex(p) }

// PoolCerts 取回某个信任锚池里的证书，用于自省 / 指标 / 诊断，不参与证书校验。
//
// x509.CertPool 本身不暴露内容，这里靠 NewPool 留下的旁路索引拿回列表；
// 若这个池是用 x509.NewCertPool() 直接构造的，则返回 nil。
//
// 参数：
//
//	p — 信任锚池
//
// 返回：
//
//	[]*x509.Certificate — 池内证书列表；没有索引时返回 nil
func PoolCerts(p *x509.CertPool) []*x509.Certificate { return poolCertIndex(p) }

var (
	poolIndexMu sync.RWMutex
	poolIndex   = map[*x509.CertPool][]*x509.Certificate{}
)

// NewPool 构造信任锚池，并额外登记一份证书列表。
//
// x509.CertPool 不暴露内容，而"续签宽限窗口"需要忽略有效期地手工走一遍签名链，
// 所以这里留一份旁路索引（见 poolCertIndex / poolSubjects / PoolCerts）。
//
// 参数：
//
//	certs — 要放进池里的信任锚证书
//
// 返回：
//
//	*x509.CertPool — 新建好的信任锚池
func NewPool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	poolIndexMu.Lock()
	poolIndex[p] = append([]*x509.Certificate(nil), certs...)
	poolIndexMu.Unlock()
	return p
}

// poolCertIndex 在读锁保护下查旁路索引，返回某信任锚池登记的证书列表。
//
// 参数：
//
//	p — 信任锚池
//
// 返回：
//
//	[]*x509.Certificate — 登记的证书列表；没有登记过则为 nil
func poolCertIndex(p *x509.CertPool) []*x509.Certificate {
	poolIndexMu.RLock()
	defer poolIndexMu.RUnlock()
	return poolIndex[p]
}

// certFromIdentity 把身份包转换成一枚 tls.Certificate。
//
// 私钥取身份密钥；Certificate 字段按 id.Chain 的顺序填整条链（自身证书在前），
// 并把 Leaf 预置为自身证书，省去每次握手重复解析。
//
// 参数：
//
//	id — 本节点身份包
//
// 返回：
//
//	tls.Certificate — 可直接用于 mTLS 的证书对象
func certFromIdentity(id *Identity) tls.Certificate {
	tc := tls.Certificate{PrivateKey: id.Key}
	for _, c := range id.Chain {
		tc.Certificate = append(tc.Certificate, c.Raw)
	}
	tc.Leaf = id.Cert
	return tc
}
