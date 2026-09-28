package node

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sync"

	"treecmd/internal/config"
	"treecmd/internal/identity"
)

// 本文件负责对外 HTTP 端点的 TLS（api.tls）：证书热重载 + 可选 mTLS。
//
// 【为什么热重载】证书由外部脚本管理是本项目的既有约定（security.cert_reload），
// 对外端点没理由要求"换证书必须重启进程" —— 重启一次意味着这一跳在拓扑上重新入网。
// 所以这里按文件 mtime 现查：变了就重新 LoadX509KeyPair，没变就复用已解析好的 *tls.Config。

// apiTLSReloader 按文件变更重新构建 api.tls 的 *tls.Config。
//
// 字段 cfg 是"当前生效"的配置；stamp 是构建它时那几个文件的指纹（mtime+size），
// 用来判断要不要重建。所有访问都走 mu —— ConfigFor 会在**每次握手**里被调用。
type apiTLSReloader struct {
	certPath    string
	keyPath     string
	caPath      string
	clientAuth  tls.ClientAuthType
	minVersion  uint16
	requireOnly bool // api.tls.require：明文请求一律拒绝

	// leafHash 当前服务端**叶子证书 DER 的 SHA-256**（RFC 5929 的 tls-server-end-point）。
	// 它是通道绑定值：客户端从自己看到的服务端证书算同一个哈希，于是签名被钉死在
	// "这张证书所代表的那个服务端"上 —— 换个服务端（中间人 / 另一个节点）就签不上。
	leafHash []byte

	mu    sync.RWMutex
	cfg   *tls.Config
	stamp string
}

// newAPITLSReloader 建一个 TLS 重载器，并**立刻**构建一次。
//
// 为什么立刻构建：证书写错要让 StartAPI 当场失败（端口起来了却握不上手最难排查），
// 而不是等到第一个客户端连上来才发现。
//
// 参数：
//
//	t — api.tls 段配置（调用方已确保 Enabled()）
//
// 返回：
//
//	*apiTLSReloader — 就绪的重载器
//	error           — 证书 / 密钥 / 客户端 CA 加载失败时返回
func newAPITLSReloader(t *config.APITLSSection) (*apiTLSReloader, error) {
	r := &apiTLSReloader{
		certPath:    t.CertPath,
		keyPath:     t.KeyPath,
		caPath:      t.CAPath,
		clientAuth:  t.ClientAuthType(),
		minVersion:  t.MinTLSVersion(),
		requireOnly: t.Require,
	}
	if _, err := r.ConfigFor(nil); err != nil {
		return nil, err
	}
	return r, nil
}

// ConfigFor 给每次 TLS 握手返回当前生效的配置（crypto/tls 的 GetConfigForClient 回调）。
//
// 接收者 r 是重载器。
//
// 参数：
//
//	_ — *tls.ClientHelloInfo；本项目不做 SNI 分派（对外端点只用一张证书），忽略即可
//
// 返回：
//
//	*tls.Config — 当前生效配置
//	error       — 文件指纹变化后重新加载失败时返回（此时握手失败；旧配置**仍会**被复用，
//	              见 build 里的处理 —— 宁可用旧证书继续服务，也不要让端点彻底不可用）
func (r *apiTLSReloader) ConfigFor(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	stamp := r.fileStamp()
	r.mu.RLock()
	cfg, cur := r.cfg, r.stamp
	r.mu.RUnlock()
	if cfg != nil && stamp == cur {
		return cfg, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg != nil && r.fileStamp() == r.stamp {
		return r.cfg, nil
	}
	cfg, err := r.build()
	if err != nil {
		// 重载失败：保留旧配置继续服务（证书轮换窗口里文件可能正写到一半），
		// 但要把错误喊出来 —— 否则"换了证书没生效"会被误判成已经生效。
		if r.cfg != nil {
			return r.cfg, fmt.Errorf("api.tls: 重新加载证书失败，继续使用旧证书: %w", err)
		}
		return nil, err
	}
	r.cfg, r.stamp = cfg, stamp
	return cfg, nil
}

// build 读盘构建一份 *tls.Config。
//
// 接收者 r 是重载器；调用方必须持有写锁。
//
// 返回：
//
//	*tls.Config — 含服务端证书链；配了 ca_path 时附带 ClientCAs 与 ClientAuth 策略
//	error       — 证书 / 密钥 / CA 加载失败时返回
func (r *apiTLSReloader) build() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		return nil, fmt.Errorf("加载服务端证书 %s / 密钥 %s: %w", r.certPath, r.keyPath, err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   r.minVersion,
		ClientAuth:   r.clientAuth,
	}
	// 通道绑定值取自**叶子证书**：cert.Certificate[0] 就是它的 DER（证书链在 [1:]）。
	// 带上 apiAuthCBLabel 做域分隔 —— 同一张证书不该在别的协议 / 用途上算出同一个绑定值。
	if len(cert.Certificate) > 0 {
		h := sha256.New()
		h.Write([]byte(apiAuthCBLabel))
		h.Write(cert.Certificate[0])
		r.leafHash = h.Sum(nil)
	}
	if r.caPath != "" {
		pool, err := loadClientCAPool(r.caPath)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
	}
	return cfg, nil
}

// fileStamp 拼出"证书 / 密钥 / 客户端 CA"这三个文件的指纹。
//
// 接收者 r 是重载器。
//
// 返回：
//
//	string — "路径:mtime:size" 逐条拼起来的串；任一文件 stat 失败时用 "!" 占位
//	         （stat 失败会让指纹每次都变 ⇒ 下次握手重试加载，从而把错误暴露出来）
func (r *apiTLSReloader) fileStamp() string {
	out := ""
	for _, p := range []string{r.certPath, r.keyPath, r.caPath} {
		if p == "" {
			out += "|-"
			continue
		}
		st, err := os.Stat(p)
		if err != nil {
			out += "|" + p + ":!"
			continue
		}
		out += "|" + p + ":" + st.ModTime().UTC().Format("20060102150405.000") + ":" + fmt.Sprint(st.Size())
	}
	return out
}

// LeafCertHash 返回当前服务端叶子证书的通道绑定值。
//
// 接收者 r 是重载器。
//
// 返回：
//
//	[]byte — 32 字节证书哈希（证书热重载后随之变化）；尚未加载成功时为 nil
func (r *apiTLSReloader) LeafCertHash() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.leafHash
}

// loadClientCAPool 读客户端 CA（文件或目录）成证书池。
//
// 参数：
//
//	path — PEM 文件或目录（目录里扫 *.crt/*.pem，与 security.ca_cert_paths 同一套约定）
//
// 返回：
//
//	*x509.CertPool — 可用于校验客户端证书的池
//	error          — 路径不存在 / 解析失败 / 目录里没有证书时返回
func loadClientCAPool(path string) (*x509.CertPool, error) {
	certs, err := identity.LoadOrScanTrustAnchors([]string{path})
	if err != nil {
		return nil, fmt.Errorf("api.tls.ca_path %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}
