package node

// user token：对外 HTTP 端点的唯一授权凭据（CA 签发、落盘 user/、按需缓存）。
//
// 【为什么是 token 而不是共享密钥 / 回环免签】
//
//	旧口径是"回环来源免签 + 非回环用 HMAC 共享密钥"。它有两个绕不过去的坑：
//	  1. 免签的判据是 **TCP 对端地址**，而它会被部署形态改写 —— API 端口前面挂了反向代理 /
//	     端口转发（nginx、ssh -L、frpc、kubectl port-forward…）时，远程请求的对端全是
//	     127.0.0.1，"本机"这个身份就烂掉了，免签等于对全网放行；
//	  2. 共享密钥是**全网一把**（或每节点各一把但要靠人工投放），既没法按人区分"谁进来的"，
//	     也无法在不动其他人的前提下收回某个人的权限。
//
//	改成 token 之后：不看来源地址（回环、内网、外网一视同仁），只看"你有没有一份本节点 CA
//	签出来的凭据"；按人一份、按文件收回（删文件即可，缓存按目录 mtime 自动失效）。
//
// 【格式】一行：`<16 位随机串>.<base64(Ed25519 签名)>`
//
//	签名内容 = canon(域 ‖ 用户名 ‖ 随机串)，密钥是本节点的 CA 私钥（security.ca_key_path）。
//	域名分隔的作用：同一把 CA 密钥给节点发证书、给用户发 token，两条用途不能互相冒充。
//	随机串是 128 bit 熵 —— 它是 token 的身份，签名证明"这份身份是本节点 CA 认可的"。
//
// 【落盘】`<节点目录>/user/<用户名>`，目录 0700、文件 0600，内容就是上面那一行 token
//	（末尾一个换行，读的时候 TrimSpace）。**用户名即文件名**：收回权限就是 `rm user/<用户名>`。
//	签发命令是 `treecmd-node -adduser <用户名> -config node.yaml`（见 cmd/node/main.go）。
//
// 【校验】API 侧不看来源地址，只要求请求头 `X-Treecmd-Token` 出示 token：
//
//	· 先查内存缓存（token → 用户名）：命中即放行；
//	· 未命中则看 user/ 目录的 mtime，变了就重扫（`-adduser` 之后立刻生效，不用重启节点）；
//	· 仍然找不到 ⇒ 403。**没有授权信息就禁止访问**，没有任何免签入口。
//
//	扫描时会用 CA 公钥逐份验签：往 user/ 目录里丢一个手工编写的文件**不算**授权，
//	只有本节点 CA 签过的才算（目录权限只是第二道）。
//
// 【明文链路要配 TLS】token 是长期凭据，每个请求都会上线，明文 HTTP 上被抄走即可原样重放。
//	对外暴露时请配 api.tls（建议 require: true），见 APITLSSection。

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"treecmd/internal/canon"
	"treecmd/internal/config"
	"treecmd/internal/identity"
)

const (
	// userTokenDomain 签名域分隔串：与证书签发、API 旧签名域都不同，用途不互相冒充。
	userTokenDomain = "treecmd/api/user/v1"
	// userTokenRandLen token 里随机串的长度（字符数）。16 个字符取自 62 字符集 ≈ 95 bit 熵。
	userTokenRandLen = 16
	// userTokenAlphabet 随机串字符集：大小写字母 + 数字（URL/头字段里都安全，不用转义）。
	userTokenAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	// userTokenSep 随机串与签名之间的分隔符。
	userTokenSep = "."
	// userTokenMaxFileBytes 单个 token 文件的读取上限：正常只有 ~70 字节，给个上界防"塞个大文件"。
	userTokenMaxFileBytes = 4 << 10
	// userTokenMaxNameLen 用户名长度上限（文件名长度也受它约束）。
	userTokenMaxNameLen = 64

	// userTokenRescanInterval 缓存未命中时的重扫节流：mtime 没变的情况下，最快多久重扫一次。
	//
	// 为什么需要：未获授权的请求会走到"重扫目录"这一步，不节流的话，随便谁都能用错 token
	// 把本节点的磁盘读打满（放大攻击）。1 秒的窗口换来的代价只是"刚签发的 token 最坏晚 1 秒
	// 生效"，而 mtime 一变就是立即重扫，实际操作里感觉不到延迟。
	userTokenRescanInterval = time.Second
)

// ValidAPIUsername 判断用户名能否作为 token 文件名。
//
// 为什么校验而不是直接拼路径：用户名会变成 `user/<用户名>` 这个**路径**，放任 `../` 之类
// 就是路径穿越（写文件时能写到目录外，读文件时能读到别处）。这里只收保守字符集：
// 字母开头，字母 / 数字 / `-` / `_` / `.`，长度 1..userTokenMaxNameLen，且不允许 `..`。
//
// 参数：
//
//	name — 用户名原文
//
// 返回：合法返回 true，否则 false。
func ValidAPIUsername(name string) bool {
	if name == "" || len(name) > userTokenMaxNameLen {
		return false
	}
	if name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return false // 隐藏文件 / 相对路径不当作用户名
	}
	for i := 0; i < len(name); i++ {
		ch := name[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9', ch == '-', ch == '_', ch == '.':
			// 数字与分隔符：位置不限（首字符可以是数字，`user/1` 并不特殊）
		default:
			return false
		}
	}
	return true
}

// UserTokenPath 给出某个用户在 user/ 目录下的 token 文件路径。
//
// 参数：
//
//	userDir  — user 目录（config.Config.UserDir）
//	username — 已通过 ValidAPIUsername 的用户名
//
// 返回：token 文件路径。
func UserTokenPath(userDir, username string) string {
	return filepath.Join(userDir, username)
}

// newUserTokenRandom 生成长度为 userTokenRandLen 的随机串。
//
// 取字节后按拒绝采样丢弃落在非均匀区间的值（256 不是 62 的整数倍，直接取模会让前几个字符
// 概率偏高），于是每个字符严格均匀。
//
// 返回：
//
//	string — 随机串
//	error  — 系统随机源不可用时返回（调用方必须当作失败处理，绝不回退到伪随机）
func newUserTokenRandom() (string, error) {
	limit := byte(256 - 256%len(userTokenAlphabet)) // 62 → 248
	out := make([]byte, 0, userTokenRandLen)
	buf := make([]byte, 32)
	for len(out) < userTokenRandLen {
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("随机源不可用: %w", err)
		}
		for _, b := range buf {
			if b >= limit {
				continue
			}
			out = append(out, userTokenAlphabet[int(b)%len(userTokenAlphabet)])
			if len(out) == userTokenRandLen {
				break
			}
		}
	}
	return string(out), nil
}

// userTokenPayload 拼接 token 的"待签内容"。
//
// 参数：
//
//	username — 用户名（owner）
//	randStr  — token 里的随机串
//
// 返回：canonical 编码后的字节串（字段顺序就是协议，签发与校验必须走这一个函数）。
func userTokenPayload(username, randStr string) []byte {
	return canon.NewWriter().
		Str(userTokenDomain).
		Str(username).
		Str(randStr).
		Out()
}

// NewUserToken 生成一份新 token：随机串 + CA 私钥签名。
//
// 参数：
//
//	caKey    — 本节点 CA 私钥（security.ca_key_path，Ed25519）
//	username — 用户名；必须已通过 ValidAPIUsername
//
// 返回：
//
//	string — token（`<随机串>.<base64 签名>`），即 token 文件的全部内容
//	error  — 随机源失败、CA 私钥为空或长度不对、用户名非法时返回
func NewUserToken(caKey ed25519.PrivateKey, username string) (string, error) {
	if !ValidAPIUsername(username) {
		return "", fmt.Errorf("用户名 %q 非法：只允许字母开头、字母/数字/-/_/.、长度 1..%d", username, userTokenMaxNameLen)
	}
	if len(caKey) != ed25519.PrivateKeySize {
		return "", errors.New("本节点没有可用的 CA 私钥（security.ca_key_path）：token 必须由 CA 签发")
	}
	rs, err := newUserTokenRandom()
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(caKey, userTokenPayload(username, rs))
	return rs + userTokenSep + base64.StdEncoding.EncodeToString(sig), nil
}

// parseUserToken 把 token 拆成"随机串 + 签名"。
//
// 参数：
//
//	raw — token 原文（允许首尾空白，内部会 TrimSpace）
//
// 返回：
//
//	string — 随机串
//	[]byte — 签名字节
//	bool   — 格式不合法（缺分隔符、随机串长度或字符集不符、签名不是合法 base64）时为 false
func parseUserToken(raw string) (string, []byte, bool) {
	raw = strings.TrimSpace(raw)
	rs, sigRaw, found := strings.Cut(raw, userTokenSep)
	if !found || len(rs) != userTokenRandLen {
		return "", nil, false
	}
	for i := 0; i < len(rs); i++ {
		if !strings.ContainsRune(userTokenAlphabet, rune(rs[i])) {
			return "", nil, false
		}
	}
	sig, err := base64.StdEncoding.DecodeString(sigRaw)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return "", nil, false
	}
	return rs, sig, true
}

// VerifyUserToken 用 CA 公钥校验一份 token 是否由该 CA 为指定用户名签发。
//
// 参数：
//
//	caPub    — 本节点 CA 公钥（从 CA 私钥导出，或取自 CA 证书）
//	username — 用户名（token 文件名）
//	raw      — token 原文
//
// 返回：核验通过返回 true；格式不合法、公钥不可用、验签失败一律 false。
func VerifyUserToken(caPub ed25519.PublicKey, username, raw string) bool {
	if len(caPub) != ed25519.PublicKeySize || !ValidAPIUsername(username) {
		return false
	}
	rs, sig, ok := parseUserToken(raw)
	if !ok {
		return false
	}
	return ed25519.Verify(caPub, userTokenPayload(username, rs), sig)
}

// AddUser 为某个用户名签发 token 并落盘到 user/<用户名>。
//
// 这是 `treecmd-node -adduser` 的实现：**不依赖节点进程运行**（直接读配置里的 CA 私钥），
// 于是"给谁发凭据"这件事可以离线完成，也不需要重启节点（API 侧按目录 mtime 自动重扫）。
//
// 参数：
//
//	cfg      — 已加载的配置（用 cfg.Security.CAKeyPath 与 cfg.UserDir）
//	username — 用户名；非法时直接报错
//	force    — false 时目标文件已存在即拒绝（避免把在用的 token 悄悄换掉）；true 时覆盖
//
// 返回：
//
//	string — 写入的 token 文件路径
//	error  — 用户名非法 / CA 私钥缺失或读不出 / 建目录或写文件失败时返回
func AddUser(cfg *config.Config, username string, force bool) (string, error) {
	if !ValidAPIUsername(username) {
		return "", fmt.Errorf("用户名 %q 非法：只允许字母开头、字母/数字/-/_/.、长度 1..%d", username, userTokenMaxNameLen)
	}
	if cfg == nil {
		return "", errors.New("配置为空")
	}
	path := UserTokenPath(cfg.UserDir, username)
	if !force {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("%s 已存在（该用户的 token 仍有效；要换一份请加 -force）", path)
		}
	}
	caKey, err := loadCAKeyForUserToken(cfg)
	if err != nil {
		return "", err
	}
	token, err := NewUserToken(caKey, username)
	if err != nil {
		return "", err
	}
	// 目录 0700、文件 0600：token 等同于凭据本身，不给同组 / 其他人任何读的机会。
	if err := os.MkdirAll(cfg.UserDir, 0o700); err != nil {
		return "", fmt.Errorf("建 user 目录 %s: %w", cfg.UserDir, err)
	}
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", fmt.Errorf("写 token 文件 %s: %w", path, err)
	}
	// MkdirAll 不会收紧已存在目录的权限，显式再chmod一次（目录已存在且权限宽松时收敛它）。
	_ = os.Chmod(cfg.UserDir, 0o700)
	_ = os.Chmod(path, 0o600)
	return path, nil
}

// loadCAKeyForUserToken 读本节点 CA 私钥。
//
// 参数：
//
//	cfg — 已加载的配置
//
// 返回：
//
//	ed25519.PrivateKey — CA 私钥
//	error              — 未配 / 文件不存在 / 内容不是 Ed25519 私钥时返回（文案里点明是"没 CA 就没法签发"）
func loadCAKeyForUserToken(cfg *config.Config) (ed25519.PrivateKey, error) {
	path := cfg.Security.CAKeyPath
	if path == "" {
		return nil, errors.New("本节点没有配置 security.ca_key_path —— token 必须由本节点 CA 签发，" +
			"没有 CA 就发不出凭据（有子节点的节点会有这份材料：treecmd-node -genkey -keydir keys -with-ca）")
	}
	key, err := identity.LoadIdentityKey(path)
	if err != nil {
		return nil, fmt.Errorf("读 CA 私钥: %w（token 必须由本节点 CA 签发）", err)
	}
	return key, nil
}

// userTokenUsername 校验一份 token 是否属于某个已授权的用户。
//
// 接收者 n 是本节点实例。
//
// 流程：内存缓存（token → 用户名）命中即返回；未命中则按 user/ 目录 mtime 判断要不要重扫
// （`-adduser` 之后立即生效），重扫后再查一次；仍然没有就返回"未授权"。
//
// 参数：
//
//	raw — 请求头 X-Treecmd-Token 的原文
//
// 返回：
//
//	string — 命中的用户名
//	error  — 未带 token / token 不在 user/ 目录里 / 本节点没有 CA 材料可验签 / 读目录失败
func (n *Node) userTokenUsername(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%s: 缺少 %s 请求头 —— 本端点没有免签来源，"+
			"请用 `treecmd-node -adduser <用户名> -config node.yaml` 签发 token 后带上它", errAPIAuthRequired, headerAPIToken)
	}
	// 格式先粗筛一遍：连格式都不对的探测不必去碰磁盘。
	if _, _, ok := parseUserToken(raw); !ok {
		return "", fmt.Errorf("%s: %s 格式不合法（应形如 <16 位随机串>.<base64 签名>）", errAPIAuthTokenInvalid, headerAPIToken)
	}
	caPub, err := n.userTokenCAPub()
	if err != nil {
		return "", err
	}
	if name, ok := n.cachedUserToken(raw); ok {
		return name, nil
	}
	if err := n.rescanUserTokens(caPub); err != nil {
		return "", err
	}
	if name, ok := n.cachedUserToken(raw); ok {
		return name, nil
	}
	return "", fmt.Errorf("%s: %s 不在本节点的 user/ 目录里（可能未签发、已收回，或不是本节点 CA 签的）",
		errAPIAuthTokenInvalid, headerAPIToken)
}

// userTokenCAPub 取用于验签的 CA 公钥。
//
// 接收者 n 是本节点实例。公钥从 CA 私钥导出：节点持有 CA 私钥才有资格签发 token，
// 也才有资格校验它 —— 这条把"谁能发凭据"与"谁能进这个端点"钉成了同一件事。
//
// 返回：
//
//	ed25519.PublicKey — CA 公钥
//	error            — 本节点不持有 CA 材料时返回（此时除了 /v1/healthz 一律拒绝）
func (n *Node) userTokenCAPub() (ed25519.PublicKey, error) {
	id := n.Id()
	if id == nil || len(id.CAKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: 本节点不持有 CA 私钥（security.ca_key_path），无法校验 user token；"+
			"请让该节点带上 CA 材料（treecmd-node -genkey -keydir keys -with-ca）后重启", errAPIAuthUnavailable)
	}
	return id.CAKey.Public().(ed25519.PublicKey), nil
}

// cachedUserToken 在缓存里查一份 token。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	raw — token 原文
//
// 返回：命中时返回用户名与 true。
func (n *Node) cachedUserToken(raw string) (string, bool) {
	n.userMu.Lock()
	defer n.userMu.Unlock()
	name, ok := n.userTokens[raw]
	return name, ok
}

// rescanUserTokens 重新扫描 user/ 目录，重建 token → 用户名 缓存。
//
// 接收者 n 是本节点实例。
//
// 【节流】目录 mtime 没变时，两次重扫之间至少隔 userTokenRescanInterval —— 否则未授权的
// 请求可以靠"错 token"逼着本节点反复读盘（放大攻击）。mtime 一变（例如刚跑了 -adduser）
// 就是立即重扫，所以正常操作感觉不到这个窗口。
//
// 扫描时逐份用 CA 公钥验签：验不过的文件**不进入缓存**（只记一条 WARN），
// 于是"往 user/ 目录塞一个自己编的文件"不构成授权。
//
// 参数：
//
//	caPub — 用于验签的 CA 公钥
//
// 返回：目录读不了（除"不存在"外）时返回错误；其余情况（含目录不存在）返回 nil 并清空缓存。
func (n *Node) rescanUserTokens(caPub ed25519.PublicKey) error {
	dir := n.C().UserDir
	st, statErr := os.Stat(dir)
	stamp := time.Time{}
	if statErr == nil {
		stamp = st.ModTime()
	}

	n.userMu.Lock()
	changed := statErr != nil || !stamp.Equal(n.userStamp) || !n.userScanned
	throttled := time.Since(n.userLastScan) < userTokenRescanInterval
	if !changed && throttled {
		n.userMu.Unlock()
		return nil
	}
	n.userMu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("%s: 读 user 目录 %s: %w", errAPIAuthUnavailable, dir, err)
		}
		entries = nil // 还没有 user/ 目录 = 一个用户都没签发；不是错误
	}

	fresh := make(map[string]string, len(entries))
	var skipped []string
	for _, e := range entries {
		if e.IsDir() || !ValidAPIUsername(e.Name()) {
			continue
		}
		raw, err := readUserTokenFile(filepath.Join(dir, e.Name()))
		if err != nil {
			skipped = append(skipped, e.Name())
			continue
		}
		if !VerifyUserToken(caPub, e.Name(), raw) {
			skipped = append(skipped, e.Name())
			continue
		}
		fresh[strings.TrimSpace(raw)] = e.Name()
	}
	if len(skipped) > 0 {
		sort.Strings(skipped)
		n.Log.Warn("api auth: user/ 目录下有验签不过的 token 文件，已忽略（不是本节点 CA 签的，或格式不对）",
			"files", strings.Join(skipped, ","), "dir", dir)
	}

	n.userMu.Lock()
	n.userTokens = fresh
	n.userStamp = stamp
	n.userScanned = true
	n.userLastScan = time.Now()
	n.userMu.Unlock()
	return nil
}

// readUserTokenFile 读一份 token 文件（去空白、封顶 userTokenMaxFileBytes）。
//
// 参数：
//
//	path — token 文件路径
//
// 返回：
//
//	string — 去首尾空白后的内容
//	error  — 打不开 / 读不动 / 超过上限时返回（调用方跳过这份文件）
func readUserTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, userTokenMaxFileBytes)
	nn, err := f.Read(buf)
	if err != nil && nn == 0 {
		return "", err
	}
	return strings.TrimSpace(string(buf[:nn])), nil
}

// userTokenCount 返回缓存里已授权的 token 数量（供启动自检日志展示）。
//
// 接收者 n 是本节点实例。
//
// 返回：缓存条数；尚未扫描过时返回 0 与 false。
func (n *Node) userTokenCount() (int, bool) {
	n.userMu.Lock()
	defer n.userMu.Unlock()
	return len(n.userTokens), n.userScanned
}
