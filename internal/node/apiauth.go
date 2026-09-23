package node

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"treecmd/internal/canon"
)

// 对外 HTTP 端点的访问控制（只作用于写操作）。
//
// 【为什么要有这一层】`api.http_addr` 可以写成 `0.0.0.0`，而写接口里躺着几个**不可逆**的
// 运维动作：`POST /v1/crl` 吊销节点（本节点不校验 `?node=` 与自己的关系，直接写 CRL 并
// 推给所有直接子）、`POST /v1/forget` 一条事务删掉注册表 / 水位 / 驱逐归档 / 结果副本、
// `POST /v1/commands` 让整棵子树执行指令。裸奔时，任何能连上这个端口的人都能做这些事 ——
// 这就是"访问控制缺失"。本文件补上它。
//
// 【口径】判定顺序如下，前一条命中就不再往下走：
//
//  1. `/v1/healthz` —— 永远放行（存活探针，只回 ok / node_id / path，不触发任何跨节点调用）
//  2. 读请求（GET / HEAD / OPTIONS）—— 只有 `api.auth.protect_reads` 打开才要签名
//  3. 回环来源（127.0.0.1 / ::1）—— 放行：本机运维脚本、控制台代理、curl localhost 都走这里
//  4. 其余（非回环的写请求）—— 必须带正确的 HMAC 签名；**没配密钥就一律拒绝**
//
// 【签名格式】三个请求头（域分隔 `treecmd/api/v1`，canonical 编码见 internal/canon）：
//
//	X-Treecmd-Timestamp: <Unix 秒>
//	X-Treecmd-Nonce:     <调用方生成的一次性随机串>
//	X-Treecmd-Signature: base64(HMAC-SHA256(secret, payload))
//
// payload = canon.Writer: Str(域) Str(方法) Str(路径) Str(原始 query) Bytes(sha256(body)) I64(时间戳) Str(nonce)
//
// 为什么这样设计：密钥**不上线**（签的是派生值，不是把密钥发出去），于是明文 HTTP 上的
// 窃听者拿不到可复用的凭据；时间窗挡"过期重放"，nonce 表挡"窗口内的重放"。
// 客户端实现见 scripts/api_call.py（两边编码必须逐字节一致，test/api-auth.sh 在证这件事）。
const (
	// apiAuthDomain 签名域分隔串：同一对密钥不会被复用到别的协议 / 用途上。
	apiAuthDomain = "treecmd/api/v1"
	// apiAuthSkew 时间戳允许的偏差（两端时钟差必须小于它，NTP 对齐时毫无压力）。
	apiAuthSkew = 60 * time.Second
	// apiAuthMaxBody 验签要先把 body 读进内存算摘要，给个上限别让人用大 body 打爆内存。
	apiAuthMaxBody = 8 << 20
	// apiAuthMaxNonces nonce 表的条数上限（满了先清过期项，再按最旧淘汰）。
	apiAuthMaxNonces = 4096
	// apiAuthMinSecretLen 密钥长度下限：短于此只在启动时告警（不拒绝启动，避免把已有部署卡死）。
	apiAuthMinSecretLen = 16

	headerAPITimestamp = "X-Treecmd-Timestamp"
	headerAPINonce     = "X-Treecmd-Nonce"
	headerAPISignature = "X-Treecmd-Signature"

	// apiPathHealthz 存活探针，永远免认证。
	apiPathHealthz = "/v1/healthz"

	errAPIAuthNotConfigured = "ERR_API_AUTH_NOT_CONFIGURED"
	errAPIAuthRequired      = "ERR_API_AUTH_REQUIRED"
	errAPIAuthFailed        = "ERR_API_AUTH_FAILED"
	errAPIAuthUnavailable   = "ERR_API_AUTH_UNAVAILABLE"
	errAPIAuthTooLarge      = "ERR_API_AUTH_TOO_LARGE"
)

// withAPIAuth 给对外 HTTP 端点套上访问控制：受保护的请求先过 authorizeAPI，再交给业务处理。
//
// 接收者 n 是本节点实例。被拒的请求会落一条 AUDIT-REJECT 审计日志并计入
// untrusted_origin_rejected_total（拒绝类事件是"有人在试探"的最早信号，必须留痕）。
//
// 参数：
//
//	next — 原来的路由处理器（即 mux）
//
// 返回：包装后的处理器；是否拦截每个请求由 apiAuthApplies 决定。
func (n *Node) withAPIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !n.apiAuthApplies(r) {
			next.ServeHTTP(w, r)
			return
		}
		if err := n.authorizeAPI(r); err != nil {
			n.auditReject("api_auth", "", "", err)
			writeErr(w, statusForAPIAuth(err), errCodeOf(err), err.Error())
			return
		}
		next.ServeHTTP(w, r)
	})
}

// apiAuthApplies 判断这个请求是否在访问控制的射程内。
//
// 接收者 n 是本节点实例。
//
//	/v1/healthz                     —— 永远不在射程内（存活探针）
//	GET / HEAD / OPTIONS            —— 取决于 api.auth.protect_reads（默认 false = 放行）
//	其余（POST 等一切写方法）        —— **一律在射程内**
//
// "写方法一律在射程内"是刻意的 fail-closed：将来新增的写接口不需要记得来改这里，
// 漏掉的是"加白名单"而不是"忘了保护"。
//
// 参数：
//
//	r — 请求
//
// 返回：需要认证时返回 true。
func (n *Node) apiAuthApplies(r *http.Request) bool {
	if r.URL.Path == apiPathHealthz {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return n.C().API.Auth.ProtectReads
	default:
		return true
	}
}

// authorizeAPI 校验一个受保护请求是否有权执行。
//
// 接收者 n 是本节点实例。规则见文件头；这里只做"放行 / 拒绝"的判定，不产生副作用
// （唯一的副作用是**验签通过后**记下 nonce，用于挡重放）。
//
// 参数：
//
//	r — 请求；需要签名时从 X-Treecmd-Timestamp / Nonce / Signature 三个头读取凭据
//
// 返回：放行返回 nil；否则返回形如 "ERR_API_AUTH_xxx: ..." 的错误（错误文本里带来源地址，
// 方便从日志里定位是谁在试探）。
func (n *Node) authorizeAPI(r *http.Request) error {
	// ① 回环来源免签：本机运维是主路径（scripts/start_node.sh、test/*.sh、控制台代理、curl localhost）。
	//
	// ⚠️ 依据是 **TCP 对端地址**（RemoteAddr），绝不能用 X-Forwarded-For 之类可伪造的头。
	// 由此带来一个部署前提：**别在 API 端口前面挂本地反向代理 / 端口转发**，否则所有请求的
	// 对端都会变成 127.0.0.1，这一条豁免就等于对所有来源放行。真要放在代理后面，请配密钥 ——
	// 配了密钥之后，回环请求里**带了签名**的仍然会被照常校验（见下面第 ④ 步）。
	if isLoopbackRemote(r.RemoteAddr) && !hasAPISignature(r) {
		return nil
	}

	// ② 取密钥。没配 ⇒ 非回环请求一律拒绝（fail-closed）。
	secret, configured, err := n.apiSecret()
	if err != nil {
		return fmt.Errorf("%s: %w", errAPIAuthUnavailable, err)
	}
	if !configured {
		return fmt.Errorf("%s: 本节点未配置 api.auth.secret / secret_path，"+
			"写接口只接受本机(回环)请求（来源 %s）", errAPIAuthNotConfigured, r.RemoteAddr)
	}

	// ③ 凭据齐全性：先把头看一遍再读 body —— 这样"什么凭据都不带"的探测连内存都吃不到。
	if !hasAPISignature(r) {
		return fmt.Errorf("%s: 非本机来源的写请求必须带 %s / %s / %s 三个头（来源 %s）",
			errAPIAuthRequired, headerAPITimestamp, headerAPINonce, headerAPISignature, r.RemoteAddr)
	}
	tsRaw := r.Header.Get(headerAPITimestamp)
	nonce := r.Header.Get(headerAPINonce)
	sigRaw := r.Header.Get(headerAPISignature)
	ts, perr := strconv.ParseInt(strings.TrimSpace(tsRaw), 10, 64)
	if perr != nil {
		return fmt.Errorf("%s: %s 不是 Unix 秒（来源 %s）", errAPIAuthFailed, headerAPITimestamp, r.RemoteAddr)
	}
	if nonce == "" {
		return fmt.Errorf("%s: %s 为空（来源 %s）", errAPIAuthFailed, headerAPINonce, r.RemoteAddr)
	}
	if d := time.Since(time.Unix(ts, 0)); d > apiAuthSkew || d < -apiAuthSkew {
		return fmt.Errorf("%s: 时间戳超出 ±%s 窗口（偏差 %s，检查两端时钟；来源 %s）",
			errAPIAuthFailed, apiAuthSkew, d.Round(time.Second), r.RemoteAddr)
	}

	// ④ 验签。body 要参与摘要（否则签名可以被搬到另一个 body 上）。
	body, err := readBodyForAuth(r)
	if err != nil {
		return err
	}
	payload := apiAuthPayload(r.Method, r.URL.Path, r.URL.RawQuery, body, ts, nonce)
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	want := mac.Sum(nil)
	got, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(sigRaw))
	if derr != nil || !hmac.Equal(want, got) {
		return fmt.Errorf("%s: 签名不匹配（来源 %s；payload 覆盖 方法/路径/query/body 摘要/时间戳/nonce）",
			errAPIAuthFailed, r.RemoteAddr)
	}

	// ⑤ 防重放：时间窗内同一个 nonce 只认一次。放在验签**之后** —— 只有持密钥的人
	// 才能往表里塞条目，否则谁都能用假 nonce 把表刷满、把合法请求挤掉。
	if !n.redeemNonce(nonce) {
		return fmt.Errorf("%s: nonce %q 已用过（重放；来源 %s）", errAPIAuthFailed, nonce, r.RemoteAddr)
	}
	return nil
}

// hasAPISignature 判断请求是否带了完整的签名三件套（缺一即视为"没带"）。
//
// 参数：
//
//	r — 请求
//
// 返回：三个头都非空时返回 true。
func hasAPISignature(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get(headerAPITimestamp)) != "" &&
		strings.TrimSpace(r.Header.Get(headerAPINonce)) != "" &&
		strings.TrimSpace(r.Header.Get(headerAPISignature)) != ""
}

// apiSecret 取当前生效的共享密钥。
//
// 接收者 n 是本节点实例。**每次请求现读**（不给内存缓存）：密钥轮换于是既不用重启、
// 也不用 SIGHUP —— 换完文件下一个请求就用新的。密钥文件不可能大，这点 I/O 可以忽略。
//
// 参数：无。
//
// 返回：
//
//	[]byte — 去空白后的密钥；空切片表示"没配"
//	bool   — 是否配了密钥（配了但内容为空按"没配"算，宁严不宽）
//	error  — 配了 secret_path 但文件读不到时返回（调用方按 500 处理，绝不降级放行）
func (n *Node) apiSecret() ([]byte, bool, error) {
	a := &n.C().API.Auth
	if !a.Configured() {
		return nil, false, nil
	}
	b, err := a.SecretBytes()
	if err != nil {
		return nil, false, err
	}
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, false, nil
	}
	return b, true, nil
}

// readBodyForAuth 把请求体读进内存算摘要，并把读出来的内容**放回** r.Body 供业务读取。
//
// 参数：
//
//	r — 请求；Body 为 nil（如 GET）时直接返回 nil，不动它
//
// 返回：
//
//	[]byte — body 原文（可能是 nil）
//	error  — 读取失败、或超过 apiAuthMaxBody 时返回（超限是 TOO_LARGE，按 413 回）
func readBodyForAuth(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, apiAuthMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%s: 读取请求体失败: %w", errAPIAuthFailed, err)
	}
	if len(b) > apiAuthMaxBody {
		return nil, fmt.Errorf("%s: 请求体超过 %d 字节", errAPIAuthTooLarge, apiAuthMaxBody)
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

// apiAuthPayload 拼接签名的"待签内容"。
//
// 参数：
//
//	method   — HTTP 方法（大写，如 POST）
//	path     — 请求路径（r.URL.Path，不含 query）
//	rawQuery — 原始 query（r.URL.RawQuery，**原样**：重排或重新转义都会算出不同的串）
//	body     — 请求体原文（空体即空切片，摘要照样参与）
//	ts       — Unix 秒时间戳
//	nonce    — 一次性随机串
//
// 返回：canonical 编码后的字节串（canon.Writer：Str 带 8 字节大端长度前缀，I64 定长 8 字节）。
func apiAuthPayload(method, path, rawQuery string, body []byte, ts int64, nonce string) []byte {
	sum := sha256.Sum256(body)
	w := canon.NewWriter().
		Str(apiAuthDomain).
		Str(method).
		Str(path).
		Str(rawQuery).
		Bytes(sum[:]).
		I64(ts).
		Str(nonce)
	return w.Out()
}

// isLoopbackRemote 判断 TCP 对端地址是否来自回环（本机）。
//
// 参数：
//
//	remoteAddr — http.Request.RemoteAddr 形式（"127.0.0.1:54321" / "[::1]:54321"）
//
// 返回：回环返回 true；解析不出 IP（含畸形输入）一律 false（宁严不宽）。
func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	return isLoopbackHost(host)
}

// isLoopbackHost 判断一个主机名字段是不是回环 IP。
//
// 参数：
//
//	host — 裸主机（"127.0.0.1" / "::1" / "[::1]" / "localhost"）
//
// 返回：回环（含 localhost）返回 true；其它一律 false（主机名与畸形输入都不算回环）。
func isLoopbackHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	// IPv4-mapped IPv6（::ffff:127.0.0.1）的 IsLoopback 为 false，要按 4 字节形态再判一次。
	if v4 := ip.To4(); v4 != nil {
		return v4.IsLoopback()
	}
	return false
}

// redeemNonce 兑换一次性 nonce：第一次见到返回 true 并记下，重复出现返回 false。
//
// 接收者 n 是本节点实例。表满了先清掉过期项，仍满则淘汰最旧的一条 —— 于是内存占用
// 有硬上限（apiAuthMaxNonces 条），不会成为新的攻击面。
//
// 参数：
//
//	nonce — 请求头里的 nonce
//
// 返回：首次出现返回 true；已用过返回 false。
func (n *Node) redeemNonce(nonce string) bool {
	now := time.Now()
	n.authMu.Lock()
	defer n.authMu.Unlock()
	if n.authNonces == nil {
		n.authNonces = map[string]time.Time{}
	}
	if _, seen := n.authNonces[nonce]; seen {
		return false
	}
	if len(n.authNonces) >= apiAuthMaxNonces {
		cutoff := now.Add(-2 * apiAuthSkew)
		for k, t := range n.authNonces {
			if t.Before(cutoff) {
				delete(n.authNonces, k)
			}
		}
		for len(n.authNonces) >= apiAuthMaxNonces {
			var oldestKey string
			var oldest time.Time
			for k, t := range n.authNonces {
				if oldestKey == "" || t.Before(oldest) {
					oldestKey, oldest = k, t
				}
			}
			delete(n.authNonces, oldestKey)
		}
	}
	n.authNonces[nonce] = now
	return true
}

// statusForAPIAuth 把鉴权失败的类别映射成 HTTP 状态码。
//
// 参数：
//
//	err — authorizeAPI 返回的错误
//
// 返回：500（密钥读取失败）、413（body 超限）、403（未配密钥 ⇒ 能力上就没有）、
// 401（缺少凭据 / 签名不符 / 过期 / 重放），以及无法识别时的默认值 401。
func statusForAPIAuth(err error) int {
	switch errCodeOf(err) {
	case errAPIAuthUnavailable:
		return 500
	case errAPIAuthTooLarge:
		return 413
	case errAPIAuthNotConfigured:
		return 403
	}
	return 401
}

// logAPIAuthPosture 启动时把"这个 HTTP 端点对外是什么口径"明确说一遍。
//
// 接收者 n 是本节点实例。**对外监听 + 没配密钥**是最需要被看见的组合（写接口只剩本机可达），
// 这种情况打 WARN；密钥过短也打 WARN（不拒绝启动，避免把已有部署卡在升级路径上）。
//
// 参数：
//
//	addr — api.http_addr 原文，用于判断是否只有本机能到达
func (n *Node) logAPIAuthPosture(addr string) {
	a := &n.C().API.Auth
	exposed := listenExposesOutside(addr)
	switch {
	case a.Configured() && a.ProtectReads:
		n.Log.Info("api auth: 写接口与读接口都要求签名（本机来源免签）", "secret_path", a.SecretPath)
	case a.Configured():
		n.Log.Info("api auth: 写接口要求签名（读接口放行；本机来源免签）", "secret_path", a.SecretPath)
	case exposed:
		n.Log.Warn("api auth: 监听地址对外可达，但没配 api.auth.secret(_path) —— " +
			"非本机来源的**写请求会被一律拒绝**（403）；要远程运维请投放 api.secret（权限 600）并重启本节点")
	default:
		n.Log.Info("api auth: 未配密钥，且监听地址只在本机可达（写接口只接受回环请求）")
	}
	if b, ok, err := n.apiSecret(); err != nil {
		n.Log.Warn("api auth: 密钥读取失败", "err", err)
	} else if ok && len(b) < apiAuthMinSecretLen {
		n.Log.Warn("api auth: 共享密钥过短，建议 ≥ 32 字节随机（如 head -c 32 /dev/urandom | base64）", "len", len(b))
	}
}

// listenExposesOutside 判断监听地址是否可能被本机之外的来源连上。
//
// 参数：
//
//	addr — 形如 "127.0.0.1:18443" / "0.0.0.0:18443" / ":18443" 的监听地址
//
// 返回：空主机名（":port" = 监听全部地址）、IPv4/IPv6 全零地址、或某个非回环的具体地址
// 都返回 true；只绑回环地址时返回 false。
func listenExposesOutside(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return true // ":18443" = 监听全部地址
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true // 主机名：当它是可达的，宁可多提示一次
	}
	if ip.IsUnspecified() {
		return true // 0.0.0.0 / ::
	}
	return !isLoopbackHost(host)
}
