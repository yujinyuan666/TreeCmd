package node

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"treecmd/internal/canon"
	"treecmd/internal/config"
)

// 对外 HTTP 端点的访问控制（只作用于写操作）。
//
// 【为什么要有这一层】`api.http_addr` 可以写成 `0.0.0.0`，而写接口里躺着几个**不可逆**的
// 运维动作：`POST /v1/crl` 吊销节点（本节点不校验 `?node=` 与自己的关系，直接写 CRL 并
// 推给所有直接子）、`POST /v1/forget` 一条事务删掉注册表 / 水位 / 驱逐归档 / 结果副本、
// `POST /v1/commands` 让整棵子树执行指令。裸奔时，任何能连上这个端口的人都能做这些事 ——
// 这就是"访问控制缺失"。本文件补上它。
//
// 【链路本身】`api.tls.require` 打开时，明文请求一律拒绝（**含回环来源**）—— 见 requireAPIHTTPS。
//
// 【口径】判定顺序如下，前一条命中就不再往下走：
//
//  1. `/v1/healthz` —— 永远放行（存活探针，只回 ok / node_id / path，不触发任何跨节点调用）
//  2. 读请求（GET / HEAD / OPTIONS）—— 只有 `api.auth.protect_reads` 打开才要签名
//  3. mTLS：出示了被 CA 验过的客户端证书且 `api.tls.trust_client_cert` 打开 ⇒ 放行
//  4. 回环来源（127.0.0.1 / ::1）且**不像被代理转发过** —— 放行：本机运维脚本、控制台代理、
//     curl localhost 都走这里（收紧的细节见 loopbackBypassAllowed）
//  5. 其余（非回环的写请求）—— 必须带正确的 HMAC 签名；**没配密钥就一律拒绝**
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
	// headerAPIAudience 签名声明的**接收方**（目标 node_id）。服务端只认"签给自己的"。
	headerAPIAudience = "X-Treecmd-Audience"
	// headerAPIChannelBinding 通道绑定值：base64(TLS exporter)，把签名钉死在这一条 TLS 连接上。
	headerAPIChannelBinding = "X-Treecmd-Channel-Binding"
	// apiAuthCBLabel 通道绑定的用途标签。**两端必须逐字节一致** —— 它决定"这份绑定是给谁用的"，
	// 换标签等于换一套绑定（避免同一张证书被复用到别的协议上）。
	apiAuthCBLabel = "treecmd/api/v1 channel binding"

	// apiPathHealthz 存活探针，永远免认证。
	apiPathHealthz = "/v1/healthz"

	errAPIAuthNotConfigured = "ERR_API_AUTH_NOT_CONFIGURED"
	errAPIAuthRequired      = "ERR_API_AUTH_REQUIRED"
	errAPIAuthFailed        = "ERR_API_AUTH_FAILED"
	errAPIAuthUnavailable   = "ERR_API_AUTH_UNAVAILABLE"
	errAPIAuthTooLarge      = "ERR_API_AUTH_TOO_LARGE"
	errAPIAuthTLSRequired   = "ERR_API_TLS_REQUIRED"
	errAPIAuthAudience      = "ERR_API_AUTH_AUDIENCE"
	errAPIAuthChannelBind   = "ERR_API_AUTH_CHANNEL_BINDING"
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
		// ⓪ 先判"这条链路本身够不够格"，再看"谁在调用"：api.tls.require 打开时连回环来源的
		// 明文请求也拒 —— 否则 TLS 终止型反向代理（对外 HTTPS、回源明文）会把远程请求伪装成
		// 本机请求递进来，那正是"本地反代绕过"的另一条路。
		if err := n.requireAPIHTTPS(r); err != nil {
			n.auditReject("api_auth", "", "", err)
			writeErr(w, statusForAPIAuth(err), errCodeOf(err), err.Error())
			return
		}
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
// requireAPIHTTPS 执行 api.tls.require：这个端点只以 HTTPS 提供。
//
// 接收者 n 是本节点实例。
//
// 为什么**连回环来源也拒**：TLS 终止型反向代理（对外 HTTPS、回源走明文 HTTP）会把远程请求
// 以"对端是 127.0.0.1 的明文请求"递进来 —— 那正是"本地反代绕过"的另一条路。只约束远程来源
// 的话，这一条正好被绕过去。
//
// 参数：
//
//	r — 请求；r.TLS 非 nil 表示它确实是从 TLS 连接上进来的
//
// 返回：要求 HTTPS 但请求是明文时返回错误；其余返回 nil。
func (n *Node) requireAPIHTTPS(r *http.Request) error {
	if !n.C().API.TLS.Require || r.TLS != nil {
		return nil
	}
	return fmt.Errorf("%s: 本端点只接受 HTTPS 请求（api.tls.require: true）；"+
		"若前面挂了 TLS 终止型反向代理，请让代理与本机之间也走 HTTPS，或关掉 require（来源 %s）",
		errAPIAuthTLSRequired, r.RemoteAddr)
}

// clientCertTrusted 判断"客户端证书"能否直接作为本次请求的身份凭据。
//
// 接收者 n 是本节点实例。成立条件（全都要满足）：
//
//  1. `api.tls.trust_client_cert` 显式打开（默认关：不能因为配了 mTLS 就悄悄免掉 HMAC）；
//  2. 请求走的是 TLS 且**真的出示了客户端证书**；
//  3. 证书通过了 CA 校验 —— 判据是 VerifiedChains 非空：crypto/tls 只在验链成功后才填它，
//     光有 PeerCertificates 不代表验过（ClientAuth 为 off 时没人去验）。
//
// 参数：
//
//	r — 请求
//
// 返回：可以用证书身份替代 HMAC 时返回 true。
func (n *Node) clientCertTrusted(r *http.Request) bool {
	t := n.C().API.TLS
	if !t.Enabled() || !t.TrustClientCert || r.TLS == nil {
		return false
	}
	return len(r.TLS.PeerCertificates) > 0 && len(r.TLS.VerifiedChains) > 0
}

func (n *Node) authorizeAPI(r *http.Request) error {
	// ① mTLS 身份：证书已经把"谁在调用"钉死，且 TLS 通道本身提供了防窃听 / 防中继 / 防篡改，
	//    此时再要求 HMAC 属于纯负担 —— 但只有显式打开 trust_client_cert 才走这条路。
	if n.clientCertTrusted(r) {
		return nil
	}

	// ② 回环来源免签：本机运维是主路径（scripts/start_node.sh、test/*.sh、控制台代理、curl localhost）。
	//
	// ⚠️ 判据是 **TCP 对端地址**（RemoteAddr），绝不能单凭 X-Forwarded-For 之类可伪造的头。
	// 但它有个前提：对端地址会被**部署形态**改写 —— API 端口前面一旦挂了本地反向代理 / 端口
	// 转发（nginx、ssh -L、frpc、kubectl port-forward…），所有远程请求的对端都变成 127.0.0.1，
	// 这一条豁免就等于对所有来源放行。所以 loopbackBypassAllowed 在这之上再压两道闸：
	// 带转发特征头的对端必须在 `api.auth.trusted_proxies` 里；在里面的，还要按 RFC 7239
	// 剥掉可信跳、确认真实来源仍是回环。配了密钥之后，回环请求里**带了签名**的仍然会被照常
	// 校验（见下面第 ④ 步）。
	if n.loopbackBypassAllowed(r) && !hasAPISignature(r) {
		return nil
	}

	// ③ 取密钥。没配 ⇒ 非回环请求一律拒绝（fail-closed）。
	secret, configured, err := n.apiSecret()
	if err != nil {
		return fmt.Errorf("%s: %w", errAPIAuthUnavailable, err)
	}
	if !configured {
		return fmt.Errorf("%s: 本节点未配置 api.auth.secret / secret_path，"+
			"写接口只接受本机(回环)请求（来源 %s）", errAPIAuthNotConfigured, r.RemoteAddr)
	}

	// ④ 凭据齐全性：先把头看一遍再读 body —— 这样"什么凭据都不带"的探测连内存都吃不到。
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

	// ⑤ 接收方（audience）：签名必须**签给本节点**。
	//
	// 挡的是这条攻击：nonce 表是**每节点一份**的，所以"签给 A 的请求"被中间人原样转发给
	// 共享同一密钥的 B 时，B 的 nonce 表里没有它 ⇒ 会被当成一次全新请求再执行一次
	// （`POST /v1/crl` 吊销、`/v1/forget` 删数据、`/v1/commands` 让整棵子树执行指令 —— 全是
	// 不可逆动作）。把目标 node_id 写进签名后，这类"跨节点中继"在验签时就断了。
	audience := strings.TrimSpace(r.Header.Get(headerAPIAudience))
	if !strings.EqualFold(audience, n.C().Node.ID) {
		return fmt.Errorf("%s: %s=%q 不是本节点（本节点 node_id=%q；"+
			"要远程调用请显式声明目标节点，别把签好的请求转发给别人（来源 %s）",
			errAPIAuthAudience, headerAPIAudience, audience, n.C().Node.ID, r.RemoteAddr)
	}

	// ⑥ 通道绑定：把签名钉死在"这一条 TLS 连接"上。
	//
	// HMAC 证明的是"请求内容没被改"，证明不了"它是从哪条链路进来的"。中间人可以把在途请求
	// 挪到**自己新建的一条连接**上投递（抓到的字节一个没改，签名照样对）。把 TLS exporter
	// （RFC 5705，双方各自从握手密钥导出、链路上不传输）纳入签名后，换一条连接就签不上。
	cbRaw := strings.TrimSpace(r.Header.Get(headerAPIChannelBinding))
	cb, cbErr := n.channelBindingOf(r)
	switch mode := n.C().API.Auth.ChannelBindingMode(); {
	case cbRaw == "" && mode == "off":
		// 明确关闭：不校验
	case cbRaw == "" && mode == "auto" && r.TLS == nil:
		// 明文链路本来就导不出绑定值 —— 让它过，但 TLS 那段 WARN 已经在启动时喊过了
	case cbRaw == "":
		return fmt.Errorf("%s: 缺少 %s（策略 %s；客户端要用本次 TLS 连接的 exporter 值签名，"+
			"或把 api.auth.channel_binding 设为 off 以明确放弃这项保护；来源 %s）",
			errAPIAuthChannelBind, headerAPIChannelBinding, mode, r.RemoteAddr)
	case cbErr != nil:
		return fmt.Errorf("%s: 本端算不出通道绑定值（%v；来源 %s）", errAPIAuthChannelBind, cbErr, r.RemoteAddr)
	default:
		got, derr := base64.StdEncoding.DecodeString(cbRaw)
		if derr != nil {
			return fmt.Errorf("%s: %s 不是 base64（来源 %s）", errAPIAuthChannelBind, headerAPIChannelBinding, r.RemoteAddr)
		}
		if !hmac.Equal(cb, got) {
			return fmt.Errorf("%s: 通道绑定值不匹配 —— 这份签名是在**另一条 TLS 连接**上签的"+
				"（典型的中间人转发；来源 %s）", errAPIAuthChannelBind, r.RemoteAddr)
		}
	}

	// ⑦ 验签。body 要参与摘要（否则签名可以被搬到另一个 body 上）。
	body, err := readBodyForAuth(r)
	if err != nil {
		return err
	}
	host := ""
	if n.C().API.Auth.HostBound() {
		host = r.Host
	}
	payload := apiAuthPayload(r.Method, r.URL.Path, r.URL.RawQuery, body, ts, nonce, audience, host, cbRaw)
	mac := hmac.New(sha256.New, secret)
	mac.Write(payload)
	want := mac.Sum(nil)
	got, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(sigRaw))
	if derr != nil || !hmac.Equal(want, got) {
		return fmt.Errorf("%s: 签名不匹配（来源 %s；payload 覆盖 方法/路径/query/body 摘要/"+
			"时间戳/nonce/接收方/Host/通道绑定）", errAPIAuthFailed, r.RemoteAddr)
	}

	// ⑧ 防重放：时间窗内同一个 nonce 只认一次。放在验签**之后** —— 只有持密钥的人
	// 才能往表里塞条目，否则谁都能用假 nonce 把表刷满、把合法请求挤掉。
	if !n.redeemNonce(nonce) {
		return fmt.Errorf("%s: nonce %q 已用过（重放；来源 %s）", errAPIAuthFailed, nonce, r.RemoteAddr)
	}
	return nil
}

// loopbackBypassAllowed 判断"回环免签"这条豁免对当前请求是否仍然成立。
//
// 接收者 n 是本节点实例。成立要同时满足三件事（见 APIAuthSection 的注释），
// 任一条不满足就 false ⇒ 请求继续往下走签名校验（fail-closed，不会变成"放行"）：
//
//  1. `api.auth.loopback_bypass` 没被显式关掉；
//  2. 请求**不带转发特征头**，或者它的对端在 `api.auth.trusted_proxies` 里 ——
//     本机 curl 不会带这些头，带了就说明前面有东西把 RemoteAddr 改写成回环了；
//  3. 剥掉可信代理跳之后的**真实来源**仍是回环（对端可信时按 X-Forwarded-For / Forwarded 解析）。
//
// 参数：
//
//	r — 请求
//
// 返回：可以免签时返回 true。
func (n *Node) loopbackBypassAllowed(r *http.Request) bool {
	a := &n.C().API.Auth
	if !a.LoopbackBypassEnabled() {
		return false
	}
	peer := hostOfRemote(r.RemoteAddr)
	if hasForwardedHeaders(r) && !a.TrustsProxy(peer) {
		return false
	}
	return isLoopbackHost(clientHostForAuth(r, a))
}

// clientHostForAuth 判定请求的"真实来源主机"。
//
// 参数：
//
//	r    — 请求
//	a    — api.auth 段配置（提供可信代理白名单）
//
// 返回：
//
//	string — 裸主机字符串。对端不在白名单里时就是对端本身（**转发头一律不信**，否则任何人
//	都能用 X-Forwarded-For: 127.0.0.1 骗到免签）；对端在白名单里时，取转发链上
//	**从右往左第一个不可信的跳**；全是可信跳或没有转发头时退回对端本身。
func clientHostForAuth(r *http.Request, a *config.APIAuthSection) string {
	peer := hostOfRemote(r.RemoteAddr)
	if !a.TrustsProxy(peer) {
		return peer
	}
	if hop := firstUntrustedForwardedHop(r, a); hop != "" {
		return hop
	}
	return peer
}

// firstUntrustedForwardedHop 从转发链里取真实客户端那一跳。
//
// 参数：
//
//	r — 请求；依次看 X-Forwarded-For（逗号分隔的 IP 列表，最左是原始客户端）与
//	    RFC 7239 的 Forwarded（`for=...`，同样按逗号分隔、最左是原始客户端）
//	a — api.auth 段配置（白名单）
//
// 返回：
//
//	string — 从右往左第一个**不在白名单里**的跳；全都可信时返回最左一跳；解析不出任何跳时返回空串
func firstUntrustedForwardedHop(r *http.Request, a *config.APIAuthSection) string {
	hops := forwardedHops(r)
	if len(hops) == 0 {
		return ""
	}
	var leftmost string
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if hop == "" {
			continue
		}
		if leftmost == "" {
			leftmost = hop
		}
		if !a.TrustsProxy(hop) {
			return hop
		}
	}
	return leftmost
}

// forwardedHops 取出请求里的转发链（按"最左 = 原始客户端"的顺序）。
//
// 参数：
//
//	r — 请求
//
// 返回：
//
//	[]string — X-Forwarded-For 的每个元素；没有 XFF 时退而解析 Forwarded 里的每个 `for=`；
//	          两个头都没有时返回 nil。X-Real-IP 只在两者都没有时作为单跳兜底。
func forwardedHops(r *http.Request) []string {
	if v := r.Header.Get("X-Forwarded-For"); strings.TrimSpace(v) != "" {
		return strings.Split(v, ",")
	}
	if v := r.Header.Get("Forwarded"); strings.TrimSpace(v) != "" {
		out := []string{}
		for _, seg := range strings.Split(v, ",") {
			for _, kv := range strings.Split(seg, ";") {
				kv = strings.TrimSpace(kv)
				if strings.EqualFold(kv, "for") || !strings.HasPrefix(strings.ToLower(kv), "for=") {
					continue
				}
				out = append(out, strings.Trim(strings.TrimSpace(kv[4:]), "\""))
			}
		}
		return out
	}
	if v := r.Header.Get("X-Real-IP"); strings.TrimSpace(v) != "" {
		return []string{v}
	}
	return nil
}

// hasForwardedHeaders 判断请求是否带有"被代理转发过"的特征头。
//
// 参数：
//
//	r — 请求
//
// 返回：
//
//	bool — 出现 Forwarded / X-Forwarded-For / X-Real-IP / Via 中任意一个（且非空）时为 true。
//	       Via 也算：只要是正常代理都会加它，本机 curl 不会产生。
func hasForwardedHeaders(r *http.Request) bool {
	for _, h := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "Via"} {
		if strings.TrimSpace(r.Header.Get(h)) != "" {
			return true
		}
	}
	return false
}

// hostOfRemote 从 RemoteAddr 里取出裸主机（去掉端口与 IPv6 方括号）。
//
// 参数：
//
//	remoteAddr — "127.0.0.1:54321" / "[::1]:54321"
//
// 返回：
//
//	string — 裸主机；解析不出 host:port 时原样返回（方括号保留，交给 isLoopbackHost 处理）
func hostOfRemote(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
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
// 字段顺序就是协议：**两端必须逐字节一致**（scripts/api_call.py 与 test/api-auth.sh 在证这件事）。
// 后三个字段（audience / host / channelBinding）是防中继用的，见 authorizeAPI 第 ⑤⑥ 步。
//
// 参数：
//
//	method         — HTTP 方法（大写，如 POST）
//	path           — 请求路径（r.URL.Path，不含 query）
//	rawQuery       — 原始 query（r.URL.RawQuery，**原样**：重排或重新转义都会算出不同的串）
//	body           — 请求体原文（空体即空切片，摘要照样参与）
//	ts             — Unix 秒时间戳
//	nonce          — 一次性随机串
//	audience       — 接收方 node_id（客户端声明的 X-Treecmd-Audience，原样参与）
//	host           — Host 头（api.auth.bind_host 为 false 时传空串）
//	channelBinding — 通道绑定值的 base64 原文（没有时传空串）
//
// 返回：canonical 编码后的字节串（canon.Writer：Str 带 8 字节大端长度前缀，I64 定长 8 字节）。
func apiAuthPayload(method, path, rawQuery string, body []byte, ts int64, nonce, audience, host, channelBinding string) []byte {
	sum := sha256.Sum256(body)
	w := canon.NewWriter().
		Str(apiAuthDomain).
		Str(method).
		Str(path).
		Str(rawQuery).
		Bytes(sum[:]).
		I64(ts).
		Str(nonce).
		Str(audience).
		Str(host).
		Str(channelBinding)
	return w.Out()
}

// channelBindingOf 取通道绑定值：服务端叶子证书 DER 的 SHA-256。
//
// 接收者 n 是本节点实例。
//
// 【为什么是证书哈希而不是 TLS exporter】标准做法两选一：RFC 5705 的 exporter（绑定"这一条连接"，
// 最强）与 RFC 5929 的 tls-server-end-point（绑定"这张证书"，即服务端身份）。这里选后者，
// 因为 exporter 需要**客户端也能导出密钥材料**，而常见客户端（Python 的 ssl、curl）没有这个
// 接口；证书哈希则是任何 TLS 客户端都能算的（Python：`sock.getpeercert(binary_form=True)`
// 再取 SHA-256）。它挡住的正是我们要挡的那件事：把签好的请求投给**另一个服务端**，
// 或者投给一个伪造的服务端 —— 那张证书不一样，哈希就对不上。
//
// 参数：
//
//	r — 请求；明文请求时返回错误（绑定值只在 TLS 上存在）
//
// 返回：
//
//	[]byte — 32 字节证书哈希
//	error  — 明文 / 本端没开 api.tls / 证书尚未加载成功时返回
func (n *Node) channelBindingOf(r *http.Request) ([]byte, error) {
	if r.TLS == nil {
		return nil, errors.New("请求不是从 TLS 连接上进来的，没有通道绑定值")
	}
	if n.apiTLS == nil {
		return nil, errors.New("本端没开 api.tls（拿不到服务端证书）")
	}
	h := n.apiTLS.LeafCertHash()
	if len(h) == 0 {
		return nil, errors.New("服务端证书尚未加载成功")
	}
	return h, nil
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
// 返回：500（密钥读取失败）、413（body 超限）、403（未配密钥 / 只接受 HTTPS ⇒ 能力上就没有）、
// 401（缺少凭据 / 签名不符 / 过期 / 重放），以及无法识别时的默认值 401。
func statusForAPIAuth(err error) int {
	switch errCodeOf(err) {
	case errAPIAuthUnavailable:
		return 500
	case errAPIAuthTooLarge:
		return 413
	case errAPIAuthNotConfigured, errAPIAuthTLSRequired:
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
	// 对外监听 + 回环免签：这是"前面挂了反代就全线失守"的组合，必须说出来。
	//
	// 为什么不是致命错误：反代是别人的部署自由，本项目无权替它决定；而且只要配了
	// trusted_proxies（或干脆关掉 loopback_bypass），这条就不再成立 —— 所以这里是 WARN
	// 而不是拒绝启动，但**每次启动都要说一遍**。
	if exposed && a.LoopbackBypassEnabled() {
		if len(a.TrustedProxies) == 0 {
			n.Log.Warn("api auth: 监听地址对外可达且回环免签开启 —— 若该端口前面有反向代理 / 端口转发，"+
				"远程请求会以 127.0.0.1 出现从而被放行；请把代理地址写进 api.auth.trusted_proxies，"+
				"或设 api.auth.loopback_bypass: false", "addr", addr)
		} else {
			n.Log.Info("api auth: 回环免签已按可信代理白名单解析真实来源",
				"addr", addr, "trusted_proxies", a.TrustedProxies)
		}
	}
	if t := n.C().API.TLS; t.Enabled() {
		n.Log.Info("api tls: 对外端点以 HTTPS 提供", "cert_path", t.CertPath,
			"client_auth", t.ClientAuth, "require", t.Require)
	} else if exposed {
		n.Log.Warn("api tls: 对外端点仍是明文 HTTP —— 指令内容 / 结果 / 拓扑在链路上可被窃听，" +
			"响应可被伪造，且中间人能把在途请求转发给别的节点再执行一次；建议配 api.tls.cert_path / key_path")
	}
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
