package node

// 对外 HTTP 端点的访问控制：**一切请求都要出示 user token，没有任何免签来源**。
//
// 【为什么要有这一层】`api.http_addr` 可以写成 `0.0.0.0`，而这些接口里躺着不可逆的运维动作：
// `POST /v1/crl` 吊销节点（本节点不校验 `?node=` 与自己的关系，直接写 CRL 并推给所有直接子）、
// `POST /v1/forget` 一条事务删掉注册表 / 水位 / 驱逐归档 / 结果副本、`POST /v1/commands` 让整棵
// 子树执行指令；读接口也暴露拓扑与结果。没有访问控制时，任何能连上这个端口的人都能看、能做。
//
// 【口径】判定顺序如下，前一条命中就不再往下走：
//
//  1. `api.tls.require` 打开时，明文请求一律拒绝（**含回环来源**：TLS 终止型反向代理会把
//     远程请求以"看起来像本机"的明文请求递进来，见 requireAPIHTTPS）；
//  2. `/v1/healthz` —— 永远放行（存活探针，只回 ok / node_id / path，不触发任何跨节点调用）；
//  3. 其余**一切请求（读接口也在内）** —— 必须带 `X-Treecmd-Token`，且该 token 必须能在本节点
//     的 `user/` 目录里找到并验签通过；找不到 ⇒ 403。回环、局域网、外网一视同仁。
//
// 【历史】这里曾有过"回环来源免签 + 非回环用 HMAC 共享密钥"的口径，上一轮还加过可信代理白名单
// 与转发头检测来收紧它。**整套已废弃并删除**：免签的判据是 TCP 对端地址，而它会被部署形态改写
// （反代 / 端口转发让远程请求的对端变成 127.0.0.1），这个前提不成立时，"本机"就不是一种授权；
// 而按来源地址区分授权，本质上是在用网络位置冒充身份。现在只看凭据：token 由本节点 CA 签发、
// 按人一份落盘 user/、删文件即收回（见 usertoken.go）。
//
// 【明文链路】token 是长期凭据，明文 HTTP 上被抄走即可原样重放 —— 对外暴露请配 api.tls
// （建议 require: true）。这一层只回答"你有没有凭据"，不解决窃听。
import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

const (
	// headerAPIToken 请求头：user token 原文（token 文件的全部内容）。
	headerAPIToken = "X-Treecmd-Token"

	// apiPathHealthz 存活探针，永远免认证（否则监控无法判断"进程活着但没人有 token"）。
	apiPathHealthz = "/v1/healthz"

	errAPIAuthRequired     = "ERR_API_AUTH_REQUIRED"      // 没带 token
	errAPIAuthTokenInvalid = "ERR_API_AUTH_TOKEN_INVALID" // token 不在 user/ 目录里 / 格式不合法
	errAPIAuthUnavailable  = "ERR_API_AUTH_UNAVAILABLE"   // 本节点没有 CA 材料可验签 / 读目录失败
	errAPIAuthTLSRequired  = "ERR_API_TLS_REQUIRED"       // api.tls.require 打开但请求是明文
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
		// ⓪ 先判"这条链路本身够不够格"：api.tls.require 打开时连回环来源的明文请求也拒。
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
//	/v1/healthz —— 永远不在射程内（存活探针）
//	其余一切请求 —— **一律在射程内**（读接口也要 token）
//
// "一律"是刻意的 fail-closed：将来新增的接口不需要记得来改这里，漏掉的是"加白名单"，
// 而不是"忘了保护"。
//
// 参数：
//
//	r — 请求
//
// 返回：需要认证时返回 true。
func (n *Node) apiAuthApplies(r *http.Request) bool {
	return r.URL.Path != apiPathHealthz
}

// authorizeAPI 校验一个受保护请求是否带了有效的 user token。
//
// 接收者 n 是本节点实例。判定完全落在凭据上（不看来源地址）：token 必须能在 `user/` 目录里
// 找到、且是本节点 CA 签的。唯一副作用是把扫描结果缓存起来（见 usertoken.go）。
//
// 参数：
//
//	r — 请求；从 X-Treecmd-Token 读取 token
//
// 返回：放行返回 nil；否则返回形如 "ERR_API_AUTH_xxx: ..." 的错误（文本里带来源地址与用户名，
// 方便从日志里定位是谁在试探）。
func (n *Node) authorizeAPI(r *http.Request) error {
	name, err := n.userTokenUsername(r.Header.Get(headerAPIToken))
	if err != nil {
		return err
	}
	n.Log.Debug("api auth ok", "user", name, "remote", r.RemoteAddr, "path", r.URL.Path)
	return nil
}

// requireAPIHTTPS 执行 api.tls.require：这个端点只以 HTTPS 提供。
//
// 接收者 n 是本节点实例。
//
// 为什么**连回环来源也拒**：TLS 终止型反向代理（对外 HTTPS、回源走明文 HTTP）会把远程请求
// 以"对端是 127.0.0.1 的明文请求"递进来。若只约束远程来源，这一条正好被绕过去 —— 而且明文
// 链路上 token 本来就会被抄走。
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

// statusForAPIAuth 把鉴权失败的类别映射成 HTTP 状态码。
//
// 参数：
//
//	err — authorizeAPI 返回的错误
//
// 返回：500（本节点 CA 材料 / user 目录读不了，属于本端故障）、403（api.tls.require 但请求是
// 明文 ⇒ 能力上就没有这个入口）、401（没带 token / token 无效），以及无法识别时的默认值 401。
func statusForAPIAuth(err error) int {
	switch errCodeOf(err) {
	case errAPIAuthUnavailable:
		return 500
	case errAPIAuthTLSRequired:
		return 403
	}
	return 401
}

// logAPIAuthPosture 启动时把"这个 HTTP 端点对外是什么口径"明确说一遍。
//
// 接收者 n 是本节点实例。要说清三件事：端点要不要凭据（永远要）、user/ 目录里现在有几份
// 有效 token、以及链路上是不是明文（明文会被 WARN）。
//
// 参数：
//
//	addr — api.http_addr 原文，用于判断是否只有本机能到达
func (n *Node) logAPIAuthPosture(addr string) {
	exposed := listenExposesOutside(addr)
	dir := n.C().UserDir

	// 启动时先扫一遍 user/：一来让下面的日志如实报出"现在有几份有效 token"，二来把缓存预热，
	// 免得第一个请求还要现扫盘。扫不动（本节点没有 CA 材料）是要说出来的 —— 那意味着
	// 除了 /v1/healthz，谁都不进来。
	if caPub, err := n.userTokenCAPub(); err != nil {
		n.Log.Warn("api auth: 无法校验 user token，除 "+apiPathHealthz+" 外的请求都会被拒绝", "err", err)
	} else if err := n.rescanUserTokens(caPub); err != nil {
		n.Log.Warn("api auth: 扫描 user token 目录失败", "dir", dir, "err", err)
	}

	switch cnt, scanned := n.userTokenCount(); {
	case cnt > 0:
		n.Log.Info("api auth: 已加载 user token（请求须带 "+headerAPIToken+"）", "dir", dir, "users", cnt)
	case scanned:
		n.Log.Warn("api auth: user/ 目录里没有有效的 user token —— 除 "+apiPathHealthz+
			" 外的一切请求都会被拒绝（401）；请执行 treecmd-node -adduser <用户名> -config node.yaml", "dir", dir)
	default:
		n.Log.Info("api auth: 请求须带 "+headerAPIToken+"（首次访问时扫描 user token 目录）", "dir", dir)
	}

	if t := n.C().API.TLS; t.Enabled() {
		n.Log.Info("api tls: 对外端点以 HTTPS 提供", "cert_path", t.CertPath,
			"client_auth", t.ClientAuth, "require", t.Require)
	} else if exposed {
		n.Log.Warn("api tls: 对外端点仍是明文 HTTP —— user token 会以明文上线，被窃听后即可原样重放；" +
			"指令内容 / 结果 / 拓扑同样可被窃听与篡改。对外暴露请配 api.tls.cert_path / key_path（建议再开 require）")
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
	return !ip.IsLoopback()
}

// isLoopbackHost 判断一个主机字段是不是回环 IP（仅用于启动自检的提示文案）。
//
// 参数：
//
//	host — 裸主机（"127.0.0.1" / "::1" / "[::1]" / "localhost"）
//
// 返回：回环（含 localhost）返回 true；其它一律 false。
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
