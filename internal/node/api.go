package node

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"treecmd/internal/canon"
	"treecmd/internal/pb"
)

// StartAPI 启动对外 HTTP 端点（只有带 api.http_addr 的节点才开）。
//
// 接收者 n 是本节点实例（一个进程就是一个节点）。
//
// 未配置 api.http_addr 时什么都不做、直接返回 nil；否则注册命令提交 / 查询、健康、树快照、
// CRL、指标等路由，并在后台 goroutine 里监听该地址。
//
// 返回：监听失败时返回包装后的错误，成功返回 nil。
func (n *Node) StartAPI() error {
	addr := n.C().API.HTTPAddr
	if addr == "" {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/commands", n.handleCommands)
	mux.HandleFunc("/v1/commands/", n.handleCommandByID)
	mux.HandleFunc("/v1/health", n.handleHealth)
	mux.HandleFunc("/v1/health/summary", n.handleHealth)
	mux.HandleFunc("/v1/tree", n.handleTree)
	mux.HandleFunc("/v1/crl", n.handleCRL)
	mux.HandleFunc("/v1/forget", n.handleForget)
	// /metrics：以 Prometheus 文本格式（text/plain; version=0.0.4）导出本节点指标。
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		n.Metrics.WriteText(w)
	})
	// /v1/healthz：极简存活探针，只回 {"ok":true,"node_id":..,"path":..}，不触发任何跨节点调用。
	mux.HandleFunc("/v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "node_id": n.C().Node.ID, "path": n.SelfPath()})
	})
	srv := &http.Server{Addr: addr, Handler: n.withAPIAuth(mux), ReadHeaderTimeout: 5 * time.Second}
	rawLn, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("api listen %s: %w", addr, err)
	}
	// TLS（api.tls）：配了 cert_path + key_path 就把监听器包成 tls.Listener。
	//
	// 为什么用 tls.NewListener 而不是 srv.ServeTLS：ServeTLS 只在"给了证书文件路径"时才会
	// 装载材料，靠 GetConfigForClient 单独供给的话它会尝试 LoadX509KeyPair("","") 并直接失败。
	// 自己包监听器还顺带让"热重载"和"握手前才决定配置"这两件事都落在同一个回调上。
	var ln net.Listener = rawLn
	scheme := "http"
	if t := n.C().API.TLS; t.Enabled() {
		rel, err := newAPITLSReloader(&t)
		if err != nil {
			_ = rawLn.Close()
			return fmt.Errorf("api tls: %w", err)
		}
		ln = tls.NewListener(rawLn, &tls.Config{
			MinVersion:         t.MinTLSVersion(),
			GetConfigForClient: rel.ConfigFor,
		})
		scheme = "https"
	}
	n.apiSrv = srv
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			n.Log.Error("http api stopped", "err", err)
		}
	}()
	n.Log.Info("http api listening", "addr", addr, "scheme", scheme)
	n.logAPIAuthPosture(addr)
	return nil
}

// stopAPI 关闭 StartAPI 启动的 HTTP 服务。
//
// 接收者 n 是本节点实例。apiSrv 为 nil（没开 HTTP）时什么都不做；
// 关闭最多等 2 秒，超时也直接放弃（进程退出时不必卡住）。
func (n *Node) stopAPI() {
	if n.apiSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = n.apiSrv.Shutdown(ctx)
	}
}

// handleCommands 处理 POST /v1/commands：解析请求体 → 提交指令 → 返回 202 + 指令 ID。
//
// 接收者 n 是本节点实例（一个进程就是一个节点）；本节点同时是指令的 OriginID 与聚合终点。
//
// 参数：
//
//	w — HTTP 响应写入器
//	r — 请求；只接受 POST，body 是 JSON 格式的提交请求
//
// 失败时错误码由 statusForSubmit 决定（如 400 / 403 / 413）。
func (n *Node) handleCommands(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "use POST")
		return
	}
	var req SubmitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "ERR_BAD_REQUEST", err.Error())
		return
	}
	res, err := n.SubmitCommand(req, n.C().Node.ID)
	if err != nil {
		writeErr(w, statusForSubmit(err), "SUBMIT_REJECTED", err.Error())
		return
	}
	writeJSON(w, 202, res)
}

// handleCommandByID 处理 /v1/commands/{id} 系列路径，按"方法 + 动作"分发到查询 / 取消 / 重试。
//
// 接收者 n 是本节点实例。
//
//	GET  /v1/commands/{id}                      —— 结果查询
//	POST /v1/commands/{id}/cancel               —— 取消
//	POST /v1/commands/{id}/retry?node=<childID> —— 子节点重跑
//
// 参数：
//
//	w — HTTP 响应写入器
//	r — 请求；路径里 {id} 是指令 ID，其后可再跟 cancel / retry 动作
//
// 其他方法 / 动作组合返回 405；单次处理超过 300ms 会打一条 slow api 警告日志。
func (n *Node) handleCommandByID(w http.ResponseWriter, r *http.Request) {
	t0 := time.Now()
	defer func() {
		if d := time.Since(t0); d > 300*time.Millisecond {
			n.Log.Warn("slow api", "path", r.URL.Path, "took", d.Round(time.Millisecond))
		}
	}()
	rest := strings.TrimPrefix(r.URL.Path, "/v1/commands/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeErr(w, 400, "ERR_BAD_REQUEST", "missing command id")
		return
	}
	id := parts[0]
	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}
	switch {
	case action == "" && r.Method == http.MethodGet:
		out, err := n.Query(id)
		if err != nil {
			writeErr(w, 502, "QUERY_FAILED", err.Error())
			return
		}
		resp := out.Resp
		if resp.Status != "OK" {
			writeErr(w, 404, "NOT_FOUND", "结果不在本节点，且索引未命中")
			return
		}
		payload := map[string]any{
			"command_id": id, "owner_path": resp.OwnerPath,
			"status":        pb.CommandStatus_name[int32(resp.CommandStatus)],
			"trace_summary": resp.TraceSummary,
		}
		data := out.Data
		if len(data) == 0 && len(resp.ResultInline) > 0 {
			data = resp.ResultInline
		}
		if len(data) > 0 {
			payload["result"] = string(data)
			payload["result_bytes"] = len(data)
			payload["result_sha256"] = base64.StdEncoding.EncodeToString(canon.DigestBytes(data))
		}
		if resp.ResultRef != nil {
			payload["result_ref"] = map[string]any{
				"kind": resp.ResultRef.Kind.String(), "size": resp.ResultRef.Size,
				"ref": resp.ResultRef.Ref,
			}
		}
		writeJSON(w, 200, payload)
	case action == "cancel" && r.Method == http.MethodPost:
		if err := n.CancelCommand(id); err != nil {
			writeErr(w, 409, "CANCEL_REJECTED", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"command_id": id, "canceled": true})
	case action == "retry" && r.Method == http.MethodPost:
		child := r.URL.Query().Get("node")
		if child == "" {
			writeErr(w, 400, "ERR_BAD_REQUEST", "missing ?node=<childID>")
			return
		}
		if err := n.RetryNode(id, child); err != nil {
			// 重试预算用尽不是"重试失败"：那一步已经**由父把这个子判定为 FAILED** 了
			// （见 RetryNode），所以这里要把"发生了什么"如实告诉调用方，
			// 而不是把它混在一个普通的 409 里 —— 否则运维会以为什么都没发生，
			// 而实际上指令已经可以收敛了。
			if errors.Is(err, ErrRetryExhausted) {
				writeJSON(w, 200, map[string]any{
					"command_id": id, "child": child, "retried": false, "judged": "FAILED",
					"note": "retry budget exhausted: the parent has judged this child FAILED " +
						"(it will no longer block this command from converging)",
				})
				return
			}
			writeErr(w, 409, "RETRY_REJECTED", err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"command_id": id, "child": child, "retried": true})
	default:
		writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "unsupported action")
	}
}

// handleHealth 处理 GET /v1/health[?command_id=..&depth=..&detail=..&timeout=..]，
// 返回本节点及其子树的健康信息，并渲染成 JSON。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	w — HTTP 响应写入器
//	r — 请求；从 query 读 command_id / depth / detail / timeout，
//	   路径以 /summary 结尾时强制 depth=1
//
// depth 合法取值为 -1 或非负整数，否则返回 400；同一周期上一轮还没跑完时返回 429。
func (n *Node) handleHealth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	depth := 1
	if v := q.Get("depth"); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil || d < -1 {
			writeErr(w, 400, "ERR_INVALID_DEPTH", "depth 合法取值为 {-1} ∪ {0,1,2,...}")
			return
		}
		depth = d
	}
	if strings.HasSuffix(r.URL.Path, "/summary") {
		depth = 1
	}
	timeout := 5 * time.Second
	if v := q.Get("timeout"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			timeout = d
		}
	}
	req := HealthRequest{
		CommandID: q.Get("command_id"), Depth: depth,
		Detail: q.Get("detail") == "true" || q.Get("detail") == "1", Timeout: timeout,
	}
	resp, err := n.Health(r.Context(), req)
	if err != nil {
		if strings.Contains(err.Error(), "IN_PROGRESS") {
			writeErr(w, 429, "IN_PROGRESS", "同周期上一轮还没跑完，请退避重试")
			return
		}
		writeErr(w, 500, "ERR_HEALTH", err.Error())
		return
	}
	writeJSON(w, 200, healthToJSON(resp, req.Detail))
}

// handleCRL 处理 /v1/crl：GET 查看本节点当前 CRL，POST 吊销某节点。
//
// 接收者 n 是本节点实例。
//
//	GET  /v1/crl             —— 返回 {version, guids, revoked}，查看当前版本 + 吊销 GUID
//	POST /v1/crl?node=<guid> —— 吊销某节点：写入本地 CRL、版本 +1、推送给所有直接子
//
// 参数：
//
//	w — HTTP 响应写入器
//	r — 请求；GET 只读快照，POST 需要 ?node=，其他方法返回 405
func (n *Node) handleCRL(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ver, guids := n.crlSnapshot()
		writeJSON(w, 200, map[string]any{"version": ver, "guids": guids, "revoked": len(guids)})
	case http.MethodPost:
		id := r.URL.Query().Get("node")
		if id == "" {
			writeErr(w, 400, "ERR_BAD_REQUEST", "missing ?node=<guid>")
			return
		}
		if err := n.Revoke(id); err != nil {
			writeErr(w, 500, "REVOKE_FAILED", err.Error())
			return
		}
		ver, guids := n.crlSnapshot()
		writeJSON(w, 200, map[string]any{"version": ver, "revoked": len(guids), "node": id})
	default:
		writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "use GET or POST")
	}
}

// handleForget 处理 /v1/forget：清理本节点名下失效的直接子节点
// （设计与取舍见 README 的「失效节点清理：`/v1/forget`」一节）。
//
// 接收者 n 是本节点实例。三个动作：
//
//	GET  /v1/forget?node=<guid>[&mode=garbage|stale][&force=1]
//	     —— 只读预览：会不会被允许、会被删掉哪些条目（不改任何数据）
//	POST /v1/forget?node=<guid>[&mode=...][&force=1][&purge=1]
//	     —— 真正清理这个 NodeID
//	POST /v1/forget?all=1[&mode=...][&force=1]
//	     —— 批量：对本节点名下所有子节点逐个尝试，逐条返回结果
//
// 参数：
//
//	w — HTTP 响应写入器
//	r — 请求；除 GET/POST 外返回 405
//
// 被拒绝时（在线 / 太新 / 不在 garbage 范围 / 查无此人）返回非 2xx，且响应体里带着完整的
// plan（含 reason 与 hint：下一步该加哪个参数），便于脚本按 reason 分支处理。
func (n *Node) handleForget(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	opts := ForgetOptions{
		NodeID: q.Get("node"),
		Mode:   q.Get("mode"),
		Force:  isTrue(q.Get("force")),
		Purge:  isTrue(q.Get("purge")),
	}
	switch r.Method {
	case http.MethodGet:
		plan, err := n.ForgetPreview(opts)
		if err != nil {
			writeErr(w, statusForForget(err), errCodeOf(err), err.Error())
			return
		}
		n.Metrics.Inc("forget_total", "result", "dry_run")
		writeJSON(w, 200, plan)
	case http.MethodPost:
		if isTrue(q.Get("all")) {
			plans, ok := n.ForgetAll(opts)
			writeJSON(w, 200, map[string]any{
				"candidates": len(plans), "forgotten": ok, "results": plans,
			})
			return
		}
		if opts.NodeID == "" {
			writeErr(w, 400, "ERR_BAD_REQUEST", "missing ?node=<guid>（批量请用 ?all=1）")
			return
		}
		plan, err := n.Forget(opts)
		if err != nil {
			// 判定不允许：把完整 plan 一起回给调用方（reason 决定 HTTP 状态码）。
			writeJSON(w, statusForForget(err), map[string]any{
				"error": errCodeOf(err), "message": err.Error(), "plan": plan,
			})
			return
		}
		writeJSON(w, 200, plan)
	default:
		writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "use GET (preview) or POST (apply)")
	}
}

// isTrue 识别查询参数里的"打开"取值（1/true）。
//
// 参数：
//
//	s — 查询参数原文
//
// 返回：s 为 "1" 或 "true" 时为 true，其余（含空串）为 false。
func isTrue(s string) bool { return s == "1" || s == "true" }

// errCodeOf 从错误文本里取出机器可读的错误码（前缀到第一个冒号为止）。
//
// 参数：
//
//	err — 形如 "ERR_CHILD_ONLINE: ..." 的错误
//
// 返回：错误码；取不到时返回 "ERR_INTERNAL"。
func errCodeOf(err error) string {
	s := err.Error()
	if i := strings.IndexAny(s, ":， "); i > 0 {
		return s[:i]
	}
	if s != "" {
		return s
	}
	return "ERR_INTERNAL"
}

// statusForForget 把清理失败的判定原因映射成 HTTP 状态码。
//
// 参数：
//
//	err — Forget / planForget 返回的错误
//
// 返回：409（在线冲突 / 需要 mode=stale）、412（沉默时长不够，需 force）、404（查无此人）、
// 500（存储写入失败），以及无法识别时的默认值 400。
func statusForForget(err error) int {
	s := err.Error()
	switch {
	case strings.Contains(s, forgetErrOnline), strings.Contains(s, forgetErrNeedsStale):
		return 409
	case strings.Contains(s, forgetErrTooRecent):
		return 412
	case strings.Contains(s, forgetErrNotFound):
		return 404
	case strings.Contains(s, "ERR_STORE"):
		return 500
	}
	return 400
}

// handleTree 处理 GET /v1/tree：返回本节点视角的整棵树快照（JSON）。
//
// 接收者 n 是本节点实例。
//
// 参数：
//
//	w — HTTP 响应写入器
//	r — 请求；不区分方法
func (n *Node) handleTree(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, n.TreeSnapshot())
}

// healthToJSON 把 pb.HealthResponse 渲染成对外 HTTP 用的 JSON map。
//
// 参数：
//
//	resp   — 健康响应，可能同时带 health（健康）与 command（指令轨迹）两部分
//	detail — 是否展开各自子树的 children 明细列表
//
// 返回：可直接交给 writeJSON 的 map；本函数不返回 error。
func healthToJSON(resp *pb.HealthResponse, detail bool) map[string]any {
	out := map[string]any{
		"node_id": resp.NodeId, "path": resp.Path, "mode": resp.Mode.String(),
		// 本节点元信息（ADR-051）：node.name / node.remark
		"node_name": resp.NodeName, "node_remark": resp.NodeRemark,
		"signer": map[string]any{
			"node_id": resp.Signer.GetNodeId(),
			"cert_fp": base64.StdEncoding.EncodeToString(resp.Signer.GetCertFingerprint()),
		},
	}
	if resp.Health != nil {
		h := map[string]any{"status": resp.Health.Status.String()}
		if resp.Health.Summary != nil {
			h["summary"] = resp.Health.Summary
		}
		if resp.Health.Metrics != nil {
			h["metrics"] = map[string]any{
				"uptime_seconds":  resp.Health.Metrics.UptimeSeconds,
				"inflight":        resp.Health.Metrics.Inflight,
				"children_online": resp.Health.Metrics.ChildrenOnline,
				"fail_rate_1h":    resp.Health.Metrics.FailRate_1H,
				"mem_mb":          resp.Health.Metrics.MemMb,
			}
		}
		checks := []map[string]any{}
		for _, c := range resp.Health.Checks {
			checks = append(checks, map[string]any{"name": c.Name, "status": c.Status.String(), "detail": c.Detail})
		}
		h["checks"] = checks
		h["truncated"] = resp.Health.Truncated
		if detail {
			kids := []map[string]any{}
			for _, c := range resp.Health.Children {
				kids = append(kids, map[string]any{
					"node_id": c.NodeId, "status": c.Status.String(), "err": c.Err,
					"node_name": c.NodeName, "node_remark": c.NodeRemark,
					"children_online": childOnlineOf(c.Report),
				})
			}
			h["children"] = kids
		}
		out["health"] = h
	}
	if resp.Command != nil {
		t := map[string]any{
			"command_id": resp.Command.CommandId, "role": resp.Command.Role.String(),
			"local_state": resp.Command.LocalState.String(), "status": resp.Command.Status.String(),
			"status_source": resp.Command.StatusSource, "error": resp.Command.Error,
		}
		if resp.Command.Summary != nil {
			t["summary"] = resp.Command.Summary
		}
		if detail {
			kids := []map[string]any{}
			for _, c := range resp.Command.Children {
				kids = append(kids, map[string]any{
					"node_id": c.NodeId, "status": c.Status.String(),
					"local_state": c.LocalState.String(), "error": c.Error, "err": c.Err,
				})
			}
			t["children"] = kids
		}
		out["command"] = t
	}
	return out
}

// childOnlineOf 从子节点上报的健康报告里取出"在线子节点数"。
//
// 参数：
//
//	r — 子节点上报的 pb.HealthReport，可能为 nil
//
// 返回：Report.Summary.Healthy（该子节点名下在线的下一跳数量）；报告或摘要为空时返回 0。
func childOnlineOf(r *pb.HealthReport) int32 {
	if r == nil || r.Summary == nil {
		return 0
	}
	return r.Summary.Healthy
}

// statusForSubmit 按错误文本里的错误码，把"提交指令失败"映射成 HTTP 状态码。
//
// 参数：
//
//	err — SubmitCommand 返回的错误
//
// 返回：413（TOO_LARGE）、403（ERR_UNAUTHORIZED）、400（越权 / 能力不支持 / 聚合未知 /
// 参数非法 / Origin 非法），以及无法识别时的默认值 400。
func statusForSubmit(err error) int {
	s := err.Error()
	switch {
	case strings.Contains(s, "TOO_LARGE"):
		return 413
	case strings.Contains(s, "ERR_TARGET_OUT_OF_SCOPE"), strings.Contains(s, "ERR_CAPABILITY_UNSUPPORTED"),
		strings.Contains(s, "ERR_UNKNOWN_AGGREGATE"), strings.Contains(s, "ERR_INVALID_"), strings.Contains(s, "ERR_ORIGIN"):
		return 400
	case strings.Contains(s, "ERR_UNAUTHORIZED"):
		return 403
	}
	return 400
}

// writeJSON 以 JSON 形式写响应：设置 Content-Type → 写状态码 → 编码 v。
//
// 参数：
//
//	w    — HTTP 响应写入器
//	code — HTTP 状态码
//	v    — 要序列化的值（map / struct 等）
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr 输出统一格式的错误响应体：{"error": errCode, "message": msg}。
//
// 参数：
//
//	w       — HTTP 响应写入器
//	code    — HTTP 状态码
//	errCode — 机器可读的错误码（如 ERR_BAD_REQUEST）
//	msg     — 人类可读的错误说明
func writeErr(w http.ResponseWriter, code int, errCode, msg string) {
	writeJSON(w, code, map[string]any{"error": errCode, "message": msg})
}
