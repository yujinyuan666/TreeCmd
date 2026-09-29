#!/usr/bin/env python3
"""下发背压验收用的探针：一次提交 N 条指令，边高频轮询 /metrics 边等它们终态。

它只做观测、不做判断 —— 判断留在 shell 侧（见 ../backpressure.sh），
这样"断言写了什么"一眼能看懂，探针只管把事实取回来。

观测的两件事：

  1. **每个直接子的在途分派数的峰值**。在途的定义见 internal/node/delivery.go 的 countInflight
     （LEASED 且租约仍有效）。取的是 max 而不是平均值：窗口是"任何时刻都不许超过"的约束，
     平均值会把超窗那一刻抹平。
  2. **每条指令的终态**。用来证明窗口只是限速、没有把任务弄丢。

用法：

    python3 probe.py --api 127.0.0.1:18493 --count 20 --sleep-ms 2500 \
        [--timeout 90] [--tag 阶段A] [--token "$(cat demo/root/user/tester)"]

**每个请求都要带 user token**：对外端点没有免签来源（含回环），只有 `/v1/healthz` 例外 ——
`/v1/commands`、`/v1/commands/{id}`、`/metrics` 全都在访问控制的射程内。探针是用
python 直接发请求的，绕过了 shell 侧那个"自动带 token"的 curl 包装器（lib/apitoken.sh），
所以凭据必须显式传进来；不传就是 401（ERR_API_AUTH_REQUIRED），而 401 在这个项目里正是
"访问控制生效"的正常表现 —— **假失败会伪装成正确答案**，所以这里出错时必须把话说明白。

成功时在 stdout 打印**一行 JSON**（别的什么都不打印，方便 shell 直接读）：

    {"tag":"阶段A","submitted":20,"sampled":143,"max_inflight":8,
     "max_inflight_by_child":{"<childID>":8},"metric_seen":true,
     "statuses":{"COMMAND_STATUS_COMPLETED":20},"pending":0,"elapsed_s":6.4}

出错时以非零码退出，并把原因打到 stderr。
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# 终态集合：与 proto 的 CommandStatus 对齐（CANCELLED 是双 L；没有一个叫 CANCELED 的状态）。
TERMINAL = {
    "COMMAND_STATUS_COMPLETED",
    "COMMAND_STATUS_FAILED",
    "COMMAND_STATUS_CANCELLED",
    "COMMAND_STATUS_TIMEOUT",
}


# 探针只打本机（127.0.0.1:18493），**绝不该经过 http_proxy**。
#
# 【为什么必须显式关掉】`urllib` 会读 `http_proxy` / `HTTP_PROXY` 环境变量，而开发机上很常见
# （随手的隧道/容器工具都会设）。此时请求被交给代理，在"端点其实没起来"时会拿到
# **502 Bad Gateway** 而不是连接失败 —— 探针的报错就变成了 502 而不是"拒连"，排查时会往错方向走；
# 而且采样 `/metrics` 的时序会被中间那一跳污染，而这个探针量的正是时序。
# curl 那一侧由 lib/apitoken.sh 的包装器统一加 `--noproxy '*'`；这里绕过了 curl，所以自己关。
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def headers_for(token=""):
    """构造请求头：token 非空时带上 X-Treecmd-Token。

    参数：

        token — user token 原文（token 文件的全部内容）；空字符串表示"不带"
                （只有 /v1/healthz 不需要它）

    返回：

        dict — 可直接交给 urllib 的请求头
    """
    return {"X-Treecmd-Token": token} if token else {}


def http_json(url, payload=None, timeout=10, token=""):
    """发一次 HTTP 请求并把响应体解析成 JSON。

    payload 为 None 时发 GET，否则发 POST（body 是 JSON）。

    参数：

        url     — 完整 URL
        payload — 要 POST 的 dict；None 表示 GET
        timeout — 单次请求超时（秒）
        token   — user token；除 /v1/healthz 外的端点都必须带

    返回：

        (status_code, 解析后的 dict 或 None)
    """
    data = None
    headers = headers_for(token)
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            body = resp.read()
            code = resp.status
    except urllib.error.HTTPError as e:
        body = e.read()
        code = e.code
    try:
        return code, json.loads(body.decode())
    except Exception:
        return code, None


def parse_inflight(text):
    """从 /metrics 文本里把 child_dispatch_inflight 的每子取值解析出来。

    参数：

        text — /metrics 的响应体

    返回：

        dict[str, float] — 键是完整 NodeID（标签值，已去掉引号），值是该子的在途条数；
                           指标还没出现过时返回空 dict
    """
    out = {}
    for line in text.splitlines():
        if not line.startswith("child_dispatch_inflight{"):
            continue
        try:
            labels, value = line.rsplit(" ", 1)
            child = labels.split('child="', 1)[1].rstrip('"}')
            out[child] = float(value)
        except (IndexError, ValueError):
            continue
    return out


def status_of(detail):
    """从 /v1/commands/{id} 的响应里把指令状态抠出来。

    返回体在不同节点上形态略有差别（可能直接把状态放在顶层，也可能裹在 command/result 里），
    所以这里按"顶层优先、再逐个内层找、最后兜底扫任何 COMMAND_STATUS_* 取值"的顺序取，
    而不是硬编码一条路径 —— 这样接口字段挪位时探针不会静默失效。

    参数：

        detail — 已解析的响应 dict（可能是 None，例如还没收敛的 404）

    返回：

        str — 状态名；取不到时返回 "UNKNOWN"
    """
    if not isinstance(detail, dict):
        return "UNKNOWN"
    if isinstance(detail.get("status"), str) and detail["status"]:
        return detail["status"]
    for k in ("command", "result", "aggregate", "summary"):
        inner = detail.get(k)
        if isinstance(inner, dict) and isinstance(inner.get("status"), str) and inner["status"]:
            return inner["status"]
    stack = [detail]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for v in cur.values():
                if isinstance(v, str) and v.startswith("COMMAND_STATUS_"):
                    return v
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return "UNKNOWN"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True, help="根节点的 HTTP API 地址，如 127.0.0.1:18493")
    ap.add_argument("--count", type=int, default=20, help="一次提交几条指令")
    ap.add_argument("--sleep-ms", type=int, default=2500, help="每条 sleep 指令睡多少毫秒")
    ap.add_argument("--timeout", type=float, default=90.0, help="等全部终态的总超时（秒）")
    ap.add_argument("--tag", default="", help="给这次观测起个名字，会原样回显在结果里")
    ap.add_argument("--interval", type=float, default=0.2, help="采样间隔（秒）")
    ap.add_argument("--token", default="",
                    help="user token 原文（X-Treecmd-Token）；除 /v1/healthz 外所有端点都要带")
    args = ap.parse_args()

    base = "http://" + args.api
    payload_b64 = __import__("base64").b64encode(str(args.sleep_ms).encode()).decode()

    ids = []
    for i in range(args.count):
        code, body = http_json(base + "/v1/commands", {
            "type": "sleep",
            "payload": payload_b64,
            "target": {"mode": "SUBTREE"},
        }, token=args.token)
        # 提交接口回的是 202 Accepted（"已收下，去轮询结果"），不是 200 —— 别写死 200。
        if not (200 <= code < 300) or not isinstance(body, dict) or "command_id" not in body:
            hint = ""
            if code in (401, 403):
                hint = ("：这多半是没带/带错了 user token（端点没有免签来源，含回环）——"
                        "用 --token 传一份（shell 侧可用 lib/apitoken.sh 的 mint_api_token 现签）")
            print("提交第 %d 条失败：HTTP %s %s%s" % (i + 1, code, body, hint), file=sys.stderr)
            return 1
        ids.append(body["command_id"])

    t0 = time.time()
    max_by_child = {}
    metric_seen = False
    sampled = 0
    statuses = {}
    pending = len(ids)

    while True:
        # 采样指标（/metrics 也在访问控制射程内 —— 要带 token）
        try:
            req = urllib.request.Request(base + "/metrics", headers=headers_for(args.token))
            with _OPENER.open(req, timeout=5) as resp:
                per_child = parse_inflight(resp.read().decode("utf-8", "replace"))
            sampled += 1
            if per_child:
                metric_seen = True
            for child, v in per_child.items():
                if v > max_by_child.get(child, 0):
                    max_by_child[child] = v
        except Exception as e:
            print("拉 /metrics 失败：%s%s" % (
                e,
                "（401/403 说明没带对 user token —— /metrics 不是免签端点）"
                if "401" in str(e) or "403" in str(e) or "Forbidden" in str(e) else ""),
                file=sys.stderr)
            return 1

        # 采样指令状态
        statuses = {}
        pending = 0
        for cid in ids:
            _, detail = http_json(base + "/v1/commands/" + cid, token=args.token)
            st = status_of(detail) if isinstance(detail, dict) and detail.get("error") is None else "UNKNOWN"
            statuses[st] = statuses.get(st, 0) + 1
            if st not in TERMINAL:
                pending += 1
        if pending == 0:
            break
        if time.time() - t0 > args.timeout:
            break
        time.sleep(args.interval)

    print(json.dumps({
        "tag": args.tag,
        "submitted": len(ids),
        "sampled": sampled,
        "max_inflight": int(max(max_by_child.values())) if max_by_child else 0,
        "max_inflight_by_child": {k: int(v) for k, v in max_by_child.items()},
        "metric_seen": metric_seen,
        "statuses": statuses,
        "pending": pending,
        "elapsed_s": round(time.time() - t0, 2),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
