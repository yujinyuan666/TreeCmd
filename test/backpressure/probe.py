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

    python3 probe.py --api 127.0.0.1:18493 --count 20 --sleep-ms 2500 [--timeout 90] [--tag 阶段A]

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


def http_json(url, payload=None, timeout=10):
    """发一次 HTTP 请求并把响应体解析成 JSON。

    payload 为 None 时发 GET，否则发 POST（body 是 JSON）。

    参数：

        url     — 完整 URL
        payload — 要 POST 的 dict；None 表示 GET
        timeout — 单次请求超时（秒）

    返回：

        (status_code, 解析后的 dict 或 None)
    """
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
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
    args = ap.parse_args()

    base = "http://" + args.api
    payload_b64 = __import__("base64").b64encode(str(args.sleep_ms).encode()).decode()

    ids = []
    for i in range(args.count):
        code, body = http_json(base + "/v1/commands", {
            "type": "sleep",
            "payload": payload_b64,
            "target": {"mode": "SUBTREE"},
        })
        # 提交接口回的是 202 Accepted（"已收下，去轮询结果"），不是 200 —— 别写死 200。
        if not (200 <= code < 300) or not isinstance(body, dict) or "command_id" not in body:
            print("提交第 %d 条失败：HTTP %s %s" % (i + 1, code, body), file=sys.stderr)
            return 1
        ids.append(body["command_id"])

    t0 = time.time()
    max_by_child = {}
    metric_seen = False
    sampled = 0
    statuses = {}
    pending = len(ids)

    while True:
        # 采样指标
        try:
            with urllib.request.urlopen(base + "/metrics", timeout=5) as resp:
                per_child = parse_inflight(resp.read().decode("utf-8", "replace"))
            sampled += 1
            if per_child:
                metric_seen = True
            for child, v in per_child.items():
                if v > max_by_child.get(child, 0):
                    max_by_child[child] = v
        except Exception as e:
            print("拉 /metrics 失败：%s" % e, file=sys.stderr)
            return 1

        # 采样指令状态
        statuses = {}
        pending = 0
        for cid in ids:
            _, detail = http_json(base + "/v1/commands/" + cid)
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
