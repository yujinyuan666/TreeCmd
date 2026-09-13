#!/usr/bin/env python3
"""treecmd 可视化测试台 —— 本地静态服务 + API 反向代理（零依赖，仅标准库）。

【为什么要代理】
控制台页面在 http://127.0.0.1:<port>，而 treecmd 根节点的 HTTP API 在另一个端口，
浏览器会按"跨源"处理并拒收响应（CORS）。走同源代理最省事：不用改程序的任何代码，
也不用给程序加 CORS 头（那属于安全面的改动，不该为测试工具去动）。

页面里可以随时改目标地址：代理把 `/api/<path>?__target=<host:port>` 转发到该地址，
并把 `__target` 从转发出去的请求里剥掉。默认**只允许转发到本机**
（127.0.0.1 / localhost / ::1），确需指向远程节点时加 `--allow-any-host`。

用法：
    python3 serve.py                                  # 端口 8899，默认目标 127.0.0.1:18443
    python3 serve.py --port 9000 --target 127.0.0.1:18493
    python3 serve.py --allow-any-host                 # 允许把 /api 转发到任意主机
"""

# 让所有注解都延迟求值：这样 `dict | None` 这种 3.10+ 写法在 3.7~3.9 上也能跑
# （系统自带的 /usr/bin/python3 在 macOS 上常常还是 3.9）
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))

# 允许作为静态文件直接吐出去的扩展名（白名单 + 路径归一化 = 防目录穿越）
STATIC_EXT = {".html": "text/html; charset=utf-8",
              ".js": "application/javascript; charset=utf-8",
              ".css": "text/css; charset=utf-8",
              ".json": "application/json; charset=utf-8",
              ".svg": "image/svg+xml",
              ".png": "image/png",
              ".ico": "image/x-icon",
              ".map": "application/json; charset=utf-8"}

LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}

DEFAULT_TARGET = "127.0.0.1:18443"
ALLOW_ANY_HOST = False
# 健康扫描可能很慢（depth=-1 全树逐跳），给足超时
PROXY_TIMEOUT = 90.0


def is_allowed_target(netloc: str) -> bool:
    """判断能否把请求转发到这个 host:port（默认只放行本机）。"""
    if ALLOW_ANY_HOST:
        return True
    host = (netloc or "").rsplit(":", 1)[0] if ":" in (netloc or "") else (netloc or "")
    return host in LOOPBACK


class Handler(BaseHTTPRequestHandler):
    server_version = "treecmd-console"
    protocol_version = "HTTP/1.1"

    # ---------- 工具 ----------

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # 同源本不需要 CORS，但加上之后"直接双击打开 index.html（file:// 源）"也能用
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

    def log_message(self, fmt, *args):  # 收敛日志：默认太吵
        sys.stderr.write("  %s %s\n" % (self.address_string(), fmt % args))

    # ---------- 静态 ----------

    def _serve_static(self) -> None:
        rel = urllib.parse.unquote(urllib.parse.urlparse(self.path).path)
        if rel in ("", "/"):
            rel = "/index.html"
        # 归一化：把 .. 之类挡在目录外
        target = os.path.normpath(os.path.join(HERE, rel.lstrip("/")))
        if not target.startswith(HERE):
            self._send(403, b"forbidden", "text/plain; charset=utf-8")
            return
        ext = os.path.splitext(target)[1].lower()
        if ext not in STATIC_EXT:
            self._send(403, b"forbidden extension", "text/plain; charset=utf-8")
            return
        if not os.path.isfile(target):
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        with open(target, "rb") as f:
            self._send(200, f.read(), STATIC_EXT[ext])

    # ---------- 代理 ----------

    def _proxy(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        target = DEFAULT_TARGET
        kept = []
        for k, v in qs:
            if k == "__target":
                target = v.strip()
            else:
                kept.append((k, v))
        if not is_allowed_target(target):
            self._send_json(403, {"error": "ERR_TARGET_NOT_ALLOWED",
                                  "detail": f"默认只允许转发到本机；{target} 需要 --allow-any-host"})
            return

        rest = parsed.path[len("/api"):] or "/"
        url = "http://" + target + rest
        if kept:
            url += "?" + urllib.parse.urlencode(kept)

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None
        req = urllib.request.Request(url, data=body, method=self.command)
        ct = self.headers.get("Content-Type")
        if ct:
            req.add_header("Content-Type", ct)
        try:
            with urllib.request.urlopen(req, timeout=PROXY_TIMEOUT) as resp:
                self._send(resp.status, resp.read(),
                           resp.headers.get("Content-Type") or "application/octet-stream")
        except urllib.error.HTTPError as e:
            # 程序用 400/404/409/502 表达业务语义，原样透传，别让前端只看到 500
            self._send(e.code, e.read(), e.headers.get("Content-Type") or "application/json; charset=utf-8")
        except Exception as e:  # noqa: BLE001 —— 连不上/超时都归到网关错误
            self._send_json(502, {"error": "ERR_PROXY", "detail": f"{type(e).__name__}: {e}",
                                  "target": target})

    # ---------- 入口 ----------

    def do_GET(self):        # noqa: N802
        if self.path.startswith("/api/"):
            self._proxy()
        else:
            self._serve_static()

    def do_HEAD(self):       # noqa: N802
        self.do_GET()

    def do_POST(self):       # noqa: N802
        if self.path.startswith("/api/"):
            self._proxy()
        else:
            self._send(405, b"use POST /api/...", "text/plain; charset=utf-8")

    def do_OPTIONS(self):    # noqa: N802
        self._send(204, b"", "text/plain; charset=utf-8")


def pick_port(preferred: int) -> int:
    """端口被占就往后找，避免"演示时才发现起不来"。"""
    for p in range(preferred, preferred + 20):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise SystemExit(f"{preferred}~{preferred + 19} 都被占用了，用 --port 换一个")


def main() -> None:
    global DEFAULT_TARGET, ALLOW_ANY_HOST
    ap = argparse.ArgumentParser(description="treecmd 可视化测试台")
    ap.add_argument("--port", type=int, default=8899)
    ap.add_argument("--target", default=DEFAULT_TARGET, help="默认的 treecmd 根节点 API 地址 host:port")
    ap.add_argument("--allow-any-host", action="store_true", help="允许把 /api 转发到非本机地址")
    args = ap.parse_args()

    DEFAULT_TARGET = args.target
    ALLOW_ANY_HOST = args.allow_any_host
    port = pick_port(args.port)

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("┌────────────────────────────────────────────────────────────┐")
    print("│  treecmd 可视化测试台                                      │")
    print("└────────────────────────────────────────────────────────────┘")
    print(f"  控制台   http://127.0.0.1:{port}/")
    print(f"  默认目标 {DEFAULT_TARGET}（页面上可随时改）")
    print(f"  转发限制 {'任意主机' if ALLOW_ANY_HOST else '仅本机（需要就加 --allow-any-host）'}")
    print("  Ctrl-C 退出")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  已退出")


if __name__ == "__main__":
    main()
