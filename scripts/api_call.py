#!/usr/bin/env python3
"""treecmd 对外 HTTP 的签名调用工具（零依赖，只用标准库）。

【什么时候需要它】
节点的对外 HTTP 端点（api.http_addr）有一层访问控制，口径是：

  · 来自**本机**（回环地址）的请求一律放行 —— 直接 curl localhost:18443/... 就行，不必用本工具；
  · 从**别的机器**发来的写请求（POST），必须带共享密钥的 HMAC 签名 —— 那正是本工具干的事。

密钥就是节点目录里的 `api.secret`（或 node.yaml 里 api.auth.secret / secret_path 指定的那份），
把它拷到运维机上，用本工具发请求即可。

【签名格式】与 internal/node/apiauth.go 一一对应（**两边必须逐字节一致**，test/api-auth.sh 在证这件事）：

  头：
    X-Treecmd-Timestamp: <Unix 秒>
    X-Treecmd-Nonce:     <一次性随机串，32 位十六进制>
    X-Treecmd-Signature: base64(HMAC-SHA256(secret, payload))
  payload（按 internal/canon 的帧格式拼接）：
    Str(域) Str(方法) Str(路径) Str(原始 query) Bytes(sha256(body)) I64(时间戳) Str(nonce)
    其中 Str/Bytes = 8 字节大端长度前缀 + 内容；I64 = 8 字节大端补码（无长度前缀）。

时间戳必须在服务端时钟的 ±60s 内，nonce 不能重复（防重放）。所以**两端时钟要对齐**，
以及**别把一次调用重放出去**（重放会拿到 401，而不是又执行一遍 —— 这正是我们要的）。

【用法】
  # 本机也能用（照签，服务端会正常校验）
  scripts/api_call.py --host 127.0.0.1:18443 --secret-file root/api.secret POST '/v1/crl?node=<GUID>'

  # 远程：把 api.secret 拷过去，指向节点对外地址
  scripts/api_call.py --host 192.168.1.10:18443 --secret-file ./api.secret \
      POST '/v1/forget?node=<GUID>&mode=stale'

  # 带 body 的提交（body 原样发送、原样参与签名；- 表示从 stdin 读）
  echo '{"type":"remote_time","aggregate":"TREE"}' | \
      scripts/api_call.py --host 127.0.0.1:18443 POST /v1/commands --data -

【输出与退出码】
  stdout = 响应体原文；stderr = "HTTP <状态码> <原因>"。
  2xx 退出码 0，其它退出码 1（方便脚本 if 判断）。
"""

# 让 3.7~3.9 也能用 `dict | None` 这类注解（macOS 自带 python3 常年是 3.9）
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.client
import os
import secrets as pysecrets
import struct
import sys
import time

# 与 internal/node/apiauth.go 的 apiAuthDomain 保持一致：域分隔，避免这对密钥被复用到别处
DOMAIN = "treecmd/api/v1"
# 默认目标与密钥文件名（与节点目录里的约定一致）
DEFAULT_HOST = "127.0.0.1:18443"
DEFAULT_SECRET_FILE = "api.secret"


def field(part: bytes) -> bytes:
    """按 internal/canon 的 Writer.Str / Bytes 帧格式拼一段：8 字节大端长度前缀 + 内容。"""
    return struct.pack(">Q", len(part)) + part


def i64(v: int) -> bytes:
    """按 internal/canon 的 Writer.I64 拼一个定长整数：8 字节大端补码，不写长度前缀。"""
    return struct.pack(">q", v)


def canonical(method: str, path: str, raw_query: str, body: bytes, ts: int, nonce: str) -> bytes:
    """拼出"待签名内容"（字段顺序必须与 apiauth.go 的 apiAuthPayload 一致）。"""
    return (field(DOMAIN.encode())
            + field(method.encode())
            + field(path.encode())
            + field(raw_query.encode())
            + field(hashlib.sha256(body).digest())
            + i64(ts)
            + field(nonce.encode()))


def sign(secret: bytes, payload: bytes) -> str:
    """对 payload 取 HMAC-SHA256 并 base64（这就是 X-Treecmd-Signature 的值）。"""
    return base64.b64encode(hmac.new(secret, payload, hashlib.sha256).digest()).decode()


def split_hostport(host: str) -> tuple[str, int]:
    """把 host:port 拆成 (主机, 端口)，端口缺省 18443；支持 [::1]:18443 这种 IPv6 写法。"""
    if host.startswith("["):
        h, _, p = host[1:].partition("]")
        return h, int(p.lstrip(":") or 18443)
    if host.count(":") == 1:
        h, _, p = host.partition(":")
        return h, int(p or 18443)
    return host, 18443


def load_secret(args) -> bytes:
    """取共享密钥：--secret > --secret-file > 环境变量 TREECMD_API_SECRET > ./api.secret。"""
    if args.secret:
        return args.secret.strip().encode()
    path = args.secret_file
    if not path:
        env = os.environ.get("TREECMD_API_SECRET", "").strip()
        if env:
            return env.encode()
        path = DEFAULT_SECRET_FILE
    try:
        with open(path, "rb") as fh:
            return fh.read().strip()
    except OSError as exc:
        sys.exit(f"读不到密钥文件 {path}：{exc}\n"
                 f"（节点目录里生成：head -c 32 /dev/urandom | base64 > api.secret && chmod 600 api.secret）")


def read_body(args) -> bytes:
    """取请求体：--data 给 '-' 时从 stdin 读，其它情况用它本身；没给就是空体。"""
    if args.data is None:
        return b""
    if args.data == "-":
        return sys.stdin.buffer.read()
    return args.data.encode()


def parse_target(first: str, second: str) -> tuple[str, str]:
    """把两个位置参数拆成 (方法, 路径)。

    两种写法都收：`<方法> <路径>`（如 `POST /v1/crl?node=X`）与只给 `<路径>`。
    判据是"哪一个以 / 开头" —— 于是 `POST /v1/crl` 与 `/v1/crl POST` 都不会被弄反
    （**踩过**：位置参数按声明顺序绑定，把方法当成了路径发出去，服务端只会回一个光秃秃的
    400 Bad Request，看着像"签名不对"，其实是请求行本身是垃圾）。
    """
    if first.startswith("/"):
        path, method = first, second
    else:
        method, path = first, second
    if not path.startswith("/"):
        raise SystemExit(f"路径要以 / 开头（拿到 {path!r}）；用法：api_call.py [方法] <路径含query>")
    return method, path


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""
    ap = argparse.ArgumentParser(
        description="treecmd 对外 HTTP 的签名调用工具",
        epilog="路径与 query 会**原样**发送并原样签名：需要转义请自己先转义。")
    ap.add_argument("first", metavar="[方法] 路径", help="如 'POST /v1/crl?node=<GUID>'，或只给 '/v1/tree'")
    ap.add_argument("second", nargs="?", default="", help="配合上面那种两段写法时的第二段")
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"目标 host:port，默认 {DEFAULT_HOST}")
    ap.add_argument("--data", default=None, help="请求体；'-' 表示从 stdin 读")
    ap.add_argument("--secret-file", default=None, help=f"密钥文件，默认 {DEFAULT_SECRET_FILE}（或环境变量 TREECMD_API_SECRET）")
    ap.add_argument("--secret", default=None, help="直接给密钥（不推荐：会留在 shell 历史里）")
    ap.add_argument("--timeout", type=float, default=30.0, help="超时秒数，默认 30")
    return ap


def main() -> int:
    """入口：拼签名 → 发请求 → 输出状态码与响应体，返回进程退出码。"""
    args = build_parser().parse_args()
    method, target = parse_target(args.first, args.second)
    method = (method or ("POST" if args.data is not None else "GET")).upper()
    path, _, raw_query = target.partition("?")
    body = read_body(args)
    secret = load_secret(args)
    if not secret:
        sys.exit("密钥为空 —— 拒绝发出请求（空密钥等于没有访问控制）")

    ts = int(time.time())
    nonce = pysecrets.token_hex(16)
    payload = canonical(method, path, raw_query, body, ts, nonce)

    host, port = split_hostport(args.host)
    headers = {
        "X-Treecmd-Timestamp": str(ts),
        "X-Treecmd-Nonce": nonce,
        "X-Treecmd-Signature": sign(secret, payload),
    }
    if body:
        headers["Content-Type"] = "application/json"

    conn = http.client.HTTPConnection(host, port, timeout=args.timeout)
    try:
        # 请求行用的是**原样**的 target（查询串不做重排），发出去的与签名的必须是同一串。
        conn.request(method, target, body=body or None, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
    except OSError as exc:
        sys.exit(f"连不上 {args.host}：{exc}")
    finally:
        conn.close()

    sys.stderr.write(f"HTTP {resp.status} {resp.reason}\n")
    sys.stdout.write(data.decode("utf-8", "replace"))
    if data and not data.endswith(b"\n"):
        sys.stdout.write("\n")
    return 0 if 200 <= resp.status < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
