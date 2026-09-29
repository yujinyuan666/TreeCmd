#!/usr/bin/env python3
"""treecmd 对外 HTTP 的调用工具（零依赖，只用标准库）。

【什么时候需要它】
节点的对外 HTTP 端点（api.http_addr）有一层访问控制：**任何来源（含本机）都要出示 user token**，
没有免签入口。凭据由节点用**它自己的 CA 私钥**签发，落盘在节点目录的 `user/<用户名>` 里：

    treecmd-node -config node.yaml -adduser alice     # 生成 user/alice，里面就是 token

把 `user/alice` 拷到运维机上，用本工具（或直接 curl）发请求即可。本工具只是把
"读 token 文件 → 放进 X-Treecmd-Token 头 → 发请求 → 打印状态码" 这几步包了一下，
顺带支持 HTTPS（--tls）与 mTLS（--cert）。

【请求头】只有一项，与 internal/node/apiauth.go 的 headerAPIToken 一致：

    X-Treecmd-Token: <user/<用户名> 文件的全部内容>

token 的格式是 `<16 位随机串>.<base64(CA 对 域‖用户名‖随机串 的 Ed25519 签名)>` ——
那是服务端 `-adduser` 写出来的东西，本工具**不生成也不校验**它，照抄文件内容即可。

【明文链路要配 TLS】token 是长期凭据，明文 HTTP 上被抄走即可原样重放 —— 跨不可信网络请用
`--tls --cafile <节点证书的 CA>`（节点侧配 api.tls，建议再开 require）。

【用法】
  # 本机（同样要 token，本机不再免签）
  scripts/api_call.py --host 127.0.0.1:18443 --token-file root/user/alice GET /v1/tree

  # 远程 + HTTPS：客户端证书校验服务端身份
  scripts/api_call.py --host 192.168.1.10:18443 --token-file ./alice --tls --cafile ./ca.crt \\
      POST '/v1/forget?node=<GUID>&mode=stale'

  # 节点开了 mTLS 时再带上客户端证书（它只加固传输层，不替代 token）
  scripts/api_call.py --host 192.168.1.10:18443 --token-file ./alice --tls --cafile ./ca.crt \\
      --cert ./client.pem --key ./client.key GET /v1/tree

  # token 也能从环境变量给，省得每条命令都写；带 body 的提交用 --data（'-' = 从 stdin 读）
  export TREECMD_API_TOKEN=$(cat ./alice)
  echo '{"type":"remote_time","aggregate":"TREE"}' | \\
      scripts/api_call.py --host 127.0.0.1:18443 POST /v1/commands --data -

【输出与退出码】
  stdout = 响应体原文；stderr = "HTTP <状态码> <原因>"。
  2xx 退出码 0，其它退出码 1（方便脚本 if 判断）。
"""

# 让 3.7~3.9 也能用 `dict | None` 这类注解（macOS 自带 python3 常年是 3.9）
from __future__ import annotations

import argparse
import http.client
import os
import ssl
import sys

# 与 internal/node/apiauth.go 的 headerAPIToken 保持一致：token 的请求头名。
TOKEN_HEADER = "X-Treecmd-Token"
# 默认目标（与节点目录里的约定一致）
DEFAULT_HOST = "127.0.0.1:18443"


def split_hostport(host: str) -> tuple[str, int]:
    """把 host:port 拆成 (主机, 端口)，端口缺省 18443；支持 [::1]:18443 这种 IPv6 写法。"""
    if host.startswith("["):
        h, _, p = host[1:].partition("]")
        return h, int(p.lstrip(":") or 18443)
    if host.count(":") == 1:
        h, _, p = host.partition(":")
        return h, int(p or 18443)
    return host, 18443


def load_token(args) -> str:
    """取 token：--token > --token-file > 环境变量 TREECMD_API_TOKEN。

    没有任何来源时**直接退出并给出签发命令** —— 与其发一个注定 401 的请求，不如把
    "token 从哪来"讲清楚（这是这个工具最常见的误用）。
    """
    if args.token:
        token = args.token.strip()
    elif args.token_file:
        try:
            with open(args.token_file, "r", encoding="utf-8") as fh:
                token = fh.read().strip()
        except OSError as exc:
            sys.exit(f"读不到 token 文件 {args.token_file}：{exc}")
    else:
        token = os.environ.get("TREECMD_API_TOKEN", "").strip()
    if not token:
        sys.exit("没有 token —— 本端点不设免签来源，任何请求都要带 " + TOKEN_HEADER + "。\n"
                 "签发：treecmd-node -config node.yaml -adduser <用户名>\n"
                 "然后： --token-file <节点目录>/user/<用户名>（或设 TREECMD_API_TOKEN）")
    return token


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
    400 Bad Request，看着像"鉴权不对"，其实是请求行本身是垃圾）。
    """
    if first.startswith("/"):
        path, method = first, second
    else:
        method, path = first, second
    if not path.startswith("/"):
        raise SystemExit(f"路径要以 / 开头（拿到 {path!r}）；用法：api_call.py [方法] <路径含query>")
    return method, path


def make_connection(args, host: str, port: int):
    """按 --tls / --cafile / --cert 建连接（明文或 HTTPS）。"""
    if not args.tls:
        return http.client.HTTPConnection(host, port, timeout=args.timeout)
    ctx = ssl.create_default_context(cafile=args.cafile)
    if args.insecure:
        # 不校验证书等于放弃了"我连的是不是真节点" —— 只在自测时用。
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif args.cafile:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
    if args.cert:
        ctx.load_cert_chain(args.cert, args.key)
    return http.client.HTTPSConnection(host, port, timeout=args.timeout, context=ctx)


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""
    ap = argparse.ArgumentParser(
        description="treecmd 对外 HTTP 调用工具（携带 user token）",
        epilog="路径与 query 会**原样**发送：需要转义请自己先转义。")
    ap.add_argument("first", metavar="[方法] 路径", help="如 'POST /v1/crl?node=<GUID>'，或只给 '/v1/tree'")
    ap.add_argument("second", nargs="?", default="", help="配合上面那种两段写法时的第二段")
    ap.add_argument("--host", default=DEFAULT_HOST, help=f"目标 host:port，默认 {DEFAULT_HOST}")
    ap.add_argument("--data", default=None, help="请求体；'-' 表示从 stdin 读")
    ap.add_argument("--token-file", default=None, help="token 文件（即节点目录里的 user/<用户名>）")
    ap.add_argument("--token", default=None, help="直接给 token 原文（不推荐：会留在 shell 历史里）")
    ap.add_argument("--tls", action="store_true", help="走 HTTPS（节点开了 api.tls 时用）")
    ap.add_argument("--cafile", default=None, help="校验服务端证书用的 CA 文件（--tls 时强烈建议给）")
    ap.add_argument("--insecure", action="store_true", help="--tls 时不校验证书（仅自测用）")
    ap.add_argument("--cert", default=None, help="客户端证书（PEM，含私钥也行）；节点开了 mTLS 时用")
    ap.add_argument("--key", default=None, help="客户端私钥（证书与私钥分开时用）")
    ap.add_argument("--timeout", type=float, default=30.0, help="超时秒数，默认 30")
    return ap


def main() -> int:
    """入口：读 token → 发请求 → 输出状态码与响应体，返回进程退出码。"""
    args = build_parser().parse_args()
    method, target = parse_target(args.first, args.second)
    method = (method or ("POST" if args.data is not None else "GET")).upper()
    body = read_body(args)
    token = load_token(args)

    host, port = split_hostport(args.host)
    headers = {TOKEN_HEADER: token}
    if body:
        headers["Content-Type"] = "application/json"

    conn = make_connection(args, host, port)
    try:
        # 请求行用的是**原样**的 target（查询串不做重排）。
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
