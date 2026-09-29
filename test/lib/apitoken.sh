#!/usr/bin/env bash
#
# apitoken.sh —— 测试脚本共用的「API 凭据」工具（被 source，不单独执行）。
#
# 【为什么需要它】对外 HTTP 端点**没有任何免签来源**（历史上有过"回环免签"，已废弃 ——
# 反向代理 / 端口转发会把所有请求的对端改写成 127.0.0.1，免签等于对全网放行）。现在唯一的
# 凭据是 user token：由节点的 CA 私钥签发、落盘 `<节点目录>/user/<用户名>`，请求带
# `X-Treecmd-Token` 出示它（详见 internal/node/usertoken.go）。
#
# 于是**每个**打 API 的测试脚本都得先有一份 token —— 本文件把这件小事收敛成一行：
#
#     . "${HERE}/lib/apitoken.sh"        # 装好 curl 包装器
#     API_TOKEN_DIR="${DEMO}/root"       # 说明"token 签在哪个节点目录下"
#
# 之后脚本里所有 `curl` 调用都会自动带上 `X-Treecmd-Token`（包括 `CURL=(curl ...)` 这种
# 数组写法 —— bash 的命令查找优先命中函数）。**healthz 不需要 token**（存活探针永远放行），
# 带上也无害。
#
# 【凭据的唯一事实来源是磁盘】每次发请求之前，包装器都把 `user/<用户名>` 的**当前内容**取来用
# （必要时才现签一份）。所以"另一个 shell 刚换过 token""某次 `$( )` 子壳里触发了签发"这类事
# 都不会让脚本拿着一份**已经被替换掉的旧 token** 去打 API —— 那会得到一个 401，而 401 在这个
# 项目里正是"访问控制生效"的正常表现，**假失败会伪装成正确答案**。详见 api_token_ensure 的注释。
#
# 【多节点的脚本】调用处自己写了 `-H "X-Treecmd-Token: ..."` 时，包装器**尊重调用处**、
# 不再注入（否则会出现两个同名头，服务端只看第一个）。所以"打中继的 API"这种场景直接写：
#
#     "${CURL[@]}" -H "X-Treecmd-Token: ${RELAY_TOKEN}" "http://${RELAY_API}/v1/tree"
#
# 【签发不走节点进程】`-adduser` 只读配置里的 CA 私钥，节点不跑也能签；重复跑用 `-force`
# 覆盖，于是脚本多次执行是幂等的。

# API_TOKEN 当前注入的 token；API_TOKEN_DIR 非空时，每次用到 curl 都与磁盘对齐（lazy）。
API_TOKEN=""
API_TOKEN_DIR=""
# 测试用的默认用户名（同名文件会被 -force 覆盖，不积累）。
API_TOKEN_USER="tester"

# api_token_path —— 当前用户的 token 文件路径（= `<节点目录>/user/<用户名>`）。
api_token_path() { printf '%s/user/%s' "${API_TOKEN_DIR}" "${API_TOKEN_USER}"; }

# mint_api_token <二进制> <节点目录> [用户名] —— 现签一份 token 并打印到 stdout。
#
# 参数：
#   $1 节点可执行文件（bin/treecmd-node）
#   $2 节点目录（含 node.yaml；token 写到它下面的 user/<用户名>）
#   $3 用户名，默认 ${API_TOKEN_USER}
#
# 返回：成功打印 token 并返回 0；失败（没 CA 私钥 / 配置不合法）把 adduser 的输出打到
#       stderr 并返回非零 —— 调用方会让脚本停下来，而不是带着空凭据去跑出一堆假失败。
mint_api_token() {
  local bin="$1" dir="$2" user="${3:-${API_TOKEN_USER}}" out
  if [ -z "${bin}" ] || [ -z "${dir}" ]; then
    printf 'mint_api_token: 缺少参数（用法：mint_api_token <二进制> <节点目录> [用户名]）\n' >&2
    return 2
  fi
  if ! out="$("${bin}" -config "${dir}/node.yaml" -adduser "${user}" -force 2>&1)"; then
    printf 'mint_api_token 失败（%s）：\n%s\n' "${dir}" "${out}" >&2
    return 1
  fi
  cat "${dir}/user/${user}"
}

# api_token_bin —— 找出节点可执行文件：脚本自己定义的 BIN / BIN_PATH 优先，
# 都没有就按"仓库根下的 bin/treecmd-node"推导（脚本里 HERE 一定先于本文件被赋好）。
api_token_bin() {
  if [ -n "${BIN:-}" ]; then printf '%s' "${BIN}"; return 0; fi
  if [ -n "${BIN_PATH:-}" ]; then printf '%s' "${BIN_PATH}"; return 0; fi
  printf '%s' "${REPO:-${HERE}/..}/bin/treecmd-node"
}

# api_token_ensure —— 让 $API_TOKEN 等于"磁盘上现在那一份 token"；没有就现签一份。
#
# 【口径：以磁盘为准】每次要发请求之前，都把 $API_TOKEN 对齐到 `<节点目录>/user/<用户名>`。
#
# 为什么不是"签过一次就记住它"：这里踩过一个很隐蔽的坑 ——
#
#   脚本里任何一次 `FOO="$(some_func)"` 都是一次**子壳**。如果 some_func 内部打了 API，
#   那么"现签 token"这件事会在子壳里发生：**token 落到磁盘上了，但 `API_TOKEN=...` 这个
#   赋值回不到父壳**。父壳手里仍是上一份、而它的事实依据（目录/文件 mtime）已经变成新的，
#   于是它理直气壮地认为"手里这份就是文件里那份"，把**一份已经被替换掉的旧 token** 发出去
#   ⇒ 服务端 401 `ERR_API_AUTH_TOKEN_INVALID`。
#
#   而 401 在这个项目里恰恰是"访问控制生效"的正常表现 —— **假失败会伪装成正确答案**。
#   backpressure.sh 的 ③ 就是这么被咬的：`WINDOW_NOW="$(window_now)"` 里那次 curl 现签了
#   一份新的，紧接着 `run_probe` 又把旧的那份塞给了探针。
#
# 代价是每次 curl 多一次 stat 加读一个 ~105 字节的文件 —— 对验收脚本可以忽略；换来的是
# **脚本侧永远不会拿着一份磁盘上不存在的凭据去打 API**。
#
# 只有两种情况真的去签发（-adduser -force，会覆盖同名文件、于是旧的那份确定性失效）：
#   · token 文件不存在（或读不出来）—— 树刚建出来，还没给这个用户发过凭据；
#   · `node.yaml` 比 token 文件新 —— 树被重建过，CA 换了，旧 token 已经不被认。
# 另：`<节点目录>/node.yaml` 都还没有时**什么都不做**（树还没建），脚本早期那些"等端口起来"
# 的 healthz 探测会跑在这里，不能因为签不出 token 就把整个脚本弄挂。
api_token_ensure() {
  local cfg tokfile
  [ -n "${API_TOKEN_DIR}" ] || return 0
  cfg="${API_TOKEN_DIR}/node.yaml"
  [ -f "${cfg}" ] || return 0
  tokfile="$(api_token_path)"
  if [ -s "${tokfile}" ] && [ ! "${cfg}" -nt "${tokfile}" ]; then
    if API_TOKEN="$(cat "${tokfile}" 2>/dev/null)" && [ -n "${API_TOKEN}" ]; then
      return 0
    fi
  fi
  API_TOKEN="$(mint_api_token "$(api_token_bin)" "${API_TOKEN_DIR}")" || return 1
  return 0
}

# curl —— 包装真正的 curl：自动带上 X-Treecmd-Token，并且**绝不走 http_proxy**。
#
# 【为什么必须 --noproxy】本仓库全部请求都指向 127.0.0.1（或本机网卡地址），永远不该经过代理。
# 但在设了 `http_proxy`/`HTTP_PROXY` 的机器上（开发机很常见，随手的容器/隧道工具都会设），
# curl 会把**发给回环地址的请求也交给代理**，然后：
#
#     curl -s http://127.0.0.1:18493/v1/healthz   # 端口上其实什么都没有
#     → 代理回 502 Bad Gateway，而 **curl 的退出码是 0**（它只在传输层失败时才非 0）
#
# 于是所有"靠退出码判断服务起没起"的写法全部被骗：等待循环立刻返回（其实压根没等到）、
# `if ! curl … healthz; then 起一个父` 这类分支判断反过来走（父明明没在跑，却当成在跑）。
# 实测就是这么让 selfupdate.sh 的 readonly 负向用例红的 —— 叶子连不上父，日志里一路
# `dial tcp 127.0.0.1:19493: connect: connection refused`，而断言在说"没有预期的失败降级"。
#
# **读退出码之外还读响应体**的地方更直接：拿到的是 "502 Bad Gateway"，json 解析失败 → 空值。
# 所以这一条统一收在这里，而不是让每个脚本各自记得写 `--noproxy '*'`（曾经只有 forget.sh 记得）。
#
# 调用处自己带了 X-Treecmd-Token 时原样透传（多节点场景靠这个换凭据）。
curl() {
  local a have=0
  for a in "$@"; do
    case "${a}" in
      [Xx]-[Tt]reecmd-[Tt]oken:*) have=1 ;;
    esac
  done
  if [ "${have}" = "1" ]; then
    command curl --noproxy '*' "$@"
    return $?
  fi
  api_token_ensure || return 1
  if [ -n "${API_TOKEN}" ]; then
    command curl --noproxy '*' -H "X-Treecmd-Token: ${API_TOKEN}" "$@"
  else
    command curl --noproxy '*' "$@"
  fi
}
