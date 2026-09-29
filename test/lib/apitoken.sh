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
# 【多节点的脚本】调用处自己写了 `-H "X-Treecmd-Token: ..."` 时，包装器**尊重调用处**、
# 不再注入（否则会出现两个同名头，服务端只看第一个）。所以"打中继的 API"这种场景直接写：
#
#     "${CURL[@]}" -H "X-Treecmd-Token: ${RELAY_TOKEN}" "http://${RELAY_API}/v1/tree"
#
# 【签发不走节点进程】`-adduser` 只读配置里的 CA 私钥，节点不跑也能签；重复跑用 `-force`
# 覆盖，于是脚本多次执行是幂等的。

# API_TOKEN 当前注入的 token；API_TOKEN_DIR 非空时，第一次用到 curl 才去现签（lazy）。
API_TOKEN=""
API_TOKEN_DIR=""
# 测试用的默认用户名（同名文件会被 -force 覆盖，不积累）。
API_TOKEN_USER="tester"

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

# ensure_api_token —— 还没 token 且有 API_TOKEN_DIR 时现签一份。
#
# 只有在 `<节点目录>/node.yaml` 已经存在时才签：脚本早期那些"等端口起来"的 healthz 探测
# 可能跑在树被建出来之前，那时连配置都没有，不能因为签不出 token 就把脚本弄挂。
api_token_ensure() {
  [ -n "${API_TOKEN}" ] && return 0
  [ -n "${API_TOKEN_DIR}" ] || return 0
  [ -f "${API_TOKEN_DIR}/node.yaml" ] || return 0
  API_TOKEN="$(mint_api_token "$(api_token_bin)" "${API_TOKEN_DIR}")" || return 1
  return 0
}

# curl —— 包装真正的 curl，自动带上 X-Treecmd-Token。
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
    command curl "$@"
    return $?
  fi
  api_token_ensure || return 1
  if [ -n "${API_TOKEN}" ]; then
    command curl -H "X-Treecmd-Token: ${API_TOKEN}" "$@"
  else
    command curl "$@"
  fi
}
