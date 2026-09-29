#!/usr/bin/env bash
#
# api-auth.sh —— 验收「对外 HTTP 端点的访问控制」。
#
# 证哪条不变量：
#   **这个端口没有免签来源** —— 不管请求从哪来（回环、网卡地址、局域网），只要拿不出本节点
#   CA 签发的 user token，就一律拒绝；读接口（/v1/tree 等）同样在射程内。唯一例外是
#   `/v1/healthz` 存活探针（只回 ok / node_id / path，不触发任何跨节点调用）。
#
# 为什么要把端口绑 0.0.0.0、还要从本机非回环地址打一遍：
#   历史上这条判据是"请求从哪来"（TCP 对端地址）—— 那正是被废弃的原因：反向代理 / 端口转发
#   会把远程请求的对端改写成 127.0.0.1，"本机"于是成了所有人的身份。现在判据是凭据本身，
#   所以这里刻意**从两个方向各打一遍**（回环 + 网卡地址），证明"从哪来"已经不影响结论。
#
# 五个阶段（每个阶段都重启一次节点，日志按"启动前挪走再建空文件"的规矩来，防假通过）：
#   ① **没有 token 时**：回环写请求 401、网卡地址写请求 401、读请求 401、
#      healthz 仍 200，且被拒的请求一条都没落进 CRL（用审计日志证明拒绝真的发生了）；
#   ② `-adduser`：文件落在 `user/<用户名>`（权限 600）、内容形如 `<16 位随机串>.<base64 签名>`；
#      拿它从**回环**与**网卡地址**各写一次全部放行；错 token / 格式不对 / 手写的伪造文件
#      一律 401（伪造文件即便放进了 user/ 目录也不算授权 —— 签名验不过）；
#   ③ **签了就生效、删了就失效**（都不重启节点）：新签的用户立刻能用；`rm user/<用户名>` 之后
#      那份 token 立刻 401，别人的不受影响；
#   ④ 反代 / 端口转发**不再有特殊含义**：带 X-Forwarded-For / Via 的请求与不带的一视同仁
#      （有 token 就过，没 token 就拒）——历史上这一条是"回环免签被绕过"的入口；
#   ⑤ **api.tls**：端点改以 HTTPS 提供（require: true）—— 明文打不进来，HTTPS 上仍要 token。
#
# 用法：
#   ./api-auth.sh          跑完整验证，结束后自动清场
#   ./api-auth.sh keep     跑完留着节点（自己 ./api-auth.sh stop 收）
#   ./api-auth.sh stop     只清场
#
#   API_AUTH_LAN_IP=172.18.90.133 ./api-auth.sh    # 自动探测不到本机非回环地址时手动指定
#
# 端口：listen 19793（回环）/ api 18793（**0.0.0.0**，与 demo 的 184xx、zero-trust 的 185xx/186xx 错开）。
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${HERE}/lib/platform.sh"   # 跨平台：文件权限 / 端口占用检测（GNU/Linux 上往往没有 lsof）
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
SCRIPTS="${REPO}/scripts"
INIT_ROOT="${SCRIPTS}/init_root.sh"

WORK="${HERE}/apiauth"
LOGS="${WORK}/logs"
ROOT_DIR="${WORK}/root"
PIDFILE="${HERE}/.apiauth.pids"

ROOT_ID="0198f0c0-0000-7000-8000-0000abc00002"
LISTEN="127.0.0.1:19793"
API_PORT=18793

# 写入探针用的 NodeID（吊销不校验关系，扔什么 GUID 进去都能观察效果）。
# 字典序即 CRL 的顺序，命名按"期望出现的先后 + 是否该出现"来定。
GUID_OK="0198f0c0-0000-7000-8000-0000abc0f001"      # ② 本机 + token 写进去的
GUID_LAN="0198f0c0-0000-7000-8000-0000abc0f002"     # ② 网卡地址 + token 写进去的
GUID_DENY="0198f0c0-0000-7000-8000-0000abc0f003"    # ①② 各种无凭据 / 错凭据的情形（必须没进去）
GUID_EVICT="0198f0c0-0000-7000-8000-0000abc0f004"   # ③ bob 被收回**之前**写进去的
GUID_TLS="0198f0c0-0000-7000-8000-0000abc0f005"     # ⑤ HTTPS + token 写进去的
GUID_REVOKED="0198f0c0-0000-7000-8000-0000abc0f006" # ③ 收回后拿旧 token 再打（必须没进去）
# ①② 阶段结束后 CRL 里**应该只有**这两条
EXPECT_CRL_12="${GUID_OK},${GUID_LAN}"
# ③ 之后（多了 bob 收回前写的那条）
EXPECT_CRL_3="${GUID_OK},${GUID_LAN},${GUID_EVICT}"
# ⑤ 之后（多了 HTTPS 那条）
EXPECT_CRL_FINAL="${GUID_OK},${GUID_LAN},${GUID_EVICT},${GUID_TLS}"

PASS=0; FAIL=0
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()   { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }
info()  { printf '    %s\n' "$*"; }
step()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
die()   { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

chk() { # chk <说明> <实际> <期望>
  if [ "$2" = "$3" ]; then ok "$1（$2）"; else bad "$1：实际=[$2] 期望=[$3]"; fi
}
contains() { # contains <说明> <文本> <子串>
  case "$2" in *"$3"*) ok "$1" ;; *) bad "$1（没找到「$3」）" ;; esac
}

# ── 本机非回环地址：证"从哪来已经不影响结论" ──────────────────────────────────
# 判定只看凭据、不看来源地址 —— 要验"换个来源地址结论一样"，就得有一个真的非回环地址去打。
# 两种系统的取法完全不同（Linux 没有 `route -n get`，macOS 没有 `ip route`），缺一边这个脚本
# 就会在 0 秒直接 die 在下面那条提示上（而提示看起来像"环境没配好"，不像"脚本只写了 macOS"）。
detect_lan_ip() {
  local ip iface
  # Linux：默认出口的源地址最准 —— `ip -4 route get` 的 src 就是它
  if command -v ip >/dev/null 2>&1; then
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null \
          | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
    [ -n "${ip}" ] && { printf '%s' "${ip}"; return 0; }
  fi
  # Linux 兜底：hostname -I 列出全部地址，取第一个私有段（避开 docker0 / 网桥之类的）
  ip="$(hostname -I 2>/dev/null | tr ' ' '\n' \
        | awk '/^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/{print; exit}')"
  [ -n "${ip}" ] && { printf '%s' "${ip}"; return 0; }
  # BSD / macOS：默认路由的网卡 + ipconfig
  for iface in $(route -n get default 2>/dev/null | awk '/interface:/{print $2}') en0 en1 en2; do
    ip="$(ipconfig getifaddr "${iface}" 2>/dev/null || true)"
    [ -n "${ip}" ] && { printf '%s' "${ip}"; return 0; }
  done
  return 1
}
LAN_IP="${API_AUTH_LAN_IP:-$(detect_lan_ip || true)}"
[ -n "${LAN_IP}" ] || die "拿不到本机非回环地址 —— 没有它就验不了「从别的地址来也一样」这件事。可显式给：API_AUTH_LAN_IP=<你的网卡 IP> ./api-auth.sh"

# ── 进程管理 ────────────────────────────────────────────────────────────────
start_root() {  # 每次启动前把上一份日志挪走（日志是追加的，留着会让"等日志出现"的断言假通过）
  mkdir -p "${LOGS}"
  [ -f "${LOGS}/root.log" ] && mv -f "${LOGS}/root.log" "${LOGS}/root.prev.log"
  : > "${LOGS}/root.log"
  "${BIN}" -config "${ROOT_DIR}/node.yaml" >> "${LOGS}/root.log" 2>&1 &
  echo "root:$!" >> "${PIDFILE}"
}

stop_root() {
  [ -f "${PIDFILE}" ] || return 0
  while IFS=: read -r _ p; do
    kill -TERM "${p}" 2>/dev/null || true
    for _ in $(seq 1 40); do kill -0 "${p}" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "${p}" 2>/dev/null || true
  done < "${PIDFILE}"
  rm -f "${PIDFILE}"
}

cmd_stop() {
  if [ -f "${PIDFILE}" ]; then stop_root; info "已停止并清场"; else info "没有在跑的验收节点"; fi
}

cleanup() { stop_root; }
trap 'stop_root' EXIT

# ./api-auth.sh stop —— 只清场（不跑验收）
if [ "${1:-}" = "stop" ]; then
  cmd_stop
  exit 0
fi

# ── 写 node.yaml：<目录> [api 段追加（自带两空格缩进）] ──────────────────────
write_root_yaml() {
  local dir="$1" api_extras="${2:-}"
  mkdir -p "${dir}"
  cat > "${dir}/node.yaml" <<EOF
node:
  id: ${ROOT_ID}
  name: apiauth-root
  remark: "访问控制验收的根"
  listen: ${LISTEN}
security:
  ca_cert_path: certs/node.crt.ca
  ca_key_path: keys/ca
  ca_cert_paths: [certs/node.crt.ca]
  enrollment: { enabled: true, token_path: enroll.token }
api:
  # 刻意绑 0.0.0.0：这正是"端点对外可达"的前提（访问控制必须在这个前提下成立）
  http_addr: 0.0.0.0:${API_PORT}
EOF
  if [ -n "${api_extras}" ]; then
    printf '%s\n' "${api_extras}" >> "${dir}/node.yaml"
  fi
  chmod 600 "${dir}/node.yaml"
}

# ── HTTP 工具 ───────────────────────────────────────────────────────────────
# 一律 --noproxy '*'：本机 HTTP 不该被 http_proxy 环境变量劫持（那会得到 502）。
hit() { # hit <方法> <url> [curl 附加参数...] —— 输出 "响应体\n状态码"
  local m="$1" url="$2"; shift 2
  curl -s --noproxy '*' ${CURL_TLS_OPT:-} -X "$m" -w $'\n%{http_code}' "$@" "$url"
}
# 带 token 的请求：<token> <方法> <url> [curl 附加参数...]
auth_hit() {
  local tok="$1"; shift
  hit "$@" -H "X-Treecmd-Token: ${tok}"
}
# 基址走变量：⑤ 阶段端点改成 HTTPS 后，只要把 LOCAL_BASE / REMOTE_BASE 换掉，其余断言不用动。
LOCAL_BASE="http://127.0.0.1:${API_PORT}"
REMOTE_BASE="http://${LAN_IP}:${API_PORT}"
local_hit()  { hit "$1" "${LOCAL_BASE}$2" "${@:3}"; }
remote_hit() { hit "$1" "${REMOTE_BASE}$2" "${@:3}"; }
local_auth_hit()  { auth_hit "${TOKEN:-}" "$1" "${LOCAL_BASE}$2" "${@:3}"; }
remote_auth_hit() { auth_hit "${TOKEN:-}" "$1" "${REMOTE_BASE}$2" "${@:3}"; }
code_of() { printf '%s' "${1##*$'\n'}"; }
body_of() { printf '%s' "${1%$'\n'*}"; }

# 取错误码：节点统一回 {"error":"ERR_XXX","message":"..."}
err_of() {
  printf '%s' "$1" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("error",""))
except Exception: print("")'
}

# mint <用户名> [附加 flag...] —— 用本节点 CA 签发一份 token 并打印（写进 user/<用户名>）
mint() {
  local user="$1"; shift
  "${BIN}" -config "${ROOT_DIR}/node.yaml" -adduser "${user}" "$@" >/dev/null || return 1
  cat "${ROOT_DIR}/user/${user}"
}
# 该用户名的 token 是否被服务端认（打印状态码）
status_with_token() { code_of "$(auth_hit "$1" POST "${LOCAL_BASE}$2")"; }

# revoked_list —— 读一次 CRL（**读接口也要 token**），打印被吊销的 GUID 列表
revoked_list() {
  body_of "$(local_auth_hit GET /v1/crl)" \
    | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin).get("guids") or []))'
}

wait_api() { # 等端口可用（启动是后台的，别用固定 sleep 赌）
  for _ in $(seq 1 40); do
    curl -s --noproxy '*' ${CURL_TLS_OPT:-} --max-time 1 -o /dev/null "${LOCAL_BASE}/v1/healthz" && return 0
    sleep 0.25
  done
  return 1
}

# ── 前置 ────────────────────────────────────────────────────────────────────
[ -x "${BIN}" ] || die "找不到 ${BIN}；请放入预编译好的 bin/treecmd-node（开发机上：go build -o bin/treecmd-node ./cmd/node）"
[ -x "${INIT_ROOT}" ] || die "找不到 ${INIT_ROOT}"

stop_root
rm -rf "${WORK}"
mkdir -p "${ROOT_DIR}" "${LOGS}"
if port_in_use "${API_PORT}"; then
  die "端口 ${API_PORT} 已被占用（有残留进程？）—— 先清掉再跑，否则验收会假通过"
fi
info "本机非回环地址 = ${LAN_IP}（用它冒充'局域网里的另一台机器'）"
"${INIT_ROOT}" "${ROOT_DIR}" "${ROOT_ID}" >/dev/null || die "init_root.sh 失败"

write_root_yaml "${ROOT_DIR}"
start_root
wait_api || { tail -20 "${LOGS}/root.log"; die "节点没在 :${API_PORT} 起来（看 ${LOGS}/root.log）"; }
REACH="$(remote_hit GET /v1/healthz || true)"
[ "$(code_of "${REACH}")" = "200" ] || die "从 ${LAN_IP} 连不到本机 API（HTTP $(code_of "${REACH}")）—— 先确认网卡地址与防火墙"
info "从 ${LAN_IP} 打本机 API：可达 ✓（healthz 不需要 token）"

# ═══════════════════════════════════════════════════════════════════════════
step '① 还没有任何 user token：谁来都进不去（含本机），只有 healthz 例外'
LOGTXT="$(cat "${LOGS}/root.log")"
contains "启动日志明确说明「user/ 目录里没有有效的 user token」" "${LOGTXT}" "没有有效的 user token"

OUT="$(local_hit POST "/v1/crl?node=${GUID_DENY}")"
chk "本机（回环）写请求、无 token → 拒绝" "$(code_of "${OUT}")" "401"
chk "  └ 错误码" "$(err_of "$(body_of "${OUT}")")" "ERR_API_AUTH_REQUIRED"
contains "  └ 文案点明「本端点没有免签来源」" "$(body_of "${OUT}")" "没有免签来源"

chk "网卡地址写请求、无 token → 同样拒绝（与回环一视同仁）" \
  "$(code_of "$(remote_hit POST "/v1/crl?node=${GUID_DENY}")")" "401"
chk "本机读请求（/v1/tree）、无 token → 也拒绝（读接口也在射程内）" \
  "$(code_of "$(local_hit GET /v1/tree)")" "401"
chk "网卡地址读请求、无 token → 拒绝" "$(code_of "$(remote_hit GET /v1/crl)")" "401"
chk "healthz 探针、无 token → 仍放行（监控要能判断'进程活着但没人有凭据'）" \
  "$(code_of "$(local_hit GET /v1/healthz)")" "200"

# 没凭据的请求必须**真的被拒**，而不是"回了 401 但仍然执行了" —— 用审计日志作证。
REJECTS="$(grep -c 'AUDIT-REJECT' "${LOGS}/root.log" || true)"
if [ "${REJECTS}" -ge 4 ]; then ok "审计日志里留下了 ${REJECTS} 条 AUDIT-REJECT（拒绝有痕迹）"
else bad "审计日志里的 AUDIT-REJECT 只有 ${REJECTS} 条，至少该有 4 条"; fi

# ═══════════════════════════════════════════════════════════════════════════
step '② -adduser 签发 token：拿到手就能用，本机与远程没有区别'
TOKEN="$(mint alice)" || die "adduser 失败"
[ -n "${TOKEN}" ] || die "token 为空"

# ① 阶段所有请求都没带凭据 ⇒ 那时 CRL 应该是空的（现在能读 CRL 了，因为它要 token）
chk "① 阶段被拒的请求一条都没落进 CRL" "$(revoked_list)" ""

TOKFILE="${ROOT_DIR}/user/alice"
chk "token 文件的权限" "$(file_mode "${TOKFILE}")" "600"
chk "user 目录的权限" "$(file_mode "${ROOT_DIR}/user")" "700"
# 格式：<16 位随机串>.<base64 签名>
chk "token 的形态（16 位随机串 + 签名）" \
  "$(python3 -c 'import sys,base64; t=open(sys.argv[1]).read().strip(); r,s=t.split("."); print("ok" if len(r)==16 and len(base64.b64decode(s))==64 else "bad")' "${TOKFILE}")" "ok"
chk "重复签发会被拦下（不悄悄换掉在用的 token）" \
  "$("${BIN}" -config "${ROOT_DIR}/node.yaml" -adduser alice >/dev/null 2>&1; echo $?)" "1"

OUT="$(local_auth_hit POST "/v1/crl?node=${GUID_OK}")"
chk "本机 + token 写请求 → 放行" "$(code_of "${OUT}")" "200"
chk "  └ 真的写进去了" \
  "$(body_of "${OUT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["revoked"])')" "1"

OUT="$(remote_auth_hit POST "/v1/crl?node=${GUID_LAN}")"
chk "网卡地址 + 同一个 token 写请求 → 放行（凭据与来源无关）" "$(code_of "${OUT}")" "200"
chk "本机读请求 + token → 放行" "$(code_of "$(local_auth_hit GET /v1/tree)")" "200"

# 错 token / 格式不对：都必须是 401（而且不能执行）
#
# FORGED 刻意做成"**格式完全合法**、但 CA 签名对不上"：把 alice 那份 token 的随机串换掉、
# 签名原样留着。这样它才会走到"扫 user/ 目录 + 验签"那一步 —— 用它才能验"目录里塞一个
# 自编的文件不算授权"；而格式都不对的串会在**碰磁盘之前**就被拦下，验不到这件事。
ALICE_TOKEN="$(cat "${TOKFILE}")"
FORGED="ZZZZZZZZZZZZZZZZ${ALICE_TOKEN:16}"
OUT="$(auth_hit "${FORGED}" POST "${LOCAL_BASE}/v1/crl?node=${GUID_DENY}")"
chk "格式合法、但不在 user/ 目录里的 token → 拒绝" "$(code_of "${OUT}")" "401"
chk "  └ 错误码" "$(err_of "$(body_of "${OUT}")")" "ERR_API_AUTH_TOKEN_INVALID"
chk "格式不对的 token（没有分隔符）→ 拒绝" \
  "$(code_of "$(auth_hit 'not-a-token' POST "${LOCAL_BASE}/v1/crl?node=${GUID_DENY}")")" "401"
chk "拿别人的文件冒充 token（空头）→ 拒绝" \
  "$(code_of "$(auth_hit '' POST "${LOCAL_BASE}/v1/crl?node=${GUID_DENY}")")" "401"

# 伪造：往 user/ 目录里塞一个自己编的 token 文件 —— 目录权限只是第二道，**签名**才是判据
printf '%s\n' "${FORGED}" > "${ROOT_DIR}/user/mallory"
chmod 600 "${ROOT_DIR}/user/mallory"
chk "手写一份 token 文件放进 user/ → 仍然拒绝（CA 签名验不过）" \
  "$(code_of "$(auth_hit "${FORGED}" POST "${LOCAL_BASE}/v1/crl?node=${GUID_DENY}")")" "401"
contains "  └ 日志里说明有验签不过的 token 文件被忽略" "$(cat "${LOGS}/root.log")" "验签不过的 token 文件"
rm -f "${ROOT_DIR}/user/mallory"

chk "被拒的 GUID 一个都没进 CRL" "$(revoked_list)" "${EXPECT_CRL_12}"

# ═══════════════════════════════════════════════════════════════════════════
step '③ 签了就生效、删了就失效 —— 全程不重启节点'
BOB="$(mint bob)" || die "给 bob 签发失败"
chk "新签的 bob 立刻可用（节点没重启过）" \
  "$(code_of "$(auth_hit "${BOB}" POST "${LOCAL_BASE}/v1/crl?node=${GUID_EVICT}")")" "200"

rm -f "${ROOT_DIR}/user/bob"
chk "删掉 user/bob 后，bob 的 token 立刻失效" \
  "$(code_of "$(auth_hit "${BOB}" POST "${LOCAL_BASE}/v1/crl?node=${GUID_REVOKED}")")" "401"
chk "  └ 别人的 token 不受影响（alice 照常）" "$(code_of "$(local_auth_hit GET /v1/tree)")" "200"
chk "被拒的 GUID 还是没进 CRL" "$(revoked_list)" "${EXPECT_CRL_3}"

# ═══════════════════════════════════════════════════════════════════════════
step '④ 反代 / 端口转发不再有任何特殊含义：转发头不改变结论'
OUT="$(local_auth_hit POST "/v1/crl?node=${GUID_OK}" -H "X-Forwarded-For: 127.0.0.1")"
chk "带 X-Forwarded-For + 有效 token → 放行（转发头不参与判定）" "$(code_of "${OUT}")" "200"
OUT="$(local_hit POST "/v1/crl?node=${GUID_DENY}" -H "X-Forwarded-For: 127.0.0.1")"
chk "带 X-Forwarded-For 冒充本机、但没有 token → 拒绝（**这一条就是历史漏洞的入口**）" \
  "$(code_of "${OUT}")" "401"
chk "带 X-Real-IP: 127.0.0.1 + Via，没 token → 拒绝" \
  "$(code_of "$(local_hit POST "/v1/crl?node=${GUID_DENY}" -H 'X-Real-IP: 127.0.0.1' -H 'Via: 1.1 proxy')")" "401"
chk "被拒的 GUID 依旧没进 CRL" "$(revoked_list)" "${EXPECT_CRL_3}"

# ═══════════════════════════════════════════════════════════════════════════
step '⑤ api.tls：端点以 HTTPS 提供 —— 明文进不来，HTTPS 上照样要 token'
mkdir -p "${WORK}/tls"
openssl req -x509 -newkey rsa:2048 -keyout "${WORK}/tls/server.key" -out "${WORK}/tls/server.crt" \
  -days 2 -nodes -subj "/CN=treecmd-api-test" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1 \
  || die "生成自签证书失败（openssl 不可用？）"

stop_root
TLS_EXTRAS="  tls:
    cert_path: ${WORK}/tls/server.crt
    key_path: ${WORK}/tls/server.key
    require: true"
write_root_yaml "${ROOT_DIR}" "${TLS_EXTRAS}"
# 这一阶段端点只以 HTTPS 提供：基址与 curl 选项一起换掉，其余断言不用动
LOCAL_BASE="https://127.0.0.1:${API_PORT}"
REMOTE_BASE="https://${LAN_IP}:${API_PORT}"
CURL_TLS_OPT="-k"
start_root
wait_api || { tail -20 "${LOGS}/root.log"; die "TLS 阶段没起来（看 ${LOGS}/root.log）"; }
contains "启动日志确认端点改以 HTTPS 提供" "$(cat "${LOGS}/root.log")" "对外端点以 HTTPS 提供"

# 明文打到 TLS 端口：Go 的 TLS 服务端认出"这是个 HTTP 请求行"后会直接回
# `400 Bad Request —— Client sent an HTTP request to an HTTPS server`，然后关掉连接。
PLAIN="$(curl -s --noproxy '*' --max-time 2 -o /dev/null -w '%{http_code}' \
          "http://127.0.0.1:${API_PORT}/v1/healthz" || true)"
chk "拿明文 HTTP 去连 TLS 端口 → 被拒（400：请求发给了 HTTPS 服务端）" "${PLAIN}" "400"
chk "HTTPS 上的存活探针 → 200" "$(code_of "$(local_hit GET /v1/healthz)")" "200"
chk "HTTPS 上不带 token → 401" "$(code_of "$(local_hit GET /v1/tree)")" "401"

# 客户端工具：--tls + --cafile + --token-file（这就是"远程运维"的真实路径）
CALL="$(python3 "${SCRIPTS}/api_call.py" --tls --cafile "${WORK}/tls/server.crt" \
        --host "127.0.0.1:${API_PORT}" --token-file "${TOKFILE}" \
        POST "/v1/crl?node=${GUID_TLS}" 2>&1)" && CALL_CODE=0 || CALL_CODE=$?
chk "api_call.py --tls（校验服务端证书 + 带 token）→ 放行" "${CALL_CODE}" "0"
contains "  └ 状态行 HTTP 200" "${CALL}" "HTTP 200"
chk "  └ 真的写进去了" "$(revoked_list)" "${EXPECT_CRL_FINAL}"

chk "最终 CRL（被拒的一个都没进来）" "$(revoked_list)" "${EXPECT_CRL_FINAL}"

# ═══════════════════════════════════════════════════════════════════════════
step '⑥ token 只能由 CA 签：没有 CA 材料就发不出来，文件名也不许穿越'
# 把 CA 私钥挪走 = 这个节点"没有能力签发"（叶子节点就是这个状态）
mv "${ROOT_DIR}/keys/ca" "${WORK}/ca.bak"
OUT="$("${BIN}" -config "${ROOT_DIR}/node.yaml" -adduser carol 2>&1)" && RC=0 || RC=$?
chk "没有 CA 私钥时 -adduser 失败" "${RC}" "1"
contains "  └ 文案点明「token 必须由本节点 CA 签发」" "${OUT}" "CA"
mv "${WORK}/ca.bak" "${ROOT_DIR}/keys/ca"

OUT="$("${BIN}" -config "${ROOT_DIR}/node.yaml" -adduser '../evil' 2>&1)" && RC=0 || RC=$?
chk "用户名带路径穿越（../evil）被拒" "${RC}" "1"
[ -e "${WORK}/evil" ] && bad "「../evil」竟然写出了文件：${WORK}/evil" || ok "  └ 没有在 user/ 之外落下任何文件"

# ═══════════════════════════════════════════════════════════════════════════
printf '\n'
if [ "${FAIL}" -eq 0 ]; then
  printf '\033[32m全部通过\033[0m：%d 项断言\n' "${PASS}"
else
  printf '\033[31m失败 %d 项\033[0m（通过 %d 项）\n' "${FAIL}" "${PASS}" >&2
fi

if [ "${1:-}" = "keep" ]; then
  info "按 keep 保留验收节点：${ROOT_DIR}（停：./api-auth.sh stop）"
else
  cleanup
fi
[ "${FAIL}" -eq 0 ]
