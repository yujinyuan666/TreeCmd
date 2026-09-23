#!/usr/bin/env bash
#
# api-auth.sh —— 验收「对外 HTTP 端点的访问控制」。
#
# 证哪条不变量：
#   **写接口（POST /v1/crl、/v1/forget、/v1/commands…）不能被"能连上这个端口的人"执行** ——
#   本机（回环）免签放行；其它来源必须带共享密钥的 HMAC 签名；**没配密钥 ⇒ 非本机写请求一律拒绝**
#   （fail-closed，而不是"没配就放行"）。读接口默认仍放行（可用 api.auth.protect_reads 一并收紧）。
#
# 为什么必须绑 0.0.0.0 才能验：
#   访问控制的判据是**请求从哪来**（TCP 对端地址）。绑 127.0.0.1 时所有请求都是回环，
#   整条规则永远不会触发 —— 那才是"验了个寂寞"。所以这里刻意把根节点的 api 绑在
#   `0.0.0.0:${API_PORT}`（漏洞成立的前提），然后**从本机自己的非回环地址**打过去 ——
#   对本机来说那条路走的是网卡、对端就是网卡地址，与"局域网里另一台机器"完全等价。
#
# 三个阶段（每个阶段都重启一次节点，日志按"启动前挪走再建空文件"的规矩来，防假通过）：
#   ① 对外监听但**没有密钥**：本机写请求照常、远程写请求 403、远程读请求仍放行；
#   ② 节点目录里放了 `api.secret`（**约定补全**，node.yaml 一个字没改）：远程无签 401、
#      正确签名真的执行了、错密钥 / 过期时间戳 / 重放 nonce / 签名搬去别的 query 全部 401；
#   ③ node.yaml 显式写 `api.auth.secret_path` + `protect_reads: true`：远程读请求也要签名。
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

# 三个只用作"写入探针"的 NodeID（吊销不校验关系，扔什么 GUID 进去都能观察效果）。
GUID_LOCAL="0198f0c0-0000-7000-8000-0000abc0f001"  # ① 本机（回环）打进去的
GUID_REMOTE="0198f0c0-0000-7000-8000-0000abc0f002" # ① 远程无签打进去的（必须没进去）
GUID_OK="0198f0c0-0000-7000-8000-0000abc0f003"     # ② 远程**带正确签名**打进去的
GUID_DENY="0198f0c0-0000-7000-8000-0000abc0f004"   # ② 各种签名失败的情形（必须没进去）
GUID_REPLAY="0198f0c0-0000-7000-8000-0000abc0f005" # ② 先正常写一次、再原样重放（重放必须没效果）
# 三个阶段结束后 CRL 里**应该只有**这三条（字典序：f001 < f003 < f005）
EXPECT_CRL="${GUID_LOCAL},${GUID_OK},${GUID_REPLAY}"

PASS=0; FAIL=0
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()   { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }
info()  { printf '    %s\n' "$*"; }
step()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
die()   { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

chk() { # chk <说明> <实际> <期望>
  if [ "$2" = "$3" ]; then ok "$1（$2）"; else bad "$1：实际=[$2] 期望=[$3]"; fi
}

# ── 本机非回环地址：访问控制要靠它才验得到 ────────────────────────────────────
detect_lan_ip() {
  local iface ip
  for iface in $(route -n get default 2>/dev/null | awk '/interface:/{print $2}') en0 en1 en2; do
    ip="$(ipconfig getifaddr "${iface}" 2>/dev/null || true)"
    [ -n "${ip}" ] && { printf '%s' "${ip}"; return 0; }
  done
  return 1
}
LAN_IP="${API_AUTH_LAN_IP:-$(detect_lan_ip || true)}"
[ -n "${LAN_IP}" ] || die "拿不到本机非回环地址 —— 没有它就验不了'非本机来源'这条路。可显式给：API_AUTH_LAN_IP=<你的网卡 IP> ./api-auth.sh"

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

# ── 写 node.yaml：<目录> <是否显式写 api.auth 段> ────────────────────────────
write_root_yaml() {
  local dir="$1" explicit_auth="$2"
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
  # ⚠️ 刻意绑 0.0.0.0：这正是"访问控制缺失"成立的前提（端口对外可达）
  http_addr: 0.0.0.0:${API_PORT}
EOF
  if [ "${explicit_auth}" = "yes" ]; then
    cat >> "${dir}/node.yaml" <<EOF
  auth:
    secret_path: api.secret
    protect_reads: true
EOF
  fi
  chmod 600 "${dir}/node.yaml"
}

# ── HTTP 工具 ───────────────────────────────────────────────────────────────
# 一律 --noproxy '*'：本机 HTTP 不该被 http_proxy 环境变量劫持（那会得到 502）。
hit() { # hit <方法> <url> [curl 附加参数...] —— 输出 "响应体\n状态码"
  local m="$1" url="$2"; shift 2
  curl -s --noproxy '*' -X "$m" -w $'\n%{http_code}' "$@" "$url"
}
# 下面四个把"从哪打"固定下来：local=回环（本机运维），remote=本机非回环地址（等价于局域网里的别人）
local_hit()  { hit "$1" "http://127.0.0.1:${API_PORT}$2" "${@:3}"; }
remote_hit() { hit "$1" "http://${LAN_IP}:${API_PORT}$2" "${@:3}"; }
code_of() { printf '%s' "${1##*$'\n'}"; }
body_of() { printf '%s' "${1%$'\n'*}"; }

# 取错误码：节点统一回 {"error":"ERR_XXX","message":"..."}
err_of() {
  printf '%s' "$1" | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("error",""))
except Exception: print("")'
}

# sig_of <密钥文件> <方法> <路径含query> <ts> <nonce> [body] —— 打印 base64 签名。
# **复用 scripts/api_call.py 的签名实现**（importlib 按路径加载），绝不在测试里重写一遍算法：
# 于是"服务端认了这个签名"本身就是"两边 canonical 编码逐字节一致"的证据。
sig_of() {
  python3 -c '
import importlib.util, sys
scripts, secret_file, method, target, ts, nonce = sys.argv[1:7]
body = sys.argv[7].encode() if len(sys.argv) > 7 else b""
spec = importlib.util.spec_from_file_location("api_call", scripts + "/api_call.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
path, _, query = target.partition("?")
secret = open(secret_file, "rb").read().strip()
sys.stdout.write(mod.sign(secret, mod.canonical(method, path, query, body, int(ts), nonce)))
' "${SCRIPTS}" "$@"
}

nonce_now() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }

# remote_post_signed <密钥文件> <路径含query> <ts> <nonce> —— 从非回环地址打一条带签名的写请求
remote_post_signed() {
  local sf="$1" target="$2" ts="$3" nonce="$4" sig
  sig="$(sig_of "$sf" POST "$target" "${ts}" "${nonce}")"
  remote_hit POST "${target}" \
    -H "X-Treecmd-Timestamp: ${ts}" -H "X-Treecmd-Nonce: ${nonce}" -H "X-Treecmd-Signature: ${sig}"
}

# revoked_list —— 本机读一次 CRL（读接口默认免签），打印被吊销的 GUID 列表
revoked_list() { body_of "$(local_hit GET /v1/crl)" | python3 -c 'import json,sys; print(",".join(json.load(sys.stdin).get("guids") or []))'; }

wait_api() { # 等端口可用（启动是后台的，别用固定 sleep 赌）
  for _ in $(seq 1 40); do
    curl -s --noproxy '*' --max-time 1 -o /dev/null "http://127.0.0.1:${API_PORT}/v1/healthz" && return 0
    sleep 0.25
  done
  return 1
}

# ── 前置 ────────────────────────────────────────────────────────────────────
[ -x "${BIN}" ] || die "找不到 ${BIN}；先 go build -o bin/treecmd-node ./cmd/node"
[ -x "${INIT_ROOT}" ] || die "找不到 ${INIT_ROOT}"

stop_root
rm -rf "${WORK}"
mkdir -p "${ROOT_DIR}" "${LOGS}"
if lsof -ti "tcp:${API_PORT}" >/dev/null 2>&1; then
  die "端口 ${API_PORT} 已被占用（有残留进程？）—— 先清掉再跑，否则验收会假通过"
fi
info "本机非回环地址 = ${LAN_IP}（用它冒充'局域网里的另一台机器'）"
"${INIT_ROOT}" "${ROOT_DIR}" "${ROOT_ID}" >/dev/null || die "init_root.sh 失败"
# 第 ① 阶段故意"没有密钥"，但签名工具总得有个密钥文件可读 —— 用一份假的，
# 用来证明"**没配密钥时，签了名也没用**"（判据是节点侧有没有密钥，不是请求侧签得好不好）。
printf '%s' 'phase1-placeholder-secret-0123456789' > "${WORK}/api.secret.placeholder"

# 起树后才能确认"这个地址真的够得到"；够不到就别把后面的失败算在访问控制头上。
write_root_yaml "${ROOT_DIR}" no
start_root
wait_api || { tail -20 "${LOGS}/root.log"; die "节点没在 :${API_PORT} 起来（看 ${LOGS}/root.log）"; }
REACH="$(remote_hit GET /v1/healthz || true)"
[ "$(code_of "${REACH}")" = "200" ] || die "从 ${LAN_IP} 连不到本机 API（HTTP $(code_of "${REACH}")）—— 先确认网卡地址与防火墙"
info "从 ${LAN_IP} 打本机 API：可达 ✓"

# ═══════════════════════════════════════════════════════════════════════════
step '① 对外监听 + 没有密钥：本机放行、远程写请求 403、远程读请求仍放行'
LOGTXT="$(cat "${LOGS}/root.log")"
case "${LOGTXT}" in
  *"api auth: 监听地址对外可达，但没配"*) ok "启动日志明确提示了「对外可达 + 未配密钥」" ;;
  *) bad "启动日志里没有「对外可达 + 未配密钥」的告警" ;;
esac

OUT="$(local_hit POST "/v1/crl?node=${GUID_LOCAL}")"
chk "本机（回环）写请求 → 放行" "$(code_of "${OUT}")" "200"
chk "  └ 真的写进去了" \
  "$(body_of "${OUT}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["revoked"])')" "1"

OUT="$(remote_hit GET /v1/tree)"
chk "远程读请求 → 仍放行（读接口默认不设防）" "$(code_of "${OUT}")" "200"

OUT="$(remote_hit POST "/v1/crl?node=${GUID_REMOTE}")"
chk "远程写请求（无签名）→ 拒绝" "$(code_of "${OUT}")" "403"
chk "  └ 错误码" "$(err_of "$(body_of "${OUT}")")" "ERR_API_AUTH_NOT_CONFIGURED"

TS="$(date +%s)"; NONCE="$(nonce_now)"
OUT="$(remote_post_signed "${WORK}/api.secret.placeholder" "/v1/crl?node=${GUID_REMOTE}" "${TS}" "${NONCE}")"
chk "远程写请求（**签了名但没配密钥**）→ 仍然拒绝" "$(code_of "${OUT}")" "403"

chk "被拒的 GUID 一个都没进 CRL" "$(revoked_list)" "${GUID_LOCAL}"

# ═══════════════════════════════════════════════════════════════════════════
step '② 节点目录里放 api.secret（node.yaml 一个字没改）：非回环必须签名'
stop_root
printf '%s' 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=' > "${ROOT_DIR}/api.secret"
chmod 600 "${ROOT_DIR}/api.secret"
printf '%s' 'wrong-secret-wrong-secret-wrong' > "${WORK}/api.secret.bad"
start_root
wait_api || { tail -20 "${LOGS}/root.log"; die "重启后没起来（看 ${LOGS}/root.log）"; }
LOGTXT="$(cat "${LOGS}/root.log")"
case "${LOGTXT}" in
  *"api auth: 写接口要求签名"*"api.secret"*) ok "启动日志确认密钥已生效（约定文件 api.secret 被自动采纳）" ;;
  *) bad "启动日志里没有「写接口要求签名 + api.secret」" ;;
esac

OUT="$(local_hit POST "/v1/crl?node=${GUID_LOCAL}")"
chk "本机写请求（无签名）→ 放行" "$(code_of "${OUT}")" "200"
OUT="$(remote_hit GET /v1/crl)"
chk "远程读请求 → 仍放行（没开 protect_reads）" "$(code_of "${OUT}")" "200"

OUT="$(remote_hit POST "/v1/crl?node=${GUID_DENY}")"
chk "远程写请求（无签名）→ 拒绝" "$(code_of "${OUT}")" "401"
chk "  └ 错误码" "$(err_of "$(body_of "${OUT}")")" "ERR_API_AUTH_REQUIRED"

# 正面用例：scripts/api_call.py 签出来的请求（这就是"远程运维"的真实路径）
CALL="$(python3 "${SCRIPTS}/api_call.py" --host "${LAN_IP}:${API_PORT}" --secret-file "${ROOT_DIR}/api.secret" \
        POST "/v1/crl?node=${GUID_OK}" 2>&1)" && CALL_CODE=0 || CALL_CODE=$?
chk "api_call.py 签名的远程写请求 → 放行" "${CALL_CODE}" "0"
case "${CALL}" in
  *"HTTP 200"*) ok "  └ 状态行 HTTP 200" ;;
  *) bad "  └ 状态行不是 HTTP 200：$(printf '%s' "${CALL}" | head -1)" ;;
esac
chk "  └ 签名请求真的执行了（CRL 里出现了它）" "$(revoked_list)" "${GUID_LOCAL},${GUID_OK}"

TS="$(date +%s)"; NONCE="$(nonce_now)"
OUT="$(remote_post_signed "${WORK}/api.secret.bad" "/v1/crl?node=${GUID_DENY}" "${TS}" "${NONCE}")"
chk "错密钥签名 → 拒绝" "$(code_of "${OUT}")" "401"

TS="$(date +%s)"; NONCE="$(nonce_now)"
OUT="$(remote_post_signed "${ROOT_DIR}/api.secret" "/v1/crl?node=${GUID_DENY}" "$((TS - 3600))" "${NONCE}")"
chk "过期时间戳（1 小时前）→ 拒绝" "$(code_of "${OUT}")" "401"

TS="$(date +%s)"; NONCE="$(nonce_now)"
OUT="$(remote_post_signed "${ROOT_DIR}/api.secret" "/v1/crl?node=${GUID_REPLAY}" "${TS}" "${NONCE}")"
chk "先来一次正常的 → 放行（为下面的重放做铺垫）" "$(code_of "${OUT}")" "200"
OUT="$(remote_post_signed "${ROOT_DIR}/api.secret" "/v1/crl?node=${GUID_REPLAY}" "${TS}" "${NONCE}")"
chk "同一个请求原样重放（同 ts + 同 nonce）→ 拒绝" "$(code_of "${OUT}")" "401"
chk "  └ 错误码" "$(err_of "$(body_of "${OUT}")")" "ERR_API_AUTH_FAILED"

TS="$(date +%s)"; NONCE="$(nonce_now)"
SIG="$(sig_of "${ROOT_DIR}/api.secret" POST "/v1/crl?node=${GUID_DENY}" "${TS}" "${NONCE}")"
OUT="$(remote_hit POST "/v1/crl?node=${GUID_REMOTE}" \
       -H "X-Treecmd-Timestamp: ${TS}" -H "X-Treecmd-Nonce: ${NONCE}" -H "X-Treecmd-Signature: ${SIG}")"
chk "签名是给 A 的、却拿去打 B（query 被改）→ 拒绝" "$(code_of "${OUT}")" "401"

TS="$(date +%s)"; NONCE="$(nonce_now)"
OUT="$(remote_hit POST "/v1/crl?node=${GUID_DENY}" \
       -H "X-Treecmd-Timestamp: ${TS}" -H "X-Treecmd-Nonce: ${NONCE}" \
       -H "X-Treecmd-Signature: $(sig_of "${ROOT_DIR}/api.secret" POST "/v1/crl?node=${GUID_REMOTE}" "${TS}" "${NONCE}")")"
chk "签名与 query 不符的另一种写法（改的是请求）→ 拒绝" "$(code_of "${OUT}")" "401"

# 回环 + **带着错误签名**：刻意也被校验（客户端 bug 不该被静默放行）
OUT="$(local_hit POST "/v1/crl?node=${GUID_DENY}" \
       -H "X-Treecmd-Timestamp: ${TS}" -H "X-Treecmd-Nonce: ${NONCE}" -H "X-Treecmd-Signature: bm90LWEtc2ln")"
chk "本机请求带了**错签名** → 也拒绝（带签名就会被校验）" "$(code_of "${OUT}")" "401"

chk "所有被拒的 GUID 都没进 CRL" "$(revoked_list)" "${EXPECT_CRL}"

# ═══════════════════════════════════════════════════════════════════════════
step '③ 显式 api.auth.secret_path + protect_reads: true：读接口也要签名'
stop_root
write_root_yaml "${ROOT_DIR}" yes
start_root
wait_api || { tail -20 "${LOGS}/root.log"; die "再次重启后没起来（看 ${LOGS}/root.log）"; }
case "$(cat "${LOGS}/root.log")" in
  *"写接口与读接口都要求签名"*) ok "启动日志确认读写都要求签名" ;;
  *) bad "启动日志里没有「写接口与读接口都要求签名」" ;;
esac
chk "远程读请求（无签名）→ 拒绝" "$(code_of "$(remote_hit GET /v1/tree)")" "401"
chk "本机读请求（无签名）→ 仍放行" "$(code_of "$(local_hit GET /v1/tree)")" "200"
chk "  └ 重启后吊销列表还在（CRL 是持久的）" "$(revoked_list)" "${EXPECT_CRL}"

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
