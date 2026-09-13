#!/usr/bin/env bash
#
# demo.sh —— 一键起一套"看得见"的 treecmd 树 + 可视化控制台。
#
#   ./demo.sh start        起树（根 + 直接叶子 + 中继 + 中继下的叶子）+ 起控制台
#   ./demo.sh stop         全部停掉
#   ./demo.sh status       看各节点活着没
#   ./demo.sh logs <name>  看某个节点的日志（root | leaf1 | relay | leaf2 | console）
#
# 为什么是这个形状：
#   · 根：自签材料（scripts/init_root.sh），提供 HTTP API —— 控制台连的就是它；
#   · 直接叶子：验证"根的直接子节点"这一层；
#   · 中继：自带 listen、且会向根申请 CA 证书 —— 验证"有下级的节点"这条路；
#   · 中继下的叶子：让整棵树真有 3 层，健康扫描（depth=-1）才有意义。
#
# 端口：根 listen 19493 / api 18493；中继 listen 19494；叶子不需要 listen。
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 本脚本在仓库的 test/ 下，所以仓库根就是它的上一级；用自身位置推导，
# 换机器 / 换目录都不必改脚本（确实要指别处时用 TREECMD_REPO 覆盖）
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
INIT_ROOT="${REPO}/scripts/init_root.sh"
DEMO="${HERE}/demo"
LOGS="${HERE}/logs"
PIDFILE="${HERE}/.demo.pids"

ROOT_ID="0198f0c0-0000-7000-8000-0000de000001"
ROOT_API="127.0.0.1:18493"
ROOT_LISTEN="127.0.0.1:19493"
RELAY_LISTEN="127.0.0.1:19494"
CONSOLE_PORT="${CONSOLE_PORT:-8899}"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── 写一个节点的 node.yaml ──────────────────────────────────────────────
# $1=目录 $2=名字 $3=备注 $4=listen（空则不写） $5=父的 host:port（空则本节点是根） $6=父的 NodeID
write_config() {
  local dir="$1" name="$2" remark="$3" listen="$4" parent="$5" parent_id="${6:-${ROOT_ID}}"
  mkdir -p "${dir}"
  {
    echo "node:"
    echo "  name: ${name}"
    echo "  remark: \"${remark}\""
    [ -n "${listen}" ] && echo "  listen: ${listen}"
    if [ -n "${parent}" ]; then
      echo "parents:"
      echo "  - id: ${parent_id}"
      echo "    addr: ${parent}"
    fi
    echo "security:"
    if [ -z "${parent}" ]; then
      # 根：全字段显式给出（自签材料）
      cat <<EOF
  identity_key_path: keys/id_ed25519
  identity_pubkey_path: keys/id_ed25519.pub
  identity_cert_path: certs/node.crt
  ca_cert_path: certs/node.crt.ca
  ca_key_path: keys/ca
  ca_cert_paths:
    - certs/node.crt.ca
  enrollment: { enabled: true, token_path: enroll.token }
EOF
    else
      cat <<EOF
  ca_cert_paths: [trust]
  enrollment: { enabled: true, token_path: enroll.token }
EOF
      # 有下级的节点要多给一个 CA 私钥路径（没这个文件也不影响叶子启动）
      [ -n "${listen}" ] && echo "  ca_key_path: keys/ca"
    fi
    [ -z "${parent}" ] && { echo "api:"; echo "  http_addr: ${ROOT_API}"; }
  } > "${dir}/node.yaml"
  chmod 600 "${dir}/node.yaml"
}

# ── 准备一个子节点：密钥 + 信任锚 + 入网许可（**不要证书**，留给运行期入网） ──
# $1=目录 $2=是否需要 CA 密钥对
prepare_child() {
  local dir="$1" with_ca="$2"
  rm -rf "${dir}"; mkdir -p "${dir}"
  if [ "${with_ca}" = "yes" ]; then
    "${BIN}" -genkey -keydir "${dir}/keys" -with-ca >/dev/null
  else
    "${BIN}" -genkey -keydir "${dir}/keys" >/dev/null
  fi
  mkdir -p "${dir}/trust"
  cp "${DEMO}/root/certs/ca.crt" "${dir}/trust/root-ca.crt"
  cp "${DEMO}/root/enroll.token" "${dir}/enroll.token"; chmod 600 "${dir}/enroll.token"
}

start_one() {   # $1=名字 $2=目录
  local name="$1" dir="$2"
  "${BIN}" -config "${dir}/node.yaml" > "${LOGS}/${name}.log" 2>&1 &
  echo "${name}:$!" >> "${PIDFILE}"
}
start_one_debug() {  # 名字 目录 —— 带 debug 级（控制台里看后台任务用）
  local name="$1" dir="$2"
  "${BIN}" -log-level debug -config "${dir}/node.yaml" > "${LOGS}/${name}.log" 2>&1 &
  echo "${name}:$!" >> "${PIDFILE}"
}
wait_registered() {  # $1=日志文件 $2=超时秒 $3=说明
  local f="$1" t="${2:-20}" what="${3:-注册}"
  for _ in $(seq 1 $((t * 2))); do
    grep -q 'msg=registered' "$f" 2>/dev/null && { ok "${what}成功"; return 0; }
    sleep 0.5
  done
  warn "${what}超时（${t}s）—— 看 ${f}"
  return 0
}

cmd_start() {
  [ -x "${BIN}" ] || die "找不到 ${BIN}；先在仓库里 go build -o bin/treecmd-node ./cmd/node"
  [ -x "${INIT_ROOT}" ] || die "找不到 ${INIT_ROOT}"
  [ -f "${PIDFILE}" ] && { warn "看起来已经在跑（${PIDFILE} 存在）；先 ./demo.sh stop"; exit 1; }

  mkdir -p "${LOGS}"

  echo "① 根节点（自签材料 + HTTP API）"
  if [ ! -f "${DEMO}/root/certs/node.crt" ]; then
    "${INIT_ROOT}" "${DEMO}/root" "${ROOT_ID}" >/dev/null
    ok "已生成根的自签材料"
  else
    ok "复用已有的根材料"
  fi
  write_config "${DEMO}/root" "demo-root" "演示根节点" "${ROOT_LISTEN}" ""
  start_one_debug root "${DEMO}/root"
  sleep 2

  echo "② 直接叶子（验证根的直接子这一层）"
  prepare_child "${DEMO}/leaf1" no
  write_config "${DEMO}/leaf1" "leaf-alpha" "根的直接子" "" "${ROOT_LISTEN}"
  start_one leaf1 "${DEMO}/leaf1"
  wait_registered "${LOGS}/leaf1.log" 20 "leaf-alpha 入网并注册"

  echo "③ 中继（自带 listen，会向根申请自己的 CA 证书）"
  prepare_child "${DEMO}/relay" yes
  write_config "${DEMO}/relay" "relay-mid" "中间层，有下级" "${RELAY_LISTEN}" "${ROOT_LISTEN}"
  start_one relay "${DEMO}/relay"
  wait_registered "${LOGS}/relay.log" 20 "relay-mid 入网并注册"
  # 中继的 node.id 是它自己生成的（UUIDv7），下级要把这个 ID 写进 parents[].id。
  # 取日志里**第一个** node_id=（它一定是本节点自己的：启动第一件事就是打印 node.id 的来源）
  RELAY_ID="$(grep -o 'node_id=[0-9a-f-]\{36\}' "${LOGS}/relay.log" | head -1 | cut -d= -f2)"
  if [ -z "${RELAY_ID}" ]; then
    # 兜底：从运行期状态文件里读（state.dat 的 self.id）
    RELAY_ID="$(grep -o '"id":"[0-9a-f-]\{36\}"' "${DEMO}/relay/state.dat" 2>/dev/null | head -1 | sed 's/.*"id":"//;s/"//')"
  fi
  [ -n "${RELAY_ID}" ] || die "读不到中继的 node_id（看 ${LOGS}/relay.log）"
  ok "中继 NodeID = ${RELAY_ID}"

  echo "④ 中继下的叶子（凑出 3 层，健康扫描才有意义）"
  prepare_child "${DEMO}/leaf2" no
  write_config "${DEMO}/leaf2" "leaf-beta" "挂在中继下面" "" "${RELAY_LISTEN}" "${RELAY_ID}"
  start_one leaf2 "${DEMO}/leaf2"
  wait_registered "${LOGS}/leaf2.log" 20 "leaf-beta 入网并注册"

  echo "⑤ 控制台"
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${CONSOLE_PORT}/" 2>/dev/null; then
    ok "控制台已在 :${CONSOLE_PORT} 上跑着，不再重复启动"
  else
    nohup /usr/bin/python3 "${HERE}/serve.py" --port "${CONSOLE_PORT}" --target "${ROOT_API}" \
      > "${LOGS}/console.log" 2>&1 &
    echo "console:$!" >> "${PIDFILE}"
    sleep 1.2
    ok "控制台已启动"
  fi

  echo
  echo "════════════════════════════════════════════════════════════"
  echo "  控制台   http://127.0.0.1:${CONSOLE_PORT}/"
  echo "  目标     ${ROOT_API}（页面上可改）"
  echo "  树       demo-root ─┬─ leaf-alpha            （根的直接子）"
  echo "                      └─ relay-mid ── leaf-beta（3 层）"
  echo "  停止     ./demo.sh stop"
  echo "════════════════════════════════════════════════════════════"

  # DEMO_HOLD=1 时留在前台等子进程（适合放进"受管后台任务"里跑：
  # 脚本一退出，它 nohup 起来的那些节点往往会被一起收走）
  if [ "${DEMO_HOLD:-0}" = "1" ]; then
    info "DEMO_HOLD=1：停在前台等子进程退出（Ctrl-C 或 ./demo.sh stop 结束）"
    wait
  fi
}

cmd_stop() {
  if [ ! -f "${PIDFILE}" ]; then info "没有在跑的演示（${PIDFILE} 不存在）"; return 0; fi
  while IFS=: read -r name pid; do
    if kill -0 "${pid}" 2>/dev/null; then
      kill -TERM "${pid}" 2>/dev/null && ok "已停止 ${name} (pid ${pid})"
    else
      info "${name} 早已退出"
    fi
  done < "${PIDFILE}"
  rm -f "${PIDFILE}"
}

cmd_status() {
  if [ ! -f "${PIDFILE}" ]; then info "没有在跑的演示"; return 0; fi
  while IFS=: read -r name pid; do
    if kill -0 "${pid}" 2>/dev/null; then ok "${name} 存活 (pid ${pid})"
    else warn "${name} 已退出 (pid ${pid})"; fi
  done < "${PIDFILE}"
  echo
  info "根 API：curl -s http://${ROOT_API}/v1/tree"
}

case "${1:-}" in
  start)  cmd_start ;;
  stop)   cmd_stop ;;
  status) cmd_status ;;
  logs)   cat "${LOGS}/${2:?用法: ./demo.sh logs <root|leaf1|relay|leaf2|console>}.log" ;;
  *) cat <<EOF
用法: ./demo.sh {start|stop|status|logs <name>}

  start   起树（根 + 直接叶子 + 中继 + 中继下的叶子）+ 起控制台
  stop    全部停掉
  status  看各节点活着没
  logs    看某个节点的日志（root | leaf1 | relay | leaf2 | console）

环境变量：
  TREECMD_REPO   仓库路径（默认 ${REPO}）
  CONSOLE_PORT   控制台端口（默认 ${CONSOLE_PORT}）
EOF
  ;;
esac
