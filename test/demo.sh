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
# 端口：根 listen 19493 / api 18493；中继 listen 19494 / api 18494；叶子不需要 listen。
#
# 为什么中继也开一个 api：**任意节点都能对外提供 API**（判定只看 `api.http_addr` 是否非空，
# 不看角色）。于是"从任意节点发起指令"是可测的 —— 发起者就是这条指令的 origin：
# 结果只落它自己 + 它名下的子树（`OriginId == 本节点` ⇒ sink=SELF，**不上报给它的父**），
# 祖先对这条指令一无所知。test/from-any-node.sh 就靠这个端口验这件事。
#
# 环境变量：
#   TREECMD_REPO        仓库路径（默认由脚本位置推导）
#   CONSOLE_PORT        控制台端口（默认 8899）
#   DEMO_PER_NODE_BIN=1 给每个节点复制一份自己的可执行文件（默认共用 bin/treecmd-node）。
#                       需要它是因为脚本目录 script/ 相对可执行文件位置推导：共用一份二进制
#                       会让所有节点共用一个脚本目录，于是"父下发脚本给子"这条链路永远走不到。
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
RELAY_API="127.0.0.1:18494"
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
    # 对外 HTTP API。**任意节点都能开** —— 判定只看 api.http_addr 是否非空，不看角色。
    # 这里按"角色"给两个节点各开一个（不按名字匹配：名字换了就失效，而且 case 不匹配会让
    # 整个函数返回非 0，在 set -e 下是个隐患）：
    #   · 根：控制台连的就是它；
    #   · 有下级的节点（中继）：用来验"从任意节点发起指令"（见文件头说明）。
    if [ -z "${parent}" ]; then
      echo "api:"
      echo "  http_addr: ${ROOT_API}"
    elif [ -n "${listen}" ]; then
      echo "api:"
      echo "  http_addr: ${RELAY_API}"
    fi
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

# run_bin 决定用哪份可执行文件起这个节点，并输出它的路径。
#
# 默认返回仓库里那份共用的 bin/treecmd-node。**DEMO_PER_NODE_BIN=1** 时改成
# "每个节点一份自己的副本"（放在节点目录里）。
#
# 为什么需要这个开关：**脚本目录 script/ 是相对可执行文件位置推导的** ——
# 共用一份二进制就等于所有节点共用一个脚本目录，于是"父把脚本下发给子"这条链路
# 永远走不到（子在自己目录里就已经找到了）。selfupdate.sh 出于同样的理由也做副本。
#
# $1=节点目录；输出要执行的可执行文件路径。
run_bin() {
  local dir="$1"
  if [ "${DEMO_PER_NODE_BIN:-0}" != "1" ]; then printf '%s' "${BIN}"; return 0; fi
  if [ ! -x "${dir}/treecmd-node" ] || ! cmp -s "${BIN}" "${dir}/treecmd-node"; then
    cp -f "${BIN}" "${dir}/treecmd-node" && chmod 755 "${dir}/treecmd-node"
  fi
  printf '%s' "${dir}/treecmd-node"
}

# start_node <名字> <目录> [二进制参数...]
#
# 【日志必须由**父进程**先清空】不能写成 `> "${LOGS}/${name}.log"` 让子进程去截断：
# 重定向是在 fork 出来的子进程里做的，而父进程 `start_node` 一返回，调用方立刻就用
# `grep` 去读那份日志了 —— 两者在竞速。子进程还没轮到调度时（这个二进制 20MB，exec 之前
# 先要把它读进来），文件里还是**上一轮**的内容，于是：
#   · `wait_registered` 会命中上一轮的 `msg=registered`，当场报"成功"，而节点其实还没入网
#     （"假的 ✓"比没有 ✓ 更坏 —— 它会掩盖真正的失败）；
#   · 更要命的是第 ③ 步要从 relay.log 里读中继自己的 NodeID：读到上一轮的，就会把
#     leaf-beta 的 parents[].id 写成**上一轮中继**的 ID。中继 NodeID 是每轮新生成的
#     UUIDv7，于是叶子之后一直以
#     `peer identity "<本轮>" != expected "<上一轮>"` 入网失败 —— 而且 demo/ 与 logs/ 都
#     清干净了也一样，因为污染来自 logs/ 里上一轮留下的**文件内容**，不是目录结构。
#     （在 openEuler aarch64 上实测踩到过。）
# 父进程先 `: >` 清空、子进程 `>>` 追加，这个窗口就不存在了。
start_node() {
  local name="$1" dir="$2"; shift 2
  : > "${LOGS}/${name}.log"
  "$(run_bin "${dir}")" "$@" -config "${dir}/node.yaml" >> "${LOGS}/${name}.log" 2>&1 &
  echo "${name}:$!" >> "${PIDFILE}"
}
start_one()       { start_node "$1" "$2"; }                  # 普通级
start_one_debug() { start_node "$1" "$2" -log-level debug; } # debug 级（控制台里看后台任务用）

# wait_registered <日志文件> <超时秒> <说明> —— 等到了返回 0，超时返回**非零**。
#
# 失败**必须**能被调用方看见：这里出问题时后面的每一步都没有意义（树都不完整），
# 而"报个 warn 然后继续跑"会让真正的失败在下游以完全不相干的样子冒出来（踩过）。
wait_registered() {
  local f="$1" t="${2:-20}" what="${3:-注册}"
  for _ in $(seq 1 $((t * 2))); do
    grep -q 'msg=registered' "$f" 2>/dev/null && { ok "${what}成功"; return 0; }
    sleep 0.5
  done
  warn "${what}超时（${t}s）—— 看 ${f}"
  return 1
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
  # 入网许可必须与根材料**同批**存在：上面走了"复用"分支时它可能已经被删过
  # （它是运行期产物、不入 git，也常被清理脚本带走）。根缺了它就直接起不来
  # （load config failed: security.enrollment.token_path: no such file），
  # 而子节点会因为没有可拷贝的 token 而失败 —— 以前是悄悄起不来，很难查。
  if [ ! -f "${DEMO}/root/enroll.token" ]; then
    openssl rand -hex 24 > "${DEMO}/root/enroll.token"
    chmod 600 "${DEMO}/root/enroll.token"
    ok "补回了缺失的入网许可 enroll.token"
  fi
  write_config "${DEMO}/root" "demo-root" "演示根节点" "${ROOT_LISTEN}" ""
  start_one_debug root "${DEMO}/root"
  sleep 2

  echo "② 直接叶子（验证根的直接子这一层）"
  prepare_child "${DEMO}/leaf1" no
  write_config "${DEMO}/leaf1" "leaf-alpha" "根的直接子" "" "${ROOT_LISTEN}"
  start_one leaf1 "${DEMO}/leaf1"
  wait_registered "${LOGS}/leaf1.log" 20 "leaf-alpha 入网并注册" \
    || die "leaf-alpha 没入网/没注册 —— 树不完整，后面的断言没有意义（看 ${LOGS}/leaf1.log）"

  echo "③ 中继（自带 listen，会向根申请自己的 CA 证书）"
  prepare_child "${DEMO}/relay" yes
  write_config "${DEMO}/relay" "relay-mid" "中间层，有下级" "${RELAY_LISTEN}" "${ROOT_LISTEN}"
  start_one relay "${DEMO}/relay"
  wait_registered "${LOGS}/relay.log" 20 "relay-mid 入网并注册" \
    || die "relay-mid 没入网/没注册 —— 树不完整（看 ${LOGS}/relay.log）"
  # 中继的 node.id 是它自己生成的（UUIDv7），下级要把这个 ID 写进 parents[].id。
  #
  # 【取法】优先问中继自己的 API：`/v1/healthz` 是**唯一免 token 的端点**（存活探针），
  # 回的正是它自己的 node_id —— 这是权威来源，不受任何日志内容影响。日志只做兜底。
  # 曾经这里只从 relay.log 里 grep 第一个 `node_id=`；而那份文件在本轮子进程完成截断
  # 之前还留着上一轮的内容，于是读到了**上一轮中继**的 ID（见 start_node 的注释）。
  RELAY_ID="$(curl -s --noproxy '*' --max-time 3 "http://${RELAY_API}/v1/healthz" 2>/dev/null \
              | sed -n 's/.*"node_id":"\([0-9a-f-]\{36\}\)".*/\1/p')"
  if [ -z "${RELAY_ID}" ]; then
    # 兜底一：日志里**第一个** node_id=（启动第一件事就是打印 node.id 的来源；此时已确认注册过）
    RELAY_ID="$(grep -o 'node_id=[0-9a-f-]\{36\}' "${LOGS}/relay.log" 2>/dev/null | head -1 | cut -d= -f2)"
  fi
  if [ -z "${RELAY_ID}" ]; then
    # 兜底二：从运行期状态文件里读（state.dat 的 self.id）
    RELAY_ID="$(grep -o '"id":"[0-9a-f-]\{36\}"' "${DEMO}/relay/state.dat" 2>/dev/null | head -1 | sed 's/.*"id":"//;s/"//')"
  fi
  [ -n "${RELAY_ID}" ] || die "读不到中继的 node_id（看 http://${RELAY_API}/v1/healthz 与 ${LOGS}/relay.log）"
  ok "中继 NodeID = ${RELAY_ID}"

  echo "④ 中继下的叶子（凑出 3 层，健康扫描才有意义）"
  prepare_child "${DEMO}/leaf2" no
  write_config "${DEMO}/leaf2" "leaf-beta" "挂在中继下面" "" "${RELAY_LISTEN}" "${RELAY_ID}"
  start_one leaf2 "${DEMO}/leaf2"
  wait_registered "${LOGS}/leaf2.log" 20 "leaf-beta 入网并注册" \
    || die "leaf-beta 没入网/没注册（3 层树不完整）—— 看 ${LOGS}/leaf2.log 里的 enroll 失败原因"

  echo "⑤ 控制台"
  # 控制台是"从本机代理到本机 API"的通道，而端点**没有免签来源**（含回环）——
  # 所以先给控制台签一份自己的凭据（用户名 demo-console），让代理转发出示它。
  # 用 -force：demo 会反复 start，已存在就换一份，保证和当前这棵树的 CA 匹配。
  if [ -f "${DEMO}/root/node.yaml" ]; then
    if "${BIN}" -config "${DEMO}/root/node.yaml" -adduser demo-console -force >/dev/null 2>&1; then
      CONSOLE_TOKEN_FILE="${DEMO}/root/user/demo-console"
      ok "已为控制台签发凭据（${CONSOLE_TOKEN_FILE}）"
    else
      warn "为控制台签发凭据失败 —— 页面上的请求会收到 401（可手动 -adduser demo-console）"
      CONSOLE_TOKEN_FILE=""
    fi
  else
    CONSOLE_TOKEN_FILE=""
  fi
  if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${CONSOLE_PORT}/" 2>/dev/null; then
    ok "控制台已在 :${CONSOLE_PORT} 上跑着，不再重复启动"
  else
    # 参数用数组拼（别用 ${VAR:+--token-file "$VAR"} 那种写法：展开里的引号不是引号，
    # 会被当字面量；而且 macOS 自带 bash 3.2 上空数组配 set -u 会报未绑定）。
    CONSOLE_ARGS=(--port "${CONSOLE_PORT}" --target "${ROOT_API}")
    # 用 if 而不是 `[ ... ] && ...`：后者在条件为假时返回非零，会被 set -e 当场引爆。
    if [ -n "${CONSOLE_TOKEN_FILE}" ]; then
      CONSOLE_ARGS+=(--token-file "${CONSOLE_TOKEN_FILE}")
    fi
    nohup /usr/bin/python3 "${HERE}/serve.py" "${CONSOLE_ARGS[@]}" \
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
  local name pid
  while IFS=: read -r name pid; do
    [ -n "${pid}" ] || continue
    if kill -0 "${pid}" 2>/dev/null; then
      if kill -TERM "${pid}" 2>/dev/null; then ok "已停止 ${name} (pid ${pid})"; fi
    else
      info "${name} 早已退出"
    fi
  done < "${PIDFILE}"

  # 【等它们真的退出，再返回】TERM 只是"请求"：进程还要走优雅收尾（断 gRPC、落盘 state.dat）。
  # 不等的话，`demo.sh stop` 一返回，上一轮节点可能还在跑：它仍然占着 19493/19494，
  # 也还握着 logs/*.log 的 fd。紧接着的一轮 `rm -rf demo` + `demo.sh start` 就会和它对撞 ——
  # 表现为端口被占、日志被旧进程写花，而验收脚本报出来的失败全是噪声（根因藏在别处）。
  # 收不住就 KILL 兜底：这里要的是"确定性地把地清干净"，不是"客气地告别"。
  while IFS=: read -r name pid; do
    [ -n "${pid}" ] || continue
    for _ in $(seq 1 60); do kill -0 "${pid}" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "${pid}" 2>/dev/null; then
      warn "${name} 不响应 TERM，已 KILL (pid ${pid})"
      kill -KILL "${pid}" 2>/dev/null || true
      for _ in $(seq 1 20); do kill -0 "${pid}" 2>/dev/null || break; sleep 0.1; done
    fi
  done < "${PIDFILE}"
  rm -f "${PIDFILE}"
  return 0   # 上面几条 `kill -0 ... && ...` 在进程刚消失时可能返回非零，别让 set -e 借此引爆
}

cmd_status() {
  if [ ! -f "${PIDFILE}" ]; then info "没有在跑的演示"; return 0; fi
  while IFS=: read -r name pid; do
    if kill -0 "${pid}" 2>/dev/null; then ok "${name} 存活 (pid ${pid})"
    else warn "${name} 已退出 (pid ${pid})"; fi
  done < "${PIDFILE}"
  echo
  info "根 API：curl -s http://${ROOT_API}/v1/tree"
  info "中继 API：curl -s http://${RELAY_API}/v1/tree —— 从任意节点发起指令时，结果落在那台节点上"
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
  TREECMD_REPO        仓库路径（默认 ${REPO}）
  CONSOLE_PORT        控制台端口（默认 ${CONSOLE_PORT}）
  DEMO_PER_NODE_BIN=1 给每个节点复制一份自己的可执行文件（脚本目录随之各自独立）
EOF
  ;;
esac
