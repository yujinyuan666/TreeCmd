#!/usr/bin/env bash
#
# selfupdate.sh —— 验证"可执行文件一致性：连上即比对、不一致就自同步并原地重启"。
#
#   ./selfupdate.sh prepare    预生成 v1 / v2 两个"内容不同"的可执行文件（编译吃内存，单独跑更稳）
#   ./selfupdate.sh all        完整验证（见下）
#   ./selfupdate.sh readonly   只跑负向用例
#   ./selfupdate.sh stop       收尾
#
# 验证形态（为什么这样设计）：
#   · 根**一直跑 v2**；三个子节点**各自以 v1 启动**（每个节点一份独立的可执行文件副本）；
#   · 于是"不一致"这件事在它们注册的那一刻自然成立 —— 不需要人为重启任何进程来制造版本差，
#     也就不依赖任何"替换正在运行的文件"的动作（见文末注记）。
#   · 断言四件事：① 子节点确实向父申请了镜像；② 校验通过后**原地重启**（PID 必须不变）；
#     ③ 磁盘上它自己那份文件真的变成了 v2 的内容；④ 整棵树收敛（root 视角 lagging_children=0）。
#   · 再补一个"一致时不动"的基线，与一个"暂存目录只读就 fail-safe"的负向用例。
#
set -euo pipefail
export LC_ALL=${LC_ALL:-en_US.UTF-8} 2>/dev/null || true

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
DEMO="${HERE}/demo"
LOGS="${HERE}/logs"
WORK="${HERE}/.selfupdate"          # 本脚本自己的工作区（节点目录 + 各自的二进制）
PIDFILE="${WORK}/nodes.pids"

ROOT_ID="0198f0c0-0000-7000-8000-0000de000001"
ROOT_API="127.0.0.1:18493"
ROOT_LISTEN="127.0.0.1:19493"
RELAY_LISTEN="127.0.0.1:19494"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

short_hash() { shasum -a 256 "$1" | cut -c1-12; }

# build_variant <版本标记> <输出路径>：只改 buildinfo.Version 注入值 —— 字节变了哈希就变了。
# 已存在时复用（prepare 用 REBUILD=1 强制重造）。
build_variant() {
  [ -x "$2" ] && [ -z "${REBUILD:-}" ] && return 0
  ( cd "${REPO}" && go build -ldflags "-X treecmd/internal/buildinfo.Version=$1" -o "$2" ./cmd/node )
}

pid_of() { [ -f "${PIDFILE}" ] || return 1; awk -F: -v n="$1" '$1==n{print $2}' "${PIDFILE}"; }

# tree_field <python 表达式>：从根的 /v1/tree 里取字段
tree_field() {
  curl -s --max-time 5 "http://${ROOT_API}/v1/tree" \
    | /usr/bin/python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null
}

# node_self_hash <日志>：节点启动时打的"本节点可执行文件 hash=… bytes=… version=…"里的哈希。
# 取最后一行 = 最近一次启动（原地重启后新进程会再打一行）。
node_self_hash() {
  grep -o 'hash=[0-9a-f]\{12\} bytes=[0-9]* version=[^ ]*' "$1" 2>/dev/null \
    | tail -1 | cut -d' ' -f1 | cut -d= -f2
}

# wait_child_converged <名字> <期望哈希> <超时秒>：等某个子节点"重启后跑上目标哈希"
wait_child_converged() {
  local name="$1" want="$2" t="${3:-60}" i
  for i in $(seq 1 $((t * 2))); do
    if [ "$(node_self_hash "${LOGS}/${name}.log")" = "${want}" ] && kill -0 "$(pid_of "${name}" || echo 0)" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

cmd_prepare() {
  step "预生成两个变体（v1 / v2）"
  REBUILD=1 build_variant v1 "${BIN}.v1"
  REBUILD=1 build_variant v2 "${BIN}.v2"
  ok "v1 = $(short_hash "${BIN}.v1")（$(stat -f%z "${BIN}.v1") 字节）"
  ok "v2 = $(short_hash "${BIN}.v2")（$(stat -f%z "${BIN}.v2") 字节）"
}

# ---------- 起树 ----------

# start_bg <名字> <可执行文件> <配置目录>：在配置目录里以该二进制启动，pid 记进 PIDFILE。
#
# 用 `( cd dir && exec nohup ... ) &`：exec 让**子 shell 自己变成那个进程**，
# 所以 $! 就是节点的真实 pid（不带 exec 的话得到的是"跑完就退出的子 shell"的 pid，
# 后面所有 kill -0 / PID 比对都会失真）。
start_bg() {
  local name="$1" exe="$2" dir="$3"
  mkdir -p "${LOGS}"
  ( cd "${dir}" && exec nohup "${exe}" -log-level debug -config node.yaml >> "${LOGS}/${name}.log" 2>&1 ) &
  local p=$!
  echo "${name}:${p}" >> "${PIDFILE}"
  sleep 0.3
}

prepare_child_dir() { # $1=目录 $2=是否要 CA 密钥 $3=父的 host:port $4=父 ID $5=名字 $6=备注 [$7=listen] [$8=额外的 selfupdate YAML]
  local dir="$1" with_ca="$2" parent="$3" pid="$4" name="$5" remark="$6" listen="${7:-}" extra="${8:-}"
  rm -rf "${dir}"; mkdir -p "${dir}/trust"
  if [ "${with_ca}" = "yes" ]; then "${BIN}.v1" -genkey -keydir "${dir}/keys" -with-ca >/dev/null
  else "${BIN}.v1" -genkey -keydir "${dir}/keys" >/dev/null; fi
  cp "${DEMO}/root/certs/node.crt.ca" "${dir}/trust/root-ca.crt"
  cp "${DEMO}/root/enroll.token" "${dir}/enroll.token"; chmod 600 "${dir}/enroll.token"
  {
    echo "node:"
    echo "  name: ${name}"
    echo "  remark: \"${remark}\""
    [ -n "${listen}" ] && echo "  listen: ${listen}"
    echo "parents:"
    echo "  - id: ${pid}"
    echo "    addr: ${parent}"
    echo "security:"
    echo "  ca_cert_paths: [trust]"
    echo "  enrollment: { enabled: true, token_path: enroll.token }"
    [ -n "${listen}" ] && echo "  ca_key_path: keys/ca"
    [ -n "${extra}" ] && printf '%s\n' "${extra}"
  } > "${dir}/node.yaml"
  chmod 600 "${dir}/node.yaml"
  return 0   # 上面两条 `[ -n ] && ...` 在留空时返回 1，别让它把 set -e 引爆
}

start_root() {
  mkdir -p "${DEMO}/root"
  cat > "${DEMO}/root/node.yaml" <<EOF
node:
  name: test-root
  remark: "自同步验证的根"
  listen: ${ROOT_LISTEN}
security:
  identity_key_path: keys/id_ed25519
  identity_pubkey_path: keys/id_ed25519.pub
  identity_cert_path: certs/node.crt
  ca_cert_path: certs/node.crt.ca
  ca_key_path: keys/ca
  ca_cert_paths: [certs/node.crt.ca]
  enrollment: { enabled: true, token_path: enroll.token }
api:
  http_addr: ${ROOT_API}
data_dir: .
EOF
  chmod 600 "${DEMO}/root/node.yaml"
  : > "${LOGS}/root.log"
  start_bg root "${BIN}.v2" "${DEMO}/root"
  sleep 2
  curl -s --max-time 3 "http://${ROOT_API}/v1/healthz" >/dev/null \
    || die "根没起来（看 ${LOGS}/root.log）"
  ok "根已启动（跑 v2 = $(node_self_hash "${LOGS}/root.log")）"
}

# ---------- 主验证 ----------

cmd_all() {
  [ -x "${BIN}.v1" ] && [ -x "${BIN}.v2" ] || die "缺变体，先跑 ./selfupdate.sh prepare"
  local h1 h2; h1="$(short_hash "${BIN}.v1")"; h2="$(short_hash "${BIN}.v2")"
  [ "${h1}" != "${h2}" ] || die "两个变体哈希相同，测试无效"

  step "① 起根（v2）：${h2}"
  rm -rf "${WORK}"; mkdir -p "${WORK}/bin" "${LOGS}"
  : > "${PIDFILE}"
  "${HERE}/demo.sh" stop >/dev/null 2>&1 || true   # 端口先让出来
  rm -f "${DEMO}/.demo.pids" 2>/dev/null || true
  # 日志必须清空：脚本靠"日志里最后一行的哈希 / 有没有申请镜像"做断言，
  # 上一轮的遗留行会把断言骗过去（踩过：取到了上一轮中继的 NodeID）。
  for f in root leaf1 relay leaf2 leaf-ok leaf-ro; do : > "${LOGS}/${f}.log"; done
  if [ ! -f "${DEMO}/root/certs/node.crt" ]; then
    info "根的自签材料还不存在 → 用 scripts/init_root.sh 现造一份"
    "${REPO}/scripts/init_root.sh" "${DEMO}/root" "${ROOT_ID}" >/dev/null || die "init_root.sh 失败"
  fi
  start_root

  step "② 三个子节点各自以 v1（${h1}）启动 —— 连上就会发现自己和父不一致"
  local bindir="${WORK}/bin"
  cp "${BIN}.v1" "${bindir}/leaf1"; chmod +x "${bindir}/leaf1"
  cp "${BIN}.v1" "${bindir}/relay"; chmod +x "${bindir}/relay"
  prepare_child_dir "${WORK}/leaf1" no  "${ROOT_LISTEN}"  "${ROOT_ID}" "t-leaf-alpha" "根的直接子" ""
  prepare_child_dir "${WORK}/relay" yes "${ROOT_LISTEN}"  "${ROOT_ID}" "t-relay-mid"  "中间层，有下级" "${RELAY_LISTEN}"
  start_bg leaf1 "${bindir}/leaf1" "${WORK}/leaf1"
  start_bg relay "${bindir}/relay" "${WORK}/relay"

  step "③ 断言 leaf1 / relay：申请 → 校验 → 原地重启 → 跑上 v2"
  wait_child_converged leaf1 "${h2}" 60 || die "leaf1 没收敛（看 ${LOGS}/leaf1.log）"
  ok "leaf1 已收敛到 v2"
  wait_child_converged relay "${h2}" 60 || die "relay 没收敛（看 ${LOGS}/relay.log）"
  ok "relay 已收敛到 v2"

  for n in leaf1 relay; do
    local log="${LOGS}/${n}.log"
    grep -q '已向父申请它的可执行文件' "${log}" || die "${n} 没有向父申请镜像"
    grep -q '父的可执行文件已收齐并校验通过'  "${log}" || die "${n} 没有看到校验通过"
    grep -q '准备原地重启'             "${log}" || die "${n} 没有走原地重启"
    local disk; disk="$(short_hash "${bindir}/${n}")"
    [ "${disk}" = "${h2}" ] \
      && ok "${n}：申请 → 校验通过 → 原地重启，磁盘上那份文件现在是 v2（${disk}）" \
      || die "${n} 磁盘上的文件不是 v2（${disk}）"
  done

  step "④ 断言中继往下游提供：leaf2 挂在中继下面，同样以 v1 启动"
  # 中继的 NodeID：优先读它自己的 state.dat（权威、不受日志内容影响），
  # 读不到再从日志里取"本节点自己那条"（第一次出现的 node_id=）
  local relay_id
  relay_id="$(grep -o '"id":[[:space:]]*"[0-9a-f-]\{36\}"' "${WORK}/relay/state.dat" 2>/dev/null \
    | head -1 | sed 's/.*"\([0-9a-f-]\{36\}\)"/\1/' || true)"
  if [ -z "${relay_id}" ]; then
    relay_id="$(grep -o 'node_id=[0-9a-f-]\{36\}' "${LOGS}/relay.log" | head -1 | cut -d= -f2 || true)"
  fi
  [ -n "${relay_id}" ] || die "读不到中继的 NodeID（看 ${WORK}/relay/state.dat 与 ${LOGS}/relay.log）"
  info "中继 NodeID = ${relay_id}"
  cp "${BIN}.v1" "${bindir}/leaf2"; chmod +x "${bindir}/leaf2"
  prepare_child_dir "${WORK}/leaf2" no "${RELAY_LISTEN}" "${relay_id}" "t-leaf-beta" "挂在中继下面" ""
  start_bg leaf2 "${bindir}/leaf2" "${WORK}/leaf2"
  wait_child_converged leaf2 "${h2}" 60 || die "leaf2 没收敛（看 ${LOGS}/leaf2.log）"
  grep -q '已向父申请它的可执行文件' "${LOGS}/leaf2.log" || die "leaf2 没有向中继申请镜像"
  [ "$(short_hash "${bindir}/leaf2")" = "${h2}" ] && ok "leaf2 从中继拿到了 v2（中继确实会向下游提供）" \
    || die "leaf2 的文件不是 v2"

  step "⑤ 断言：重启是"原地 exec"，不是"退出等拉起"（PID 必须不变）"
  for n in leaf1 relay leaf2; do
    local p; p="$(pid_of "${n}")"
    if kill -0 "${p}" 2>/dev/null; then ok "${n} PID 不变且存活（${p}）"; else die "${n} 进程没了（PID ${p}）"; fi
  done

  step "⑥ 基线：一致时什么都不做（子节点也用 v2 冷启动 → 不得出现任何重启）"
  local base="${WORK}/baseline"; rm -rf "${base}"; mkdir -p "${base}/bin"
  cp "${BIN}.v2" "${base}/bin/leaf-ok"; chmod +x "${base}/bin/leaf-ok"
  prepare_child_dir "${base}/leaf-ok" no "${ROOT_LISTEN}" "${ROOT_ID}" "t-leaf-ok" "同版本基线" ""
  start_bg leaf-ok "${base}/bin/leaf-ok" "${base}/leaf-ok"
  sleep 6
  grep -q '已向父申请它的可执行文件' "${LOGS}/leaf-ok.log" && die "同版本也去申请镜像了（不该发生）" \
    || ok "同版本节点没有任何同步动作（只注册，不拉取）"
  [ "$(short_hash "${base}/bin/leaf-ok")" = "${h2}" ] && ok "它的文件也没被动过"

  step "⑦ 收敛视图：根 /v1/tree 与 /metrics"
  tree_field 'json.dumps({"build_hash":d["build_hash"],"build_version":d["build_version"],"lagging_children":d["lagging_children"],"selfupdate_enforced":d["selfupdate_enforced"],"children":[{"name":c["node_name"],"build_hash":c["build_hash"],"mismatch":c["build_mismatch"]} for c in d["children"]]},ensure_ascii=False)'
  curl -s --max-time 5 "http://${ROOT_API}/metrics" \
    | grep -E '^(selfupdate_total|selfupdate_serve_total|selfupdate_lagging_children|binary_info)' | head -8 || true
  [ "$(tree_field 'd["lagging_children"]')" = "0" ] && ok "lagging_children=0（全树收敛）" || die "还有节点没跟上"

  step "⑧ 负向用例：暂存目录只读 → fail-safe（继续服务、不重启循环）"
  readonly_case

  step "完成"
  info "证据都在 ${LOGS}/ 下（每个节点一份日志），${WORK}/ 下是各节点目录与各自的二进制"
}

# readonly_case：叶子以 v1 启动、暂存目录只读 → 拉取必然写不进去 → 必须"继续服务"
readonly_case() {
  mkdir -p "${WORK}/bin" "${LOGS}"
  [ -f "${PIDFILE}" ] || : > "${PIDFILE}"
  [ -x "${BIN}.v1" ] || die "缺 v1 变体，先跑 ./selfupdate.sh prepare"
  local rook; rook="$(mktemp -d)"; chmod 0555 "${rook}"
  local dir="${WORK}/leaf-ro"; rm -rf "${dir}"; mkdir -p "${dir}"
  cp "${BIN}.v1" "${WORK}/bin/leaf-ro"; chmod +x "${WORK}/bin/leaf-ro"
  prepare_child_dir "${dir}" no "${ROOT_LISTEN}" "${ROOT_ID}" "t-leaf-ro" "暂存目录只读" "" \
"selfupdate:
  enabled: true
  on_mismatch: sync
  dir: ${rook}"
  start_bg leaf-ro "${WORK}/bin/leaf-ro" "${dir}"
  sleep 12
  local p; p="$(pid_of leaf-ro)"
  kill -0 "${p}" 2>/dev/null || die "leaf-ro 死了（预期是继续服务）"
  ok "进程仍存活（pid ${p}）"
  grep -q '拉取父的可执行文件失败' "${LOGS}/leaf-ro.log" \
    && ok "日志里有"拉取失败 → 继续用当前镜像服务"" || die "没有预期的失败降级（看 ${LOGS}/leaf-ro.log）"
  [ "$(short_hash "${WORK}/bin/leaf-ro")" = "$(short_hash "${BIN}.v1")" ] \
    && ok "它自己的文件没被改动（仍是 v1）"
  grep -q '"target_hash"' "${dir}/state.dat" \
    && ok "state.dat 记下了这次尝试（防重启循环靠它跨 exec 存活）" || warn "state.dat 里没看到 target_hash"
  grep -o '拉取父的可执行文件失败.*' "${LOGS}/leaf-ro.log" | tail -1 || true
  chmod 0755 "${rook}" 2>/dev/null || true; rm -rf "${rook}"
}

cmd_stop() {
  if [ -f "${PIDFILE}" ]; then
    while IFS=: read -r name pid; do
      [ -n "${pid}" ] && kill -TERM "${pid}" 2>/dev/null && printf '    已停止 %s (%s)\n' "${name}" "${pid}"
    done < "${PIDFILE}"
  fi
  rm -f "${PIDFILE}" "${WORK}"/*.pid 2>/dev/null || true
  "${HERE}/demo.sh" stop >/dev/null 2>&1 || true
  ok "已停掉验证用的节点"
}

case "${1:-all}" in
  prepare)  cmd_prepare ;;
  all)      trap 'cmd_stop >/dev/null 2>&1 || true' EXIT; cmd_all ;;
  readonly) readonly_case ;;
  stop)     cmd_stop ;;
  *) cat <<EOF
用法: ./selfupdate.sh [prepare|all|readonly|stop]

  prepare   只预生成 v1 / v2 两个变体（编译吃内存，单独跑一遍更稳）
  all       完整验证：根跑 v2、子节点各自以 v1 启动 → 断言申请/校验/原地重启/PID 不变/收敛
  readonly  只跑负向用例（暂存目录只读 → fail-safe）
  stop      收尾

注：本脚本**不需要**"替换正在运行的可执行文件"这个动作。原因见 build.go 的 commit()：
替换必须走"写暂存文件 + rename"，而 macOS 上"原地覆盖某个可执行文件之后立刻 exec"会被
内核直接判死（Killed: 9、日志一行都没有）—— 这正是程序自己用 rename 的原因。
EOF
     ;;
esac
