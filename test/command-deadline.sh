#!/usr/bin/env bash
#
# command-deadline.sh —— 指令"收尾"语义的回归（残留子节点 / 死线 / 重试预算用尽）
#
# 盯三条规则，都属于"注释或文档承诺了、但实现漏了"那一类：
#
#   ① **收尾时必须点名「始终没有上报的子」**，并给出 `/v1/forget` 的指引。否则症状是
#      "指令莫名其妙 TIMEOUT / FAILED，可别人的结果明明都是好的"，光看状态毫无线索。
#      这不是锦上添花：残留子节点会让**之后每条指令**都白等到期限，而运维此前只能看到
#      一个没有上下文的终态。
#   ② **重试预算用尽 ⇒ 由父侧判定该子失败**（`command.max_retry_node_count` 的承诺，
#      见 examples/node.yaml："超了由父直接判定失败"）。在此之前 `ErrRetryExhausted`
#      **全仓库没人接**：运维把重派次数用光之后，那个子仍会挂在"等待中"，指令只能干等到
#      deadline —— 运维唯一能表达的手段被堵死了。消费侧（`waitChildren` 的 partition →
#      adjudicated）其实早就建好了，缺的只是生产者。
#   ③ **死线仍然有效**：不能因为上面两条就把死线弄成摆设 —— 真有子不回来时必须按时 TIMEOUT。
#
# ── 用例怎么构造（关键，也是已经踩过的坑）────────────────────────────────────
#
# **不能用「杀掉一个子节点」来构造**。第一版脚本就是这么写的，结果拿到 FAILED 而不是 TIMEOUT。
# 实测原因：被杀的子确实留在注册表里，但指令**不会因此卡住** —— 另一条分支先把它带走了
# （那次的结果 JSON 里 `failed[]` 指的是中继，整条指令 200ms 内就按失败策略收敛了）。
#
# 真正会"卡到期限"的形态只有一种：**注册表里有、但本进程从未连上过的残留子节点**。
# 它没有断线事件可触发，所以父给它建的 Assignment 会一直挂在"等待中"。构造办法（两阶段）：
#
#   阶段一 `demo.sh start` 起一次完整树 —— 让根的 `state.dat` 记下两个直接子的身份，然后全停；
#   阶段二 **只起 根 + 中继 + 中继下的叶子**，故意不启动那个直接叶子。
#          这些目录里的 `keys/` 与 `certs/` 都还在，所以它们的 NodeID 与阶段一**完全一致**；
#          而 leaf1 就成了"根知道它、它却永远不会出现"的残留节点 —— 正是线上那种
#          "重建过密钥 / 换过机器，旧 NodeID 留在 known_children 里"的情形。
#
# 用法：
#   ./command-deadline.sh          跑全部
#   ./command-deadline.sh stop     只停树
#
# 注意：**不使用 rm**（清场一律 mv）—— 本仓库的测试环境踩过"批量删除被沙箱拦下、脚本半途而废"的坑。

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# API 没有免签来源（含本机）：所有请求都要带 user token —— 见 lib/apitoken.sh
. "${HERE}/lib/apitoken.sh"   # 对外 API 一律要 user token：装好后所有 curl 自动带上
DEMO="${HERE}/demo"
API_TOKEN_DIR="${DEMO}/root"      # token 签在哪个节点目录下（下面所有 curl 自动带上）
LOGS="${HERE}/logs"
PIDFILE="${HERE}/.demo.pids"
ROOT_API="127.0.0.1:18493"
BIN="${HERE}/../bin/treecmd-node"
PY="${PYTHON:-/usr/bin/python3}"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; stop_tree; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

stop_tree() {
  "${HERE}/demo.sh" stop >/dev/null 2>&1 || true
  pkill -f 'treecmd-node' >/dev/null 2>&1 || true
  pkill -f 'test/serve.py' >/dev/null 2>&1 || true
  [ -f "${PIDFILE}" ] && mv "${PIDFILE}" "${TMPDIR:-/tmp}/treecmd-deadline-pids-$$" 2>/dev/null
  return 0
}

archive_state() {
  local trash="${TMPDIR:-/tmp}/treecmd-deadline-trash-$(date +%s)-$$"
  mkdir -p "${trash}"
  for d in "${DEMO}" "${LOGS}" "${PIDFILE}"; do
    [ -e "${d}" ] && mv "${d}" "${trash}/" 2>/dev/null
  done
  info "上一轮的状态已挪到 ${trash}（没有删除，方便回查）"
}

# 等根上"在线直接子"的数量达到 $1
wait_online() {
  local want="$1" t="${2:-30}" i n
  for i in $(seq 1 $((t * 2))); do
    n="$(curl -s --max-time 3 "http://${ROOT_API}/v1/tree" 2>/dev/null | "${PY}" -c '
import json,sys
try:
    print(sum(1 for c in json.load(sys.stdin).get("children", []) if c.get("online")))
except Exception:
    print(0)' 2>/dev/null)"
    [ "${n:-0}" -ge "${want}" ] && return 0
    sleep 0.5
  done
  return 1
}

# 手工启动一个**已存在**的节点目录（不重建材料 ⇒ NodeID 与上一轮一致）。
# 不用 demo.sh start 的原因：那个会对子节点目录 rm -rf + 重新 genkey，NodeID 就变了。
start_existing() { # $1=名字 $2=目录
  nohup "${BIN}" -config "$2/node.yaml" > "${LOGS}/$1.log" 2>&1 &
  echo "$1:$!" >> "${PIDFILE}"
}

# 提交一条指令，回显 command_id（写进全局 $CMD_ID）
submit() {
  local resp
  resp="$(curl -s --max-time 5 -XPOST "http://${ROOT_API}/v1/commands" -d "$1" || true)"
  CMD_ID="$(printf '%s' "${resp}" | "${PY}" -c 'import json,sys;print(json.load(sys.stdin).get("command_id",""))' 2>/dev/null || true)"
  [ -n "${CMD_ID}" ] || die "提交失败：${resp}"
}

# 读一次指令状态（结果还没回传时打印 NOT_FOUND —— 那是"还在跑"的正常中间态）
cmd_status() {
  curl -s --max-time 5 "http://${ROOT_API}/v1/commands/$1" \
    | "${PY}" -c 'import json,sys;d=json.load(sys.stdin);print(d.get("status") or d.get("error") or "UNKNOWN")' 2>/dev/null || echo UNKNOWN
}

# 轮询到终态并打印它；超时则打印当前状态
wait_status() {
  local id="$1" budget="${2:-30}" i st=""
  for i in $(seq 1 "${budget}"); do
    st="$(cmd_status "${id}")"
    case "${st}" in
      COMMAND_STATUS_COMPLETED|COMMAND_STATUS_FAILED|COMMAND_STATUS_TIMEOUT|COMMAND_STATUS_CANCELLED)
        printf '%s' "${st}"; return 0 ;;
    esac
    sleep 1
  done
  printf '%s' "${st}"
}

case "${1:-all}" in
  stop) stop_tree; ok "已停"; exit 0 ;;
  all)  ;;
  *)    die "用法：$0 [all|stop]" ;;
esac

[ -x "${BIN}" ] || die "找不到 ${BIN}；先在仓库里 go build -o bin/treecmd-node ./cmd/node"

step "〇 阶段一：起一次完整树，让根的 state.dat 记下两个直接子的身份，然后全停"
stop_tree
archive_state
"${HERE}/demo.sh" start >/dev/null 2>&1 || die "demo.sh start 失败（看 ${LOGS}/*.log）"
wait_online 2 25 || die "等不到 2 个直接子 online"
ok "完整树已就绪（4 个节点各自拿到证书）"
# leaf1 的身份要从它自己的日志里读 —— 阶段二不会再启动它，所以不会有新日志
LEAF1_ID="$(sed -n 's/.*node_id=\([0-9a-f-]\{36\}\).*/\1/p' "${LOGS}/leaf1.log" | head -1)"
RELAY_ID="$(sed -n 's/.*node_id=\([0-9a-f-]\{36\}\).*/\1/p' "${LOGS}/relay.log" | head -1)"
[ -n "${LEAF1_ID}" ] && [ -n "${RELAY_ID}" ] || die "读不到子节点的 node_id（看 ${LOGS}/leaf1.log 与 relay.log）"
LEAF1_SHORT="${LEAF1_ID:0:8}"
info "leaf1 = ${LEAF1_ID}（阶段二将**不启动**它），中继 = ${RELAY_ID}"
stop_tree

step "① 阶段二：只起 根 + 中继 + 中继下的叶子 —— **故意不启动 leaf1**"
mkdir -p "${LOGS}"
: > "${PIDFILE}"
start_existing root "${DEMO}/root"
sleep 2
start_existing relay "${DEMO}/relay"
sleep 2
start_existing leaf2 "${DEMO}/leaf2"
wait_online 1 30 || die "中继没连上来（看 ${LOGS}/relay.log）"
ok "根与中继已就绪；leaf1 **从未在本进程出现过**"

# 还要等中继**自己的**子（leaf2）注册完再往下走。踩过：不等它就会出事 ——
# 指令提交时 leaf2 才刚注册 0.3s，中继等不到它的上报，**中继自己那份逐跳递减的死线**先到，
# 于是中继按超时收尾并上报 SELF_FAILED，根随即按失败策略收敛成 FAILED，
# 而我们要验的"残留子节点把根拖到死线"根本轮不上（实测拿到 FAILED 而不是 TIMEOUT）。
for i in $(seq 1 60); do
  grep -q 'child registered' "${LOGS}/relay.log" && break
  sleep 0.5
done
grep -q 'child registered' "${LOGS}/relay.log" \
  && ok "中继下的叶子也注册完了（整棵健康分支已热起来）" \
  || die "中继下的叶子一直没注册（看 ${LOGS}/relay.log）"

# 关键前提：leaf1 必须仍在根的注册表里（只是 offline），否则后面的构造不成立
TREEJSON="$(curl -s --max-time 3 "http://${ROOT_API}/v1/tree" || true)"
printf '%s' "${TREEJSON}" | grep -q "${LEAF1_ID}" \
  && ok "确认 leaf1 仍在注册表里（/v1/tree 里可见，只是 offline）—— 这就是残留子节点" \
  || die "leaf1 不在 /v1/tree 里，构造前提不成立：${TREEJSON}"
printf '%s' "${TREEJSON}" | grep -q "${RELAY_ID}" \
  && ok "确认中继在线（它会在下面正常上报）" \
  || die "中继不在 /v1/tree 里：${TREEJSON}"

step "② 负例（死线仍然有效）：echo + 8s 死线 ⇒ 必须 TIMEOUT，且收尾日志点名 leaf1"
# 死线要给健康分支留出余量（8s）：中继那一层要等它自己的子，而**每一跳的死线都是递减的**
# （留下上报余量）。给太紧的话中继会先到点、按超时上报，根就跟着按失败策略收敛，
# 根本轮不到"根自己的死线"—— 那样测的就不是这条规则了。
submit '{"type":"echo","payload":"aGVsbG8=","aggregate":"TREE","max_duration":"8s"}'
info "指令 ${CMD_ID} 已提交，最多等 30s…"
ST="$(wait_status "${CMD_ID}" 30)"
[ "${ST}" = "COMMAND_STATUS_TIMEOUT" ] \
  && ok "按时判了 TIMEOUT（${ST}）—— 死线没有被顺手改坏" \
  || die "期望 TIMEOUT，实际 ${ST}"

grep -q '收尾时有子节点始终没有上报' "${LOGS}/root.log" \
  && ok "收尾日志点名了「始终没有上报的子」" \
  || die "收尾日志里没有那句话（看 ${LOGS}/root.log）—— 运维就只剩「莫名 TIMEOUT」可看了"
grep -q 'unreported=1' "${LOGS}/root.log" \
  && ok "而且数字对得上（unreported=1）" \
  || warn "日志里的 unreported 计数不是 1，去看 ${LOGS}/root.log"
grep -q 'GET /v1/forget?node=' "${LOGS}/root.log" \
  && ok "并且给了清理指引（GET /v1/forget?node=… 预览）" \
  || die "日志里没有 /v1/forget 的指引"
# 点名的必须是 leaf1。shortID 只取前 8 位，而 NodeID 是 UUIDv7（时间有序）——
# 同一毫秒启动的两个子前缀会一样，所以先确认这次没撞前缀，再做断言。
if [ "${LEAF1_SHORT}" = "${RELAY_ID:0:8}" ]; then
  warn "leaf1 与中继的 shortID 前缀相同（${LEAF1_SHORT}）—— 跳过「点名的是谁」这条断言"
else
  grep -q "${LEAF1_SHORT}" "${LOGS}/root.log" \
    && ok "点到的正是 leaf1（${LEAF1_SHORT}）" \
    || die "日志里没有出现 leaf1 的 shortID ${LEAF1_SHORT}"
fi

step "③ 正例（重试预算用尽 ⇒ 父侧判失败）：echo + 20s 死线，把 leaf1 的 retry 打到用尽"
submit '{"type":"echo","payload":"aGVsbG8=","aggregate":"TREE","max_duration":"20s"}'
info "指令 ${CMD_ID} 已提交"
# 先等它进入 RUNNING（RetryNode 要求指令处于 RUNNING / PARTIAL）
for i in $(seq 1 20); do
  [ "$(cmd_status "${CMD_ID}")" = "COMMAND_STATUS_RUNNING" ] && break
  sleep 0.5
done
info "状态 = $(cmd_status "${CMD_ID}")，开始重试…"

RETRY_BUDGET=3   # = command.max_retry_node_count 的默认值
LAST_BODY=""
for i in $(seq 1 $((RETRY_BUDGET + 1))); do
  LAST_BODY="$(curl -s --max-time 5 -XPOST \
    "http://${ROOT_API}/v1/commands/${CMD_ID}/retry?node=${LEAF1_ID}" || true)"
  info "第 ${i} 次 retry → ${LAST_BODY}"
done
printf '%s' "${LAST_BODY}" | grep -q '"judged":"FAILED"' \
  && ok "第 $((RETRY_BUDGET + 1)) 次重试被识别为「预算用尽」，并明确回报「该子已被父判 FAILED」" \
  || die "最后一次 retry 没有回报 judged=FAILED：${LAST_BODY}"
grep -q '重试次数用尽：父侧判定该子失败' "${LOGS}/root.log" \
  && ok "日志确认：父侧真的把它判失败了" \
  || die "日志里没有「重试次数用尽」那行（看 ${LOGS}/root.log）"

info "等它收敛（死线是 20s；修复到位的话应当几秒内就收尾）…"
ST="$(wait_status "${CMD_ID}" 10)"
case "${ST}" in
  COMMAND_STATUS_FAILED)
    ok "指令收敛为 FAILED（不是 TIMEOUT，也不是一直 RUNNING）—— 那个子不再阻塞收敛" ;;
  COMMAND_STATUS_RUNNING)
    die "10 秒后还在 RUNNING：重试用尽没有让父判该子失败，指令只能干等到 20s 死线" ;;
  *)
    die "期望 FAILED，实际 ${ST}" ;;
esac

step "④ 收尾"
stop_tree
ok "全部断言通过"
info "证据：${LOGS}/root.log 里的「收尾时有子节点始终没有上报」与「重试次数用尽：父侧判定该子失败」两行"
