#!/usr/bin/env bash
#
# backpressure.sh —— 下发背压（在途窗口）专项验收
#
# 背景：加这个功能之前，父端下发只有**一个**刹车 —— 字节上限（fetch_response_max_bytes）。
# 没有任何"同时在途条数"的限制，于是一个子可以一次把它名下所有分派全拉走；父端并不知道
# "我已经给了这个子多少还没回终态的东西"。等子用 LocalBusy 说"我忙不过来"时，那批指令
# 早就发出去了 —— LocalBusy 是逐条、事后的，管不住这件事。在途窗口就是补这个缺口。
#
# 验三件事：
#   ① 窗口生效：一次提交一批指令，**任何一个子的在途分派数在任何时刻都不超过窗口**
#   ② 限速不丢任务：这一批最终全部到达终态
#   ③ 对照组：把窗口改成 0（不限）热更进去，同样一批会被**一次拉走**（在途远超窗口）
#      这一步顺带证明新字段走 SIGHUP 热更是通的（command. 段不进 config_hash，不会触发重注册）
#
# 用法：
#   ./backpressure.sh          跑全部
#   ./backpressure.sh stop     只停树（清场）
#
# 环境变量：
#   WINDOW       期望的每子在途窗口（默认 8，与 max_dispatch_inflight_per_child 的默认值一致）
#   COUNT        一次提交多少条（默认 20）
#   SLEEP_MS     每条睡多久（默认 2500）
#   RENEW        拉取/续租周期（默认 2s，**只为了让本脚本跑得快**，见下）
#   TICK         巡检间隔（默认 1s，同上）
#   PYTHON       python3 解释器（默认 /usr/bin/python3）
#
# 关于 RENEW / TICK 这两个加速项：它们跟被测的窗口**毫无关系**，但会把一轮验收拖到好几分钟，
# 所以脚本起树之后热更它们，只为让脚本能在一分钟内跑完。
#   · renew_at（默认 30s）既是子的续租周期、**也是它的拉取周期**（见 upstream.go 的 fetchLoop）。
#     父只在提交那一刻通知一次，之后剩下的分派要靠子的下一次轮询才拿得到 —— 所以"限速"的
#     实际轮次间隔就是这个值。热更成 2s 后，一轮只剩几秒。
#   · tick_interval（默认 22.5s = min(child_stuck_timeout, lease_ttl)/4）决定"跑完之后多久
#     被判定为终态"。
# **它们不会放松断言** —— 拉得越勤、给"超过窗口"的机会越多，断言只会更严。
# 注意 renew_at 有一条硬约束：renew_at × 3 ≤ lease_ttl（90s），2s 远在范围内。
#
# 注意：**本脚本刻意不使用 rm** —— 清场一律 mv 到临时目录。本仓库的测试环境踩过
# "批量删除被沙箱拦下、脚本半途而废"的坑，而验收脚本必须能反复跑、跑完不留垃圾状态。

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
PROBE="${HERE}/backpressure/probe.py"
INJECT="${HERE}/backpressure/inject.py"

WINDOW="${WINDOW:-8}"
COUNT="${COUNT:-20}"
SLEEP_MS="${SLEEP_MS:-2500}"
RENEW="${RENEW:-2s}"
TICK="${TICK:-1s}"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; stop_tree; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ── 清场：把上一次的运行时目录挪走（不删） ────────────────────────────────────
# 之所以不删：一是沙箱对批量删除有配额，二是"挪走"能留下现场，出问题时可以回头翻日志。
# 每次挪到一个带时间戳的目录，所以反复跑也不会互相覆盖。
archive_state() {
  local stamp; stamp="$(date +%s)-$$"
  local trash="${TMPDIR:-/tmp}/treecmd-backpressure-trash-${stamp}"
  mkdir -p "${trash}"
  for d in "${DEMO}" "${LOGS}" "${PIDFILE}"; do
    [ -e "${d}" ] && mv "${d}" "${trash}/" 2>/dev/null
  done
  info "上一轮的状态已挪到 ${trash}（没有删除，方便回查）"
}

stop_tree() {
  "${HERE}/demo.sh" stop >/dev/null 2>&1 || true
  pkill -f 'treecmd-node' >/dev/null 2>&1 || true
  pkill -f 'test/serve.py' >/dev/null 2>&1 || true
  # stop 只在正常路径清 pidfile；残留会让下一次 start 直接拒绝启动
  [ -f "${PIDFILE}" ] && mv "${PIDFILE}" "${TMPDIR:-/tmp}/treecmd-backpressure-pids-$$" 2>/dev/null
  return 0
}

# ── 等树就绪：根 + 2 个直接子在 /v1/tree 里 online ─────────────────────────────
wait_tree() {
  local t="${1:-25}" i
  for i in $(seq 1 $((t * 2))); do
    local n
    n="$(curl -s --max-time 3 "http://${ROOT_API}/v1/tree" 2>/dev/null \
      | "${PY}" -c 'import json,sys
try:
    d=json.load(sys.stdin)
    print(sum(1 for c in d.get("children",[]) if c.get("online")))
except Exception:
    print(0)' 2>/dev/null)"
    [ "${n:-0}" -ge 2 ] && return 0
    sleep 0.5
  done
  return 1
}

# ── 跑一次观测 ────────────────────────────────────────────────────────────────
# $1=标签；结果写进全局 $PROBE_OUT（供调用方断言，不回显 —— 见脚本末尾的说明）
run_probe() {
  local tag="$1"
  # 探针是 python 直接发请求的，**绕过了本文件 source 的那个"自动带 token"的 curl 包装器**，
  # 所以凭据要显式传进去：/v1/commands、/v1/commands/{id}、/metrics 都在访问控制射程内。
  #
  # 这里的 ensure 不是"防止拿不到"，而是**防止拿到一份旧的**：它会把 $API_TOKEN 对齐到
  # `<节点目录>/user/tester` 此刻的内容（见 lib/apitoken.sh）。这一点在本脚本里尤其要紧 ——
  # 阶段③ 上面那行 `WINDOW_NOW="$(window_now)"` 是一次 `$( )` 子壳，子壳里那次 curl 可能刚
  # 现签了一份新 token（token 文件更新了，但赋值回不到本壳）；不对齐就会把**已被替换掉的旧
  # token** 发给探针，换回一个 401，而 401 正是"访问控制生效"的正常表现 —— 假失败会伪装成
  # 正确答案。
  api_token_ensure || die "签不出 API token（看 ${API_TOKEN_DIR}/node.yaml 与 CA 私钥）"
  [ -n "${API_TOKEN}" ] || die "API_TOKEN 为空 —— 探针会吃 401（假失败会伪装成「访问控制生效」）"
  PROBE_OUT="$("${PY}" "${PROBE}" --api "${ROOT_API}" --count "${COUNT}" \
      --sleep-ms "${SLEEP_MS}" --tag "${tag}" --token "${API_TOKEN}" 2>&1)" || {
    echo "${PROBE_OUT}" >&2
    die "探针（${tag}）执行失败"
  }
}

# 从 $PROBE_OUT 里取一个字段（用 python 解析，避免依赖 jq）
probe_field() {
  printf '%s' "${PROBE_OUT}" | "${PY}" -c "
import json,sys
try:
    print(json.load(sys.stdin).get('$1'))
except Exception:
    print('')"
}

# ── 热更某节点的运行参数：写文件（幂等块）→ SIGHUP → 等它真的重读完 ──────────────
# $1 = 节点名（root|leaf1|relay|leaf2），其余是 key=value。
# Reload() 走的是**整份 config.Load 热替换**，不像 ConfigPush 那样受 allowedHotKey 白名单限制；
# 而 command.* 不进 config_hash，所以只要不碰别的段就只会热更、不会触发全量重注册。
hot_apply() {
  local name="$1"; shift
  local dir="${DEMO}/${name}" log="${LOGS}/${name}.log"
  local pid before after i
  pid="$(sed -n "s/^${name}:\([0-9]*\)$/\1/p" "${PIDFILE}" 2>/dev/null | head -1)"
  [ -n "${pid}" ] || die "从 ${PIDFILE} 里取不到 ${name} 的 PID"
  before="$(reload_count "${log}")"
  "${PY}" "${INJECT}" "${dir}/node.yaml" "$@" || die "写入 ${name} 的运行参数失败"
  kill -HUP "${pid}" || die "给 ${name} 发 SIGHUP 失败"
  for i in $(seq 1 40); do
    after="$(reload_count "${log}")"
    [ "${after:-0}" -gt "${before:-0}" ] && return 0
    sleep 0.25
  done
  die "${name} 在 SIGHUP 之后没有记录 config reload（看 ${log}）"
}

# 数一数某个节点日志里出现过几次 config reload。
# 注意 `grep -c` 在"零匹配"时会同时**打印 0 并返回非零退出码** —— 所以这里只能配 `|| true`，
# 绝不能写 `|| echo 0`（那会输出两行 "0"，后面的整数比较会直接报 "integer expression expected"）。
# 参数：$1 = 日志文件路径
reload_count() {
  grep -c 'config reload:' "$1" 2>/dev/null || true
}

# 对所有节点都热更一遍。
# renew_at 是**子侧**参数（每个节点都在等它自己的父），只改根没用 —— 中继也在等根，
# 中继下面的叶子还在等中继。所以四个节点都要改。
hot_apply_all() {
  local n
  for n in root leaf1 relay leaf2; do
    hot_apply "${n}" "$@"
  done
}

# 读一次根上"当前生效的每子窗口"
window_now() {
  curl -s --max-time 3 "http://${ROOT_API}/metrics" | sed -n 's/^dispatch_window_per_child //p'
}

case "${1:-all}" in
  stop) stop_tree; ok "已停"; exit 0 ;;
  all)  ;;
  *)    die "用法：$0 [all|stop]" ;;
esac

[ -x "${BIN}" ] || die "找不到 ${BIN}；请放入预编译好的 bin/treecmd-node（开发机上：go build -o bin/treecmd-node ./cmd/node）"
[ -f "${PROBE}" ] || die "找不到探针 ${PROBE}"

step "〇 清场并起树（复用 demo.sh：根 + 直接叶子 + 中继 + 中继下的叶子）"
stop_tree
archive_state
"${HERE}/demo.sh" start >/dev/null 2>&1 || die "demo.sh start 失败（看 ${LOGS}/*.log）"
wait_tree 25 || die "等不到 2 个直接子 online（看 ${LOGS}/*.log）"
ok "树已就绪"

# 先把 renew_at / tick_interval 热更下去（纯加速，见文件头的说明）
hot_apply_all "renew_at=${RENEW}" "tick_interval=${TICK}" || die "热更加速参数失败"
info "本批 = ${COUNT} 条 × ${SLEEP_MS}ms；加速项 renew_at=${RENEW} / tick_interval=${TICK}"
[ "$(window_now)" = "${WINDOW}" ] \
  && ok "热更后窗口仍是配置默认的 ${WINDOW}（没有把不相干的参数改坏）" \
  || die "热更后窗口变成了 $(window_now)，期望 ${WINDOW}"

step "① 窗口生效：${COUNT} 条同时提交，任何时刻每个子的在途数都不超过 ${WINDOW}"
run_probe "阶段A-默认窗口"
info "峰值：$(probe_field max_inflight_by_child)（采样 $(probe_field sampled) 次、耗时 $(probe_field elapsed_s)s）"
MAX_INFLIGHT="$(probe_field max_inflight)"
[ "$(probe_field metric_seen)" = "True" ] \
  || die "整轮都没看到 child_dispatch_inflight 有值 —— 窗口可能根本没生效（看 /metrics）"
[ "${MAX_INFLIGHT}" -le "${WINDOW}" ] \
  && ok "峰值在途 ${MAX_INFLIGHT} ≤ 窗口 ${WINDOW}：一次一个子最多只能拉走 ${WINDOW} 条" \
  || die "峰值在途 ${MAX_INFLIGHT} 超过了窗口 ${WINDOW} —— 窗口没起作用"

step "② 限速不丢任务：这一批全部到达终态"
PENDING="$(probe_field pending)"
STATUSES="$(probe_field statuses)"
[ "${PENDING}" = "0" ] \
  && ok "${COUNT} 条全部终态：${STATUSES}（窗口只限速，没有把任务弄丢）" \
  || die "还有 ${PENDING} 条没到终态：${STATUSES}"

step "③ 对照组：把窗口改成 0（不限）热更进去，同一批应当被一次拉走"
hot_apply_all "renew_at=${RENEW}" "tick_interval=${TICK}" \
  "max_dispatch_inflight_per_child=0" "max_dispatch_inflight=0" \
  || die "热更窗口失败"
grep -q 'config reload: 仅运行参数热更' "${LOGS}/root.log" \
  && ok "SIGHUP 热更生效，且**没有**触发全量重注册（command. 段不进 config_hash）" \
  || die "根没有记录运行参数热更（看 ${LOGS}/root.log）"

WINDOW_NOW="$(window_now)"
[ "${WINDOW_NOW}" = "0" ] \
  && ok "窗口已在运行期改成 0（不限）" \
  || die "热更后窗口仍是 ${WINDOW_NOW}，期望 0"

run_probe "阶段B-窗口不限"
MAX_FREE="$(probe_field max_inflight)"
info "峰值：$(probe_field max_inflight_by_child)（耗时 $(probe_field elapsed_s)s）"
# 对照组的意义：证明 ① 那个上限确实是**窗口**带来的，而不是因为任务本来就快、天然不会同时在途。
# 所以要求不限窗口时明显超过窗口值。
[ "${MAX_FREE}" -gt "${WINDOW}" ] \
  && ok "不限窗口时峰值在途 ${MAX_FREE} > ${WINDOW}：说明 ① 的上限确实来自窗口" \
  || die "不限窗口时峰值只有 ${MAX_FREE}，没有超过 ${WINDOW} —— 这个对照组证明不了任何事"
[ "$(probe_field pending)" = "0" ] \
  && ok "对照组也全部终态：$(probe_field statuses)" \
  || warn "对照组仍有 $(probe_field pending) 条没终态：$(probe_field statuses)"

step "④ 收尾"
stop_tree
ok "全部断言通过"
info "阶段A 峰值在途 = ${MAX_INFLIGHT}（窗口 ${WINDOW}）"
info "阶段B 峰值在途 = ${MAX_FREE}（窗口 0 = 不限）"
