#!/usr/bin/env bash
#
# forget.sh —— 「清理失效子节点」（/v1/forget）的端到端验证。
#
#   ./forget.sh          起一套 3 层的树 → 逐条验证护栏与清理 → 停树
#
# 为什么是这个形状：
#   · 清理的对象是"父端的记录"，所以验证要在**父**（根）上打 API，而不是在子身上；
#   · 三种必须分开验的输入：**在线**（必须拒绝）、**曾连上过但已掉线**（默认拒绝，需 mode=stale/force）、
#     **查无此人**（404）；
#   · "掉线"要真的掉线：kill 掉 leaf1 之后要等 /v1/tree 报 online=false，否则验到的是在线护栏；
#   · 最容易漏的是"删完会不会又被写回来" —— 所以最后**重启一次根**再断言一遍（known_children 回灌闭环）。
#
# 本脚本只动 test/ 下的演示目录（test/demo、test/logs，均已在 .gitignore 里），不改任何源码。
#
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
ROOT_API="${ROOT_API:-127.0.0.1:18493}"
DEMO="${HERE}/demo"

PASS=0; FAIL=0
ok()    { printf '  \033[32m✓\033[0m %s\n' "$*"; PASS=$((PASS + 1)); }
bad()   { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; FAIL=$((FAIL + 1)); }
info()  { printf '    %s\n' "$*"; }
title() { printf '\n\033[1m%s\033[0m\n' "$*"; }
die()   { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

cleanup() { "${HERE}/demo.sh" stop >/dev/null 2>&1 || true; }
trap cleanup EXIT   # 节点进程只在本次运行的生命周期内存活，必须起树/验证/停树一气呵成

# curl 加 --noproxy：本机 HTTP 不该被 http_proxy 环境变量劫持（那会得到 502）。
get() { curl -s --noproxy '*' "$@"; }

chk() { # chk <说明> <实际> <期望>
  if [ "$2" = "$3" ]; then ok "$1（$2）"; else bad "$1：实际=[$2] 期望=[$3]"; fi
}

# py <代码> [参数...]：把 JSON 从 stdin 喂给 python，代码里用 sys.argv 取参数。
# 一律用 argv 传值，避免把值嵌进 python 代码里（引号地狱）。
py() { python3 -c "$1" "${@:2}"; }

# child_id <node_name> <online:true|false|any>：从 /v1/tree 里挑一个直接子的 NodeID。
child_id() {
  get "http://${ROOT_API}/v1/tree" | py '
import json,sys
d=json.load(sys.stdin); name,want=sys.argv[1],sys.argv[2]
for c in d.get("children") or []:
    if c.get("node_name")==name and (want=="any" or str(c.get("online")).lower()==want):
        print(c["node_id"]); break
' "$1" "$2"
}

# field <json> <字段表达式>：取一个字段（表达式里用 d 指代顶层对象）。
field() { printf '%s' "$1" | py "import json,sys; d=json.load(sys.stdin); print(d${2})"; }

[ -x "${REPO}/bin/treecmd-node" ] || die "找不到 ${REPO}/bin/treecmd-node；先 go build -o bin/treecmd-node ./cmd/node"

cleanup
"${HERE}/demo.sh" start >/tmp/treecmd-forget-demo.log 2>&1 || { tail -20 /tmp/treecmd-forget-demo.log; exit 1; }
sleep 1

RELAY=$(child_id relay-mid true)
LEAF=$(child_id leaf-alpha true)
[ -n "${RELAY}" ] && [ -n "${LEAF}" ] || die "树里没找到在线子节点（看 ${HERE}/logs/root.log）"
info "在线 relay-mid  = ${RELAY}"
info "在线 leaf-alpha = ${LEAF}"

title '① 护栏：在线的一律不删（force 也不能越过）'
D=$(get "http://${ROOT_API}/v1/forget?node=${RELAY}")
chk "预览 reason" "$(field "${D}" '["reason"]')" "ERR_CHILD_ONLINE"
chk "预览 allowed" "$(field "${D}" '["allowed"]')" "False"
chk "POST force=1 仍被拒" \
  "$(get -o /dev/null -w '%{http_code}' -X POST "http://${ROOT_API}/v1/forget?node=${RELAY}&force=1")" "409"
chk "数据零变化（relay 还在树里）" "$(get "http://${ROOT_API}/v1/tree" | grep -c "${RELAY}")" "1"

title '② 查无此人：404'
chk "预览 reason" \
  "$(field "$(get "http://${ROOT_API}/v1/forget?node=00000000-0000-7000-8000-000000000000")" '["reason"]')" "ERR_CHILD_NOT_FOUND"
chk "POST（HTTP）" \
  "$(get -o /dev/null -w '%{http_code}' -X POST "http://${ROOT_API}/v1/forget?node=00000000-0000-7000-8000-000000000000")" "404"

title '③ 让 leaf-alpha 真的掉线（清理对象必须是已掉线的节点）'
kill "$(awk -F: '/^leaf1:/{print $2}' "${HERE}/.demo.pids")" 2>/dev/null || true
online=unknown
for _ in $(seq 1 20); do
  TREE=$(get "http://${ROOT_API}/v1/tree")
  online=$(printf '%s' "${TREE}" | py '
import json,sys
d=json.load(sys.stdin); want=sys.argv[1]
print(next((str(c.get("online")).lower() for c in d.get("children") or [] if c.get("node_id")==want), "gone"))
' "${LEAF}")
  [ "${online}" = "false" ] && break
  sleep 0.5
done
chk "leaf-alpha 已离线" "${online}" "false"

title '④ 默认最保守：曾连上过的节点，garbage 模式拒绝（409）'
D=$(get "http://${ROOT_API}/v1/forget?node=${LEAF}")
info "$(printf '%s' "${D}" | py '
import json,sys
d=json.load(sys.stdin)
print({k: d[k] for k in ("online","known","confirmed","has_watermark","allowed","reason","silence_seconds")})
')"
chk "reason" "$(field "${D}" '["reason"]')" "ERR_NEEDS_STALE"
chk "POST 默认模式（HTTP）" \
  "$(get -o /dev/null -w '%{http_code}' -X POST "http://${ROOT_API}/v1/forget?node=${LEAF}")" "409"
chk "被拒后数据完好（仍在树里）" "$(get "http://${ROOT_API}/v1/tree" | grep -c "${LEAF}")" "1"

title '⑤ mode=stale：沉默时长不够 → 需 force（412）'
chk "reason" "$(field "$(get "http://${ROOT_API}/v1/forget?node=${LEAF}&mode=stale")" '["reason"]')" "ERR_TOO_RECENT"
chk "POST（HTTP）" \
  "$(get -o /dev/null -w '%{http_code}' -X POST "http://${ROOT_API}/v1/forget?node=${LEAF}&mode=stale")" "412"

title '⑥ force=1：真正清理（一条事务删四个桶）'
BODY=$(get -w '\n%{http_code}' -X POST "http://${ROOT_API}/v1/forget?node=${LEAF}&force=1")
CODE=$(printf '%s' "${BODY}" | tail -1)
JSON=$(printf '%s' "${BODY%$'\n'*}")
chk "POST（HTTP）" "${CODE}" "200"
info "回执 deleted=$(field "${JSON}" '["deleted"]')"
chk "applied" "$(field "${JSON}" '["applied"]')" "True"
chk "watermark 已删" "$(field "${JSON}" '["deleted"]["watermark"]')" "1"
chk "注册表已删" "$(field "${JSON}" '["deleted"]["registry"]')" "1"
chk "state.dat 已同步落盘" "$(field "${JSON}" '["deleted"]["state_saved"]')" "True"
chk "默认保留 child_reports" "$(field "${JSON}" '["deleted"]["reports"]')" "0"

title '⑦ 清理后的现场'
chk "从 /v1/tree 消失" "$(get "http://${ROOT_API}/v1/tree" | grep -c "${LEAF}")" "0"
chk "从 state.dat.known_children 消失" "$(grep -c "${LEAF}" "${DEMO}/root/state.dat")" "0"
chk "在线的 relay-mid 未受影响" "$(get "http://${ROOT_API}/v1/tree" | grep -c "${RELAY}")" "1"
chk "AUDIT-FORGET 已入日志" "$(grep -c 'AUDIT-FORGET' "${HERE}/logs/root.log")" "1"
chk "指标 forget_total 已暴露" \
  "$(get "http://${ROOT_API}/metrics" | py 'import sys;print("1" if any(l.startswith("forget_total{") for l in sys.stdin) else "0")')" "1"

title '⑧ 重启根：结果是否持久（不被 known_children 写回来）'
kill "$(awk -F: '/^root:/{print $2}' "${HERE}/.demo.pids")" 2>/dev/null || true
sleep 1
"${REPO}/bin/treecmd-node" -config "${DEMO}/root/node.yaml" > "${HERE}/logs/root.log" 2>&1 &
echo "root:$!" >> "${HERE}/.demo.pids"
sleep 3
chk "重启后仍不含被清的节点" "$(get "http://${ROOT_API}/v1/tree" | grep -c "${LEAF}")" "0"

title '⑨ 批量：POST /v1/forget?all=1'
D=$(get -X POST "http://${ROOT_API}/v1/forget?all=1&force=1")
info "候选=$(field "${D}" '["candidates"]')  已清=$(field "${D}" '["forgotten"]')"
chk "至少清掉 1 个" \
  "$(printf '%s' "${D}" | py 'import json,sys;print("1" if json.load(sys.stdin)["forgotten"]>=1 else "0")')" "1"
chk "结果列表逐条带 allowed" \
  "$(printf '%s' "${D}" | py 'import json,sys;print(all("allowed" in r for r in json.load(sys.stdin)["results"]))')" "True"

printf '\n\033[1m  通过 %d / 失败 %d\033[0m\n' "${PASS}" "${FAIL}"
[ "${FAIL}" -eq 0 ] || exit 1
