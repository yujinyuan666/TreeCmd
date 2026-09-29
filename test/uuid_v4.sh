#!/usr/bin/env bash
# uuid_v4.sh —— 一条命令验证「树里每个节点各调一次外部 API，结果层层回传给父节点」。
#
#   cd test
#   ./uuid_v4.sh         起干净的 3 层树 → 提交 → 轮询 → 断言 → 停树
#   ./uuid_v4.sh keep    跑完留着树（自己 ./demo.sh stop）
#
# 断言四件事：
#   ① 指令最终 COMPLETED；
#   ② 聚合结果里的 UUID 条数 == 树里的节点数（4：根 + 叶子 + 中继 + 中继下的叶子）；
#   ③ 这些 UUID **两两不同** —— 这是"每个节点都真的自己去调了上游"的证据；
#   ④ 负向：没登记的类型必须在提交期就被拒。
#
# 依赖 bin/treecmd-node（缺失或比源码旧时自动重建）、demo.sh、Python 3。
# 产物只落在本目录（logs/ 与 demo/，都已 gitignore）。

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "${HERE}" || exit 1

KEEP="${1:-}"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
API="127.0.0.1:18493"
DEMO="${HERE}/demo"
API_TOKEN_DIR="${DEMO}/root"      # token 签在哪个节点目录下（下面所有 curl 自动带上）
# 本机可能配了 HTTP_PROXY，而它通常不管 127.0.0.1 —— 不加 --noproxy 会拿到 Connection refused
CURL=(curl -s --noproxy '*' --max-time 5)

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
FAILED=0

trap '[ "${KEEP}" = "keep" ] || ./demo.sh stop >/dev/null 2>&1 || true' EXIT

# ⓪ 二进制：改了代码没重建是最容易踩的坑（跑出来是旧行为），所以这里自动补上
mkdir -p logs
if [ ! -x "${BIN}" ] ||
   [ -n "$(find "${REPO}/cmd" "${REPO}/internal" -name '*.go' -newer "${BIN}" -print -quit 2>/dev/null)" ]; then
  info "重建 bin/treecmd-node（缺失或比源码旧）"
  (cd "${REPO}" && go build -o bin/treecmd-node ./cmd/node) || { bad "编译失败"; exit 1; }
fi
ok "镜像已是最新"

# ① 起一层干净的树：残留的僵尸子节点会让父端等不到 done=total（指令不进终态）
printf '\n① 起树\n'
./demo.sh stop >/dev/null 2>&1 || true
rm -f .demo.pids
rm -rf demo
./demo.sh start > logs/uuid_v4.start.log 2>&1 || { bad "demo.sh start 失败"; tail -20 logs/uuid_v4.start.log; exit 1; }
for _ in $(seq 1 40); do "${CURL[@]}" -o /dev/null "http://${API}/v1/healthz" && break; sleep 0.5; done
ok "根 + leaf-alpha + relay-mid + leaf-beta（3 层）就绪"

# ② 提交。SUB 是全局变量 —— 别用 $(submit) 捕获，那会把函数里的回显一起捕获进去
SUB=""
submit() {
  local b64="$1" body r
  body="{\"type\":\"uuid_v4\",\"aggregate\":\"TREE\",\"on_failure\":\"ALL_MUST_SUCCEED\",\"max_duration\":\"30s\",\"attest_depth\":0"
  [ -n "${b64}" ] && body="${body},\"payload\":\"${b64}\""
  r="$("${CURL[@]}" -H 'Content-Type: application/json' -XPOST "http://${API}/v1/commands" -d "${body}}")"
  info "提交 → ${r}"
  SUB="$(printf '%s' "${r}" | sed -n 's/.*"command_id":"\([^"]*\)".*/\1/p')"
}
# 轮询到终态：父端的 NOT_FOUND（"还没收敛"）是正常中间态，不是错误
poll() {
  local out="" i
  for i in $(seq 1 40); do
    out="$("${CURL[@]}" "http://${API}/v1/commands/$1")"
    case "${out}" in *'"result"'*|*COMMAND_STATUS_FAILED*) break ;; esac
    sleep 1
  done
  printf '%s' "${out}"
}

printf '\n② 提交并等收敛\n'
submit ""
[ -n "${SUB}" ] || { bad "提交被拒"; exit 1; }
OUT="$(poll "${SUB}")"

printf '\n③ 核对父节点拿到的结果\n'
if RESULT_JSON="${OUT}" EXPECT=4 python3 <<'PY'
import json, os, sys

doc = json.loads(os.environ["RESULT_JSON"])
if doc.get("status") != "COMMAND_STATUS_COMPLETED":
    print("  指令没成功：status=%s" % doc.get("status")); sys.exit(1)

agg, rows = json.loads(doc["result"]), []
def walk(n, d):
    me = n.get("self") or {}
    for u in me.get("uuids") or []:
        rows.append((d, me.get("path") or "?", u))
    for c in n.get("nodes") or []:
        walk(c, d + 1)
walk(agg, 0)

for d, path, u in rows:
    pad = "  " * (d + 1)
    print("%s%s\n%s└─ %s" % (pad, path, pad, u))

bad = []
if len(rows) != int(os.environ["EXPECT"]):
    bad.append("期望 %d 个节点各回一条，实际 %d 条" % (int(os.environ["EXPECT"]), len(rows)))
if len(set(r[2] for r in rows)) != len(rows):
    bad.append("UUID 有重复 —— 说明不是每个节点都真的调了上游")
for b in bad:
    print("  %s" % b)
sys.exit(1 if bad else 0)
PY
then ok "4 个节点各调一次上游，结果全部回传到父节点"
else bad "断言未通过"; FAILED=1; fi

printf '\n④ 负向：没登记的类型必须在提交期就被拒\n'
BOGUS="$("${CURL[@]}" -H 'Content-Type: application/json' -XPOST "http://${API}/v1/commands" \
  -d '{"type":"uuid_v9_not_registered","aggregate":"TREE"}')"
case "${BOGUS}" in
  *ERR_CAPABILITY_UNSUPPORTED*) ok "提交被拒（执行器表里没有这个类型）" ;;
  *) bad "未登记类型竟然被接受：${BOGUS}"; FAILED=1 ;;
esac

[ "${KEEP}" = "keep" ] && info "树留着：控制台 http://127.0.0.1:8899/"
printf '\n'
[ "${FAILED}" = "0" ] && printf '\033[32m全部通过\033[0m\n' || printf '\033[31m有失败项，日志在 logs/\033[0m\n'
exit "${FAILED}"
