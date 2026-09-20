#!/usr/bin/env bash
# from-any-node.sh —— 验证「从任意节点发起指令」这条不变量：
# 发起者就是这条指令的 origin ⇒ 结果只落它自己 + 它名下的子树，**祖先完全不知情**。
#
#   cd test
#   ./from-any-node.sh          起干净的 3 层树 → 放脚本 → 从中继提交 → 断言 → 停树
#   ./from-any-node.sh keep     跑完留着树（自己 ./demo.sh stop）
#
# 为什么值得单独立一条：`Target` 只有 `SUBTREE` 一种模式，加上 `handle.go:347` 那句
# `OriginId == 本节点 ⇒ sink=SELF`（本节点结果**不上报给自己的父**），所以"以任意节点为根
# 发起一次局部指令"应当天然成立 —— 这个脚本就是来证它，顺带钉住"祖先不知情"这条边界。
#
# 它断言七件事：
#   ① 中继的 API 可用（**任意节点都能开 api**：判定只看 `api.http_addr` 非空，不看角色）；
#   ② 脚本只放进中继的 `script/`（发起者就是脚本源），根与 leaf-alpha 的 script/ 里始终没有；
#   ③ 中继提交成功，且结果里**只有 2 个节点**（中继自己 + 它的直接子 leaf-beta）；
#   ④ 聚合结果的顶层节点就是**中继**（不是根）—— 说明这棵"子树"以发起者为根；
#   ⑤ **根查这条指令 = NOT_FOUND**：祖先连它存在都不知道；
#   ⑥ leaf-alpha 与根**从未参与**（日志里没有这个指令 ID、script/ 里没有脚本）；
#   ⑦ leaf-beta 从中继那里拿到了脚本（逐字节一致），且**验签通过、签名者就是中继**
#      —— "下发及签名都用当前节点的身份"。
#
# 依赖 bin/treecmd-node（缺失或比源码旧时自动重建）、demo.sh、Python 3。
# 产物只落在本目录（logs/ 与 demo/，都已 gitignore）。

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "${HERE}" || exit 1

KEEP="${1:-}"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
ROOT_API="127.0.0.1:18493"
RELAY_API="127.0.0.1:18494"
DEMO="${HERE}/demo"
SCRIPT_NAME="local.sh"
PARAMS='{"scope":"本子树"}'

# 本机可能配了 HTTP_PROXY，而它通常不管 127.0.0.1 —— 不加 --noproxy 会拿到 Connection refused
CURL=(curl -s --noproxy '*' --max-time 5)

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
FAILED=0
fail() { bad "$*"; FAILED=1; }

trap '[ "${KEEP}" = "keep" ] || ./demo.sh stop >/dev/null 2>&1 || true' EXIT

# ⓪ 二进制：改了代码没重建是最容易踩的坑（跑出来是旧行为），所以这里自动补上
mkdir -p logs
if [ ! -x "${BIN}" ] ||
   [ -n "$(find "${REPO}/cmd" "${REPO}/internal" -name '*.go' -newer "${BIN}" -print -quit 2>/dev/null)" ]; then
  info "重建 bin/treecmd-node（缺失或比源码旧）"
  (cd "${REPO}" && go build -o bin/treecmd-node ./cmd/node) || { bad "编译失败"; exit 1; }
fi
ok "镜像已是最新"

# ① 起树。必须 DEMO_PER_NODE_BIN=1：每节点一份自己的二进制，脚本目录才各自独立
printf '\n① 起树（每节点一份二进制）\n'
./demo.sh stop >/dev/null 2>&1 || true
rm -f .demo.pids
rm -rf demo
if ! DEMO_PER_NODE_BIN=1 ./demo.sh start > logs/fromany.start.log 2>&1; then
  bad "demo.sh start 失败"; tail -20 logs/fromany.start.log; exit 1
fi
for _ in $(seq 1 40); do "${CURL[@]}" -o /dev/null "http://${ROOT_API}/v1/healthz" && break; sleep 0.5; done
# 根的 API 要真的探一次（那个等待循环不校验结果，探不到也会继续）
if ! "${CURL[@]}" -o /dev/null "http://${ROOT_API}/v1/healthz"; then
  fail "根的 API（${ROOT_API}）没起来"; tail -5 logs/root.log; exit 1
fi
ok "根的 API 可用：${ROOT_API}"
# 中继的 API 是新开的（demo.sh 给"根 + 有下级的节点"各配一个 api 段）
relay_api_ok=0
for _ in $(seq 1 20); do
  if "${CURL[@]}" -o /dev/null "http://${RELAY_API}/v1/healthz"; then relay_api_ok=1; break; fi
  sleep 0.5
done
if [ "${relay_api_ok}" != "1" ]; then
  fail "中继的 API（${RELAY_API}）没起来 —— 任意节点开 api 这条没做到"
  tail -5 logs/relay.log
else
  ok "中继的 API 可用：${RELAY_API}（任意节点都能开 api，判定只看 api.http_addr 非空）"
fi
if ! grep -q 'msg=registered' logs/leaf2.log 2>/dev/null; then
  fail "leaf-beta 没注册上来（3 层树不完整），后面的断言没有意义"; tail -5 logs/leaf2.log; exit 1
fi
ok "根 + leaf-alpha + relay-mid + leaf-beta（3 层）都已注册"

# 中继的身份，用来核对"签名者就是它"
RELAY_ID="$(sed -n 's/.*"id": *"\([0-9a-f-]\{36\}\)".*/\1/p' demo/relay/state.dat 2>/dev/null | head -1)"
if [ -z "${RELAY_ID}" ]; then
  RELAY_ID="$(sed -n 's/.*node_id=\([0-9a-f-]\{36\}\).*/\1/p' logs/relay.log 2>/dev/null | head -1)"
fi
[ -n "${RELAY_ID}" ] && info "中继 NodeID = ${RELAY_ID:0:8}…" || warn "没取到中继的 NodeID（下面那条签名者断言会放宽）"

# ② 脚本**只**放进中继的 script/ —— 发起者就是脚本源
printf '\n② 把脚本放进中继的 script/（发起者 = 脚本源）\n'
RELAY_SCRIPT="${DEMO}/relay/script/${SCRIPT_NAME}"
cat > "${RELAY_SCRIPT}" <<'SCRIPT'
#!/bin/sh
# 把唯一参数原样写进结果；顺带报出本节点的工作目录，便于确认"是谁在跑"
printf '{"ran_in":"%s","argv1":%s}' "$(pwd)" "${1:-\"\"}" > result.json
SCRIPT
chmod 755 "${RELAY_SCRIPT}"
RELAY_SHA="$(shasum -a 256 "${RELAY_SCRIPT}" | awk '{print $1}')"
info "脚本 sha256=${RELAY_SHA:0:12}…"
miss=0
for n in root leaf1; do [ -f "${DEMO}/${n}/script/${SCRIPT_NAME}" ] && miss=1; done
if [ "${miss}" = "1" ]; then
  fail "根或 leaf-alpha 里已经有这个脚本了 —— 这次验证说明不了" 
else
  ok "根的 script/ 与 leaf-alpha 的 script/ 里都没有它"
fi

# ③ 从**中继**提交
printf '\n③ 从中继提交（发起者 = 中继）\n'
PAYLOAD="$(printf '{"script":"%s","params":%s}' "${SCRIPT_NAME}" "${PARAMS}" | base64 | tr -d '\n')"
R="$("${CURL[@]}" -H 'Content-Type: application/json' -XPOST "http://${RELAY_API}/v1/commands" \
    -d "{\"type\":\"script\",\"aggregate\":\"TREE\",\"on_failure\":\"ALL_MUST_SUCCEED\",\"max_duration\":\"60s\",\"attest_depth\":0,\"payload\":\"${PAYLOAD}\"}")"
info "提交 → ${R}"
ID="$(printf '%s' "${R}" | sed -n 's/.*"command_id":"\([^"]*\)".*/\1/p')"
if [ -z "${ID}" ]; then bad "从中继提交失败"; exit 1; fi

# ④ 轮询中继的 API 到终态（NOT_FOUND = "还没收敛"，是正常中间态）
OUT=""
for _ in $(seq 1 40); do
  OUT="$("${CURL[@]}" "http://${RELAY_API}/v1/commands/${ID}")"
  case "${OUT}" in *'"result"'*|*COMMAND_STATUS_FAILED*) break ;; esac
  sleep 1
done
printf '\n④ 中继自己拿到的结果\n'
if RELAY_OUT="${OUT}" EXPECT_NODES=2 TOP_ID="${RELAY_ID}" PARAMS="${PARAMS}" python3 <<'PY'
import json, os, sys

doc = json.loads(os.environ["RELAY_OUT"])
if doc.get("status") != "COMMAND_STATUS_COMPLETED":
    print("  指令没成功：status=%s" % doc.get("status")); sys.exit(1)
agg = json.loads(doc["result"])
rows = []


def walk(n, d):
    rows.append((d, n.get("node_id", "?"), n.get("self")))
    for c in n.get("nodes") or []:
        walk(c, d + 1)


walk(agg, 0)
for d, nid, me in rows:
    print("%s%s" % ("  " * (d + 1), nid[:13] + "…"))

problems = []
want = int(os.environ["EXPECT_NODES"])
if len(rows) != want:
    problems.append("期望 %d 个节点（中继自己 + 它的子），实际 %d 个" % (want, len(rows)))
top = os.environ.get("TOP_ID") or ""
if top and rows and rows[0][1] != top:
    problems.append("顶层节点不是中继（期望 %s，实际 %s）" % (top[:8], rows[0][1][:8]))
for _, nid, me in rows:
    if isinstance(me, str):
        try:
            me = json.loads(me)
        except Exception:
            pass
    if not (isinstance(me, dict) and me.get("argv1")):
        problems.append("节点 %s 的结果不是脚本产出的" % nid[:8])
for p in problems:
    print("  %s" % p)
sys.exit(1 if problems else 0)
PY
then ok "结果为「中继 + 它的直接子」共 2 个节点，顶层就是中继（子树以发起者为根）"
else fail "聚合结果不符合预期（见上）"; fi

# ⑤ 祖先是否知情
printf '\n⑤ 发起者的父（根）知道这条指令吗\n'
RROOT="$("${CURL[@]}" "http://${ROOT_API}/v1/commands/${ID}")"
case "${RROOT}" in
  *NOT_FOUND*) ok "根查这条指令 = NOT_FOUND —— 祖先对它一无所知（结果只落在子树内）" ;;
  *'"result"'*) fail "根竟然能查到这条指令：sink=SELF 的判定出问题了 → ${RROOT}" ;;
  *) fail "根返回了意外内容：${RROOT}" ;;
esac

# ⑥ 旁支有没有被卷进来
printf '\n⑥ 旁支（根、leaf-alpha）有没有被卷进来\n'
for n in root leaf1; do
  if [ -f "${DEMO}/${n}/script/${SCRIPT_NAME}" ]; then
    fail "${n} 的 script/ 里出现了这个脚本 —— 下发越界了"
  else
    ok "${n} 从未收到这个脚本"
  fi
  if grep -q "${ID}" "logs/${n}.log" 2>/dev/null; then
    fail "${n} 的日志里出现了这条指令 —— 它本不该参与"
  else
    ok "${n} 的日志里没有这条指令"
  fi
done

# ⑦ leaf-beta：脚本怎么来的、谁签的名
printf '\n⑦ leaf-beta 的脚本从哪来、谁签的名\n'
LEAF_SCRIPT="${DEMO}/leaf2/script/${SCRIPT_NAME}"
if [ ! -f "${LEAF_SCRIPT}" ]; then
  fail "leaf-beta 没有拿到脚本"
else
  got="$(shasum -a 256 "${LEAF_SCRIPT}" | awk '{print $1}')"
  if [ "${got}" = "${RELAY_SHA}" ]; then ok "已从中继下发到 leaf-beta，且逐字节一致"; else fail "内容与中继那份不一致"; fi
fi
if grep -q "脚本身份背书校验通过" logs/leaf2.log 2>/dev/null; then
  SIGNER="$(sed -n 's/.*脚本身份背书校验通过.*signer=\([0-9a-f]*\).*/\1/p' logs/leaf2.log | tail -1)"
  if [ -z "${SIGNER}" ]; then
    fail "日志里没有验签通过的记录（或格式变了）"
  elif [ -z "${RELAY_ID}" ]; then
    warn "验签通过；签名者=${SIGNER}（没取到中继 ID，跳过比对）"
  elif [ "${SIGNER}" = "${RELAY_ID:0:8}" ]; then
    ok "验签通过，且签名者就是中继（signer=${SIGNER}）—— 下发与签名都用发起那一跳自己的身份"
  else
    fail "签名者 ${SIGNER} 与中继 ${RELAY_ID:0:8} 不符"
  fi
else
  fail "leaf-beta 的日志里没有验签通过记录 —— 签名这道闸门可能没生效"
fi

printf '\n⑧ 收尾\n'
if [ "${KEEP}" = "keep" ]; then info "树留着：中继 http://${RELAY_API}/v1/tree"; else info "停树"; fi
printf '\n'
if [ "${FAILED}" = "0" ]; then
  printf '全部通过\n'
else
  printf '有失败项\n'
fi
exit "${FAILED}"
