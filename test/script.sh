#!/usr/bin/env bash
# script.sh —— 一条命令验证「执行外部脚本」这条链路（type: "script"）。
#
#   cd test
#   ./script.sh          起干净的 3 层树 → 放脚本 → 提交 → 断言 → 停树
#   ./script.sh keep     跑完留着树（自己 ./demo.sh stop）
#
# 这条链路与其它几条的区别：前几条看的是"指令跑得对不对"，这一条看的是
# **脚本本体怎么到每个节点上去的** —— 根节点的 script/ 目录里放一份脚本，
# 子节点在执行前发现本地没有（或哈希不对），就向父索取、校验、覆盖，然后才执行。
#
# 它断言七件事：
#   ① 指令最终 COMMAND_STATUS_COMPLETED；
#   ② 执行前**每个子节点的 script/ 里都没有**这个脚本，执行后**都有**且内容与根逐字节一致，
#      而且这份字节带着**父的身份背书**、子端验签通过
#      —— 这是"父把脚本下发给子"的直接证据；
#   ③ 树里每一层都产出了本节点结果（TREE 聚合里节点数 == 4），且脚本收到的参数**原样**就是提交时给的；
#   ④ 先往某子节点塞一份**同名但内容错误**的脚本，提交后它被无条件覆盖回正确内容，结果也来自正确脚本；
#   ⑤ 脚本名带路径穿越（../../keys/id_ed25519）在提交期就被拒；
#   ⑥ 不存在的脚本在提交期就被拒（fail-fast，不用等它铺到全树）；
#   ⑦ result.json 超过上限时该节点失败，且错误信息明确 —— 结果绝不会走到"对象存储引用"
#      （引用无法跨节点取回）。
#
# 关键前提：脚本目录 `script/` 是**相对可执行文件位置**推导的，所以这里必须让每个节点
# 用自己那份二进制（`DEMO_PER_NODE_BIN=1`）—— 否则四个节点共用一个 script/ 目录，
# "下发"这条链路永远走不到（子在自己目录里就已经找到了）。
#
# 依赖 bin/treecmd-node（缺失或比源码旧时自动重建）、demo.sh、Python 3。
# 产物只落在本目录（logs/ 与 demo/，都已 gitignore）。

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
# API 没有免签来源（含本机）：所有请求都要带 user token —— 见 lib/apitoken.sh
. "${HERE}/lib/apitoken.sh"   # 对外 API 一律要 user token：装好后所有 curl 自动带上
cd "${HERE}" || exit 1

KEEP="${1:-}"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
API="127.0.0.1:18493"
DEMO="${HERE}/demo"
API_TOKEN_DIR="${DEMO}/root"      # token 签在哪个节点目录下（下面所有 curl 自动带上）
SCRIPT_NAME="hello.sh"
# 本机可能配了 HTTP_PROXY，而它通常不管 127.0.0.1 —— 不加 --noproxy 会拿到 Connection refused
CURL=(curl -s --noproxy '*' --max-time 5)

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
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

# ① 起树。必须 DEMO_PER_NODE_BIN=1：每个节点一份自己的二进制，脚本目录才各自独立
printf '\n① 起树\n'
./demo.sh stop >/dev/null 2>&1 || true
rm -f .demo.pids
rm -rf demo
if ! DEMO_PER_NODE_BIN=1 ./demo.sh start > logs/script.start.log 2>&1; then
  bad "demo.sh start 失败"; tail -20 logs/script.start.log; exit 1
fi
for _ in $(seq 1 40); do "${CURL[@]}" -o /dev/null "http://${API}/v1/healthz" && break; sleep 0.5; done
# 树必须真的齐：leaf-beta 没注册上来时，后面的断言会以很难看懂的方式失败
#（曾经在上一轮遗留的脏状态下踩过 —— 中继换了 node_id，leaf-beta 挂在旧 ID 上永远注册不上）
for n in root leaf1 relay leaf2; do
  [ -d "${DEMO}/${n}" ] || { fail "节点目录缺失：${DEMO}/${n}"; exit 1; }
done
if ! grep -q 'msg=registered' logs/leaf2.log 2>/dev/null; then
  fail "leaf-beta 没注册上来（3 层树不完整），后面的断言没有意义"
  tail -5 logs/leaf2.log
  exit 1
fi
ok "根 + leaf-alpha + relay-mid + leaf-beta（3 层）都已注册，每节点一份二进制"

# ② 把脚本放进**根节点**的 script/ 目录（其余节点都不放 —— 它们要靠下发拿到）
printf '\n② 把脚本放进根节点的 script/ 目录\n'
ROOT_SCRIPT="${DEMO}/root/script/${SCRIPT_NAME}"
cat > "${ROOT_SCRIPT}" <<'SCRIPT'
#!/bin/sh
# 演示脚本：把收到的那一个参数（完整载荷 JSON）原样写进本节点的结果文件。
# 手动执行时没有参数也能跑 —— 那样只是写出一个空结果文件。
param="${1:-}"
printf '%s' "${param}" > result.json
echo "hello.sh ran in $(pwd)" >&2
SCRIPT
chmod 755 "${ROOT_SCRIPT}"
ROOT_SHA="$(shasum -a 256 "${ROOT_SCRIPT}" | awk '{print $1}')"
ok "已放置（sha256=${ROOT_SHA:0:12}…）"

# 超限用例的脚本：往 result.json 写 5MB（超过 4MB 上限）
cat > "${DEMO}/root/script/big.sh" <<'SCRIPT'
#!/bin/sh
head -c 5000000 /dev/zero | tr '\0' a > result.json
SCRIPT
chmod 755 "${DEMO}/root/script/big.sh"

CHILD_SCRIPTS=("${DEMO}/leaf1/script/${SCRIPT_NAME}" "${DEMO}/relay/script/${SCRIPT_NAME}" "${DEMO}/leaf2/script/${SCRIPT_NAME}")
missing=0
for f in "${CHILD_SCRIPTS[@]}"; do [ -f "$f" ] && missing=1; done
if [ "${missing}" = "1" ]; then
  fail "执行前子节点就已经有该脚本了 —— 这次验证说明不了下发（检查 DEMO_PER_NODE_BIN）"
else
  ok "执行前 3 个子节点都没有该脚本（下发链路必须真的走一次）"
fi

# ③ 提交。SUB 是全局变量 —— 别用 $(submit) 捕获，那会把函数里的回显一起捕获进去
SUB=""
submit() {
  local body="$1" r
  r="$("${CURL[@]}" -H 'Content-Type: application/json' -XPOST "http://${API}/v1/commands" -d "${body}")"
  info "提交 → ${r}"
  SUB="$(printf '%s' "${r}" | sed -n 's/.*"command_id":"\([^"]*\)".*/\1/p')"
}
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }
payload() { b64 "$(printf '{"script":"%s","params":%s}' "$1" "$2")"; }
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

PARAMS='{"who":"tree","n":1}'
printf '\n③ 提交 script 指令（TREE 聚合）\n'
submit "{\"type\":\"script\",\"aggregate\":\"TREE\",\"on_failure\":\"ALL_MUST_SUCCEED\",\"max_duration\":\"60s\",\"attest_depth\":0,\"payload\":\"$(payload "${SCRIPT_NAME}" "${PARAMS}")\"}"
if [ -z "${SUB}" ]; then fail "提交被拒"; exit 1; fi
OUT="$(poll "${SUB}")"

printf '\n④ 核对结果\n'
if RESULT_JSON="${OUT}" EXPECT_NODES=4 EXPECT_SCRIPT="${SCRIPT_NAME}" EXPECT_PARAMS="${PARAMS}" python3 <<'PY'
import json, os, sys

doc = json.loads(os.environ["RESULT_JSON"])
if doc.get("status") != "COMMAND_STATUS_COMPLETED":
    print("  指令没成功：status=%s" % doc.get("status"))
    sys.exit(1)

agg = json.loads(doc["result"])
rows = []


def walk(n, depth):
    me = n.get("self")
    rows.append((depth, n.get("node_id", "?"), me))
    for c in n.get("nodes") or []:
        walk(c, depth + 1)


walk(agg, 0)

expect_nodes = int(os.environ["EXPECT_NODES"])
expect_script = os.environ["EXPECT_SCRIPT"]
expect_params = json.loads(os.environ["EXPECT_PARAMS"])

problems = []
if len(rows) != expect_nodes:
    problems.append("期望 %d 个节点各有一条结果，实际 %d 条" % (expect_nodes, len(rows)))
for depth, node_id, me in rows:
    pad = "  " * (depth + 1)
    ok = isinstance(me, dict) and me.get("script") == expect_script and me.get("params") == expect_params
    print("%s%s  %s" % (pad, node_id[:13] + "…" if node_id else "?",
                        "params 一致" if ok else "!! 结果不符：%r" % (me,)))
    if not ok:
        problems.append("节点 %s 的结果不是脚本产出的" % node_id[:13])
    if isinstance(me, dict) and not me.get("sha256"):
        problems.append("载荷里没有 sha256 —— 预提交钩子没生效")

for p in problems:
    print("  %s" % p)
sys.exit(1 if problems else 0)
PY
then ok "4 个节点各跑了一次，脚本收到的参数原样就是提交时给的"
else fail "断言未通过（见上）"; fi

printf '\n⑤ 脚本真的落到子节点上了吗（且带父的身份背书）\n'
for f in "${CHILD_SCRIPTS[@]}"; do
  if [ ! -f "$f" ]; then fail "子节点没有拿到脚本：${f}"; continue; fi
  got="$(shasum -a 256 "$f" | awk '{print $1}')"
  if [ "$got" != "${ROOT_SHA}" ]; then fail "子节点的脚本内容与根不一致：${f}"; else ok "下发且逐字节一致：${f#${DEMO}/}"; fi
done
# 落盘只说明"字节到了"；还要确认这份字节带着**父的身份背书**、而且子端验过了。
# 验签发生在收片方（也就是这几个子节点），所以看的是它们自己的日志。
for n in leaf1 relay leaf2; do
  if grep -q "脚本身份背书校验通过" "logs/${n}.log" 2>/dev/null; then
    ok "父的身份背书校验通过：${n}"
  else
    fail "${n} 的日志里没有验签通过记录 —— 签名这道闸门可能没生效"
  fi
done

printf '\n⑥ 冲突覆盖：先塞一份错的同名脚本\n'
TAMPERED="${DEMO}/leaf1/script/${SCRIPT_NAME}"
cat > "${TAMPERED}" <<'SCRIPT'
#!/bin/sh
printf '%s' '{"tampered":true}' > result.json
SCRIPT
chmod 755 "${TAMPERED}"
if [ "$(shasum -a 256 "${TAMPERED}" | awk '{print $1}')" = "${ROOT_SHA}" ]; then
  fail "篡改后的脚本与正确内容相同，用例无效"
else
  ok "已把 ${TAMPERED#${DEMO}/} 换成一份内容错误的脚本"
fi

submit "{\"type\":\"script\",\"aggregate\":\"TREE\",\"on_failure\":\"ALL_MUST_SUCCEED\",\"max_duration\":\"60s\",\"attest_depth\":0,\"payload\":\"$(payload "${SCRIPT_NAME}" "${PARAMS}")\"}"
if [ -z "${SUB}" ]; then
  fail "提交被拒"
else
  OUT2="$(poll "${SUB}")"
  case "${OUT2}" in
    *'"tampered"'*) fail "执行了被篡改的脚本 —— 哈希校验没生效" ;;
    *COMMAND_STATUS_COMPLETED*) ok "被覆盖回正确内容并执行成功（哈希校验 + 无条件覆盖都生效）" ;;
    *) fail "终态不符合预期：${OUT2}" ;;
  esac
  if [ "$(shasum -a 256 "${TAMPERED}" | awk '{print $1}')" = "${ROOT_SHA}" ]; then
    ok "磁盘上的脚本已被覆盖回与根一致"
  else
    fail "磁盘上的脚本没被覆盖回正确内容"
  fi
fi

printf '\n⑦ 负向用例\n'
neg() {  # $1=说明 $2=script 名 $3=期望在响应里出现的关键词
  local label="$1" name="$2" want="$3" r
  r="$("${CURL[@]}" -H 'Content-Type: application/json' -XPOST "http://${API}/v1/commands" \
      -d "{\"type\":\"script\",\"aggregate\":\"TREE\",\"payload\":\"$(payload "${name}" "${PARAMS}")\"}")"
  case "${r}" in
    *"${want}"*) ok "${label}（${want}）" ;;
    *) fail "${label}：期望响应含 ${want}，实际 ${r}" ;;
  esac
}
neg "路径穿越在提交期被拒" "../../keys/id_ed25519" "脚本名"
neg "不存在的脚本在提交期被拒" "no_such_script_xyz" "没有可用的脚本"

submit "{\"type\":\"script\",\"aggregate\":\"TREE\",\"on_failure\":\"ALL_MUST_SUCCEED\",\"max_duration\":\"60s\",\"attest_depth\":0,\"payload\":\"$(payload "big.sh" '{}')\"}"
if [ -z "${SUB}" ]; then
  fail "big.sh 提交被拒"
else
  OUT4="$(poll "${SUB}")"
  case "${OUT4}" in
    *COMMAND_STATUS_FAILED*)
      # 结果查询只回状态、不回错误文案 —— 要看原因得走指令轨迹（/v1/health?command_id=）
      TRACE="$("${CURL[@]}" "http://${API}/v1/health?command_id=${SUB}&depth=-1&detail=true&timeout=20s")"
      case "${TRACE}" in
        *超过上限*) ok "result.json 超限被明确拒绝（不会走到对象存储引用）" ;;
        *) fail "指令失败了，但轨迹里没有'超过上限'的说明：$(printf '%s' "${TRACE}" | head -c 300)" ;;
      esac
      ;;
    *) fail "超限用例的终态不符合预期：${OUT4}" ;;
  esac
fi

printf '\n⑧ 收尾\n'
if [ "${KEEP}" = "keep" ]; then
  info "树留着：控制台 http://127.0.0.1:8899/"
fi
printf '\n'
[ "${FAILED}" = "0" ] && printf '\033[32m全部通过\033[0m\n' || printf '\033[31m有失败项，日志在 logs/\033[0m\n'
exit "${FAILED}"
