#!/usr/bin/env bash
#
# run_all.sh —— 一条命令把 test/ 下的全部端到端验收串起来跑完，逐个存日志。
#
#   ./run_all.sh                跑全部 12 套
#   ./run_all.sh <名字>...      只跑指定几套（名字见下面的 SUITES）
#   ./run_all.sh --list         只列名字，不跑
#
# 产物：
#   ${RUNLOG_DIR}/<名字>.log    每套的完整输出（SUMMARY 之外再看细节就看这里）
#   ${RUNLOG_DIR}/SUMMARY.txt   环境指纹（主机/系统/架构/四份产物的哈希）+ 逐套 rc 与耗时
#   ${RUNLOG_TARBALL}           上面整个目录的 tar.gz —— 传回开发机上复盘用
#
# 退出码：全部 rc=0 时为 0；有任一套非 0 时为 1（**能在 CI 里直接当门禁**）。
#
# 环境变量：
#   TREECMD_REPO     仓库路径（默认由脚本位置推导）
#   RUNLOG_DIR       日志目录（默认 ${HERE}/.runlogs）
#   RUNLOG_TARBALL   日志包路径（默认 ${TMPDIR:-/tmp}/treecmd-runlogs.tar.gz；设为空串则不打包）
#   PYTHON           python3 解释器（默认取 PATH 上的 python3）
#
# ── 为什么值得单独有一个驱动脚本 ────────────────────────────────────────────
#
# 各套脚本自己都是自包含的（各自起树、自己收尾），但**串起来跑**时会出现只在
# "上一套刚跑完"这个时刻才有的问题，最要紧的是 `clean()` 里那两件：
#
#   · `demo/root/state.dat` 记着"这个根历史上注册过哪些子节点"，而 `demo.sh start`
#     每次都会给子节点换一批 NodeID（`prepare_child` 重新 genkey）⇒ 上一轮那批变成
#     **永远不上报的死人**。指令要等**所有登记过的子**都落终态，死人会把每条指令一路
#     拖到期限：第一次跑的时候 `api_manual` 的 4 条聚合指令各等了 40 秒（`wait_done`
#     超时），而程序完全正常 —— "跑得慢"于是被误读成"功能坏了"。
#   · `logs/` 里的旧内容会污染"日志里有没有这条指令 ID"这类断言。
#
# 所以每套开跑前把 `demo/`、`logs/`、`.demo.pids` 一起挪走。用 `mv` 挪到临时目录而不是
# `rm`：现场留下来便于回查（每次挪到带时间戳与 pid 的目录，反复跑不互相覆盖）。
#
# ── 和"目标机不装 Go"的关系 ────────────────────────────────────────────────
#
# 这个脚本**不编译、也不设置任何编译相关的环境变量**（不起 `GOFLAGS`/`GOPROXY`/
# `GOTOOLCHAIN`，也不往 PATH 里塞 Go）。产物从哪来是各套脚本通过 `lib/prebuilt.sh`
# 自己决定的事 —— 有 Go 就现编，没有就用带来的预编译产物。驱动只负责两件事：
# 开跑前**如实报告**产物齐不齐（只读检查，不代编），跑完**如实汇总** rc。
#
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
CA_HELPER="${REPO}/bin/ca-rotate"

. "${HERE}/lib/platform.sh"   # 跨平台：文件摘要（GNU 上是 sha256sum，BSD 上是 shasum）

export LANG=C.UTF-8 LC_ALL=C.UTF-8

# python3：本仓库的约定是 `/usr/bin/python3`（macOS 与 openEuler 都自带），
# 但既然这是入口脚本，就多兜一步 —— 取不到 PATH 上的再退回那个约定路径。
PY="${PYTHON:-$(command -v python3 2>/dev/null || echo /usr/bin/python3)}"
export PYTHON="${PY}"

cd "${HERE}" || { echo "进不去 ${HERE}" >&2; exit 1; }

OUT="${RUNLOG_DIR:-${HERE}/.runlogs}"
mkdir -p "${OUT}"
SUM="${OUT}/SUMMARY.txt"

ROOT_API=127.0.0.1:18493

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

if command -v go >/dev/null 2>&1; then
  GO_NOTE="本机有 Go，用到它的那套会现编"
else
  GO_NOTE="本机没有 Go，用到它的那套会响亮报错（见 lib/prebuilt.sh）"
fi

# clean —— 把上一套可能留下的进程/端口/运行目录清干净，避免"串到旧树上"的假象。
clean() {
  ./demo.sh       stop >/dev/null 2>&1 || true
  ./zero-trust.sh stop >/dev/null 2>&1 || true
  ./enroll-policy.sh stop >/dev/null 2>&1 || true
  ./api-auth.sh   stop >/dev/null 2>&1 || true
  ./selfupdate.sh stop >/dev/null 2>&1 || true
  # 用 [t] 的字符类写法：直接写 'treecmd-node' 会让 pkill 匹配到"自己这条命令行"
  # （远端 shell 的 argv 里就带着这个字符串），于是脚本把自己杀掉。
  # pkill 在精简发行版里可能没有（本仓库的测试机就缺过别的工具），缺了不致命：上面的
  # 各 `stop` 才是主线，pkill 只是兜底那些没记进 pid 表的残留。
  if command -v pkill >/dev/null 2>&1; then
    pkill -f '[t]reecmd-node' >/dev/null 2>&1 || true
    pkill -f '[t]est/serve.py' >/dev/null 2>&1 || true
  fi
  local trash="${TMPDIR:-/tmp}/tc-run-trash-${SECONDS}-$$"
  mkdir -p "${trash}"
  local d
  for d in demo logs .demo.pids; do
    [ -e "${d}" ] && mv "${d}" "${trash}/" 2>/dev/null
  done
  sleep 1
}

# digest_or_absent <路径> —— 摘要前 16 位；文件不在就回「（未提供）」。
#
# 不直接用 lib/platform.sh 的 sha256_of 有一个原因：它**刻意不吞错误**（取不到就返回非 0，
# 让调用方的断言自己失败 —— 静默返回空串会让断言以"值不对"的形式失败，看不出是工具缺失）。
# 那个口径对断言是对的，但 SUMMARY 的环境指纹只是**说明性**的，缺 v1/v2 是完全正常的
# （本机有 Go 的话它们要到跑 selfupdate 时才现编），不该在这里喷三行 No such file or directory。
digest_or_absent() {
  [ -x "$1" ] || { printf '%s' '（未提供）'; return 0; }
  sha256_of "$1" 2>/dev/null | cut -c1-16
}

# ── 前置检查：产物齐不齐（**只读**，不代编）────────────────────────────────
# 缺产物必须**在开跑之前**说出来。否则要等到某一套红了才发现，而红的原因看起来像
# "功能坏了" —— 这正是 lib/prebuilt.sh 那一整节想避免的读取方式。
preflight() {
  local f missing=0
  for f in "${BIN}" "${BIN}.v1" "${BIN}.v2" "${CA_HELPER}"; do
    if [ -x "${f}" ]; then
      ok "产物在：${f#${REPO}/}  $(digest_or_absent "${f}")"
    else
      warn "缺产物：${f} —— ${GO_NOTE}"
      missing=1
    fi
  done
  # 主镜像不在就一套都跑不了，这是唯一值得当场中止的。
  [ -x "${BIN}" ] || die "主镜像 ${BIN} 不在，无法开始"
  [ "${missing}" -eq 0 ] || \
    warn "有产物缺失：下面是**照跑**的，但请把相关那几套的 rc 读成「环境缺产物」而不是「功能坏了」"
  return 0
}

# ── 附加：手工 API 冒烟（8 种聚合/失败策略 + 取消/轨迹/清理预览 + 拒绝路径）──
# 这一套不属于 test/ 下的某个脚本，但把"HTTP API 全表"过一遍，补上各脚本各自的局部覆盖。
api_manual() {
  ./demo.sh start
  sleep 1
  TOK="$("${BIN}" -config demo/root/node.yaml -adduser manual -force >/dev/null 2>&1; cat demo/root/user/manual)"
  get()  { curl -s --noproxy '*' -H "X-Treecmd-Token: ${TOK}" "$@"; }
  submit() {  # submit <json> → 只回 command_id
    get -H 'Content-Type: application/json' -XPOST "http://${ROOT_API}/v1/commands" -d "$1" \
      | "${PY}" -c 'import json,sys
try: print(json.load(sys.stdin).get("command_id",""))
except Exception: print("")'
  }
  # 轮询到终态；超时时**把最后一次响应原文打出来**。
  #
  # 为什么必须打：`NOT_FOUND（结果不在本节点，且索引未命中）`是"还在跑"的正常中间态，
  # 而它和"这条指令根本没人管"在只看状态摘要时长得一模一样（都取不到 status）。
  # 超时不带证据的话，看到的就是一行 `status = None`，什么也说明不了。
  # 另外：`wait_done` 里**必须继续轮询** NOT_FOUND，别把它当错误。
  LAST_RAW=""
  wait_done() {  # wait_done <cid> [秒]
    local i st=""
    for i in $(seq 1 "${2:-40}"); do
      LAST_RAW="$(get "http://${ROOT_API}/v1/commands/$1")"
      st="$(printf '%s' "${LAST_RAW}" | "${PY}" -c 'import json,sys
try: print(json.load(sys.stdin).get("status",""))
except Exception: print("")' 2>/dev/null)"
      case "${st}" in
        COMMAND_STATUS_COMPLETED|COMMAND_STATUS_FAILED|COMMAND_STATUS_TIMEOUT|COMMAND_STATUS_CANCELLED) printf '%s' "${st}"; return 0 ;;
      esac
      sleep 1
    done
    printf '%s' "${st:-POLL_TIMEOUT}"
  }
  show() { get "http://${ROOT_API}/v1/commands/$1" | "${PY}" -c '
import json,sys
d=json.load(sys.stdin)
print("  status =", d.get("status"), " result_bytes =", d.get("result_bytes"))
r=d.get("result")
if isinstance(r,str):
    try: r=json.loads(r)
    except Exception: pass
print("  result =", json.dumps(r, ensure_ascii=False)[:600])
'; }

  # 提交一条聚合并等终态，顺带给出**明确结论**（不是只把响应摊在那里）。
  # 失败时把最后一次响应原文打出来 —— 否则只看到一行 `status = None`，无从判断是
  # "还在跑"还是"程序真的坏了"。
  run_agg() {   # run_agg <显示名> <提交 JSON>
    local name="$1" body="$2" cid st
    cid="$(submit "${body}")"
    if [ -z "${cid}" ]; then
      echo "  ✗ ${name}：提交就没成功（空 command_id）"
      return 1
    fi
    st="$(wait_done "${cid}")"
    echo "  cid=${cid} 终态=${st}"
    show "${cid}"
    if [ "${st}" = "COMMAND_STATUS_COMPLETED" ]; then
      echo "  ✓ ${name} 跑通"
    else
      echo "  ✗ ${name} 没到终态（${st}）"
      echo "    最后一次响应：${LAST_RAW}"
    fi
  }

  echo "════ /v1/tree（RAW，看字段口径）════"
  get "http://${ROOT_API}/v1/tree" | "${PY}" -m json.tool

  echo
  echo "════ /v1/health?depth=-1&detail=true（RAW，看 SubtreeSummary 的真实键名）════"
  get "http://${ROOT_API}/v1/health?depth=-1&detail=true&timeout=20s" | "${PY}" -m json.tool | head -80

  echo
  echo "════ /v1/health/summary ════"
  get "http://${ROOT_API}/v1/health/summary?depth=-1&timeout=20s" | "${PY}" -m json.tool | head -30

  echo
  echo "════ /v1/crl ════"
  get "http://${ROOT_API}/v1/crl"; echo

  echo
  echo "════ /metrics ════"
  get "http://${ROOT_API}/metrics" | head -40

  echo
  echo "════ ① COUNT 聚合（4 节点树应得 4）════"
  run_agg "COUNT 聚合" '{"type":"noop","aggregate":"COUNT"}'

  echo
  echo "════ ② SUM 聚合 ════"
  run_agg "SUM 聚合" '{"type":"noop","aggregate":"SUM"}'

  echo
  echo "════ ③ MERGE 聚合 ════"
  run_agg "MERGE 聚合" '{"type":"echo","payload":"eyJhIjoxfQ==","aggregate":"MERGE"}'

  echo
  echo "════ ④ CUSTOM 聚合（内建 subtree_count）════"
  run_agg "CUSTOM 聚合" '{"type":"noop","aggregate":"CUSTOM","aggregate_name":"subtree_count"}'

  echo
  echo "════ ⑤ 未注册的自定义聚合器 → 提交期即拒 ════"
  echo -n "  响应: "; get -H 'Content-Type: application/json' -XPOST "http://${ROOT_API}/v1/commands" \
    -d '{"type":"noop","aggregate":"CUSTOM","aggregate_name":"nope_not_registered"}'; echo

  echo
  echo "════ ⑥ target=NODE（点对点已下线）→ ERR_TARGET_NOT_SUPPORTED ════"
  echo -n "  响应: "; get -H 'Content-Type: application/json' -XPOST "http://${ROOT_API}/v1/commands" \
    -d '{"type":"noop","target":{"mode":"NODE","node_id":"0198f0c0-0000-7000-8000-0000de000001"}}'; echo

  echo
  echo "════ ⑦ idempotent 标志的真实口径（**它不是"幂等键"**）════"
  # 这里原来写的是一条**错的**用例，而且它会"空手通过"，值得说清楚：
  #   · 提交体里写的是 {"idempotent":"manual-idem-1"} —— 把 idempotent 当成了字符串幂等键；
  #   · 而它在 API 里是 **bool**（`bool idempotent = 13`，见 api/proto/node.proto 与
  #     internal/node/submit.go 的 SubmitRequest）⇒ 服务端 400
  #     `json: cannot unmarshal string into Go struct field SubmitRequest.idempotent of type bool`；
  #   · 老写法只看"两次拿到的 command_id 是否相同"，而**两次失败都拿到空串、空串等于空串**
  #     ⇒ 报告出来是"✓ 幂等命中"，纯属自欺。
  # 现在的口径：字段是布尔标志（"同一 command_id 被重投时回放终态"，实现见
  # internal/node/handle.go 的"已终态：幂等命中，直接回放终态"），提交接口**不做内容级去重**。
  IDEM_BODY="${OUT}/.idem.json"
  LAST_ID=""
  P() {  # P <说明> <json> → 打印 HTTP 码与响应体，并把 command_id 留在 $LAST_ID
    printf '  %-42s → ' "$1"
    curl -s -o "${IDEM_BODY}" -w 'HTTP %{http_code}  ' \
      -H "X-Treecmd-Token: ${TOK}" -H 'Content-Type: application/json' \
      -XPOST "http://${ROOT_API}/v1/commands" -d "$2"
    cat "${IDEM_BODY}"; echo
    LAST_ID="$("${PY}" -c 'import json,sys
try: print(json.load(open(sys.argv[1])).get("command_id",""))
except Exception: print("")' "${IDEM_BODY}")"
  }
  P "idempotent=true（合法布尔）" '{"type":"noop","aggregate":"COUNT","idempotent":true}'
  I1="${LAST_ID}"
  P "同样内容再提一次" '{"type":"noop","aggregate":"COUNT","idempotent":true}'
  I2="${LAST_ID}"
  P "idempotent 写成字符串（类型不对）" '{"type":"noop","aggregate":"COUNT","idempotent":"manual-idem-1"}'
  if [ -n "${I1}" ] && [ -n "${I2}" ] && [ "${I1}" != "${I2}" ]; then
    echo "  ✓ idempotent 是布尔标志、提交不做内容级去重（两次拿到不同的指令 ID）"
  else
    echo "  ✗ 期望两次拿到**不同**的非空指令 ID（I1='${I1}' I2='${I2}'）"
  fi
  if grep -q 'idempotent of type bool' "${IDEM_BODY}" 2>/dev/null; then
    echo "  ✓ 类型写错被明确拒绝（文案点名 idempotent 是 bool）—— 说明它不是「幂等键」"
  else
    echo "  ✗ 类型写错没有按预期被拒：$(cat "${IDEM_BODY}")"
  fi

  echo
  echo "════ ⑧ 失败策略：全树 fail（4 个节点全失败）════"
  for pol in ALL_MUST_SUCCEED BEST_EFFORT TOLERATE_N:2; do
    CID="$(submit "{\"type\":\"fail\",\"aggregate\":\"COUNT\",\"on_failure\":\"${pol}\"}")"
    echo "  on_failure=${pol} → 终态 $(wait_done "$CID" 25)"
  done

  echo
  echo "════ ⑨ 慢指令（sleep 5000ms）+ 取消 ════"
  CID="$(submit '{"type":"sleep","payload":"NTAwMA==","aggregate":"COUNT"}')"
  printf '  cid=%s（payload=NTAwMA== 即 "5000" 毫秒）\n' "$CID"
  sleep 1
  echo -n "  取消响应: "; get -XPOST "http://${ROOT_API}/v1/commands/${CID}/cancel"; echo
  echo "  取消后终态 = $(wait_done "$CID" 15)"

  echo
  echo "════ ⑩ 指令轨迹（/v1/health?command_id=）════"
  get "http://${ROOT_API}/v1/health?command_id=${CID}&depth=-1&detail=true&timeout=20s" \
    | "${PY}" -m json.tool | head -40

  echo
  echo "════ ⑪ /v1/forget 清理预览（GET，只读）════"
  LEAF="$(get "http://${ROOT_API}/v1/tree" | "${PY}" -c '
import json,sys
d=json.load(sys.stdin)
for c in d.get("children") or []:
    if c.get("node_name")=="leaf-alpha": print(c["node_id"]); break')"
  echo "  leaf-alpha = ${LEAF}"
  get "http://${ROOT_API}/v1/forget?node=${LEAF}" | "${PY}" -m json.tool | head -20

  echo
  echo "════ ⑫ scripts/api_call.py（GET 读 + POST 提交）════"
  echo "  --- GET /v1/tree ---"
  "${PY}" "${REPO}/scripts/api_call.py" GET /v1/tree --host "${ROOT_API}" \
      --token-file demo/root/user/manual 2>&1 | head -c 400; echo
  echo "  --- POST /v1/commands ---"
  echo '{"type":"echo","payload":"YXBpX2NhbGw=","aggregate":"TREE"}' \
    | "${PY}" "${REPO}/scripts/api_call.py" POST /v1/commands --host "${ROOT_API}" \
        --token-file demo/root/user/manual --data - 2>&1 | head -5

  ./demo.sh stop
}

# selfupdate 一套其实是三个子命令，而且三个都得跑完（各自的日志都是证据）。
# 所以这里**不用 `&&` 短路**：全跑，再按"有一个非 0 就算这套非 0"汇总。
suite_selfupdate() {
  local p a r
  ./selfupdate.sh prepare;  p=$?
  ./selfupdate.sh all;      a=$?
  ./selfupdate.sh readonly; r=$?
  [ "${p}" -eq 0 ] && [ "${a}" -eq 0 ] && [ "${r}" -eq 0 ]
}

SUITES="api_manual uuid_v4 script from-any-node forget zero-trust enroll-policy api-auth ca-rotate backpressure command-deadline selfupdate"
case "${1:-}" in
  -h|--help) sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  --list)    printf '%s\n' ${SUITES}; exit 0 ;;
esac
[ $# -gt 0 ] && SUITES="$*"

preflight

# Ctrl-C 时别把树留在后台占着 18493/19493 —— 下一套起不来会表现成"端口被占"的假失败。
trap 'echo; warn "收到中断，正在停树…"; clean; exit 130' INT TERM

: > "${SUM}"
{
  echo "══════════════════════ 环境 ══════════════════════"
  echo "主机      : $(hostname)"
  if [ -r /etc/os-release ]; then
    echo "系统      : $(sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '"')"
  else
    echo "系统      : $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null)"
  fi
  echo "架构/内核 : $(uname -m) / $(uname -r)"
  echo "Go        : $(command -v go || echo '未安装 —— 走 test/lib/prebuilt.sh 的预编译通路，不在目标机编译')"
  echo "python3   : ${PY}"
  echo "主镜像    : $(digest_or_absent "${BIN}")"
  echo "变体 v1   : $(digest_or_absent "${BIN}.v1")"
  echo "变体 v2   : $(digest_or_absent "${BIN}.v2")"
  echo "CA 做旧   : $(digest_or_absent "${CA_HELPER}")"
  echo "日志目录  : ${OUT}"
  echo
} >> "${SUM}"

FAILED=0
for name in ${SUITES}; do
  clean
  t0=${SECONDS}
  case "${name}" in
    api_manual)       api_manual > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    uuid_v4)          ./uuid_v4.sh    > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    script)           ./script.sh     > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    from-any-node)    ./from-any-node.sh > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    forget)           ./forget.sh     > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    zero-trust)       ./zero-trust.sh > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    enroll-policy)    ./enroll-policy.sh > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    api-auth)         ./api-auth.sh   > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    ca-rotate)        ./ca-rotate.sh  > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    backpressure)     ./backpressure.sh > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    command-deadline) ./command-deadline.sh > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    selfupdate)       suite_selfupdate > "${OUT}/${name}.log" 2>&1 ; rc=$? ;;
    *)                echo "未知用例 ${name}（可用：${SUITES}）" > "${OUT}/${name}.log" ; rc=99 ;;
  esac
  dt=$((SECONDS - t0))
  # 断言条数也记进 SUMMARY：只看 rc 的话，"跑了但一条断言都没执行"和"全过"是同一个 0。
  # 注意别写成 `grep -c … || echo 0` —— 没命中时 `grep -c` **已经**打了一个 0 并以 1 退出，
  # 于是会多打一行、把后面几列挤歪。取到空串时才补 0。
  n_ok=$(grep -c '✓' "${OUT}/${name}.log" 2>/dev/null || true)
  n_bad=$(grep -c '✗' "${OUT}/${name}.log" 2>/dev/null || true)
  printf '%-17s rc=%-3s %4ss  ✓=%-4s ✗=%s\n' "${name}" "${rc}" "${dt}" "${n_ok:-0}" "${n_bad:-0}" >> "${SUM}"
  printf '[%-16s] rc=%-3s %4ss  ✓=%-4s ✗=%s\n' "${name}" "${rc}" "${dt}" "${n_ok:-0}" "${n_bad:-0}"
  [ "${rc}" -eq 0 ] || FAILED=$((FAILED + 1))
done

clean

if [ "${FAILED}" -eq 0 ]; then
  printf '\n全部 %s 套 rc=0\n' "$(printf '%s\n' ${SUITES} | wc -l | tr -d ' ')" | tee -a "${SUM}"
else
  printf '\n有 %s 套非 0（明细见上面的 rc 与各套日志）\n' "${FAILED}" | tee -a "${SUM}"
fi

echo
echo "════════════ SUMMARY ════════"
cat "${SUM}"

TARBALL="${RUNLOG_TARBALL-${TMPDIR:-/tmp}/treecmd-runlogs.tar.gz}"
if [ -n "${TARBALL}" ]; then
  "${PY}" - "$OUT" "$TARBALL" <<'PY'
import os, sys, tarfile
src, dst = sys.argv[1], sys.argv[2]
if os.path.exists(dst):
    os.remove(dst)
with tarfile.open(dst, 'w:gz') as t:
    t.add(src, arcname=os.path.basename(src))
print("日志包：%s （%.1f KB）" % (dst, os.path.getsize(dst) / 1024))
PY
fi

[ "${FAILED}" -eq 0 ] || exit 1
exit 0
