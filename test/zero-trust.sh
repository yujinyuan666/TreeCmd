#!/usr/bin/env bash
#
# zero-trust.sh —— 验收「子节点的信任锚可以从自己的证书链自举」
#
# 证哪条不变量：
#   **入网成功之后，`trust/` 与 `security.ca_cert_paths` 都可以删掉** —— 子节点仍然能启动
#   （不 REFUSE TO START）、仍然能连上父、父仍然能验它的证书、指令仍然跑得完。
#   信任锚的来源变成"本节点自己的证书链"（`identity.ChainAnchors`，取 `chain[1:]`）。
#
# 顺带把三条**刻意设计**的边界钉死（它们是设计而不是遗漏，所以必须被脚本证到）：
#   ① 配置里写了 `ca_cert_paths`、文件却被删了 ⇒ **按预期拒绝启动**（fail-fast，不静默降级）；
#   ② 首次入网（手上还没有证书）**仍然必须有锚** —— 没有证书就没有可自举的链，
#      而首跳必须能把父的服务端证书验到某个锚上，否则谁都能冒充父给你发证书；
#   ③ 首次入网要的锚是「**父的** CA」—— 父的 `certs/node.crt.ca`（整份文件，含父 CA 一路到根），
#      **不需要根节点的 CA**。这正是"每个节点只对自己的父节点负责"在部署上的落点。
#
# 另有一段与信任锚正交、但同属"部署形态"的验证（第 ⓪ 步）：
#   `scripts/init_root.sh` 的**零参数**形态 —— 目录默认当前目录、NodeID 现场生成 UUIDv7，
#   且 `node.yaml` 里不写 `node.id` 也能起来（程序按 ADR-050 从证书里读回同一枚 ID）。
#
# 用法：
#   ./zero-trust.sh          跑完整验证，结束后自动清场
#   ./zero-trust.sh keep     跑完留着树（自己 ./zero-trust.sh stop 收）
#   ./zero-trust.sh stop     只清场
#
# 端口：根 listen 19593 / api 18593；中继 listen 19594（与 demo.sh 的 19493/18493 错开）。
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
INIT_ROOT="${REPO}/scripts/init_root.sh"
WORK="${HERE}/zerotrust"
LOGS="${WORK}/logs"
PIDFILE="${HERE}/.zerotrust.pids"

ROOT_ID="0198f0c0-0000-7000-8000-0000abc00001"
ROOT_LISTEN="127.0.0.1:19593"
ROOT_API="127.0.0.1:18593"
RELAY_LISTEN="127.0.0.1:19594"
# 第 ⓪ 步（init_root.sh 零参数形态）起的那个临时根用的端口
AUTO_LISTEN="127.0.0.1:19693"
AUTO_API="127.0.0.1:18693"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# ── 写 node.yaml ────────────────────────────────────────────────────────────
# write_root_yaml <目录>
write_root_yaml() {
  local dir="$1"
  mkdir -p "${dir}"
  cat > "${dir}/node.yaml" <<EOF
node:
  name: zt-root
  remark: "zero-trust 验收的根"
  listen: ${ROOT_LISTEN}
security:
  ca_cert_path: certs/node.crt.ca
  ca_key_path: keys/ca
  ca_cert_paths: [certs/node.crt.ca]
  enrollment: { enabled: true, token_path: enroll.token }
api:
  http_addr: ${ROOT_API}
EOF
  chmod 600 "${dir}/node.yaml"
}

# write_child_yaml <目录> <名字> <备注> <listen或空> <父 addr> <父 ID> <yes=写 ca_cert_paths>
write_child_yaml() {
  local dir="$1" name="$2" remark="$3" listen="$4" parent="$5" parent_id="$6" anchors="$7"
  mkdir -p "${dir}"
  {
    echo "node:"
    echo "  name: ${name}"
    echo "  remark: \"${remark}\""
    [ -n "${listen}" ] && echo "  listen: ${listen}"
    echo "parents:"
    echo "  - id: ${parent_id}"
    echo "    addr: ${parent}"
    echo "security:"
    # anchors=no 就是"入网成功后把 ca_cert_paths 整段删掉"的那个形态
    [ "${anchors}" = "yes" ] && echo "  ca_cert_paths: [trust]"
    [ -n "${listen}" ] && echo "  ca_key_path: keys/ca"
    echo "  enrollment: { enabled: true, token_path: enroll.token }"
  } > "${dir}/node.yaml"
  chmod 600 "${dir}/node.yaml"
}

# ── 进程管理 ────────────────────────────────────────────────────────────────
start_one() {  # <名字> <目录>
  local name="$1" dir="$2"
  # 每次启动**先把上一份日志挪走再建空文件**。日志是追加的，留在原地会让"等待某条日志出现"
  # 这类断言匹配到**上一次启动**的记录而**假通过**（实测踩到：第④步重启中继时，
  # wait_registered 立刻命中了第②步那条 msg=registered，紧接着本次启动的锚来源行还没落盘，
  # 断言就扑空了）。想回看上一轮就看 <名字>.prev.log。
  if [ -f "${LOGS}/${name}.log" ]; then mv -f "${LOGS}/${name}.log" "${LOGS}/${name}.prev.log"; fi
  : > "${LOGS}/${name}.log"
  "${BIN}" -config "${dir}/node.yaml" >> "${LOGS}/${name}.log" 2>&1 &
  echo "${name}:$!" >> "${PIDFILE}"
}

stop_one() {   # <名字> —— 停掉并从 pid 表摘掉
  local name="$1"
  [ -f "${PIDFILE}" ] || return 0
  while IFS=: read -r n p; do
    [ "${n}" = "${name}" ] || continue
    kill -TERM "${p}" 2>/dev/null || true
    for _ in $(seq 1 40); do kill -0 "${p}" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "${p}" 2>/dev/null || true
  done < "${PIDFILE}"
  grep -v "^${name}:" "${PIDFILE}" > "${PIDFILE}.tmp" || true
  mv "${PIDFILE}.tmp" "${PIDFILE}"
}

cmd_stop() {
  [ -f "${PIDFILE}" ] || { info "没有在跑的验收树"; return 0; }
  while IFS=: read -r n p; do
    kill -TERM "${p}" 2>/dev/null && ok "已停止 ${n} (pid ${p})" || info "${n} 早已退出"
  done < "${PIDFILE}"
  rm -f "${PIDFILE}"
}

wait_registered() {  # <日志> <超时秒> <说明>
  local f="$1" t="${2:-20}" what="${3:-注册}"
  for _ in $(seq 1 $((t * 2))); do
    grep -q 'msg=registered' "$f" 2>/dev/null && { ok "${what}"; return 0; }
    sleep 0.5
  done
  warn "${what}超时（${t}s）—— 看 ${f}"
  return 1
}

wait_api() {  # <超时秒>
  for _ in $(seq 1 $((${1:-20} * 2))); do
    curl -s -o /dev/null --max-time 1 "http://${ROOT_API}/v1/healthz" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}

# expect_refuse <说明> <期望错误关键字> <目录> —— 起一次，必须在几秒内非零退出且报出该关键字
#
# ⚠️ 刻意**有界**：如果被验的配置其实能起来，前台直接跑会把这个验收脚本永久挂住
# （实测踩过：一条本该拒绝启动的用例因为凭据里自带了 CA 而启动成功，脚本就再也不返回了）。
# 所以这里后台起、轮询等待退出，超时即判失败并杀掉。
expect_refuse() {
  local what="$1" want="$2" dir="$3" log="${LOGS}/refuse.log" rc=0
  : > "${log}"
  "${BIN}" -config "${dir}/node.yaml" >> "${log}" 2>&1 &
  local pid=$!
  local alive=1
  for _ in $(seq 1 40); do
    if ! kill -0 "${pid}" 2>/dev/null; then alive=0; break; fi
    sleep 0.25
  done
  if [ "${alive}" = "1" ]; then
    kill -TERM "${pid}" 2>/dev/null || true
    sleep 0.5
    kill -KILL "${pid}" 2>/dev/null || true
    die "${what}：本该拒绝启动，它却一直在跑（看 ${log}）"
  fi
  wait "${pid}" 2>/dev/null || rc=$?
  [ "${rc}" -ne 0 ] || die "${what}：退出码是 0，本该非零（看 ${log}）"
  grep -q "${want}" "${log}" || die "${what}：拒绝了，但错误里没有「${want}」（看 ${log}）"
  ok "${what}"
}

# ── 主流程 ──────────────────────────────────────────────────────────────────
cmd_run() {
  [ -x "${BIN}" ] || die "找不到 ${BIN}；先在仓库里 go build -o bin/treecmd-node ./cmd/node"
  [ -x "${INIT_ROOT}" ] || die "找不到 ${INIT_ROOT}"

  cmd_stop >/dev/null 2>&1 || true
  rm -rf "${WORK}"
  mkdir -p "${LOGS}"

  # 端口体检：上一轮被中断（比如某个断言 die 了）时可能留下**还在跑**的旧节点，
  # 而旧进程照样在监听同样的端口 —— 于是"根已上线"会变成**假通过**（命中的是旧进程的 API），
  # 后面所有结论都建立在错的树上。宁可在这里明确失败，也不静默串台。
  if command -v lsof >/dev/null 2>&1; then
    for p in "${ROOT_API##*:}" "${ROOT_LISTEN##*:}" "${RELAY_LISTEN##*:}" "${AUTO_API##*:}" "${AUTO_LISTEN##*:}"; do
      if lsof -nP -iTCP:"${p}" -sTCP:LISTEN >/dev/null 2>&1; then
        die "端口 ${p} 已被占用 —— 多半是上一次验收留下的节点。先 ./zero-trust.sh stop，或手工 kill 掉占用者再跑"
      fi
    done
  fi

  echo "════════════════════════════════════════════════════════════════"
  echo " zero-trust 验收：信任锚自举（入网成功后不再需要 trust/）"
  echo "   工作目录  ${WORK}"
  echo "   二进制    ${BIN}"
  echo "════════════════════════════════════════════════════════════════"

  step "⓪ init_root.sh 的零参数形态：目录 = 当前目录、NodeID 自动生成、node.yaml 不用填 node.id"
  # 这一段证的是"根怎么造出来"最省的那条路（与信任锚正交，但同属部署形态，所以放一起）：
  #   · 不带任何参数跑 → 材料落在**当前目录**，NodeID 由脚本现场造一枚 UUIDv7；
  #   · node.yaml 里**不写** node.id 也能起来 —— 程序按 ADR-050 的顺序解析身份
  #     （node.yaml → 证书身份 → state.dat → 新生成），证书一旦签发就是权威来源。
  AUTO_DIR="${WORK}/autoargs"
  mkdir -p "${AUTO_DIR}"
  OUT="$(cd "${AUTO_DIR}" && "${INIT_ROOT}" 2>&1)" || die "零参数 init_root.sh 失败了：
${OUT}"
  AUTO_ID="$(printf '%s\n' "${OUT}" | sed -n 's/^ *根节点 ID  \([0-9a-f-]\{36\}\).*/\1/p' | head -1)"
  [ -n "${AUTO_ID}" ] || die "没能从输出里解析出自动生成的 NodeID（输出见上）"
  case "${AUTO_ID}" in
    ????????-????-7???-[89ab]???-????????????) ;;
    *) die "自动生成的 ID 不符合 UUIDv7 形态（版本位/变体位不对）: ${AUTO_ID}" ;;
  esac
  [ -f "${AUTO_DIR}/certs/node.crt" ] || die "材料没落在**当前目录** —— 节点目录的默认值不对"
  AUTO_CN="$(openssl x509 -in "${AUTO_DIR}/certs/node.crt" -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
  [ "${AUTO_CN}" = "${AUTO_ID}" ] || die "证书 CN（${AUTO_CN}）≠ 自动生成的 NodeID（${AUTO_ID}）"
  ok "零参数 = 当前目录 + 自动 UUIDv7（${AUTO_ID}），且证书 CN 就是它"

  # 故意**不写** node.id
  cat > "${AUTO_DIR}/node.yaml" <<EOF
node:
  name: zt-auto
  listen: ${AUTO_LISTEN}
security:
  ca_cert_path: certs/node.crt.ca
  ca_key_path: keys/ca
api:
  http_addr: ${AUTO_API}
EOF
  start_one autoargs "${AUTO_DIR}"
  FOUND=0
  for _ in $(seq 1 40); do
    grep -q 'node.id 取自证书身份' "${LOGS}/autoargs.log" 2>/dev/null && { FOUND=1; break; }
    sleep 0.25
  done
  [ "${FOUND}" = "1" ] || die "程序没有从证书里解析出 node.id（看 ${LOGS}/autoargs.log）"
  AUTO_RUN="$(curl -s -m 2 "http://${AUTO_API}/v1/healthz" \
    | python3 -c 'import sys,json;print(json.load(sys.stdin).get("node_id",""))' 2>/dev/null || true)"
  [ "${AUTO_RUN}" = "${AUTO_ID}" ] || die "运行时身份（${AUTO_RUN:-空}）≠ 自动生成的 NodeID（${AUTO_ID}）"
  ok "node.yaml 不填 node.id 也能起来，身份就是那枚自动生成的 ID（ADR-050）"
  stop_one autoargs

  step "① 根（自签材料，提供 HTTP API）"
  "${INIT_ROOT}" "${WORK}/root" "${ROOT_ID}" >/dev/null
  ok "根的自签材料已生成"
  write_root_yaml "${WORK}/root"
  start_one root "${WORK}/root"
  wait_api 20 || die "根的 HTTP API 没起来（看 ${LOGS}/root.log）"
  ok "根已上线"

  step "② 中继：首次入网 —— 只投放**父（根）的** CA 证书链"
  "${BIN}" -genkey -keydir "${WORK}/relay/keys" -with-ca >/dev/null
  mkdir -p "${WORK}/relay/trust"
  cp "${WORK}/root/certs/node.crt.ca" "${WORK}/relay/trust/parent-ca.crt"
  cp "${WORK}/root/enroll.token" "${WORK}/relay/enroll.token"; chmod 600 "${WORK}/relay/enroll.token"
  write_child_yaml "${WORK}/relay" "zt-relay" "中间层" "${RELAY_LISTEN}" "${ROOT_LISTEN}" "${ROOT_ID}" yes
  start_one relay "${WORK}/relay"
  wait_registered "${LOGS}/relay.log" 25 "中继用「父的 CA」入网并注册" || die "中继没能入网"
  RELAY_ID="$(grep -o 'node_id=[0-9a-f-]\{36\}' "${LOGS}/relay.log" | head -1 | cut -d= -f2)"
  [ -n "${RELAY_ID}" ] || die "读不到中继的 node_id（看 ${LOGS}/relay.log）"
  ok "中继 NodeID = ${RELAY_ID}"

  step "③ 中继：删掉 trust/ —— 边界①「配置写了就必须存在」仍要拦"
  rm -rf "${WORK}/relay/trust"
  stop_one relay
  expect_refuse "配置写了 ca_cert_paths、目录却被删 ⇒ 拒绝启动" "security.ca_cert_paths" "${WORK}/relay"

  step "④ 中继：连 ca_cert_paths 一起删掉 —— 信任锚由自己的证书链自举"
  write_child_yaml "${WORK}/relay" "zt-relay" "中间层" "${RELAY_LISTEN}" "${ROOT_LISTEN}" "${ROOT_ID}" no
  start_one relay "${WORK}/relay"
  wait_registered "${LOGS}/relay.log" 25 "中继在「没有 trust/、没有 ca_cert_paths」下启动并注册" \
    || die "自举失败：中继起不来或没连上根"
  grep -q '信任锚未配置 security.ca_cert_paths' "${LOGS}/relay.log" \
    || die "日志里没有"锚从哪来"那一行（看 ${LOGS}/relay.log）"
  ANCHORS="$(grep -o 'anchors=[0-9]*' "${LOGS}/relay.log" | head -1)"
  SRC="$(grep -o 'from_credential=[0-9]* from_self_chain=[0-9]*' "${LOGS}/relay.log" | head -1)"
  ok "日志确认锚来源（${SRC}，去重后 ${ANCHORS}：凭据里内嵌的根 CA 与自己链里的根 CA 是同一张)"

  step "⑤ 叶子：首次入网投放的是**父（中继）的** CA —— 不是根的"
  "${BIN}" -genkey -keydir "${WORK}/leaf/keys" >/dev/null
  mkdir -p "${WORK}/leaf/trust"
  cp "${WORK}/relay/certs/node.crt.ca" "${WORK}/leaf/trust/parent-ca.crt"
  cp "${WORK}/root/enroll.token" "${WORK}/leaf/enroll.token"; chmod 600 "${WORK}/leaf/enroll.token"
  # 这一份必须**不是**根的 CA —— 否则"子节点不需要认识根"这句话就没被证到
  if cmp -s "${WORK}/leaf/trust/parent-ca.crt" "${WORK}/root/certs/ca.crt"; then
    die "叶子拿到的是根 CA，本用例失去意义"
  fi
  NCERT="$(grep -c 'BEGIN CERTIFICATE' "${WORK}/leaf/trust/parent-ca.crt")"
  [ "${NCERT}" -ge 2 ] || die "父的 CA 文件只含 ${NCERT} 张证书 —— 应当是「父CA + 根CA」整条链"
  FCN="$(openssl x509 -in "${WORK}/leaf/trust/parent-ca.crt" -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
  case "${FCN}" in *"${RELAY_ID}"*) ok "锚是「父（中继）的 CA + 根 CA」共 ${NCERT} 张，首张 CN 含中继 ID" ;;
    *) die "锚文件首张证书的 CN=${FCN}，不含中继 ID ${RELAY_ID}" ;;
  esac
  write_child_yaml "${WORK}/leaf" "zt-leaf" "中继下的叶子" "" "${RELAY_LISTEN}" "${RELAY_ID}" yes
  start_one leaf "${WORK}/leaf"
  wait_registered "${LOGS}/leaf.log" 25 "叶子用「父的 CA」入网并注册（中继用自举锚验了它的证书）" \
    || die "叶子没能入网"

  step "⑥ 叶子：同样删掉 trust/ 与 ca_cert_paths"
  rm -rf "${WORK}/leaf/trust"
  stop_one leaf
  write_child_yaml "${WORK}/leaf" "zt-leaf" "中继下的叶子" "" "${RELAY_LISTEN}" "${RELAY_ID}" no
  start_one leaf "${WORK}/leaf"
  wait_registered "${LOGS}/leaf.log" 25 "叶子在「没有 trust/、没有 ca_cert_paths」下启动并注册" \
    || die "自举失败：叶子起不来或没连上中继"
  grep -q '信任锚未配置 security.ca_cert_paths' "${LOGS}/leaf.log" || die "叶子的日志里没有"锚从哪来"那一行"

  step "⑦ 边界②：首次入网（还没证书）却一个锚都不给 ⇒ 必须拒绝启动（不许裸奔）"
  "${BIN}" -genkey -keydir "${WORK}/bare/keys" >/dev/null
  # 刻意**连引导凭据都不放**：凭据里内嵌着父的 CA 链，一旦放进来它自己就是锚，
  # 这一档就测不到"一个锚都没有"了（而且它会真的起起来、入网成功）。
  # 所以这里手写一份不含 token_path 的配置 —— 也顺带证明"没配凭据"本身不是启动错误。
  mkdir -p "${WORK}/bare"
  cat > "${WORK}/bare/node.yaml" <<EOF
node:
  name: zt-bare
  remark: "无证书、无锚、无凭据"
parents:
  - id: ${ROOT_ID}
    addr: ${ROOT_LISTEN}
security:
  enrollment: { enabled: true }
EOF
  chmod 600 "${WORK}/bare/node.yaml"
  expect_refuse "无证书 + 无任何锚 ⇒ 拒绝启动" "待入网但没有任何信任锚" "${WORK}/bare"

  step "⑧ 整树跑一条指令（证明这棵树真的能用，而不只是能起来）"
  CID="$(curl -s -XPOST "http://${ROOT_API}/v1/commands" \
        -d '{"type":"noop","target":{"mode":"SUBTREE"},"aggregate":"COUNT","on_failure":"ALL_MUST_SUCCEED"}' \
        | python3 -c 'import sys,json;print(json.load(sys.stdin).get("command_id",""))')"
  [ -n "${CID}" ] || die "提交指令失败（根 API 拒绝了）"
  info "指令 ${CID} 已提交"
  ST=""
  for _ in $(seq 1 60); do
    # 接口给的是枚举全名（COMMAND_STATUS_COMPLETED），去掉前缀好比对
    ST="$(curl -s "http://${ROOT_API}/v1/commands/${CID}" \
          | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status",""))' 2>/dev/null \
          | sed 's/^COMMAND_STATUS_//' || true)"
    case "${ST}" in COMPLETED|FAILED|TIMEOUT|CANCELLED|PARTIAL) break ;; esac
    sleep 0.5
  done
  [ "${ST}" = "COMPLETED" ] || die "指令没跑到 COMPLETED（最后状态 ${ST}）"
  ok "全树指令 COMPLETED"

  echo
  echo "════════════════════════════════════════════════════════════════"
  echo " 全部通过。被证到的不变量："
  echo "   · 入网成功后 trust/ 与 security.ca_cert_paths 可删（锚从自己的证书链自举）"
  echo "   · 首次入网要的锚是**父的** CA，不是根的（子节点不必认识根）"
  echo "   · 配置写了 ca_cert_paths 就必须存在（fail-fast，不静默降级）"
  echo "   · 无证书 + 无锚 ⇒ 拒绝启动（不许裸奔）"
  echo "   · 删锚重启后整棵树仍然能跑完指令"
  echo "════════════════════════════════════════════════════════════════"

  if [ "${1:-}" != "keep" ]; then
    echo
    cmd_stop
  else
    info "keep：树留着，收场用 ./zero-trust.sh stop"
  fi
}

case "${1:-start}" in
  stop)  cmd_stop ;;
  keep)  cmd_run keep ;;
  ""|start|run) cmd_run ;;
  *) cat <<EOF
用法: ./zero-trust.sh [keep|stop]

  无参数   跑完整验证，结束后自动清场
  keep     跑完留着树（自己 ./zero-trust.sh stop 收）
  stop     只清场

环境变量：TREECMD_REPO（默认 ${REPO}）
EOF
  ;;
esac
