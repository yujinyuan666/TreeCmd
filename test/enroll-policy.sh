#!/usr/bin/env bash
#
# enroll-policy.sh —— 验收**父端的入网授权策略**（谁可以进来 / 凭什么进来）
#
# 证哪条不变量（每一条都是"授权"语义，不是"功能"语义）：
#   ① **有许可就能进**：子节点只带**一份引导凭据**（permit + 父的 CA 链）就能入网 ——
#      目录里既没有 trust/ 也没配 ca_cert_paths；
#   ② **许可不对就进不来**：`ERR_ENROLL_BAD_PERMIT`，且**没有签发任何证书**；
#   ③ **父端没配许可 ⇒ 拒绝一切**：入网认证只留许可一个口径（`ERR_ENROLL_NO_PERMIT_POLICY`）。
#      这一条同时是那条**授权绕过**的回归：曾经"配了 allow_ids 白名单、没配许可"也能放行，
#      而白名单挡不住"自报一个公开的 NodeID + 自建一对密钥"（NodeID 与密钥对没有密码学绑定）
#      ⇒ 该字段已删除，现在无论子节点自报什么 ID、提交什么许可，父端没配许可就一律拒。
#
# 用法：
#   ./enroll-policy.sh          跑完自动清场
#   ./enroll-policy.sh keep     跑完留着树（自己 ./enroll-policy.sh stop 收）
#
# 端口：根 listen 19693 / api 18693。
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
BIN="${REPO}/bin/treecmd-node"
INIT_ROOT="${REPO}/scripts/init_root.sh"
MAKE_BOOTSTRAP="${REPO}/scripts/make_bootstrap.sh"
WORK="${HERE}/enroll-policy"
LOGS="${WORK}/logs"
PIDFILE="${HERE}/.enroll-policy.pids"

ROOT_ID="0198f0c0-0000-7000-8000-0000abc00011"
CHILD_ID="0198f0c0-0000-7000-8000-0000abc00077"
ROOT_LISTEN="127.0.0.1:19693"
ROOT_API="127.0.0.1:18693"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# write_root_yaml <模式> —— 每种模式改的都只是 security.enrollment 那一段
#   permit : 有许可（token_path: enroll.token）
#   none   : 开了入网但**没有许可**（入网认证只留许可一个口径 ⇒ 它会拒绝一切请求）
#
# ⚠️ 段序有讲究：enrollment 必须写在 `security:` 之后、`api:` 之前 ——
# 它是 security 的子键，一旦被追加到 `api:` 后面就成了 api 的键，
# 而程序是**非严格**的 yaml 反序列化（未知键静默忽略）⇒ 配置"看起来写了"其实没生效。
write_root_yaml() {
  local mode="$1"
  mkdir -p "${WORK}/root"
  cat > "${WORK}/root/node.yaml" <<EOF
node:
  name: ep-root
  remark: "enroll-policy 验收的根"
  listen: ${ROOT_LISTEN}
security:
  ca_cert_path: certs/node.crt.ca
  ca_key_path: keys/ca
  ca_cert_paths: [certs/node.crt.ca]
EOF
  case "${mode}" in
    permit)
      cat >> "${WORK}/root/node.yaml" <<'EOF'
  enrollment: { enabled: true, token_path: enroll.token }
EOF
      ;;
    none)
      cat >> "${WORK}/root/node.yaml" <<'EOF'
  enrollment: { enabled: true }
EOF
      ;;
    *) die "未知模式 ${mode}" ;;
  esac
  cat >> "${WORK}/root/node.yaml" <<EOF
api:
  http_addr: ${ROOT_API}
EOF
  chmod 600 "${WORK}/root/node.yaml"
}

write_child_yaml() {
  mkdir -p "${WORK}/child"
  cat > "${WORK}/child/node.yaml" <<EOF
node:
  id: ${CHILD_ID}
  name: ep-child
  remark: "入网策略验收的子节点"
parents:
  - id: ${ROOT_ID}
    addr: ${ROOT_LISTEN}
security:
  enrollment: { enabled: true, token_path: enroll.token }
EOF
  chmod 600 "${WORK}/child/node.yaml"
}

start_one() {  # <名字> <目录>
  "${BIN}" -config "$2/node.yaml" >> "${LOGS}/$1.log" 2>&1 &
  echo "$1:$!" >> "${PIDFILE}"
}

stop_one() {   # <名字>
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

# restart_root <模式> —— 改父端策略并重启它
restart_root() {
  write_root_yaml "$1"
  stop_one root
  start_one root "${WORK}/root"
  for _ in $(seq 1 40); do
    curl -s -o /dev/null --max-time 1 "http://${ROOT_API}/v1/healthz" 2>/dev/null && return 0
    sleep 0.5
  done
  die "根没起来（看 ${LOGS}/root.log）"
}

# try_child <阶段名> —— 让子节点重新走一次入网（先删掉它的证书，强制回到"待入网"）
try_child() {
  stop_one child
  rm -f "${WORK}/child/certs/node.crt" "${WORK}/child/certs/node.crt.ca"
  start_one child "${WORK}/child"
}

# wait_registered <超时秒>
wait_registered() {
  for _ in $(seq 1 $((${1:-20} * 2))); do
    grep -q 'msg=registered' "${LOGS}/child.log" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}

# expect_denied <说明> <期望错误码>
expect_denied() {
  local what="$1" want="$2" found=0
  try_child "${what}"
  for _ in $(seq 1 40); do
    grep -q "${want}" "${LOGS}/child.log" 2>/dev/null && { found=1; break; }
    sleep 0.5
  done
  [ "${found}" = "1" ] || die "${what}：子节点日志里没出现 ${want}（看 ${LOGS}/child.log）"
  # 光有错误码还不够 —— **必须确认真的没有证书被签发出去**
  [ ! -f "${WORK}/child/certs/node.crt" ] || die "${what}：竟然拿到了证书 ${WORK}/child/certs/node.crt（授权被绕过了！）"
  ok "${what}（${want}，且未签发任何证书）"
  stop_one child
}

cmd_run() {
  [ -x "${BIN}" ] || die "找不到 ${BIN}；请放入预编译好的 bin/treecmd-node（开发机上：go build -o bin/treecmd-node ./cmd/node）"
  [ -x "${INIT_ROOT}" ] || die "找不到 ${INIT_ROOT}"
  [ -x "${MAKE_BOOTSTRAP}" ] || die "找不到 ${MAKE_BOOTSTRAP}"

  cmd_stop >/dev/null 2>&1 || true
  rm -rf "${WORK}"
  mkdir -p "${LOGS}"

  echo "════════════════════════════════════════════════════════════════"
  echo " 入网授权策略验收（谁可以进来 / 凭什么进来）"
  echo "   工作目录  ${WORK}"
  echo "════════════════════════════════════════════════════════════════"

  step "① 根材料 + 引导凭据（make_bootstrap.sh 产出：permit + 根的 CA 链）"
  "${INIT_ROOT}" "${WORK}/root" "${ROOT_ID}" >/dev/null
  PERMIT="$(sed -n 's/^permit=//p' "${WORK}/root/enroll.token")"
  [ -n "${PERMIT}" ] || die "根没产出许可（看 ${WORK}/root/enroll.token）"
  ok "根材料就绪，许可 ${PERMIT:0:8}…"

  step "② 有许可就能进 —— 而且子节点**只有这一份凭据**（没有 trust/、没配 ca_cert_paths）"
  "${BIN}" -genkey -keydir "${WORK}/child/keys" >/dev/null
  mkdir -p "${WORK}/child"
  write_child_yaml
  cp "${WORK}/root/enroll.token" "${WORK}/child/enroll.token"; chmod 600 "${WORK}/child/enroll.token"
  [ ! -d "${WORK}/child/trust" ] || die "子节点目录里不该有 trust/"
  restart_root permit
  try_child "首次入网"
  wait_registered 25 || die "有许可却入不了网（看 ${LOGS}/child.log）"
  [ -f "${WORK}/child/certs/node.crt" ] || die "入网成功却没写证书文件"
  ok "入网成功、证书已落盘（材料 = 密钥对 + 一份凭据）"
  stop_one child

  step "③ 许可不对 ⇒ ERR_ENROLL_BAD_PERMIT（父端策略不变）"
  restart_root permit
  sed "s/^permit=.*/permit=0000000000000000000000000000000000000000000000ff/" \
    "${WORK}/root/enroll.token" > "${WORK}/child/enroll.token"
  chmod 600 "${WORK}/child/enroll.token"
  expect_denied "许可串错误" "ERR_ENROLL_BAD_PERMIT"

  step "④ 父端没配许可 ⇒ 拒绝一切（入网认证只留许可一个口径）"
  # 父端**完全没有许可**，子节点却带着一份格式正确的凭据（非空 permit）来敲门 —— 必须被拒。
  # 这一条同时是那条授权绕过的回归：曾经"配了 allow_ids 白名单、没配许可"会放行，
  # 而白名单挡不住"自报一个公开的 NodeID + 自建一对密钥"，所以该字段已删除。
  #
  # ⚠️ 必须把凭据文件也挪走：配置里不写 token_path 时，约定会自动补 `enroll.token`
  #（"目录里真有这个文件就用它"），所以"文件在"就等于"父端有许可"，测不到这一档。
  mv -f "${WORK}/root/enroll.token" "${WORK}/root/.enroll.token.saved"
  restart_root none
  grep -q 'enrollment 已开启但没有入网许可' "${LOGS}/root.log" \
    && ok "父端启动时已提醒「enrollment 开启但没有许可 ⇒ 拒绝一切入网」" \
    || warn "父端启动日志里没有那条提醒（不影响结论，但可观测性少了点）"
  # 子节点这一侧刻意模仿攻击者：它知道父端地址、也拿着一条像样的许可串（但父端不认识它），
  # 于是随便自报一个 NodeID 就来申请 —— 父端必须因为"自己没配许可"而拒绝一切。
  {
    echo "permit=attacker-supplied-garbage"
    cat "${WORK}/root/certs/node.crt.ca"
  } > "${WORK}/child/enroll.token"
  chmod 600 "${WORK}/child/enroll.token"
  expect_denied "父端没配许可（自报什么 ID、提交什么许可都一样拒）" "ERR_ENROLL_NO_PERMIT_POLICY"
  mv -f "${WORK}/root/.enroll.token.saved" "${WORK}/root/enroll.token"

  step "⑤ 恢复许可后又能进（证明④拒的是「没有许可」，不是把树弄坏了）"
  restart_root permit
  cp "${WORK}/root/enroll.token" "${WORK}/child/enroll.token"; chmod 600 "${WORK}/child/enroll.token"
  try_child "恢复许可"
  wait_registered 25 || die "恢复许可后仍入不了网（看 ${LOGS}/child.log）"
  ok "凭据放回后又正常入网"
  stop_one child

  echo
  echo "════════════════════════════════════════════════════════════════"
  echo " 全部通过。被证到的不变量："
  echo "   · 一份引导凭据（permit + 父 CA 链）就够入网，不需要 trust/ 与 ca_cert_paths"
  echo "   · 许可不对 / 缺失 ⇒ 一律拒发证书（而且父端「没配许可」时拒的是**一切**请求）"
  echo "   · 入网认证只有许可一个口径（allow_ids 已删除，它挡不住自报 ID）"
  echo "════════════════════════════════════════════════════════════════"

  if [ "${1:-}" != "keep" ]; then
    echo
    cmd_stop
  else
    info "keep：树留着，收场用 ./enroll-policy.sh stop"
  fi
}

case "${1:-start}" in
  stop) cmd_stop ;;
  keep) cmd_run keep ;;
  ""|start|run) cmd_run ;;
  *) cat <<EOF
用法: ./enroll-policy.sh [keep|stop]

  无参数   跑完整验证，结束后自动清场
  keep     跑完留着树（自己 ./enroll-policy.sh stop 收）
  stop     只清场

环境变量：TREECMD_REPO（默认 ${REPO}）
EOF
  ;;
esac
