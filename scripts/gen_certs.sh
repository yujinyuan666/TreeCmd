#!/usr/bin/env bash
#
# gen_certs.sh —— 为 treecmd 节点生成身份材料与证书。
#
# 它解决的是《手动部署指南》里那句"证书必须自带（由你自己的脚本签发/投放）"——
# 现在这个"你自己的脚本"就有现成的了。
#
# 与 nginx 那类"一张 RSA 自签证书"的脚本的区别（treecmd 的硬要求）：
#   1. 算法必须是 Ed25519（LoadIdentityKey 只认 ed25519，RSA 会被直接拒绝启动）
#   2. 必须是两层：CA 证书（CA:TRUE + keyUsage certSign）+ 由它签发的身份证书
#      —— 启动强校验要求"证书链能验到 ca_cert_paths[] 里的信任锚"
#   3. 身份证书的 CN 必须**严格等于 node.id**（不一致就 REFUSE TO START）
#   4. 换证书**不用重启进程**：换完 `kill -USR1 <pid>`（或等 30s 轮询）程序会自己热重载
#
# 用法:
#   ./scripts/gen_certs.sh root  <节点目录> <node-id> [身份证书天数] [额外SAN]
#   ./scripts/gen_certs.sh child <节点目录> <父节点的CA证书> [enroll.token 内容]
#   ./scripts/gen_certs.sh issue <父节点目录> <子节点目录> <child-id> [天数]
#   ./scripts/gen_certs.sh renew <节点目录> [阈值天数，默认 30]
#   ./scripts/gen_certs.sh check <节点目录>
#
# 例子:
#   ./scripts/gen_certs.sh root  /opt/treecmd/root 0198f0c0-0000-7000-8000-000000000001
#   ./scripts/gen_certs.sh child /opt/treecmd/c1   /opt/treecmd/root/certs/node.crt.ca
#   ./scripts/gen_certs.sh renew /opt/treecmd/root          # 身份证书快到期就重签（CA 不动）
#   ./scripts/gen_certs.sh check /opt/treecmd/root
#
# 环境要求: bash + openssl ≥ 1.1.1（需要 Ed25519 支持）。
#   macOS 自带的 /usr/bin/openssl 是 LibreSSL，通常**不带** Ed25519；
#   用 Homebrew 的（brew install openssl）并确保 `openssl version` 显示 OpenSSL 1.1.1+。

set -euo pipefail

# ---------- 小工具 ----------
info() { printf '%s\n' "$*"; }
ok()   { printf '  \033[32m✅\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m⚠️\033[0m %s\n' "$*"; }
die()  { printf '  \033[31m❌ %s\033[0m\n' "$*" >&2; exit 1; }

# 私钥/证书文件名（与 docs/手动部署指南.md 的约定一致）
KEY_FILE_NAME="id_ed25519"   # 身份私钥（PKCS8 PEM）
CERT_FILE_NAME="node.crt"    # 身份证书链（叶子在前，CA 在后）
CA_CERT_NAME="node.crt.ca"   # 本节点自己的 CA 证书链（有下级的节点才有）
CA_KEY_NAME="ca.key"         # 本节点自己的 CA 私钥

require_openssl() {
  command -v openssl >/dev/null 2>&1 || die "找不到 openssl"
  # 能生成 Ed25519 才继续；LibreSSL / 过老的 OpenSSL 在这里就会失败
  local tmp
  tmp="$(mktemp -d)"
  if ! openssl genpkey -algorithm ed25519 -out "${tmp}/t.key" >/dev/null 2>&1; then
    rm -rf "${tmp}"
    die "当前 openssl 不支持 Ed25519（$(openssl version)）。macOS 请用 Homebrew 的 openssl。"
  fi
  rm -rf "${tmp}"
}

# 生成一对 Ed25519 身份密钥：私钥 PKCS8 PEM、公钥 PKIX PEM
# （与 treecmd-node -genkey 写出的格式完全一致）
gen_identity_keys() {
  local dir="$1"
  mkdir -p "${dir}/keys"
  chmod 700 "${dir}/keys"
  openssl genpkey -algorithm ed25519 -out "${dir}/keys/${KEY_FILE_NAME}" 2>/dev/null
  chmod 600 "${dir}/keys/${KEY_FILE_NAME}"
  openssl pkey -in "${dir}/keys/${KEY_FILE_NAME}" -pubout -out "${dir}/keys/${KEY_FILE_NAME}.pub" 2>/dev/null
  ok "身份密钥对：keys/${KEY_FILE_NAME} + keys/${KEY_FILE_NAME}.pub"
}

write_extfile() {
  # $1=文件 $2=CN $3=额外 SAN（可空）
  local out="$1" cn="$2" extra="${3:-}"
  local san="DNS:localhost,IP:127.0.0.1,URI:spiffe://treecmd/node/${cn}"
  if [ -n "${extra}" ]; then san="${san},${extra}"; fi
  cat > "${out}" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, serverAuth
subjectKeyIdentifier = hash
subjectAltName = ${san}
EOF
}

# 算证书还剩多少天；解析不出来时返回非 0。
#
# 为什么不用 `openssl x509 -checkend N`：它在部分构建里**只把结论打到 stdout、退出码恒为 0**
# （官方文档说"会在 N 秒内过期就返回 1"，实测 OpenSSL 3.6 并非如此）。所以自己算天数最稳。
cert_days_left() {
  local cert="$1" notafter end_s now_s
  notafter="$(openssl x509 -in "${cert}" -noout -enddate 2>/dev/null | cut -d= -f2)"
  [ -n "${notafter}" ] || return 1
  # macOS 的 date 不支持 -d，要用 -j -f；Linux 用 -d。两种都试一遍。
  end_s="$(LC_ALL=C date -j -f '%b %d %T %Y %Z' "${notafter}" +%s 2>/dev/null || true)"
  if [ -z "${end_s}" ]; then
    end_s="$(date -d "${notafter}" +%s 2>/dev/null || true)"
  fi
  [ -n "${end_s}" ] || return 1
  now_s="$(date +%s)"
  printf '%s' "$(( (end_s - now_s) / 86400 ))"
}

# ---------- root：自签 CA + 由它签发本节点身份证书 ----------
cmd_root() {
  local dir="${1:-}" nodeid="${2:-}" days="${3:-825}" extra_san="${4:-}"
  [ -n "${dir}" ] && [ -n "${nodeid}" ] || die "用法: root <节点目录> <node-id> [天数] [额外SAN]"
  require_openssl
  mkdir -p "${dir}/certs" "${dir}/trust"
  chmod 700 "${dir}/certs"

  # ① 身份密钥对
  if [ -f "${dir}/keys/${KEY_FILE_NAME}" ]; then
    warn "身份私钥已存在，保留不覆盖：keys/${KEY_FILE_NAME}"
  else
    gen_identity_keys "${dir}"
  fi

  # ② CA 密钥对 + 自签 CA 证书（CN 含 node-id，启动校验会检查这一点）
  local ca_key="${dir}/certs/${CA_KEY_NAME}" ca_crt="${dir}/certs/ca.crt"
  if [ -f "${ca_key}" ]; then
    warn "CA 私钥已存在，保留不覆盖：certs/${CA_KEY_NAME}"
  else
    openssl genpkey -algorithm ed25519 -out "${ca_key}" 2>/dev/null
    chmod 600 "${ca_key}"
    ok "CA 私钥：certs/${CA_KEY_NAME}"
  fi

  local tmp; tmp="$(mktemp -d)"
  cat > "${tmp}/ca.cnf" <<EOF
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
  if [ -f "${ca_crt}" ]; then
    warn "CA 证书已存在，保留不覆盖：certs/ca.crt"
  else
    openssl req -new -x509 -key "${ca_key}" -out "${ca_crt}" -days 3650 \
      -subj "/O=treecmd/CN=${nodeid}-root-ca" \
      -config "${tmp}/ca.cnf" -extensions v3_ca 2>/dev/null
    ok "CA 证书：certs/ca.crt（CA:TRUE，keyUsage=keyCertSign）"
  fi

  # ③ 身份证书（CN=node-id，SAN 带 URI/DNS/IP）
  write_extfile "${tmp}/leaf.cnf" "${nodeid}" "${extra_san}"
  openssl req -new -key "${dir}/keys/${KEY_FILE_NAME}" -out "${tmp}/leaf.csr" -subj "/O=treecmd/CN=${nodeid}" 2>/dev/null
  openssl x509 -req -in "${tmp}/leaf.csr" -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
    -out "${tmp}/leaf.crt" -days "${days}" -extfile "${tmp}/leaf.cnf" 2>/dev/null
  ok "身份证书：CN=${nodeid}，有效期 ${days} 天"

  # ④ 组装 treecmd 要的链文件
  cat "${tmp}/leaf.crt" "${ca_crt}" > "${dir}/certs/${CERT_FILE_NAME}"
  chmod 644 "${dir}/certs/${CERT_FILE_NAME}"
  cp "${ca_crt}" "${dir}/certs/${CA_CERT_NAME}"
  ok "身份证书链：certs/${CERT_FILE_NAME}（叶子 → CA）"
  ok "本节点 CA 链：certs/${CA_CERT_NAME}"

  # ⑤ 信任锚目录：自己的 CA 也放进去（根是自己信任自己）
  cp "${ca_crt}" "${dir}/trust/ca.crt"
  ok "信任锚：trust/ca.crt"

  # ⑥ 入网许可（子节点拿它来换证书）
  if [ ! -f "${dir}/enroll.token" ]; then
    openssl rand -hex 24 > "${dir}/enroll.token"
    chmod 600 "${dir}/enroll.token"
    ok "入网许可：enroll.token（记得把同样的内容放到每个子节点）"
  fi

  rm -rf "${tmp}"
  print_config_hint "${dir}" root
}

# ---------- child：只准备密钥 + 信任锚 + 许可，证书留给运行期入网 ----------
cmd_child() {
  local dir="${1:-}" parent_ca="${2:-}" token="${3:-}"
  [ -n "${dir}" ] && [ -n "${parent_ca}" ] || die "用法: child <节点目录> <父节点的CA证书> [enroll.token 内容]"
  [ -f "${parent_ca}" ] || die "找不到父节点 CA 证书：${parent_ca}"
  require_openssl
  mkdir -p "${dir}/trust"
  if [ -f "${dir}/keys/${KEY_FILE_NAME}" ]; then
    warn "身份私钥已存在，保留不覆盖"
  else
    gen_identity_keys "${dir}"
  fi
  cp "${parent_ca}" "${dir}/trust/parent-ca.crt"
  ok "信任锚：trust/parent-ca.crt"
  if [ -n "${token}" ]; then
    printf '%s' "${token}" > "${dir}/enroll.token"
    chmod 600 "${dir}/enroll.token"
    ok "入网许可：enroll.token"
  else
    warn "没给 enroll.token 内容：请自己放好（或父端用 allow_ids 白名单模式）"
  fi
  info ""
  info "  ⚠️ 本节点**不需要**预置证书：启动时会用上面的密钥向父入网换取（私钥不出本机）。"
  print_config_hint "${dir}" child
}

# ---------- issue：用父节点的 CA 离线给子节点签一张身份证书 ----------
cmd_issue() {
  local pdir="${1:-}" cdir="${2:-}" cid="${3:-}" days="${4:-825}"
  [ -n "${pdir}" ] && [ -n "${cdir}" ] && [ -n "${cid}" ] || die "用法: issue <父节点目录> <子节点目录> <child-id> [天数]"
  require_openssl
  local ca_key="${pdir}/certs/${CA_KEY_NAME}" ca_crt="${pdir}/certs/ca.crt"
  [ -f "${ca_key}" ] || die "父节点没有 CA 私钥（${ca_key}）—— 它是叶子节点，不能签发子证书"
  [ -f "${ca_crt}" ] || die "父节点没有 CA 证书（${ca_crt}）"
  [ -f "${cdir}/keys/${KEY_FILE_NAME}" ] || die "子节点还没有身份密钥（先在子节点跑 child 子命令）"

  local tmp; tmp="$(mktemp -d)"
  write_extfile "${tmp}/leaf.cnf" "${cid}"
  openssl req -new -key "${cdir}/keys/${KEY_FILE_NAME}" -out "${tmp}/leaf.csr" -subj "/O=treecmd/CN=${cid}" 2>/dev/null
  openssl x509 -req -in "${tmp}/leaf.csr" -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
    -out "${tmp}/leaf.crt" -days "${days}" -extfile "${tmp}/leaf.cnf" 2>/dev/null
  mkdir -p "${cdir}/certs"
  cat "${tmp}/leaf.crt" "${ca_crt}" > "${cdir}/certs/${CERT_FILE_NAME}"
  cp "${ca_crt}" "${cdir}/trust/parent-ca.crt" 2>/dev/null || true
  rm -rf "${tmp}"
  ok "已为 ${cid} 签发身份证书：${cdir}/certs/${CERT_FILE_NAME}"
  info "  （也可以用运行期入网：子节点自己向父换证书，不用这一步）"
}

# ---------- check：只看不动 ----------
cmd_check() {
  local dir="${1:-}"
  [ -n "${dir}" ] || die "用法: check <节点目录>"
  local cert="${dir}/certs/${CERT_FILE_NAME}"
  info "== 证书材料自检：${dir} =="
  for f in "keys/${KEY_FILE_NAME}" "keys/${KEY_FILE_NAME}.pub" "certs/${CERT_FILE_NAME}" "certs/${CA_KEY_NAME}" "certs/${CA_CERT_NAME}" "enroll.token"; do
    if [ -e "${dir}/${f}" ]; then
      printf '  %-28s %s\n' "${f}" "存在"
    else
      printf '  %-28s %s\n' "${f}" "(缺)"
    fi
  done
  if [ -d "${dir}/trust" ]; then
    printf '  %-28s %s\n' "trust/" "$(ls -1 "${dir}/trust" 2>/dev/null | tr '\n' ' ')"
  fi
  [ -f "${cert}" ] || { warn "没有身份证书：这个节点会走「运行期入网」，或者还没准备好"; return 0; }

  local cn notafter ca_flag left
  cn="$(openssl x509 -in "${cert}" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
  notafter="$(openssl x509 -in "${cert}" -noout -enddate 2>/dev/null | cut -d= -f2)"
  ca_flag="$(openssl x509 -in "${cert}" -noout -text 2>/dev/null | grep -c 'CA:TRUE' || true)"
  printf '  %-28s %s\n' "身份证书 CN" "${cn:-（取不到）}"
  printf '  %-28s %s\n' "到期时间" "${notafter:-（取不到）}"
  if left="$(cert_days_left "${cert}")"; then
    if [ "${left}" -ge 0 ]; then
      printf '  %-28s %s 天（未过期）\n' "剩余" "${left}"
    else
      printf '  %-28s %s 天（**已过期**）\n' "剩余" "${left}"
    fi
  fi
  info "  链里第一张证书的 CA 标记数：${ca_flag}（身份证书应为 0）"
  info ""
  info "  提示：证书身份必须与 node.yaml 的 node.id 一致；用 treecmd-node -check 会逐条校验。"
}

# ---------- renew：到期前重签身份证书（CA 保持不动） ----------
cmd_renew() {
  local dir="${1:-}" threshold="${2:-30}"
  [ -n "${dir}" ] || die "用法: renew <节点目录> [阈值天数，默认 30]"
  case "${threshold}" in (*[!0-9]*|"") die "阈值必须是整数天数：${threshold}" ;; esac
  local cert="${dir}/certs/${CERT_FILE_NAME}" ca_crt="${dir}/certs/ca.crt" ca_key="${dir}/certs/${CA_KEY_NAME}"
  [ -f "${cert}" ] || die "没有身份证书可续：${cert}"
  [ -f "${ca_key}" ] || die "没有 CA 私钥，无法重签（${ca_key}）"

  local left
  if ! left="$(cert_days_left "${cert}")"; then
    warn "算不出证书到期时间（${cert}）—— 不做盲签，请手工确认后重跑"
    return 1
  fi
  if [ "${left}" -ge "${threshold}" ]; then
    ok "证书还剩 ${left} 天（阈值 ${threshold} 天），无需处理"
    return 0
  fi

  local cn; cn="$(openssl x509 -in "${cert}" -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
  [ -n "${cn}" ] || die "从现有证书里取不到 CN，无法重签（${cert}）"
  warn "证书只剩 ${left} 天（阈值 ${threshold} 天），重签身份证书（CN=${cn}）……"
  local tmp; tmp="$(mktemp -d)"
  write_extfile "${tmp}/leaf.cnf" "${cn}"
  openssl req -new -key "${dir}/keys/${KEY_FILE_NAME}" -out "${tmp}/leaf.csr" -subj "/O=treecmd/CN=${cn}" 2>/dev/null
  openssl x509 -req -in "${tmp}/leaf.csr" -CA "${ca_crt}" -CAkey "${ca_key}" -CAcreateserial \
    -out "${tmp}/leaf.crt" -days 825 -extfile "${tmp}/leaf.cnf" 2>/dev/null
  cat "${tmp}/leaf.crt" "${ca_crt}" > "${cert}"
  rm -rf "${tmp}"
  ok "已重签（新有效期 825 天）。CA 没变，所以**别人的 trust/ 不用动**。"
  info "  让程序立刻生效（不必重启）：kill -USR1 <node.pid>"
}

# ---------- 把要填进 node.yaml 的字段打出来 ----------
print_config_hint() {
  local dir="$1" role="$2"
  info ""
  info "== 填进 node.yaml（路径按你的节点目录换算）=="
  cat <<EOF
security:
  identity_key_path: keys/${KEY_FILE_NAME}
  identity_pubkey_path: keys/${KEY_FILE_NAME}.pub
  identity_cert_path: certs/${CERT_FILE_NAME}
  ca_cert_paths: [trust]
EOF
  if [ "${role}" = "root" ]; then
    cat <<EOF
  ca_cert_path: certs/${CA_CERT_NAME}
  ca_key_path: certs/${CA_KEY_NAME}
  enrollment:
    enabled: true
    token_path: enroll.token
EOF
    info ""
    info "  根节点：node.id 必须等于上面那张身份证书的 CN（也可以留空，程序会从证书取）。"
  fi
  info ""
  info "  自检：treecmd-node -check -config node.yaml"
}

# ---------- 入口 ----------
main() {
  local sub="${1:-}"
  shift || true
  case "${sub}" in
    root)  cmd_root  "$@" ;;
    child) cmd_child "$@" ;;
    issue) cmd_issue "$@" ;;
    renew) cmd_renew "$@" ;;
    check) cmd_check "$@" ;;
    ""|-h|--help|help)
      sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
      ;;
    *) die "未知子命令：${sub}（用 -h 看用法）" ;;
  esac
}

main "$@"
