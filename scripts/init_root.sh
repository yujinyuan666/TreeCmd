#!/usr/bin/env bash
#
# init_root.sh —— 根节点**首次启动前**的身份材料（一次性 bootstrap）
#
# 为什么需要它：根节点没有父，**没有任何人能给根签发证书**（子节点可以走"运行期入网"向父换取）。
# 而"给其它节点 / 其它客户端签发证书"的前提，恰恰是根先有一套自己的信任锚材料 ——
# 所以这一步必须在根第一次启动**之前**做一次，之后证书的签发与续期就都归程序管了。
#
# 一次性产物（全部落在 <节点目录> 下，路径与 node.yaml 的默认约定完全一致）：
#   keys/id_ed25519             根的身份私钥（PKCS8 PEM，权限 600）
#   keys/id_ed25519.pub         根的身份公钥（PKIX PEM）
#   keys/ca                     根的 CA 私钥（给子节点签发用，权限 600）
#   keys/ca.pub                 根的 CA 公钥
#                               —— 路径与 node.yaml 的 security.ca_key_path 默认约定一致
#   certs/ca.crt                根的自签 CA 证书 —— **全树的信任锚**
#   certs/node.crt              根的身份证书链（身份证书 + CA 证书串接）
#   certs/node.crt.ca           根本节点自己的 CA 证书链（内容 = ca.crt）
#   trust/root-ca.crt           信任锚副本（校验对端用；node.yaml 默认扫 trust/ 目录）
#   enroll.token                入网许可（每个子节点的 enroll.token 内容必须与它一致）
#
# 用法：
#   ./scripts/init_root.sh <节点目录> <根节点ID> [身份证书天数=30] [CA 天数=3650]
#
# 例：
#   ./scripts/init_root.sh /opt/treecmd/root 0198f0c0-0000-7000-8000-000000000001
#   ./scripts/init_root.sh /opt/treecmd/root 0198f0c0-0000-7000-8000-000000000001 90 3650   # 想自己指定就显式给天数
#
# 身份证书天数默认 30：**与程序给子节点签发的口径一致**。根没有父，但它自己持有 CA 材料，
# 所以程序会在"剩余不足生命期 1/3"时自签续期（启动时若已进窗口也会先续再启动），
# 第一次启动之后就全自动了 —— 见 docs/手动部署指南.md 第五节。
# CA 天数默认 3650（10 年）：CA 是全树信任锚，换 CA 意味着所有下级都要重新分发 trust/，
# 所以给长期并**不参与自动续期**（程序只自续身份证书，CA 保持不变）。
#
# 幂等：已存在的材料**默认不覆盖**。加 -f 才会覆盖 —— 但覆盖会换掉 CA，
# 意味着全树的 trust/ 都要重新分发，慎用。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

FORCE=0
ARGS=()
for a in "$@"; do
  case "${a}" in
    -f|--force) FORCE=1 ;;
    -h|--help) sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) ARGS+=("${a}") ;;
  esac
done
set -- "${ARGS[@]:-}"

DIR="${1:-}"
NODE_ID="${2:-}"
IDENTITY_DAYS="${3:-30}"       # 与程序签发子节点证书同口径：之后由程序自动续期
CA_DAYS="${4:-3650}"           # CA 是全树信任锚：换 CA 要重新分发 trust/，所以给长期

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[ -n "${DIR}" ] || { info "用法: ./scripts/init_root.sh <节点目录> <根节点ID> [身份证书天数] [CA 天数]"; exit 2; }
[ -n "${NODE_ID}" ] || { info "用法: ./scripts/init_root.sh <节点目录> <根节点ID> [身份证书天数] [CA 天数]"; exit 2; }

# 根节点的 NodeID 必须是 UUIDv7 形态（程序按 UUIDv7 校验，见 internal/identity）
case "${NODE_ID}" in
  *[!0-9a-fA-F-]*) die "根节点 ID 只能含 0-9a-f 与短横线，收到: ${NODE_ID}" ;;
esac
[ "${#NODE_ID}" -eq 36 ] || die "根节点 ID 必须是 36 字符的 UUIDv7，收到 ${#NODE_ID} 字符: ${NODE_ID}"
case "${NODE_ID}" in
  ????????-????-7???-????-????????????) ;;
  *) die "根节点 ID 不像 UUIDv7（第 15 位应为 '7'）: ${NODE_ID}" ;;
esac

command -v openssl >/dev/null 2>&1 || die "找不到 openssl"

# 找 treecmd-node：优先 $TREECMD_NODE，其次仓库里的 bin/，最后 PATH
BIN="${TREECMD_NODE:-}"
if [ -z "${BIN}" ]; then
  if [ -x "${REPO_DIR}/bin/treecmd-node" ]; then BIN="${REPO_DIR}/bin/treecmd-node"
  elif command -v treecmd-node >/dev/null 2>&1; then BIN="$(command -v treecmd-node)"
  else die "找不到 treecmd-node：先 go build -o bin/treecmd-node ./cmd/node，或用 TREECMD_NODE=<路径> 指定"
  fi
fi

KEY="${DIR}/keys/id_ed25519"
LEAF_CERT="${DIR}/certs/node.crt"
if [ "${FORCE}" -eq 0 ] && [ -f "${LEAF_CERT}" ]; then
  die "${LEAF_CERT} 已存在 —— 根的身份材料还在。要重做请加 -f（会换掉 CA，全树 trust/ 需重新分发）"
fi

echo "════════════════════════════════════════════════════════════════"
echo " 初始化根节点身份材料"
echo "   节点目录   ${DIR}"
echo "   根节点 ID  ${NODE_ID}"
echo "   身份证书   ${IDENTITY_DAYS} 天（根本身无续签通道，故默认长期）"
echo "   CA 证书    ${CA_DAYS} 天"
echo "   treecmd-node  ${BIN}"
echo "════════════════════════════════════════════════════════════════"
echo

mkdir -p "${DIR}/keys" "${DIR}/certs" "${DIR}/trust"
chmod 700 "${DIR}/keys" "${DIR}/certs" "${DIR}/trust"

# ── ① 密钥对：交给程序生成，保证格式与 Go 侧（PKCS8 / PKIX PEM）完全一致 ──
echo "① 生成密钥对（由 treecmd-node -genkey 产出，格式与程序读取口径一致）"
KEYGEN_ARGS=(-genkey -keydir "${DIR}/keys" -with-ca)
if [ "${FORCE}" -eq 1 ]; then KEYGEN_ARGS+=(-force); fi
"${BIN}" "${KEYGEN_ARGS[@]}" >/dev/null
[ -f "${KEY}" ] || die "没有生成 ${KEY}"
chmod 600 "${KEY}"
ok "身份密钥对 keys/id_ed25519 和 keys/id_ed25519.pub"

# CA 私钥留在 keys/ca：这正是 node.yaml 里 security.ca_key_path 的默认约定，
# 也是 -genkey -keydir keys 的原生产出，所以样例配置不用改路径
[ -f "${DIR}/keys/ca" ] || die "没有生成 CA 私钥（${DIR}/keys/ca）"
chmod 600 "${DIR}/keys/ca"
chmod 644 "${DIR}/keys/ca.pub"
ok "CA 密钥对 keys/ca 和 keys/ca.pub"

# ── ② 自签 CA 证书：全树信任锚 ──
echo
echo "② 自签 CA 证书（certs/ca.crt）"
# CN 只需"包含" nodeID（程序校验 CA 证书时用的是 strings.Contains）
openssl req -new -x509 -key "${DIR}/keys/ca" -sha512 \
  -out "${DIR}/certs/ca.crt" -days "${CA_DAYS}" \
  -subj "/O=treecmd/CN=${NODE_ID}-root-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" 2>/dev/null
ok "CA 证书 certs/ca.crt（CA:TRUE + keyCertSign，有效期 ${CA_DAYS} 天）"

# ── ③ 用 CA 给根自己的身份公钥签身份证书 ──
echo
echo "③ 签发根的身份证书（certs/node.crt）"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
# CN 必须"恰好等于" nodeID：程序取证书身份时优先取 CN（CN 空才回退 SAN 的 spiffe:// 末段）
openssl req -new -key "${KEY}" -out "${TMP}/leaf.csr" -subj "/O=treecmd/CN=${NODE_ID}" 2>/dev/null
cat > "${TMP}/leaf.cnf" <<EOF
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth, serverAuth
subjectKeyIdentifier = hash
subjectAltName = URI:spiffe://treecmd/node/${NODE_ID},DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "${TMP}/leaf.csr" -CA "${DIR}/certs/ca.crt" -CAkey "${DIR}/keys/ca" \
  -CAcreateserial -out "${TMP}/leaf.crt" -days "${IDENTITY_DAYS}" -sha512 \
  -extfile "${TMP}/leaf.cnf" 2>/dev/null
# 证书链：叶子在前、CA 在后（程序按顺序读，第一张当身份证书）
cat "${TMP}/leaf.crt" "${DIR}/certs/ca.crt" > "${LEAF_CERT}"
chmod 644 "${LEAF_CERT}"
ok "身份证书链 certs/node.crt（身份证书 + CA，有效期 ${IDENTITY_DAYS} 天）"

# 本节点自己的 CA 证书链（program 用它给子节点签发时做父证书）
cp -f "${DIR}/certs/ca.crt" "${DIR}/certs/node.crt.ca"
chmod 644 "${DIR}/certs/node.crt.ca"
rm -f "${DIR}/certs/ca.srl"   # openssl -CAcreateserial 的副产品，材料里不需要
ok "本节点 CA 证书链 certs/node.crt.ca"

# ── ④ 信任锚副本 ──
echo
echo "④ 投放信任锚副本（未显式配 ca_cert_paths 时程序会自动扫 trust/；也给子节点当信任锚）"
cp -f "${DIR}/certs/ca.crt" "${DIR}/trust/root-ca.crt"
chmod 644 "${DIR}/trust/root-ca.crt"
ok "信任锚 trust/root-ca.crt"

# ── ⑤ 入网许可 ──
echo
echo "⑤ 生成入网许可（enroll.token）"
if [ -f "${DIR}/enroll.token" ] && [ "${FORCE}" -eq 0 ]; then
  warn "enroll.token 已存在，保留不覆盖（内容必须与每个子节点一致）"
else
  openssl rand -hex 24 > "${DIR}/enroll.token"
  chmod 600 "${DIR}/enroll.token"
  ok "入网许可 enroll.token（把它原样拷到每个子节点）"
fi
info "根端 node.yaml 里配 security.enrollment: { enabled: true, token_path: enroll.token }"
info "  —— 根是签发方，enrollment 必须开启，否则子节点会被拒（ERR_ENROLL_DISABLED）"

# ── ⑥ 材料自验（不依赖 node.yaml）──
echo
echo "⑥ 自验关键点（与程序启动强校验同一口径）"
CN_OUT="$(openssl x509 -in "${LEAF_CERT}" -noout -subject 2>/dev/null | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"
[ "${CN_OUT}" = "${NODE_ID}" ] && ok "身份证书 CN = nodeID" || die "身份证书 CN = ${CN_OUT}，不是 ${NODE_ID}"
if openssl verify -CAfile "${DIR}/certs/ca.crt" "${TMP}/leaf.crt" >/dev/null 2>&1; then
  ok "身份证书能验到 CA（信任锚）"
else
  die "身份证书验不到 CA —— 材料有问题"
fi
CA_FLAG="$(openssl x509 -in "${DIR}/certs/ca.crt" -noout -text 2>/dev/null | grep -c 'CA:TRUE' || true)"
[ "${CA_FLAG}" -ge 1 ] && ok "CA 证书带 basicConstraints CA:TRUE" || die "CA 证书不是 CA"
KEY_MOD="$(openssl pkey -in "${KEY}" -noout -text 2>/dev/null | head -1 | tr -d ' ')"
case "${KEY_MOD}" in *ED25519*) ok "身份私钥是 Ed25519" ;; *) die "身份私钥不是 Ed25519：${KEY_MOD}" ;; esac

# 若有 node.yaml，顺手跑一次程序自检
echo
if [ -f "${DIR}/node.yaml" ]; then
  echo "⑦ 发现 node.yaml，跑一次程序自检"
  if "${BIN}" -check -config "${DIR}/node.yaml"; then
    ok "程序自检通过：可以启动"
  else
    warn "程序自检未通过 —— 按上面的输出改 node.yaml 后再试"
  fi
else
  echo "⑦ 还没有 ${DIR}/node.yaml"
  info "生成一份带注释的根节点配置，然后启动："
  info "  ${BIN} -print-sample-config root > ${DIR}/node.yaml"
  info "  # 至少改 node.id 为 ${NODE_ID}，其余按约定即可"
  info "  ${BIN} -check -config ${DIR}/node.yaml     # 自检（只读）"
  info "  ${BIN} -config ${DIR}/node.yaml            # 启动"
fi

echo
echo "════════════════════════════════════════════════════════════════"
echo " 根节点材料就绪。之后证书的**签发与续期都归程序管**："
echo "   · 子节点首次上线：启动后自动走「运行期入网」，由根用 keys/ca 签发（对方私钥不出本机）"
echo "   · 子节点证书续期：程序在剩余有效期不足 1/3 时自动换发（由父签发）"
echo "   · 根自己的证书：程序每小时检查一次，剩余不足生命期 1/3 时**自签续期**；"
echo "                  停机很久导致证书过期时，下次启动会先自签续期再启动"
echo "════════════════════════════════════════════════════════════════"
