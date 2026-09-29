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
#   certs/ca.crt                根的自签 CA 证书 —— 信任链的顶端
#                               （**下级要的不是这一份**：每个子节点拿的是它**自己父**的
#                                certs/node.crt.ca，含父 CA 一路到根；子节点不需要认识根）
#   certs/node.crt              根的身份证书链（身份证书 + CA 证书串接）
#   certs/node.crt.ca           根本节点自己的 CA 证书链（内容 = ca.crt）——**给直接子节点的投放物**
#   trust/root-ca.crt           根自己的信任锚副本（校验对端用；node.yaml 默认扫 trust/ 目录）
#   enroll.token                入网**引导凭据**：入网许可 + 根自己的 CA 证书链（含到根）。
#                               **整份**拷给每个子节点即可 —— 子节点不用再单独拷 CA、也不用配 trust/
#
# 用法（**所有参数都可省**）：
#   ./scripts/init_root.sh [节点目录] [根节点ID] [身份证书天数=30] [CA 天数=3650]
#
#   不带参数   = 在**当前目录**初始化，NodeID 自动生成            ← 最常用
#   只给目录   = 在指定目录初始化，NodeID 自动生成
#   目录 + ID  = 用你指定的 ID（例：复用一份已知身份）
#   只想给 ID  = ./scripts/init_root.sh --id <根节点ID>（目录仍是当前目录）
#
# 例：
#   cd /opt/treecmd/root && /path/to/scripts/init_root.sh      # 当前目录 + 自动 NodeID
#   ./scripts/init_root.sh /opt/treecmd/root                   # 指定目录 + 自动 NodeID
#   ./scripts/init_root.sh /opt/treecmd/root 0198f0c0-0000-7000-8000-000000000001
#   ./scripts/init_root.sh /opt/treecmd/root <ID> 90 3650      # 想自己指定天数就显式给
#
# NodeID 自动生成时：由本脚本现场造一枚 **UUIDv7**，直接写进证书的 CN。
#   node.yaml 里的 node.id **留空就行** —— 程序按"node.yaml → 证书身份 → state.dat → 新生成"
#   的顺序解析身份（ADR-050），证书一旦签发就是权威来源，它自己会读到这一枚。
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
WANT_ID=""
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -f|--force) FORCE=1; shift ;;
    # 帮助文本直接从本文件头部的注释块里取（到 `set -euo pipefail` 前一行为止），
    # 这样改注释不会让帮助内容错位（旧写法写死了 2,40p，注释一动就漏行）。
    -h|--help)
      sed -n '2,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//' | sed '/./,$!d'
      exit 0 ;;
    --id)  [ $# -ge 2 ] || { echo "--id 后面要跟一个 NodeID" >&2; exit 2; }; WANT_ID="$2"; shift 2 ;;
    --id=*) WANT_ID="${1#--id=}"; shift ;;
    -*)    echo "未知选项 $1（用 -h 看用法）" >&2; exit 2 ;;
    *)     ARGS+=("$1"); shift ;;
  esac
done
set -- "${ARGS[@]:-}"

DIR="${1:-}"
NODE_ID="${2:-}"

# 宽容一点：第一个位置参数如果本身就是 UUIDv7 形态，说明用户想"只给 ID"（目录回到当前目录）。
case "${DIR}" in
  ????????-????-7???-????-????????????)
    if [ -z "${NODE_ID}" ]; then NODE_ID="${DIR}"; DIR=""; fi ;;
esac
# --id 显式指定优先于位置参数
# （写成 if 而不是 `[ ... ] && ...`：后者在条件不成立时整体返回非零，会被 set -e 当成失败退出）
if [ -n "${WANT_ID}" ]; then NODE_ID="${WANT_ID}"; fi

IDENTITY_DAYS="${3:-30}"       # 与程序签发子节点证书同口径：之后由程序自动续期
CA_DAYS="${4:-3650}"           # CA 是全树信任锚：换 CA 要重新分发 trust/，所以给长期

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# ── 节点目录：没给就用**当前目录**（在哪里跑就在哪里初始化）──
[ -n "${DIR}" ] || DIR="$(pwd)"
[ -d "${DIR}" ] || mkdir -p "${DIR}" || die "建不出节点目录 ${DIR}"
DIR="$(cd "${DIR}" && pwd)"    # 规范化成绝对路径，日志与后续提示里看着清楚

# now_ms —— 当前 Unix 毫秒时间戳。
#
# GNU date 支持 %N（纳秒），而 BSD/macOS 的 date 会把 "%N" 原样吐出来，所以要判一下是不是纯数字：
# 拿不到就退化成"秒 × 1000"（毫秒位为 0）。两者都是合法的 UUIDv7 时间戳，区别只是精度；
# 唯一性由随机部分保证（74 bit），与时间精度无关。
now_ms() {
  local s ns
  s="$(date +%s)"
  ns="$(date +%N 2>/dev/null || true)"
  case "${ns}" in
    ''|*[!0-9]*) printf '%s' "$(( s * 1000 ))" ;;
    *)           printf '%s' "$(( s * 1000 + 10#${ns:0:3} ))" ;;
  esac
}

# gen_uuidv7 —— 现场造一枚 UUIDv7，字段口径与 internal/identity.NewNodeID 一致：
#   48 bit 毫秒时间戳 | 4 bit 版本(=7) | 12 bit 随机 | 2 bit 变体(=10xx) | 62 bit 随机
#
# 为什么不用 python3/其它解释器：部署机上不一定有。openssl 是本脚本**本来就要**的依赖，
# 所以随机底座直接从 `openssl rand` 取，再按位覆盖时间戳与版本/变体位。
gen_uuidv7() {
  local ms hex
  ms="$(( $(now_ms) & 0xFFFFFFFFFFFF ))"    # 只留低 48 bit（多出来的位会破坏 8-4-4-4-12 的定长）
  hex="$(openssl rand -hex 16)"             # 32 个十六进制字符，当随机底座
  printf '%08x-%04x-7%s-%x%s-%s\n' \
    "$(( ms >> 16 ))"                    \
    "$(( ms & 0xFFFF ))"                 \
    "${hex:0:3}"                         \
    "$(( (0x${hex:3:1} & 3) | 8 ))" "${hex:4:3}" \
    "${hex:7:12}"
}

# ── 根节点 ID：没给就现场生成（写进证书 CN；程序启动时会从证书里读到它）──
AUTO_ID=0
if [ -z "${NODE_ID}" ]; then
  NODE_ID="$(gen_uuidv7)"
  AUTO_ID=1
fi

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

if [ "${AUTO_ID}" -eq 1 ]; then
  ID_NOTE="（本次**自动生成** —— 程序启动会从证书里读到它，node.yaml 的 node.id 可以留空）"
else
  ID_NOTE="（你指定的 —— 若 node.yaml 里也写了 node.id，两者必须一致）"
fi

echo "════════════════════════════════════════════════════════════════"
echo " 初始化根节点身份材料"
echo "   节点目录   ${DIR}"
echo "   根节点 ID  ${NODE_ID}"
echo "              ${ID_NOTE}"
echo "   身份证书   ${IDENTITY_DAYS} 天（根没有父可签发，所以之后由程序自签续期）"
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
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT
# CN 只需"包含" nodeID（程序校验 CA 证书时用的是 strings.Contains）
#
# 这里刻意走"CSR + x509 -req -extfile"，而不是 `openssl req -new -x509 -addext …`：
# `-addext` 是把扩展**追加**到系统 openssl.cnf 里 `[req] x509_extensions` 指向的那一节
# （RHEL 系发行版——RHEL/CentOS/Fedora/openEuler——配置里就是 `[v3_ca]`，自带
# basicConstraints/SKID/AKID），于是 basicConstraints 被写进去两次。macOS 的 openssl 配置
# 没有 x509_extensions，所以本地一直没暴露。而 **Go 的 crypto/x509 对重复扩展是硬报错**：
#     REFUSE TO START: … x509: certificate contains duplicate extension with OID "2.5.29.19"
# 显式给 -extfile 就与系统配置完全无关，扩展严格等于下面这份清单（叶子走的是同一套路）。
cat > "${TMP}/ca.cnf" <<EOF
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF
openssl req -new -key "${DIR}/keys/ca" -out "${TMP}/ca.csr" \
  -subj "/O=treecmd/CN=${NODE_ID}-root-ca" 2>/dev/null
# 不给 -sha512：Ed25519 的摘要算法是固定的（内部就是 SHA-512），显式指定反而有害 ——
# OpenSSL 1.1.1 上 `x509 -req -signkey <ed25519> -sha512` 会报
# `elliptic curve routines:pkey_ecd_ctrl:invalid digest type` 并以非零码退出（RHEL 系默认就是 1.1.1）。
openssl x509 -req -in "${TMP}/ca.csr" -signkey "${DIR}/keys/ca" \
  -out "${DIR}/certs/ca.crt" -days "${CA_DAYS}" \
  -extfile "${TMP}/ca.cnf" 2>/dev/null
ok "CA 证书 certs/ca.crt（CA:TRUE + keyCertSign，有效期 ${CA_DAYS} 天）"

# ── ③ 用 CA 给根自己的身份公钥签身份证书 ──
echo
echo "③ 签发根的身份证书（certs/node.crt）"
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
echo "④ 投放根自己的信任锚副本"
echo "   （未显式配 ca_cert_paths 时程序会自动扫 trust/；根是链条顶端，用它自己的 CA 当锚）"
echo "   ⚠️ 这一份是**根自己用**的。子节点要的是**它们自己父**的 certs/node.crt.ca，"
echo "      不是这份根 CA —— 每个节点只对自己的父节点负责，子节点不需要认识根。"
cp -f "${DIR}/certs/ca.crt" "${DIR}/trust/root-ca.crt"
chmod 644 "${DIR}/trust/root-ca.crt"
ok "信任锚 trust/root-ca.crt"
info "给直接子节点的投放物是：${DIR}/certs/node.crt.ca（内容含 CA 一路到根）"

# ── ⑤ 入网引导凭据 ──
echo
echo "⑤ 生成入网引导凭据（enroll.token = 入网许可 + 根自己的 CA 证书链）"
"${SCRIPT_DIR}/make_bootstrap.sh" "${DIR}" >/dev/null
# 已存在时 make_bootstrap.sh **沿用原有许可**（不轮换），只把 CA 链补进去 ——
# 子节点手上很可能已经拿着那枚许可，轮换它会把在途部署全部作废。
ok "入网引导凭据 enroll.token（已存在则许可沿用原值，仅补齐 CA 链）"
info "根端 node.yaml 里配 security.enrollment: { enabled: true, token_path: enroll.token }"
info "  —— 根是签发方，enrollment 必须开启，否则子节点会被拒（ERR_ENROLL_DISABLED）"
info "把这个文件**整份**拷给每个子节点即可：许可与父的 CA 都在里面（不用再单独拷 trust/）"

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

# 材料自验之后，给出"下一步"。材料到底合不合程序的口味，最终由**程序启动强校验**说了算：
# 有问题它会打 REFUSE TO START 并以非零码退出，日志里原因写得很清楚。
echo
if [ -f "${DIR}/node.yaml" ]; then
  echo "⑦ 已有 ${DIR}/node.yaml —— 直接启动即可"
  info "${BIN} -config ${DIR}/node.yaml"
else
  echo "⑦ 还没有 ${DIR}/node.yaml"
  info "从样例配置抄一份（**node.id 留空就行**，其余按约定即可）："
  info "  cp ${REPO_DIR}/examples/node.yaml ${DIR}/node.yaml"
  info "  ${BIN} -config ${DIR}/node.yaml            # 启动"
fi
info ""
info "关于 node.yaml 里的 node.id：留空 = 程序自己从证书里读到 ${NODE_ID}；"
info "  若你显式填了，就必须与这个 ID 一致 —— 不一致会被启动强校验拒绝（REFUSE TO START）。"

echo
echo "════════════════════════════════════════════════════════════════"
echo " 根节点材料就绪。之后证书的**签发与续期都归程序管**："
echo "   · 子节点首次上线：启动后自动走「运行期入网」，由根用 keys/ca 签发（对方私钥不出本机）"
echo "   · 子节点证书续期：程序在剩余有效期不足 1/3 时自动换发（由父签发）"
echo "   · 根自己的证书：程序每小时检查一次，剩余不足生命期 1/3 时**自签续期**；"
echo "                  停机很久导致证书过期时，下次启动会先自签续期再启动"
echo "════════════════════════════════════════════════════════════════"
