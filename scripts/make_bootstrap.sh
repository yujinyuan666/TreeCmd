#!/usr/bin/env bash
#
# make_bootstrap.sh —— 产出 / 升级一个节点的「入网引导凭据」（默认就地写 enroll.token）
#
# 【为什么需要它】
# 部署一个子节点要从它父那里拿两样东西：
#   ① **入网许可**（permit）—— 父授权你进来。这是"父要不要收我"的**唯一**判据。
#   ② **父的 CA 证书链** —— 首跳必须能把父的服务端证书验到某个锚，否则谁都能冒充父发证书。
# 两样职责不同、**不能互相替代**（许可管授权、CA 管身份），但可以装进**同一份文件** ——
# 本脚本产出的就是那份文件。于是"部署一个子节点"只需要拷**一个**文件，不用再单独拷父的 CA。
#
# 【用法】
#   ./scripts/make_bootstrap.sh <节点目录> [输出文件] [--new-permit]
#
#   <节点目录>    **父节点**的目录。里面必须有 certs/node.crt.ca：
#                   · 根：由 init_root.sh 产出；
#                   · 中继：由它**自己向父入网**时签发写入 ⇒ 所以中继要**先完成自己的入网**，
#                     才能给下级发凭据（顺序天然如此）。
#   [输出文件]    默认 = <节点目录>/enroll.token（就地更新）
#   --new-permit  强制换一枚新许可（默认严格沿用原值，避免把子节点手上的旧凭据作废）
#
# 【产出的格式】（权威定义：internal/identity/bootstrap.go，本脚本必须与之一致）
#   # 注释行
#   permit=<许可串>
#   -----BEGIN CERTIFICATE-----   ← 本节点自己的 CA 证书链，含本节点 CA 一路到根
#   ...
#   -----END CERTIFICATE-----
#
# 【为什么不只放"父那一张"CA 证书】
# 链能不能验通只看"能否接到**某个**信任锚"，所以两种形态都能用起来；但：
#   · 只放**根**：父的 CA 作为中间证书参与验链，够用；
#   · 只放**父那一张**：上级节点签发的跨跳委托（ReqAuth）那条链**末端是根** ⇒ 在孙节点上验不过。
# 所以这里内嵌**整条链**（父 CA → … → 根），两种情形都覆盖。脚本会自检"最后一张必须是自签的根"。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

DIR=""
OUT=""
NEW_PERMIT=0
for a in "$@"; do
  case "${a}" in
    -h|--help) usage ;;
    --new-permit) NEW_PERMIT=1 ;;
    -*) die "未知参数 ${a}（用 --help 看用法）" ;;
    *) if [ -z "${DIR}" ]; then DIR="${a}"; elif [ -z "${OUT}" ]; then OUT="${a}"; else die "多余参数 ${a}"; fi ;;
  esac
done
[ -n "${DIR}" ] || usage
[ -d "${DIR}" ] || die "节点目录不存在: ${DIR}"

CA_CHAIN="${DIR}/certs/node.crt.ca"
SRC="${DIR}/enroll.token"
[ -n "${OUT}" ] || OUT="${SRC}"
[ -f "${CA_CHAIN}" ] || die "找不到 ${CA_CHAIN}：有下级的节点才有 CA 证书；中继要**先用父给的凭据完成自己的入网**，才会拿到它"

command -v openssl >/dev/null 2>&1 || die "找不到 openssl"

# ── ① 许可：默认严格沿用已存在的那个 ────────────────────────────────────────
PERMIT=""
if [ -f "${SRC}" ]; then
  # 新格式：permit=xxx
  PERMIT="$(sed -n 's/^[[:space:]]*permit[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*$/\1/p' "${SRC}" | head -1)"
  if [ -z "${PERMIT}" ]; then
    # 旧格式：整个文件就是一行裸许可串（且不含 PEM 块）
    if ! grep -q -- '-----BEGIN' "${SRC}" 2>/dev/null; then
      CAND="$(tr -d '\r\n' < "${SRC}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
      case "${CAND}" in
        ''|*'='*) ;;                 # 空 / 看起来像 key=value ⇒ 不当许可
        *) PERMIT="${CAND}" ;;
      esac
    fi
  fi
fi
if [ -z "${PERMIT}" ]; then
  if [ -f "${SRC}" ] && [ "${NEW_PERMIT}" -eq 0 ]; then
    die "${SRC} 里解析不出许可串（格式不认识）—— 换新许可会让子节点手上的旧凭据全部作废，" \
        "确实要换请显式加 --new-permit；否则先修好这个文件"
  fi
  PERMIT="$(openssl rand -hex 24)"
  ok "生成新的入网许可（${#PERMIT} 个字符的十六进制，192 bit）"
else
  ok "沿用已有的入网许可（不轮换，子节点手上的旧凭据继续有效）"
fi

# ── ② 锚：本节点自己的 CA 证书链（整条，含到根） ─────────────────────────────
TMPD="$(mktemp -d)"
trap 'rm -rf "${TMPD}"' EXIT
awk -v d="${TMPD}" '/BEGIN CERTIFICATE/{n++} {if (n>0) print > (d "/" n ".pem")}' "${CA_CHAIN}"
NCERT="$(ls -1 "${TMPD}" | wc -l | tr -d ' ')"
[ "${NCERT}" -ge 1 ] || die "${CA_CHAIN} 里没有证书"
LAST="${TMPD}/${NCERT}.pem"
# openssl 会带 "issuer=" / "subject=" 前缀，先剥掉再比（不然永远不相等，实测踩过）
LAST_IS="$(openssl x509 -in "${LAST}" -noout -issuer | sed 's/^issuer=//')"
LAST_SB="$(openssl x509 -in "${LAST}" -noout -subject | sed 's/^subject=//')"
[ "${LAST_IS}" = "${LAST_SB}" ] \
  || die "CA 证书链的最后一张不是自签的根 ⇒ ${CA_CHAIN} 里没有'到根'的完整链。" \
         "子节点必须拿到「本节点 CA → … → 根」整条链：只给一张会让上级签发的跨跳委托在孙节点上验不过"
FIRST_CN="$(openssl x509 -in "${TMPD}/1.pem" -noout -subject | sed -n 's/.*CN *= *\([^,]*\).*/\1/p')"

# ── ③ 原子写出（先写临时文件再 rename，别让别处读到"写了一半"的凭据） ──────
TMP_OUT="${OUT}.tmp"
{
  echo "# treecmd 入网引导凭据（由父节点产出，整份拷给每个子节点）"
  echo "# 格式定义见 internal/identity/bootstrap.go：permit 行 + 本节点 CA 证书链（含到根）"
  echo "permit=${PERMIT}"
  cat "${CA_CHAIN}"
} > "${TMP_OUT}"
chmod 600 "${TMP_OUT}"
mkdir -p "$(dirname "${OUT}")"
mv -f "${TMP_OUT}" "${OUT}"

echo
echo "════════════════════════════════════════════════════════════════"
echo " 入网引导凭据已就绪"
echo "   文件        ${OUT}"
echo "   许可        ${PERMIT:0:8}…（共 ${#PERMIT} 字符，完整值在文件里）"
echo "   内嵌锚      ${NCERT} 张（首张 CN=${FIRST_CN}，末张为自签根）"
echo "   下一步      把这一份文件拷给每个子节点（chmod 600）—— 它就是子节点要的全部材料"
echo "════════════════════════════════════════════════════════════════"
info "子节点侧：security.enrollment.token_path: enroll.token"
info "          （凭据里已含父的 CA 链 ⇒ 连 security.ca_cert_paths 与 trust/ 都不用配）"
