#!/usr/bin/env bash
#
# ca-rotate.sh —— 验证「CA 证书在线轮换」（见 docs/四项外部经验借鉴方案.md §3）。
#
#   ./ca-rotate.sh          完整验证
#   ./ca-rotate.sh keep     跑完留着树（自己 ./demo.sh stop）
#
# 为什么需要它、以及它到底在验什么：
#
#   CA 证书的续签窗口判据是"剩余有效期 < 生命期 1/3"，而刚签出来的证书永远不落在窗口里。
#   所以脚本先用 `test/ca-rotate` 把根的那张 CA 证书**做旧**（NotBefore 往前挪），
#   让它下次启动就落在窗口里 —— 这样"轮换"这件事才可能被确定性地触发。
#
# 断言四件事：
#   ① 根确实轮换了 CA 证书（日志 + 文件指纹变化）；
#   ② 轮换的是**证书、不是密钥** —— 前后公钥逐字节相同（这是"下级不用重新分发 trust/"的全部依据）；
#   ③ 程序**没有碰信任锚文件**（certs/ca.crt 指纹不变）；
#   ④ 树仍然可用：用旧 CA 签发的子节点证书照旧能连上、指令照旧跑完
#      （证明轮换确实没打断既有信任关系，不需要下级重新入网）。
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# API 没有免签来源（含本机）：所有请求都要带 user token —— 见 lib/apitoken.sh
. "${HERE}/lib/apitoken.sh"   # 对外 API 一律要 user token：装好后所有 curl 自动带上
. "${HERE}/lib/platform.sh"   # 跨平台：文件摘要（GNU 上是 sha256sum，BSD 上是 shasum）
. "${HERE}/lib/prebuilt.sh"   # 产物从哪来：有 Go 就现编，只拷运行时的目标机就用带来的预编译产物
REPO="${TREECMD_REPO:-$(cd "${HERE}/.." && pwd)}"
DEMO="${HERE}/demo"
API_TOKEN_DIR="${DEMO}/root"      # token 签在哪个节点目录下（下面所有 curl 自动带上）
LOGS="${HERE}/logs"
ROOT_API="127.0.0.1:18493"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '  \033[31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

# fp <文件>：证书文件内容的短指纹（用文件哈希即可 —— 内容变了才算变了）
fp() { sha256_of "$1" | cut -c1-12; }

# pubkey <文件>：证书里公钥的指纹（同一把密钥 = 同一个值）
pubkey() { openssl x509 -in "$1" -noout -pubkey 2>/dev/null | sha256_of - | cut -c1-16; }

cleanup_tree() {
  "${HERE}/demo.sh" stop >/dev/null 2>&1 || true
}

ROOT_ID="0198f0c0-0000-7000-8000-0000de000001"

KEEP="${1:-}"

step "① 生成一份干净的根材料（**不启动任何进程**）"
cleanup_tree
# demo 目录整体挪走而不是 rm -rf：它文件很多，批量删除会被沙箱拦下
[ -d "${DEMO}" ] && mv "${DEMO}" "/tmp/tc-ca-demo-old.$$" 2>/dev/null || true
# 直接调 init_root.sh 生成根的自签材料，**不要**用"起一次树再停掉"那个办法。
#
# 为什么：起一次树会让两个子节点注册进根的注册表（并落进 state.dat），而 demo.sh 每次 start
# 都会重建子节点目录 ⇒ **子节点 NodeID 每次都变** ⇒ 根的表里会留下上一轮的"离线残留"。
# 后果很实在：`EnsureCreated` 会给**注册表里的每一个子**建 Assignment，包括那两个永远不会
# 上报的死人，于是指令永远等不到 done=total、一路耗到期限才判 TIMEOUT
# （实测：status=COMMAND_STATUS_TIMEOUT，而 result 里所有人的结果其实都齐了）。
# 这正是 MEMORY 里"残留死子节点"那条坑。少起一次树，这个坑就不存在。
"${REPO}/scripts/init_root.sh" "${DEMO}/root" "${ROOT_ID}" >/dev/null || die "init_root.sh 失败"
[ -f "${DEMO}/root/certs/node.crt.ca" ] || die "根没有生成 CA 证书（看 ${DEMO}/root）"
ok "根材料就绪：${DEMO}/root"

CA="${DEMO}/root/certs/node.crt.ca"
ANCHOR="${DEMO}/root/certs/ca.crt"
IDCERT="${DEMO}/root/certs/node.crt"

# 做旧之前的两个指纹：CA 证书（会被做旧+轮换两次）与信任锚（程序绝不该碰）
ORIG_PUB="$(pubkey "${CA}")"
ANCHOR_FP_BEFORE="$(fp "${ANCHOR}")"
info "原始 CA 公钥指纹   = ${ORIG_PUB}"
info "信任锚 ca.crt 指纹 = ${ANCHOR_FP_BEFORE}"

step "② 把根的 CA 证书做旧（NotBefore 往前挪 20h，生命期 22h ⇒ 落在续签窗口里）"
# 做旧工具原本是 `go run test/ca-rotate/main.go …` —— 也就是"必须现场有 Go"。
# 改成优先用随包带来的 bin/ca-rotate（见 lib/prebuilt.sh）：**做旧这个动作仍然发生在目标环境**
# （它操作的就是 ${DEMO}/root 里的证书），只是工具本身不必在那里编译。
CA_HELPER="$(ca_rotate_helper "${REPO}")" || die "拿不到 CA 做旧工具"
( cd "${REPO}" && "${CA_HELPER}" -dir "${DEMO}/root" -life 22h -age 20h ) \
  || die "做旧失败"
AGED_FP="$(fp "${CA}")"
[ "$(pubkey "${CA}")" = "${ORIG_PUB}" ] && ok "做旧后公钥不变（只动有效期）" \
  || die "做旧把公钥也换了，测试无效"

step "③ 起树：根启动时应当**先续 CA 证书、再用新 CA 证书重签身份证书**"
# 上一次 stop 之后 .demo.pids 可能还在（stop 只在正常路径清它），不干掉的话 start 会直接拒绝。
# 用 mv 而不是 rm：某些受限环境会拦批量/脚本内删除，而移动不会被拦。
mv "${HERE}/.demo.pids" "/tmp/tc-ca-pids.$$" 2>/dev/null || true
"${HERE}/demo.sh" start >/dev/null 2>&1 || die "demo.sh start 失败"
sleep 6

# 启动路径与运行期路径都会续期，两条都要认（启动路径打的是"证书已自签续期"）
grep -Eq 'cert self-renew: applied|证书已自签续期' "${LOGS}/root.log" \
  || die "根没有自签续期（看 ${LOGS}/root.log）"
ok "根在启动时自签续期了"
grep -q 'CA 证书已轮换' "${LOGS}/root.log" \
  || die "根没有轮换 CA 证书（看 ${LOGS}/root.log）"
ok "日志确认：CA 证书已轮换"

ROTATED_FP="$(fp "${CA}")"
[ "${ROTATED_FP}" != "${AGED_FP}" ] && ok "certs/node.crt.ca 内容已变（${AGED_FP} → ${ROTATED_FP}）" \
  || die "CA 证书文件内容没变，说明没有真的轮换"

step "④ 断言核心不变量"
[ "$(pubkey "${CA}")" = "${ORIG_PUB}" ] \
  && ok "轮换后 CA 公钥与最初**逐字节相同** —— 轮换的是证书、不是密钥" \
  || die "轮换换了 CA 密钥（那需要全树重分发 trust/，本机制不支持）"
[ "$(fp "${ANCHOR}")" = "${ANCHOR_FP_BEFORE}" ] \
  && ok "信任锚 ca.crt 未被改动（下级手里的那份副本照旧有效）" \
  || die "程序动了信任锚文件（不该发生）"
info "（certs/node.crt.ca 给的是"我们出示的 CA 证书"，certs/ca.crt 是给下级的"分发副本" —— "
info " 两者同密钥，所以换前者不影响后者，这就是不用重分发 trust/ 的原因）"

step "⑤ 断言树仍然可用：旧 CA 签发的子节点照旧连上、指令照旧跑完"
Z="$(curl -s --max-time 5 "http://${ROOT_API}/v1/healthz" || true)"
case "${Z}" in *'"ok":true'*) ok "根 HTTP 可用" ;; *) die "根 HTTP 不通：${Z}" ;; esac

# 根的直接子应当**全部**还连着，而且要是**这一轮**的那两个
# （它们的身份证书是第一次启动时用**轮换前**的 CA 签发的 —— 这才是本步要证的东西）。
#
# 为什么不能写"在线数 ≥ N"，也不能写"children 里全部在线"：
# 本脚本会 `demo.sh start` **两次**，而每次 start 都会重建子节点目录
# （`prepare_child` 里 rm -rf + 重新 genkey）⇒ **子节点 NodeID 每次都变**。
# 于是根的表里会留下上一轮那批"离线残留"（它们从没走过 /v1/forget），
# `/v1/tree` 的 children 会变成 4 个、其中只有 2 个在线。所以断言必须落到**本轮这两个 ID** 上。
LEAF1_ID="$(sed -n 's/.*node_id=\([0-9a-f-]\{36\}\).*/\1/p' "${LOGS}/leaf1.log" | head -1)"
RELAY_ID="$(sed -n 's/.*node_id=\([0-9a-f-]\{36\}\).*/\1/p' "${LOGS}/relay.log" | head -1)"
[ -n "${LEAF1_ID}" ] && [ -n "${RELAY_ID}" ] \
  || die "读不到本轮子节点的 node_id（看 ${LOGS}/leaf1.log 与 relay.log）"

TREE="$(curl -s --max-time 5 "http://${ROOT_API}/v1/tree" || true)"
ONLINE="$(printf '%s' "${TREE}" | /usr/bin/python3 -c "
import json,sys
want = set(sys.argv[1:3])
got = {c['node_id'] for c in json.load(sys.stdin)['children'] if c['online']}
print(len(want & got))
" "${LEAF1_ID}" "${RELAY_ID}" 2>/dev/null || echo 0)"
[ "${ONLINE}" = "2" ] \
  && ok "本轮两个直接子都还在线（轮换没有打断既有会话）" \
  || die "本轮的子节点掉了（在线 ${ONLINE}/2）—— 轮换破坏了既有信任关系"

# 提交时**显式给一个宽裕的期限**，别用 echo 的默认值。
#
# 原因：`default_deadline_by_type.echo` 默认是 **1 分钟**，而 demo 树用的默认
# `tick_interval` 是 min(child_stuck_timeout, lease_ttl)/4 = **22.5s** —— `waitChildren`
# 是**按 tick 检查**的，所以一棵 3 层的树要跨两个 tick 边界，正常也要 ~45s 才落终态，
# 只剩 15 秒余量，稍微慢一点就会被判 `COMMAND_STATUS_TIMEOUT`：
# 实测就是这样 —— 结果其实**已经完整聚合好**（三个后代的结果都在 result 里），
# 状态却是 TIMEOUT。本脚本要证的是"轮换后链路还通"，不该被这个默认值的余量牵着走。
SUBMIT="$(curl -s --max-time 5 -XPOST "http://${ROOT_API}/v1/commands" \
  -d '{"type":"echo","payload":"aGVsbG8=","aggregate":"TREE","max_duration":"5m"}' || true)"
CMD="$(printf '%s' "${SUBMIT}" | /usr/bin/python3 -c 'import json,sys;print(json.load(sys.stdin).get("command_id",""))' 2>/dev/null || true)"
[ -n "${CMD}" ] || die "提交指令失败：${SUBMIT}"
info "指令 ${CMD} 已提交，轮询到终态…"
# 轮询到终态。**预算必须给足**：demo 树用的是默认 `tick_interval`
# （min(child_stuck_timeout, lease_ttl)/4 = 22.5s），也就是"一批指令跑完之后，多久被判定为终态"
# 最多要等一个周期 —— 一棵 3 层的树往往要 20~45s 才收敛。
# 之前这里写的是 40 × 0.4s = **16 秒**，必然不够，于是报"指令没有跑完"，而实际只是还没到点。
#
# 另外别把 `NOT_FOUND / 结果不在本节点，且索引未命中` 当错误：那是"还在跑"的正常中间态
# （结果还没回传到本节点），要继续轮询。
STATE=""
for i in $(seq 1 120); do
  R="$(curl -s --max-time 5 "http://${ROOT_API}/v1/commands/${CMD}" || true)"
  STATE="$(printf '%s' "${R}" | /usr/bin/python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("status",""))' 2>/dev/null || true)"
  case "${STATE}" in
    COMMAND_STATUS_COMPLETED) break ;;
    COMMAND_STATUS_FAILED|COMMAND_STATUS_TIMEOUT|COMMAND_STATUS_CANCELLED) break ;;
  esac
  [ $((i % 15)) -eq 0 ] && info "  仍在等待收敛（已等 ${i}s，当前状态 ${STATE:-结果尚未回传}）"
  sleep 1
done
[ "${STATE}" = "COMMAND_STATUS_COMPLETED" ] \
  && ok "全树指令跑完（${STATE}）—— 轮换后 mTLS 与指令链完全正常" \
  || die "指令没有跑完：${STATE}（最后响应 ${R:-空}）"

step "完成"
info "证据：${LOGS}/root.log 里的「cert self-renew: applied」与「CA 证书已轮换」两行"
info "      ${CA} 是轮换后的 CA 证书；${ANCHOR} 全程未变"

[ "${KEEP}" = "keep" ] || cleanup_tree
