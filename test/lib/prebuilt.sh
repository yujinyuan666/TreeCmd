#!/usr/bin/env bash
#
# lib/prebuilt.sh —— 「目标机不装 Go」这种部署形态下，让验收脚本照样跑得起来。
#
# 为什么需要这一层：
#
#   验收脚本原先默认「仓库里有源码，缺什么现编什么」。而 treecmd 的实际部署形态是
#   **只拷运行时**：目标机上没有 Go 工具链，也不该在那里编译。这时脚本若照旧去 `go build`，
#   会得到两种都不该出现的结果 ——
#
#     · `go: command not found`：报错长得像"功能坏了"，其实是环境不对；
#     · 更糟的是：某个断言因为"产物没造出来"而根本没跑到，报告里却不显眼
#       ⇒ **没测到伪装成测过了**。
#
#   所以把"产物从哪来"收口到这一层，口径写死成三条：
#
#     1. **有 Go 且源码在** → 照旧现编（开发机上的行为一个字不变）；
#     2. **没有 Go**        → 用随包带来的预编译产物，并且**不因为「源码比二进制新」重建**；
#     3. **没有 Go 又缺产物** → 响亮报错，说清缺哪一份、该在哪儿编。
#
#   第 3 条最要紧：静默退化会把 ✓ 变成噪声。
#
# 预编译产物的约定位置（都相对仓库根）：
#
#   bin/treecmd-node        主镜像
#   bin/treecmd-node.v1     变体（-X treecmd/internal/buildinfo.Version=v1）
#   bin/treecmd-node.v2     变体（…=v2）—— v1/v2 只差这一个注入值，但**字节不同 ⇒ 哈希不同**
#   bin/ca-rotate           test/ca-rotate/main.go 编出来的「CA 证书做旧」工具
#
# 在开发机上交叉编译（目标机零编译）：
#
#   export CGO_ENABLED=0 GOOS=linux GOARCH=amd64
#   go build -trimpath -o bin/treecmd-node    ./cmd/node
#   go build -trimpath -ldflags "-X treecmd/internal/buildinfo.Version=v1" -o bin/treecmd-node.v1 ./cmd/node
#   go build -trimpath -ldflags "-X treecmd/internal/buildinfo.Version=v2" -o bin/treecmd-node.v2 ./cmd/node
#   go build -trimpath -o bin/ca-rotate       test/ca-rotate/main.go
#
# 自带打印函数（带 _pb_ 前缀），不依赖调用方先定义 ok/info/die —— 免得 source 顺序
# 变成一条隐式约定。
_pb_info() { printf '    %s\n' "$*"; }
_pb_bad()  { printf '  \033[31m✗\033[0m %s\n' "$*" >&2; }
_pb_warn() { printf '  \033[33m!\033[0m %s\n' "$*" >&2; }

# have_go —— 本机有没有可用的 Go 工具链。
have_go() { command -v go >/dev/null 2>&1; }

# _pb_src_newer <仓库根> <文件> —— 仓库里有比该文件更新的 .go 源码吗？
#
# 注意「只拷运行时」的包里没有 cmd/ 与 internal/，"源码比二进制新"这件事就无从谈起 ——
# 这正是想要的：没有源码就没有重建的理由，老老实实用带来的那份。
#
# 所有函数都**显式 return**：`[ -n "$( )" ]` 在条件为假时返回 1，若它恰好是函数的最后一条
# 命令，函数也就返回 1；调用处写在 `set -e` 的脚本里当裸语句时会被引爆。
_pb_src_newer() {
  local repo="$1" f="$2"
  [ -d "${repo}/cmd" ] || [ -d "${repo}/internal" ] || return 1
  [ -n "$(find "${repo}/cmd" "${repo}/internal" -name '*.go' -newer "${f}" -print -quit 2>/dev/null)" ]
}

# ensure_node_bin <仓库根> <主镜像路径> —— 保证主镜像可用。
#
# 返回：
#   0 — 可用（可能刚编出来，也可能是带来的那份）
#   1 — 不可用（缺产物且本机编不出来）；调用方应当据此**响亮失败**，别再往下跑
ensure_node_bin() {
  local repo="$1" bin="$2"
  if [ -x "${bin}" ] && ! _pb_src_newer "${repo}" "${bin}"; then
    return 0
  fi
  if have_go; then
    _pb_info "重建 ${bin}（缺失或比源码旧）"
    ( cd "${repo}" && go build -o bin/treecmd-node ./cmd/node ) || { _pb_bad "编译失败"; return 1; }
    return 0
  fi
  if [ -x "${bin}" ]; then
    # 文件在，只是"源码比它新"。本机没有 Go，这个"新"不构成必须重建的理由：
    # 只拷运行时的包里压根没有源码，而 mtime 的"新"也可能只是拷贝顺序造成的假象。
    _pb_warn "本机没有 Go，跳过重建，直接用带来的 $(basename "${bin}")"
    return 0
  fi
  _pb_bad "缺少 ${bin}，而本机没有 Go 工具链（本环境约定：不在目标机编译）"
  _pb_info "请在开发机上编好再拷过来：go build -o bin/treecmd-node ./cmd/node"
  _pb_info "（交叉编译时加 CGO_ENABLED=0 GOOS=linux GOARCH=<目标架构>）"
  return 1
}

# ensure_variant <仓库根> <主镜像路径> <标记> [force] —— 保证 ${主镜像}.<标记> 这份变体可用。
#
# v1 / v2 的区别**只**在 `-ldflags -X treecmd/internal/buildinfo.Version=<标记>`：版本号本身只用于
# 展示，但它改了字节，于是哈希不同 —— 这正是不一致检测需要的输入。
#
#   · 有 Go：默认「已存在就复用」；force 非空则强制重造（selfupdate.sh 的 prepare 这么用）。
#   · 没有 Go：必须已经带着这份变体。**不能静默跳过** —— 跳过的话自更新用例会因为
#     "缺 v1/v2"而红，看报告的人会以为功能坏了。
ensure_variant() {
  local repo="$1" bin="$2" tag="$3" force="${4:-}" out="$2.$3"
  if [ -x "${out}" ] && [ -z "${force}" ]; then
    return 0
  fi
  if have_go; then
    _pb_info "编译变体 ${tag} → ${out}"
    ( cd "${repo}" && go build -ldflags "-X treecmd/internal/buildinfo.Version=${tag}" -o "${out}" ./cmd/node ) \
      || { _pb_bad "变体 ${tag} 编译失败"; return 1; }
    return 0
  fi
  if [ -x "${out}" ]; then
    _pb_warn "本机没有 Go，跳过重建，直接用带来的 $(basename "${out}")"
    return 0
  fi
  _pb_bad "缺少预编译变体 ${out}，而本机没有 Go 工具链"
  _pb_info "请在开发机上编好再拷过来："
  _pb_info "  go build -ldflags \"-X treecmd/internal/buildinfo.Version=${tag}\" -o bin/treecmd-node.${tag} ./cmd/node"
  return 1
}

# ca_rotate_helper <仓库根> —— **回显**「CA 做旧工具」的可执行文件路径（诊断信息走 stderr）。
#
# ⚠️ 这个函数用 stdout 当返回值，所以它**所有**诊断都必须走 stderr —— 哪怕 `_pb_info` 平时是
# 打 stdout 的。混进去一个字，调用方 `CA_HELPER="$(ca_rotate_helper …)"` 就会拿到一坨带
# 提示语的"路径"，然后在下一步以一个毫不相干的错误炸掉。
#
# 优先用带来的 bin/ca-rotate；没有它就看本机能不能现编（源码在 test/ca-rotate/main.go）。
# 两条路都不通时返回非零，并把"缺什么、去哪儿编"打出来。
#
# 为什么把它拆成一个独立的可执行文件：它原本是 `go run test/ca-rotate/main.go …`，
# 也就是"必须现场有 Go"。而它做的事（把 CA 证书的 NotBefore 往前挪）是**在目标环境的
# 节点目录上**完成的，工具本身只是手段 —— 把它编译好随包带上，目标机就不需要 Go 了。
ca_rotate_helper() {
  local repo="$1"
  # ⚠️ 必须分成两句：bash 的 `local a="$1" b="${a}/x"` 里，两个字**都在赋值之前展开**，
  # 所以 `${a}` 拿到的是外层的（未定义的）a —— 实测会把路径拼成 "/bin/ca-rotate"，
  # 然后在"文件不存在"的分支上炸掉，看起来像"预编译产物没带"，其实是解析错了路径。
  local helper="${repo}/bin/ca-rotate"
  if [ -x "${helper}" ]; then
    printf '%s' "${helper}"; return 0
  fi
  if have_go && [ -f "${repo}/test/ca-rotate/main.go" ]; then
    _pb_info "本机有 Go，现编 CA 做旧工具 → ${helper}" >&2
    ( cd "${repo}" && go build -o "${helper}" test/ca-rotate/main.go ) || return 1
    printf '%s' "${helper}"; return 0
  fi
  _pb_bad "缺少 ${helper}，而本机没有 Go 工具链（也编不出来）"
  _pb_info "请在开发机上编好再拷过来：go build -o bin/ca-rotate test/ca-rotate/main.go" >&2
  _pb_info "（交叉编译时加 CGO_ENABLED=0 GOOS=linux GOARCH=<目标架构>）" >&2
  return 1
}

# require_node_bin <主镜像路径> —— 只要求"文件在"（不关心源码新旧）的那些脚本用这个。
# 与 ensure_node_bin 的区别：这里不尝试重建，只把"该在哪儿准备"说清楚。
require_node_bin() {
  [ -x "$1" ] && return 0
  _pb_bad "找不到 $1"
  _pb_info "请放入预编译好的 bin/treecmd-node（开发机上：go build -o bin/treecmd-node ./cmd/node）"
  return 1
}
