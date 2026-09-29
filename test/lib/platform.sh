#!/usr/bin/env bash
#
# platform.sh —— 跨平台小工具：把"macOS 能跑、Linux 不能跑"的那几个命令收口成函数。
#
# 为什么需要它：本仓库的验收脚本原先是按 macOS 写的，搬到 Linux（如 openEuler）上会踩三处，
# 而且**都不报错、只给出错误结论**（比直接失败更难查）：
#
#   · `stat`：BSD 用 `stat -f '%Lp'` 取权限、`stat -f%z` 取字节数；GNU 是 `-c '%a'` / `-c %s`。
#     GNU 下 `-f` 的语义是"文件系统统计"，会把格式串当**文件名**去 stat —— 于是打出无关内容
#     并以 1 退出。断言会以"权限不对"这种误导性方式失败。
#   · `lsof`：精简 Linux 发行版常常没装（openEuler 最小安装就没有）。
#     端口占用检测改走 `ss`（iproute2，系统自带）；最后再兜底到 bash 的 `/dev/tcp`。
#   · `shasum`：其实两边都有（perl-Digest-SHA），但更通用的是 coreutils 的 `sha256sum`。
#
# 用法：
#   . "${HERE}/lib/platform.sh"
#
# 全部函数只读、无副作用；本文件不 set -e（由调用脚本负责）。
# 这两个函数刻意**不**吞掉错误：取不到就返回非 0，让调用方的断言自己失败 —— 静默返回空串
# 会让 `[ "$(file_mode f)" = "600" ]` 这种断言以"值不对"的形式失败，看不出是工具缺失。

# file_size <路径> —— 输出字节数。
file_size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }

# file_mode <路径> —— 输出八进制权限（如 600、700）。注意 GNU 的 `-c %a` 不带前导 0。
file_mode() { stat -c %a "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# sha256_of <路径|-> —— 输出 64 位十六进制摘要；`-` 表示读 stdin。
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# port_in_use <端口> —— 0 = 有人在监听，1 = 没有。
# 判据是"有输出"而不是退出码：`ss` 在没有匹配项时**照样返回 0**（实测 openEuler ss 1.46）。
port_in_use() {
  local p="$1" out
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"${p}" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    return 1
  fi
  if command -v ss >/dev/null 2>&1; then
    out="$(ss -lntH "sport = :${p}" 2>/dev/null)" && [ -n "${out}" ] && return 0
    return 1
  fi
  # 兜底：能连上就算占用（只探回环；本目录下的用例都绑 127.0.0.1）
  (exec 3<>/dev/tcp/127.0.0.1/"${p}") >/dev/null 2>&1 && return 0
  return 1
}
