#!/usr/bin/env bash
# 单服务器手工部署的节点启动脚本（一个进程一个 node.yaml）。
#
#   ./scripts/start_node.sh <node.yaml 路径> [日志文件]
#   ./scripts/start_node.sh examples/child.yaml /var/log/treecmd/child.log
#
# 做四件事：① 先自检（配置 + 密钥 + 证书 + 信任锚）；② 后台启动并记 pid；
#          ③ 打印怎么"热重载证书"与"热更配置"；④ 支持 stop/status 子命令。
#
# 证书由你自己的脚本管理时：换完证书执行
#   kill -USR1 <pid>      # 立即重载证书（秒级生效，不重启、不断连接）
# 改了 node.yaml 的运行参数后执行
#   kill -HUP  <pid>      # 配置热更（关键字段变了才会触发重注册）
set -euo pipefail
export LC_ALL=${LC_ALL:-en_US.UTF-8} 2>/dev/null || true

cd "$(dirname "$0")/.."
BIN=./bin/treecmd-node

usage() {
  cat <<'EOF'
用法:
  ./scripts/start_node.sh <node.yaml> [日志文件]     启动（先自检）
  ./scripts/start_node.sh stop   <node.yaml>         停止
  ./scripts/start_node.sh status <node.yaml>         查看状态
  ./scripts/start_node.sh reload <node.yaml>         立即重载证书（SIGUSR1）
  ./scripts/start_node.sh conf   <node.yaml>         热更配置（SIGHUP）
  ./scripts/start_node.sh check  <node.yaml>         只自检
EOF
  exit 2
}

[ $# -ge 1 ] || usage
ACTION=start
case "${1}" in
  stop|status|reload|conf|check) ACTION="${1}"; shift ;;
esac
[ $# -ge 1 ] || usage
CFG="${1}"; shift || true
[ -f "${CFG}" ] || { echo "找不到配置文件: ${CFG}" >&2; exit 1; }

# pid 文件与日志跟配置文件放一起（同一节点一个目录，便于整目录搬迁）
DIR="$(cd "$(dirname "${CFG}")" && pwd)"
PIDFILE="${DIR}/node.pid"
LOG="${1:-${DIR}/node.log}"

[ -x "${BIN}" ] || { echo "先构建: go build -o bin/treecmd-node ./cmd/node" >&2; exit 1; }

running_pid() {
  [ -f "${PIDFILE}" ] || return 1
  local p; p="$(cat "${PIDFILE}" 2>/dev/null || true)"
  [ -n "${p}" ] && kill -0 "${p}" 2>/dev/null && { echo "${p}"; return 0; }
  return 1
}

case "${ACTION}" in
  check)
    exec "${BIN}" -check -config "${CFG}"
    ;;
  status)
    if p="$(running_pid)"; then echo "运行中 pid=${p}（${CFG}）"; else echo "未运行（${CFG}）"; exit 1; fi
    ;;
  stop)
    if p="$(running_pid)"; then
      kill -TERM "${p}"
      for _ in $(seq 1 30); do kill -0 "${p}" 2>/dev/null || break; sleep 0.2; done
      kill -0 "${p}" 2>/dev/null && kill -KILL "${p}" || true
      rm -f "${PIDFILE}"
      echo "已停止 pid=${p}"
    else
      echo "未运行（${CFG}）"
    fi
    ;;
  reload)
    if p="$(running_pid)"; then kill -USR1 "${p}"; echo "已请求重载证书 pid=${p}（看日志确认 cert reload: applied）"
    else echo "未运行（${CFG}）" >&2; exit 1; fi
    ;;
  conf)
    if p="$(running_pid)"; then kill -HUP "${p}"; echo "已请求配置热更 pid=${p}"
    else echo "未运行（${CFG}）" >&2; exit 1; fi
    ;;
  start)
    if p="$(running_pid)"; then echo "已在运行 pid=${p}"; exit 0; fi
    echo "== ① 自检 =="
    "${BIN}" -check -config "${CFG}"
    echo
    echo "== ② 启动（日志 ${LOG}）=="
    nohup "${BIN}" -config "${CFG}" >> "${LOG}" 2>&1 &
    echo $! > "${PIDFILE}"
    sleep 1
    p="$(running_pid)" || { echo "启动失败，看日志: ${LOG}" >&2; tail -20 "${LOG}" >&2; exit 1; }
    echo "已启动 pid=${p}"
    echo "  热重载证书: $0 reload ${CFG}"
    echo "  热更配置:   $0 conf   ${CFG}"
    echo "  查看日志:   tail -f ${LOG}"
    ;;
  *)
    usage
    ;;
esac
