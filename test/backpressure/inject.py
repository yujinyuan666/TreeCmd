#!/usr/bin/env python3
"""把一组 `command.*` 运行参数幂等地写进某个 node.yaml —— 供背压验收脚本做热更。

为什么需要它：验收脚本要"改窗口 → SIGHUP → 看行为变化"。直接往文件末尾 `echo` 追加是不行的，
第二次改就会写出**两个 `command:` 段**，而 yaml.v3 对重复键是报错（配置直接读不进来，
节点下次启动都起不来）。所以这里用一对标记把它变成一个可反复覆盖的块。

它只做**文本**操作，不依赖 PyYAML（测试环境不保证装了这个库）。

用法：

    python3 inject.py <node.yaml> key=value [key=value ...]
    python3 inject.py --strip <node.yaml>          # 去掉注入块，恢复文件原样

多个键会按传入顺序写进同一个 `command:` 段。
"""

import os
import sys
import tempfile

BEGIN = "# >>> treecmd-backpressure 注入（本块由 test/backpressure.sh 生成，可反复覆盖）"
END = "# <<< treecmd-backpressure 注入结束"


def strip_block(text):
    """把上一次注入的整块（含标记）从文本里去掉。

    参数：

        text — 文件全文

    返回：

        str — 去掉注入块后的全文；没有注入块时原样返回
    """
    line = text.find(BEGIN)
    if line < 0:
        return text
    tail = text.find(END, line)
    if tail < 0:
        return text[:line]
    tail = text.find("\n", tail)
    if tail < 0:
        return text[:line]
    return text[:line] + text[tail + 1:]


def write_atomic(path, text):
    """原地原子写：同目录临时文件 → fsync → rename。

    参数：

        path — 目标文件路径
        text — 要写入的全文
    """
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".inject-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)  # node.yaml 里可能写着路径与开关，保持 600
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "--strip":
        path = argv[2]
        with open(path) as f:
            orig = f.read()
        write_atomic(path, strip_block(orig))
        return 0

    path = argv[1]
    pairs = []
    for arg in argv[2:]:
        if "=" not in arg:
            print("坏参数（要 key=value）：%s" % arg, file=sys.stderr)
            return 2
        k, v = arg.split("=", 1)
        pairs.append((k.strip(), v.strip()))
    if not pairs:
        print("至少要给一个 key=value", file=sys.stderr)
        return 2

    with open(path) as f:
        body = strip_block(f.read())
    if not body.endswith("\n"):
        body += "\n"
    block = [BEGIN, "command:"]
    for k, v in pairs:
        block.append("  %s: %s" % (k, v))
    block.append(END)
    write_atomic(path, body + "\n".join(block) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
