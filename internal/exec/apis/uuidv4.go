package apis

import (
	"context"
	"net/url"

	"treecmd/internal/exec"
)

// uuidV4URL 是 uuidtools.com 的 UUID v4 生成接口。
//
// 上游行为（2026-09-14 实测）：响应是 JSON 字符串数组，如 ["d7e6c356-2daf-4a4e-aa71-5f080a123223"]；
// **免费接口忽略 count**（带 count=3 或 count=99999 都只回 1 条），所以这里固定带 count=1。
const uuidV4URL = "https://www.uuidtools.com/api/generate/v4"

// uuidV4 调一次 uuidtools 的 v4 接口，返回本节点拿到的那条（或几条）UUID。
//
// 参数：
//
//	ctx — 执行上下文；被取消会中断这次 HTTP 调用
//	s   — 指令输入；本接口不读 Payload（上游不接受除 count 外的参数）
//
// 返回：
//
//	any   — 一个 map：node / path / uuids。带上 node 与 path 是为了聚合后仍能看出
//	        "每条 UUID 是哪个节点拿到的"，与内置 echo 执行器一致
//	error — 请求失败、状态码非 2xx、或响应不是字符串数组时返回
func uuidV4(ctx context.Context, s exec.Spec) (any, error) {
	var uuids []string
	if err := getJSON(ctx, uuidV4URL, url.Values{"count": {"1"}}, &uuids); err != nil {
		return nil, err
	}
	return map[string]any{"node": s.NodeID, "path": s.Path, "uuids": uuids}, nil
}
