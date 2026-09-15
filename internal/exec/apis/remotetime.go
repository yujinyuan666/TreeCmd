package apis

import (
	"context"
	"net/url"

	"treecmd/internal/exec"
)

// remoteTimeURL 是 timeapi.io 的"当前时间"接口。
//
// 上游行为（2026-09-14 实测）：GET + 查询参数 timeZone，返回一个**扁平 JSON 对象**，
// 其中 dateTime 形如 "2026-09-14T19:01:24.6326558"（带 7 位小数秒）。
const remoteTimeURL = "https://timeapi.io/api/Time/current/zone"

// remoteTime 向 timeapi.io 取一次深圳时区的当前时间。
//
// 用途是"各节点对时"：同一棵树里每个节点各自取一次，把结果放在一起就能看出
// 各节点的时钟差了多少（treecmd 自己也用 clock_offset_ms 跟踪这件事）。
// 与 uuidV4 相比，它多演示了两件事：**带查询参数**、以及**解一个 JSON 对象**（不是数组）。
//
// 参数：
//
//	ctx — 执行上下文；被取消会中断这次 HTTP 调用
//	s   — 指令输入；本接口不读 Payload（时区固定在代码里，要换就改下面那行）
//
// 返回：
//
//	any   — 一个 map：node / path / timezone / remote_time。带上 node 与 path 是为了
//	        聚合后仍能看出"这个时间是哪个节点取到的"，与 uuidV4 的做法一致
//	error — 请求失败、状态码非 2xx、或响应不是预期 JSON 时返回
func remoteTime(ctx context.Context, s exec.Spec) (any, error) {
	// 只需要这两个字段；上游多给的字段 encoding/json 会自动忽略
	var r struct {
		DateTime string `json:"dateTime"`
		TimeZone string `json:"timeZone"`
	}
	if err := getJSON(ctx, remoteTimeURL, url.Values{"timeZone": {"Asia/Shanghai"}}, &r); err != nil {
		return nil, err
	}
	return map[string]any{
		"node":        s.NodeID,
		"path":        s.Path,
		"timezone":    r.TimeZone,
		"remote_time": r.DateTime,
	}, nil
}
