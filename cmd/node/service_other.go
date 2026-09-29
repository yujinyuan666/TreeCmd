//go:build !linux

package main

import "fmt"

// installService 非 Linux 平台的占位实现：服务管理目前只支持 systemd，这里恒报错。
//
// 参数：
//
//	_ — 配置路径占位（Linux 实现用），本平台忽略
//
// 返回：
//
//	error — 恒返回"当前平台不支持"
func installService(_ string) error {
	return fmt.Errorf("-install 只支持 Linux (systemd)，当前平台不支持")
}

// uninstallService 非 Linux 平台的占位实现：服务管理目前只支持 systemd，这里恒报错。
//
// 参数：无。
//
// 返回：
//
//	error — 恒返回"当前平台不支持"
func uninstallService() error {
	return fmt.Errorf("-uninstall 只支持 Linux (systemd)，当前平台不支持")
}

// serviceAction 非 Linux 平台的占位实现：服务管理目前只支持 systemd，这里恒报错。
//
// 参数：
//
//	_ — 操作名占位（Linux 实现用），本平台忽略
//
// 返回：
//
//	error — 恒返回"当前平台不支持"
func serviceAction(_ string) error {
	return fmt.Errorf("-start/-stop/-restart/-status 只支持 Linux (systemd)，当前平台不支持")
}
