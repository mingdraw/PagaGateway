package main

import (
	"fmt"
	"io"
	"strings"
)

func isHelp(argument string) bool {
	return argument == "help" || argument == "-h" || argument == "--help"
}

func writeHelp(output io.Writer, topic string) error {
	var text string
	switch topic {
	case "":
		text = `PagaGateway - Page TCP 中转网关

用法:
  pagagateway <命令> [参数]

命令:
  server       中转服务端，提供前台运行和后台管理命令
  client       内网跳板客户端，提供前台运行和后台管理命令
  certificate  生成 Server 证书、私钥并显示 SHA-256 指纹
  version      显示版本
  help         显示帮助，可指定 server、client 或 certificate

服务管理命令:
  run          前台运行，日志输出到终端
  start        后台运行，关闭终端后继续运行
  status       查看后台运行状态
  stop         停止后台实例
  restart      重新读取原配置并重启后台实例
  clients      查看客户端地址和在线状态，仅 Server 支持

示例:
  pagagateway server start -config server.json
  pagagateway client start -config client.json
  pagagateway server restart
  pagagateway client status
  pagagateway server help
  pagagateway client help
  pagagateway certificate -host relay.example.com

run/start 需要 -config；status/stop/restart 自动沿用 start 的配置。
使用 -h 或 --help 也可查看帮助。
`
	case "server", "client":
		text = roleHelp(topic)
	case "certificate":
		text = `PagaGateway certificate - 生成 Server 证书

用法:
  pagagateway certificate [参数]

参数:
  -host name  Server 域名或 IP（默认 localhost）
  -cert file  证书输出路径（默认 server.crt）
  -key file   私钥输出路径（默认 server.key）

示例:
  pagagateway certificate -host relay.example.com
  pagagateway certificate -host 192.168.1.10 -cert relay.crt -key relay.key

输出证书的 SHA-256 指纹，供 Client 和 PagaShell 配置使用；不会覆盖已有文件。
`
	default:
		return fmt.Errorf("unknown help topic %q; use pagagateway help", topic)
	}
	_, err := io.WriteString(output, text)
	return err
}

func roleHelp(role string) string {
	description := "中转服务端"
	if role == "client" {
		description = "内网跳板客户端，主动连接 Server 并访问目标服务"
	}
	var text strings.Builder
	fmt.Fprintf(&text, "PagaGateway %s - %s\n\n用法:\n  pagagateway %s <命令> [参数]\n\n", role, description, role)
	text.WriteString(`命令:
  run -config file.json    前台运行，日志输出到终端
  start -config file.json  后台运行，关闭终端后继续运行
  status                  查看后台实例的 PID、配置和日志路径
  stop                    停止后台实例
  restart                 重新读取原配置并重启后台实例
`)
	if role == "server" {
		text.WriteString("  clients                 查看配置中的客户端地址和在线状态\n")
	}
	text.WriteString("  help                    显示本服务的帮助\n\n参数:\n")
	text.WriteString("  -config file  JSON 配置路径，run/start 必填；管理命令可省略\n")
	text.WriteString("  -pidfile file 后台状态文件，默认 <配置文件>.pid；多实例管理时用于选择实例\n")
	fmt.Fprintf(&text, "  -log file     后台日志路径，仅 start 使用，默认配置目录下的 %s.log\n", role)
	if role == "server" {
		text.WriteString("  -json         以 JSON 数组输出客户端列表，仅 clients 使用\n")
	}
	fmt.Fprintf(&text, "\n示例:\n  pagagateway %s run -config %s.json\n  pagagateway %s start -config %s.json\n  pagagateway %s status\n  pagagateway %s restart\n  pagagateway %s stop\n", role, role, role, role, role, role, role)
	if role == "server" {
		text.WriteString("  pagagateway server clients\n  pagagateway server clients -json\n")
	}
	fmt.Fprintf(&text, "  pagagateway %s restart -pidfile /path/to/%s.pid\n\n", role, role)
	text.WriteString("status/stop/restart 无需 -config，使用同一用户和同一路径的程序自动定位后台实例。\n同类实例有多个时使用 -pidfile 选择；restart 保留原配置路径、日志路径和启动目录。\n")
	fmt.Fprintf(&text, "省略 run 也可前台运行：pagagateway %s -config %s.json\n", role, role)
	return text.String()
}
