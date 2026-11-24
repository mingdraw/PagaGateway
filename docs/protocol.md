# Page v1 TCP 协议

PagaShell 与 PagaGateway 共用的独立协议，不复用 frp 消息格式。

## 帧

Server 同时配置 `cert_file`、`key_file` 时使用 TLS 1.3；客户端配置非空指纹，按固定 SHA-256 DER 叶证书指纹验证 Server，再发送帧。Server 两项证书配置同时省略或为空时使用未加密 TCP，Client/PagaShell 的指纹须为空；两种模式共用相同 Page v1 帧，不自动协商或降级。仅配置一项证书字段会失败。每帧为 `4 字节大端无符号长度 + UTF-8 JSON`，长度 `1..8192`，须精确读取，不得吞掉后续帧或目标字节。

每条 JSON 消息都有 `version: 1`、`kind`。未知版本/非法帧关闭连接。不记录完整帧；无证书模式中的令牌为明文，仅 Server 启动时输出以下风险提示。首帧期限 15 秒。

> WARNING: TLS is disabled. Traffic and tokens are sent in plaintext, and the server identity is not verified. Use only on trusted networks.

| 首帧 kind | 字段 | 验证与结果 |
|---|---|---|
| `register` | `client_id`, `token`，可选 `max_tunnels`、`dial_feedback` | route 注册令牌；返回 `registered`，保持控制连接 |
| `open` | `client_id`, `token`, `host`, `port`，可选 `timeout_ms` | route 访问令牌；等待回连，成功返回 `ready` |
| `work` | `client_id`, `token`, `id`, 可选 `error` | route 注册令牌及当前控制会话的一次性 ID；不回响应帧 |

注册成功后 Client 每 10 秒发 `ping`，Server 回 `pong`，两侧读超时 35 秒。Server 对每个访问请求生成 32 个随机字节的十六进制 `id`，关联当前控制会话，通过控制连接发：

```json
{"version":1,"kind":"dial","id":"64位十六进制随机ID","host":"10.0.0.10","port":22}
```

Client 检查目标允许列表（`allowed_targets` 包含 `"*"` 时允许任意目标地址和端口）、拨号目标（最多 10 秒），按控制连接相同的 TLS / 无证书 TCP 模式新建工作连接并发 `work` 首帧。成功不含 `error`；旧 Client 通过 `work.error` 回报目标拒绝或不可用。Server 只接受当前 route、当前控制会话且尚未消费的请求 ID，过期或重复 ID 拒绝。

### 可选的 v1 扩展

- 新 Client 可在 `register` 报告 `max_tunnels` 和 `dial_feedback: true`。Server 按 Client 报告值与 route 配置值中较低的正数控制并发；未报告且未配置时，使用服务端总额度。旧 Client 收到的 `registered`、`dial`、`pong` 保留原字段和格式。
- 只有 `registered` 确认 `dial_feedback: true`，Client 才会在控制连接上发 `{"version":1,"kind":"dialFailed","id":"请求 ID","error":"code"}`。允许的原因是 `clientBusy`、`workUnavailable`、`targetDenied`、`targetUnavailable`、`targetTimeout`；其他原因归为 `targetUnavailable`。过期反馈忽略。协商成功的 Client 在成功的 `work` 首帧携带 `dial_feedback: true`，Server 拒绝此类工作流时直接关闭，避免把协议错误帧当成目标数据。
- `open.timeout_ms` 表示调用方剩余等待时间，Server 只用它缩短本地期限。协商成功后，`dial.timeout_ms` 带上发出时剩余的配对预算；Client 在这段预算内完成目标和工作连接的拨号。双方不依赖机器时钟同步。

成功配对后 Server 先向访问连接写 `ready`，双方开始传原始 TCP 字节。工作连接上提前发送的 SSH banner 等必须保留，并在 `ready` 后交给 PagaShell。

```json
{"version":1,"kind":"open","client_id":"office","token":"访问令牌","host":"10.0.0.10","port":22}
```

```json
{"version":1,"kind":"ready"}
```

## 错误与关闭

错误帧 `{"version":1,"kind":"error","error":"code"}`，随后关闭。访问端可收到 `unauthorized`、`clientOffline`、`invalidTarget`、`gatewayBusy`、`clientBusy`、`workUnavailable`、`targetDenied`、`targetUnavailable`、`targetTimeout`；注册还可能收到 `clientAlreadyOnline` 或 `gatewayBusy`；旧工作连接仍可收到 `unknownRequest`。不返回令牌、目标系统错误或任意 Client 错误字符串。

Server 对每条待配对访问同时计入访问连接和预留工作连接，总预算最多 15 秒，包含首帧和配对，超时释放预留。控制连接消失时关闭其在途及已配对连接。数据 EOF 保留半关闭，反向数据可排空；读写错误关闭两端。进程停止清理连接。重新注册不延续原 SSH/RDP 状态。
