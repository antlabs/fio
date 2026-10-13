# examples

三个协议的最小例子，每个都是「服务端 + 客户端」一对。三个服务端是同一套
接口（`GET /hello`、`POST /echo` 回显请求体），方便横向对比。

| 目录 | 协议 | 服务端 | 客户端 |
|---|---|---|---|
| `http1/` | HTTP/1.1 | `fio/http`（跑在 engine 上） | 标准库 `net/http`（fio 目前没有 HTTP/1.1 客户端） |
| `http2/` | HTTP/2 (h2c，明文) | `fio/http2` | `fio/http2` 自己的客户端连接（跑在 engine 上） |
| `http3/` | HTTP/3 | `fio/http3`（帧层是 fio 的，QUIC 用 quic-go） | `fio/http3.NewClient`（标准库 http.Client + fio 的 Transport） |

只支持 linux / darwin（引擎基于 epoll/kqueue）。

## HTTP/1.1

```bash
go run ./examples/http1/server     # 监听 127.0.0.1:8001
go run ./examples/http1/client     # 或 curl -v http://127.0.0.1:8001/hello
```

## HTTP/2（h2c）

```bash
go run ./examples/http2/server     # 监听 127.0.0.1:8002
go run ./examples/http2/client
```

客户端在一条连接上发两条流（`GET /hello` 和 `POST /echo`）——这是 HTTP/2
的多路复用，对照 `http1/` 看最清楚。

用明文 h2c 是为了例子里只有帧和流、没有 TLS 的干扰。TLS 上的 HTTP/2 见
`conformance/server`（`-proto=h2`）：在 HTTP/2 外面包一层
`fiotls.NewConnHandler`，`NextProtos` 配 `"h2"` 即可。

## HTTP/3

```bash
go run ./examples/http3/server     # 监听 127.0.0.1:8003 (UDP)
go run ./examples/http3/client     # 或 curl --http3 -k https://127.0.0.1:8003/hello
```

QUIC 强制 TLS 1.3，例子里服务端用自签证书（`fiotls.SelfSignedCert`），
客户端跳过验证。

## 端口

三个服务端的端口都用 `-addr` 改，客户端的 `-addr` 跟着改。
