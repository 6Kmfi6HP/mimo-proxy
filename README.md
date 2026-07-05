# mimo-proxy

MiMoCode Free API 的反向代理，支持 OpenAI 和 Anthropic 格式。

## 功能

- 支持 OpenAI 格式 (`/v1/chat/completions`)
- 支持 Anthropic 格式 (`/v1/messages`)
- 支持流式和非流式响应
- 支持 API Key 认证
- 自动刷新 JWT
- 支持 reasoning_content (思考过程)
- 跨平台编译 (Linux, Windows, macOS)
- 仅支持 `mimo-auto` 模型（上游限制）

## 安装

### 从 Release 下载

从 [GitHub Releases](../../releases) 下载对应平台的 zip 文件，解压后即可使用。

### 从源码编译

```bash
go build -o mimo-proxy .
```

### Docker 镜像

CI 会在推送到 `main` 或 `v*` tag 时发布 GHCR 镜像：

```bash
docker pull ghcr.io/6kmfi6hp/mimo-proxy:latest
docker run --rm -p 5000:5000 -v "$PWD/config.yaml:/app/config.yaml:ro" ghcr.io/6kmfi6hp/mimo-proxy:latest
```

### Docker Compose 部署

```bash
docker compose up -d
```

默认使用 `ghcr.io/6kmfi6hp/mimo-proxy:latest`，并挂载当前目录的 `config.yaml` 到容器内 `/app/config.yaml`。如需指定镜像版本：

```bash
MIMO_PROXY_IMAGE=ghcr.io/6kmfi6hp/mimo-proxy:v0.1.0 docker compose up -d
```

## 配置

编辑 `config.yaml`：

```yaml
# 监听端口 (默认: 5000)
port: 5000

# API Key 认证 (可选，留空则不需要认证)
api_key: ""

# 上游 API 地址 (默认: https://api.xiaomimimo.com)
# base_url: https://api.xiaomimimo.com
```

### 环境变量

环境变量会覆盖配置文件：

- `PORT`: 监听端口
- `MIMO_BASE_URL`: 上游 API 地址
- `MIMO_SOCKS5`: SOCKS5 代理地址（优先级高于配置文件）

### SOCKS5 代理

如果网络环境需要代理访问上游 API，可以在 `config.yaml` 或环境变量中配置：

```yaml
# config.yaml
socks5: "socks5h://100.74.21.88:7890"
```

或通过环境变量：

```bash
export MIMO_SOCKS5="socks5h://100.74.21.88:7890"
```

代理地址支持的格式：

| 协议 | 示例 |
|------|------|
| SOCKS5 | `socks5://127.0.0.1:7890` |
| SOCKS5 with auth | `socks5://user:pass@127.0.0.1:7890` |
| SOCKS5H（代理端解析域名） | `socks5h://100.74.21.88:7890` |

## 使用

### 启动代理

```bash
./mimo-proxy
```

### OpenAI 格式

```bash
curl -X POST http://localhost:5000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mimo-auto",
    "stream": true,
    "messages": [
      {"role": "user", "content": "你好"}
    ]
  }'
```

### Anthropic 格式

```bash
curl -X POST http://localhost:5000/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "model": "mimo-auto",
    "max_tokens": 100,
    "stream": true,
    "messages": [
      {"role": "user", "content": "你好"}
    ]
  }'
```

### 带 API Key 认证

如果配置了 API Key，客户端需要在请求头中提供：

```bash
curl -X POST http://localhost:5000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-api-key" \
  -d '{
    "model": "mimo-auto",
    "messages": [
      {"role": "user", "content": "你好"}
    ]
  }'
```

## 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/health` | GET | 健康检查（不需要认证） |
| `/v1/models` | GET | 模型列表 |
| `/v1/chat/completions` | POST | OpenAI 格式聊天 |
| `/v1/messages` | POST | Anthropic 格式聊天 |

## License

MIT
