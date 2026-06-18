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

## 安装

### 从 Release 下载

从 [GitHub Releases](../../releases) 下载对应平台的 zip 文件，解压后即可使用。

### 从源码编译

```bash
go build -o mimo-proxy .
```

## 配置

复制示例配置文件：

```bash
cp config.example.yaml config.yaml
```

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
    "model": "gpt-4",
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
    "model": "claude-3-opus-20240229",
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
    "model": "gpt-4",
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
