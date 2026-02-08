# Spleen: 轻量级内网穿透工具

Spleen 是一款采用 Go 语言编写的反向隧道工具。它用于在复杂网络环境下, 通过 TLS 加密中转实现私有内网服务的公网暴露。该项目零外部依赖, 纯 Go 实现。

**典型使用场景**: 将没有公网 IP 的小型服务器（如家庭 NAS、开发机）通过一台具备公网 IP 的中转服务器暴露到外网，实现随时随地通过 SSH/HTTP 等协议访问内网资源。

## 核心功能与安全特性

Spleen 侧重于简洁的配置流与多层级的安全防护:

*   **连接池复用**: 通过预建立隧道减少 TCP 握手开销, 提升请求响应速度.
*   **指纹锁定 (TOFU)**: 采用 Trust-On-First-Use 机制, 首次连接自动记录并锁定服务端指纹, 防范中间人攻击.
*   **全链路加密**: 所有隧道流量均强制运行在 TLS 1.2/1.3 之上, 确保传输私密性.
*   **身份验证机制**: 使用基于 Nonce 的挑战响应协议, 防范重放攻击.
*   **只读控制台**: 实时展示连接状态、流量统计及**所有连接尝试（包含地理位置与成功/失败审计）**。
*   **地理位置识别**: 自动识别访问者归属地，支持内网 IP 识别。
*   **失败审计**: 自动记录并展示所有失败的访问尝试，帮助识别潜在的扫描与暴力破解行为。
*   **透明化配置**: 支持一键生成配对的 JSON 配置文件.
*   **抗 DDoS 与资源保护**: 内置连接频率限制与报文长度校验，有效降低内存放大风险与黑客攻击.

---

## 快速启动

推荐使用 Docker Compose 完成快速部署.

### 1. 准备工作

在**公网服务器**与**内网服务器**上分别执行以下命令克隆项目:

```bash
git clone https://github.com/leviathan0992/spleen.git
cd spleen
```

### 2. 生成安全令牌 (推荐在内网服务器执行)

为了安全，推荐在**内网服务器**生成 Token。运行初始化命令，会生成一个高强度的全局安全令牌:

```bash
docker-compose run --rm spleen-init
```

> [!NOTE]
> 该命令仅用于生成并打印 Token, `--rm` 参数用于在任务完成后自动清理容器。

### 3. 配置并启动内网客户端 (获取 ClientID)

为了配置服务端的静态映射规则，我们需要先获取客户端的唯一 ID。

1.  **编辑 `client-config.json`**:
    *   将 `token` 字段改为您生成的 Token。
    *   将 `server_addr` 改为您的公网服务器 IP。
2.  **启动客户端**:
    ```bash
    docker-compose up -d spleen-client
    ```
3.  **获取 ID (两种方式)**:
    *   **方式一 (推荐)**: 直接查看本地文件获取:
        ```bash
        cat data/client/.spleen_client_id
        ```
    *   **方式二**: 查看容器日志:
        ```bash
        docker-compose logs --tail=20 spleen-client
        ```

### 4. 配置并启动公网服务端

基于初始化的 Token 和 ClientID，配置服务端：

1.  **编辑 `server-config.json`**:
    *   将 `token` 修改为 init 时生成的令牌。
    *   在 `mapping_rules` 中填入客户端初始化时生成的 `client_id`。
    *   (可选) 修改 `dashboard_pwd` (默认为 `admin`)。
2.  **启动服务端**:
    ```bash
    docker-compose up -d spleen-server
    ```

### 5. 访问控制台

打开 `http://<公网IP>:54321`, 查看状态与映射信息。  
说明:
- 控制台只读, 用于观测和排障, 不用于写入配置.
- 映射规则列表会展示静态规则与动态规则, 但不会返回 Token 等敏感字段.

---

## 参数设置

### 服务端配置示例说明)
```json
{
  "token": "your-secret-token", 
  "tunnel_listen_address": "0.0.0.0:5432",
  "panel": {
    "dashboard_addr": "0.0.0.0:54321",
    "dashboard_user": "admin",
    "dashboard_pwd": "admin."
  },
  "mapping_rules": [
    {
      "id": "ssh-main",
      "client_id": "",
      "public_port": 2222,
      "target_port": 22,
      "remark": "备注信息"
    }
  ]
}
```

**参数说明**:

| 参数 | 说明 | 示例值 |
|------|------|--------|
| `token` | **全局安全令牌**。所有连接（静态映射与动态注册）均使用此令牌进行挑战响应验证。 | 任意长随机字符串 |
| `tunnel_listen_address` | TLS 隧道监听地址（Client 连接此端口） | `0.0.0.0:5432` |
| `panel.dashboard_addr` | Dashboard HTTP 监听地址 | `0.0.0.0:54321` |
| `panel.dashboard_user` | Dashboard 登录用户名 | `admin` |
| `panel.dashboard_pwd` | Dashboard 登录密码（PBKDF2 哈希） | 使用 `-gen-pwd` 生成 |
| `mapping_rules` | 静态映射规则列表 | 详见下方 |


**映射规则字段**:

| 字段 | 说明 | 是否必填 |
|------|------|:-------:|
| `id` | 规则唯一标识符 | ✅ |
| `client_id` | 客户端 UUID（与客户端 `.spleen_client_id` 一致） | ✅ |
| `public_port` | 公网服务器暴露的接收端口 | ✅ |
| `target_port` | 流量转发到内网客户端的目标端口 | ✅ |
| `remark` | 备注信息 | ❌ |


### 如何新增内网节点 (多客户端)

由于采用“全站统一 Token”设计，新增第 2、3...n 个内网节点非常简单：

1.  **Git Clone**: 在新的内网服务器上克隆仓库：`git clone https://github.com/leviathan0992/spleen.git
`。
2.  **配置**: 编辑仓库自带的 `client-config.json`，填入公网服务器地址及全局 `token`。
3.  **启动**: 运行 `docker-compose up -d spleen-client`。客户端启动后会自动生成独特的 ID。
4.  **获取 ID**: 运行 `cat data/client/.spleen_client_id` 获取该客户端的 ID。
5.  **关联**: 将新生成的 `client_id` 填入公网服务器 `server-config.json` 的 `mapping_rules` 中并重启服务端。

---

## 安全建议

1.  **最小权限运行**: 建议使用非 root 用户运行 Spleen 进程。
2.  **文件权限**: `server-config.json` 和 `client-config.json` 包含敏感凭据。使用 `spleen-init` 时会自动以 `0600` 权限（仅属主可读写）创建。若手动创建，请务必执行 `chmod 600 *.json`。
3.  **防火墙策略**:
    - 公网服务器建议**仅放行** `tunnel_listen_address` (如 5432) 和必要的业务映射端口。

---

## 开源协议
[Apache License 2.0](LICENSE)

---

## 安全防护策略

Spleen 采用多层次的安全设计来保护您的内网资源：

1.  **隧道连接保护 (Auth Guard)**:
    -   如果同一个内网客户端累计 8 次认证失败（Token 错误或 Nonce 重放），服务端将自动**封禁该来源 IP 20 分钟**。
    -   封禁期间，该 IP 的所有握手请求将直接被拒绝。

2.  **公网出口保护**:
    -   **超时机制**: 如果公网有人尝试连接但没有可用的内网隧道（或隧道忙），服务端会在 5 秒后主动断开。
    -   **失败审计**: 所有失败的连接尝试（如超时、空池等）都会实时记录并展示在控制台，您可以根据 IP 手动干预。

3.  **零信任访问**:
    -   不持有有效 Token 和认证 ClientID 的客户端无法建立任何隧道。
    -   采用 TOFU 机制锁定服务端，防止中间人拦截。
