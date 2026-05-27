# SFTPxy

企业级托管文件传输平台 (Enterprise Managed File Transfer Platform)

## 项目概述

SFTPxy 是一套企业级、安全、可配置、可审计、可扩展的托管文件传输平台，支持 SFTP、SCP、FTP/S、WebDAV 和 HTTP/S 等多种文件传输协议。

## 核心特性

- **多协议支持**: SFTP/SCP, FTP/FTPS, WebDAV, HTTP/HTTPS
- **多种存储后端**: 本地文件系统、加密本地文件系统、远程SFTP、HTTPFs
- **统一权限控制**: 细粒度的文件权限、配额管理、带宽限制、IP过滤
- **认证方式**: 密码认证、SSH公钥、TOTP MFA、OIDC、LDAP插件
- **Web管理界面**: WebAdmin管理端 + WebClient文件客户端
- **REST API**: 完整的OpenAPI 3接口
- **事件驱动**: 文件事件触发HTTP回调、命令执行、邮件通知
- **审计日志**: 结构化JSON日志，完整的操作审计
- **监控指标**: Prometheus metrics暴露
- **灵活部署**: 单二进制、Docker、Linux systemd、Windows服务

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端语言 | Go 1.21+ |
| HTTP路由 | Chi v5 |
| API规范 | REST + OpenAPI 3 |
| 数据库 | SQLite (默认) / MySQL 8.0+ |
| 数据迁移 | Goose |
| 数据访问 | SQLC (类型安全) |
| 配置管理 | Viper |
| 日志 | Zap (JSON结构化) |
| 指标 | Prometheus client_golang |
| SSH/SFTP | golang.org/x/crypto/ssh, pkg/sftp |
| FTP | fclairamb/ftpserverlib |
| WebDAV | golang.org/x/net/webdav |

## 快速开始

### 本地运行

```bash
# 克隆仓库
git clone https://github.com/sftpxy/sftpxy.git
cd sftpxy

# 构建
make build

# 使用默认配置运行
./bin/sftpxy --config config.yaml.example

# 或者复制配置文件并修改
cp config.yaml.example config.yaml
./bin/sftpxy --config config.yaml
```

### Docker运行

```bash
# 构建镜像
docker build -t sftpxy:latest .

# 运行容器
docker run -d \
  -p 2022:2022 \
  -p 8080:8080 \
  -v $(pwd)/config.yaml:/etc/sftpxy/config.yaml \
  -v sftpxy-data:/data/sftpxy \
  sftpxy:latest
```

### Docker Compose

```bash
docker-compose up -d
```

### Windows服务

```powershell
# 安装为Windows服务
sftpxy.exe install

# 启动服务
sftpxy.exe start

# 停止服务
sftpxy.exe stop

# 卸载服务
sftpxy.exe remove

# 调试模式运行
sftpxy.exe debug
```

### Linux systemd服务

```bash
# 使用安装脚本
sudo ./deploy/systemd/install.sh

# 或者手动安装
sudo cp bin/sftpxy /usr/local/bin/
sudo cp deploy/systemd/sftpxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sftpxy
sudo systemctl start sftpxy
```

## 项目结构

```
gosftp/
├── cmd/sftpxy/           # 应用入口
├── internal/
│   ├── auth/             # 认证模块 (密码/公钥/MFA)
│   ├── config/           # 配置管理
│   ├── database/         # 数据库连接
│   ├── events/           # 事件管理器
│   ├── logger/           # 日志系统
│   ├── metrics/          # Prometheus指标
│   ├── policy/           # 统一策略引擎
│   ├── protocols/        # 协议服务器
│   │   ├── ssh/          # SSH/SFTP/SCP
│   │   ├── ftp/          # FTP/FTPS
│   │   ├── webdav/       # WebDAV
│   │   └── httpd/        # HTTP服务器
│   ├── repository/       # 数据访问层
│   └── storage/          # 存储后端
│       ├── local/        # 本地文件系统
│       └── storage.go    # FileSystem接口
├── migrations/           # 数据库迁移脚本
│   ├── sqlite/
│   └── mysql/
├── sqlc/                 # SQLC配置
├── Makefile              # 构建脚本
├── Dockerfile            # Docker镜像
├── docker-compose.yml    # Docker Compose配置
└── config.yaml.example   # 示例配置
```

## 配置

主要配置项见 `config.yaml.example`：

```yaml
# SSH/SFTP配置
ssh:
  enabled: true
  listen_port: 2022
  password_auth: true
  public_key_auth: true

# HTTP配置
httpd:
  enabled: true
  listen_port: 8080
  webadmin_enabled: true
  webclient_enabled: true
  rest_api_enabled: true

# 数据库配置
data_provider:
  driver: "sqlite"
  connection_string: "./data/sftpxy.db"
```

## API文档

启动后访问 `http://localhost:8080/openapi` 查看OpenAPI文档。

## 监控指标

Prometheus指标暴露在 `http://localhost:9090/metrics`。

## 开发

```bash
# 安装依赖
go mod download

# 运行测试
make test

# 代码生成 (SQLC)
make generate

# 运行linter
make lint
```

## 许可证

MIT License
