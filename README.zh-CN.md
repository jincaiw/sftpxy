# SFTPxy

[English](./README.md) | [文档](https://sftp.mujizi.com/) | [下载](https://sftp.mujizi.com/downloads/) | [Releases](https://github.com/jincaiw/sftpxy/releases) | [Issues](https://github.com/jincaiw/sftpxy/issues)

SFTPxy 是一个自托管文件传输服务，支持 SFTP、WebAdmin、WebClient、FTP/S、WebDAV、REST API 和可插拔存储后端。

当前版本：`v0.2.3`。

## 特点

- 单文件、安装包或 Docker 部署
- 支持 Linux、Windows、macOS
- 提供 Web 管理端、Web 客户端和 OpenAPI
- 安装和使用文档清晰易读

## 快速开始

1. 打开 [下载页](https://sftp.mujizi.com/downloads/)。
2. 下载对应平台安装程序：DEB/RPM、Windows EXE 或 macOS DMG。
3. 查看安装指南：
   - [Linux](https://sftp.mujizi.com/install/linux/)
   - [Windows](https://sftp.mujizi.com/install/windows/)
   - [macOS](https://sftp.mujizi.com/install/macos/)
   - [Docker](https://sftp.mujizi.com/install/docker/)
4. 启动服务。
5. 打开 `http://localhost:30080/`。

## 默认端口

| 服务 | URL 或端口 |
| --- | --- |
| WebAdmin + REST/OpenAPI | `http://localhost:30080/` |
| WebClient | `http://localhost:30081/` |
| SFTP | `30082` |
| FTP 被动端口范围 | `30085-30088` |

## 更多文档

- [用户手册](https://sftp.mujizi.com/manual/)
- [配置说明](https://sftp.mujizi.com/configuration/)
- [发布检查清单](./docs/RELEASE_CHECKLIST.md)

## 许可证

MIT License。
