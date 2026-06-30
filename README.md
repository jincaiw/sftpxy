# SFTPxy

[中文文档](./README.zh-CN.md) | [Docs](https://sftp.mujizi.com/) | [Releases](https://github.com/jincaiw/sftpxy/releases) | [Issues](https://github.com/jincaiw/sftpxy/issues)

SFTPxy is a self-hosted file transfer service with SFTP, WebAdmin, WebClient, FTP/S, WebDAV, REST APIs, and pluggable storage backends.

> If the docs site is not reachable, confirm GitHub Pages is enabled with the custom domain `sftp.mujizi.com` in repository settings.

## Highlights

- Single binary, installer, or Docker deployment
- Linux, Windows, and macOS support
- Web admin, web client, and OpenAPI
- Easy-to-follow install and user guides

## Quick start

1. Download the latest release for your platform.
2. Read the matching install guide:
   - [Linux](https://sftp.mujizi.com/install/linux/)
   - [Windows](https://sftp.mujizi.com/install/windows/)
   - [macOS](https://sftp.mujizi.com/install/macos/)
   - [Docker](https://sftp.mujizi.com/install/docker/)
3. Start the service.
4. Open `http://localhost:30080/`.

## Default ports

| Service | URL or port |
| --- | --- |
| WebAdmin + REST/OpenAPI | `http://localhost:30080/` |
| WebClient | `http://localhost:30081/` |
| SFTP | `30082` |
| FTP passive range | `30085-30088` |

## More docs

- [User manual](https://sftp.mujizi.com/manual/)
- [Configuration notes](https://sftp.mujizi.com/configuration/)
- [Release checklist](./docs/RELEASE_CHECKLIST.md)

## License

MIT License.
