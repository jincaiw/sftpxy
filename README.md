# SFTPxy

[中文文档](./README.zh-CN.md) | [Docs](https://sftp.mujizi.com/) | [Downloads](https://sftp.mujizi.com/downloads/) | [Releases](https://github.com/jincaiw/sftpxy/releases) | [Issues](https://github.com/jincaiw/sftpxy/issues)

SFTPxy is a self-hosted file transfer service with SFTP, WebAdmin, WebClient, FTP/S, WebDAV, REST APIs, and pluggable storage backends.

Current release: `v0.2.3`.

## Highlights

- Single binary, installer, or Docker deployment
- Linux, Windows, and macOS support
- Web admin, web client, and OpenAPI
- Easy-to-follow install and user guides

## Quick start

1. Open the [Downloads](https://sftp.mujizi.com/downloads/) page.
2. Download the installer for your platform: DEB/RPM, Windows EXE, or macOS DMG.
3. Read the matching install guide:
   - [Linux](https://sftp.mujizi.com/install/linux/)
   - [Windows](https://sftp.mujizi.com/install/windows/)
   - [macOS](https://sftp.mujizi.com/install/macos/)
   - [Docker](https://sftp.mujizi.com/install/docker/)
4. Start the service.
5. Open `http://localhost:30080/`.

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
- [Release card](./docs/RELEASE_CARD.md)
- [Release checklist](./docs/RELEASE_CHECKLIST.md)

## License

MIT License.
