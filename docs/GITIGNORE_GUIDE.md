# .gitignore 说明

本文档按用途说明当前仓库的 `.gitignore` 规则，帮助区分：哪些是应该忽略的本地产物，哪些是应保留在仓库中的源码/资源。

## 1. 构建产物

用于忽略编译、打包、发布过程中生成的文件和目录：

- `SFTPxy`
- `SFTPxy.exe`
- `/output/`
- `/dist/`
- `/build/`
- `/release/`
- `/artifacts/`
- `/coverage/`
- `/test-results/`
- `/playwright-report/`

## 2. 测试与运行产物

用于忽略测试执行后生成的数据库、日志和临时文件：

- `SFTPxy.db`
- `SFTPxy.db-shm`
- `SFTPxy.db-wal`
- `*.db`
- `*.db-shm`
- `*.db-wal`
- `*.log`
- `*.pid`
- `*.tmp`
- `*.bak`
- `*.backup`
- `backups/`
- `logs/`
- `env.d/`

## 3. 测试插件二进制

用于忽略测试目录下由 Go build 生成的本地可执行文件：

- `tests/ipfilter/ipfilter`
- `tests/eventsearcher/eventsearcher`

## 4. 本地密钥与证书

用于忽略开发/测试时在仓库根目录生成的 SSH 密钥和证书：

- `/id_rsa`
- `/id_rsa.pub`
- `/id_ecdsa`
- `/id_ecdsa.pub`
- `/id_ed25519`
- `/id_ed25519.pub`
- `/*.pem`
- `/*.key`
- `/*.crt`

## 5. 本地开发缓存与工具状态

用于忽略本地工具缓存和私有状态目录：

- `.gocache/`
- `.gopath/`
- `.trae/`
- `.DS_Store`
- `.env`
- `.env.*`
- `!.env.example`

## 6. 发布辅助产物

用于忽略本地发布流程生成的临时文件：

- `pkgs/dist/`
- `windows-installer/output/`
- `/docs/RELEASE_SOP.md`

## 7. 说明

### 应该忽略的

- 编译产物
- 测试产物
- 临时日志
- 本地缓存
- 本地密钥/证书
- 发布临时文件

### 不应该忽略的

- 源码目录
- 文档源码
- 配置模板
- 真实示例文件
- 需要纳入版本控制的测试代码

## 8. 维护建议

如果后续新增以下内容，优先判断是否应加入 `.gitignore`：

- 新的本地数据库文件
- 新的构建输出目录
- 新的临时证书/密钥文件
- 新的发布包中间目录

如果是长期保留的示例/文档/测试源码，不要加入忽略规则。
