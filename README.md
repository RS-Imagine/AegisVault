# AegisVault

本地优先的个人密码与银行卡管理器，支持 Web/PWA、Windows 便携版和 Android 测试版。使用 React、TypeScript 和 Web Crypto；可选的 Cloudflare Worker 只同步密文。

## 下载

前往 [GitHub Releases](https://github.com/RS-Imagine/AegisVault/releases) 下载预览版：

- **Windows x64**：解压 `Windows-x64-portable.zip`，在可写目录运行 `AegisVault-Portable.exe`。需要 Microsoft Edge WebView2 Runtime。数据保存在同级 `aegis-data` 目录，迁移时复制整个目录。EXE 未进行代码签名。
- **Android**：安装 `Android-test.apk`。当前为调试签名测试版，后续构建可能需要先备份再卸载重装；系统级自动填充尚未实现。
- `SHA256SUMS.txt` 可用于核对下载文件的 SHA-256。

## 功能与安全边界

- PBKDF2-HMAC-SHA256（默认 600,000 次）派生不可导出的 AES-256-GCM 密钥；新建密码库使用 V3 整库认证，记录及分类在本地加密。
- IndexedDB 持久化，支持加密备份导入/导出、主密码轮换和空闲自动锁定。
- 本地字体与图标，PWA 支持离线启动；演示数据与正式密码库隔离。
- 可选的 Cloudflare Durable Objects 同步提供版本冲突检查和历史密文快照。

V3 可检测整库删改，并使用本设备保存的已验证检查点拒绝已观察版本之前的云端快照；**没有检查点的新设备不能证明云端返回的是全局最新版本**。V2 仍可读取，可在解锁后显式备份升级。并发保存发生冲突时会保留当前表单，供重新打开记录后合并。升级前应先更新同步 Worker 和所有客户端，详见 [V3 格式、迁移与安全边界](docs/v3-format.md)。本项目尚未经过独立安全审计，请保留独立加密备份；[首次审阅记录](docs/security-review.md)保留历史发现。

## 本地开发

需要 Node.js >= 22.13：

```sh
npm ci --legacy-peer-deps
npm run dev
npm test
npm run lint
npm run build
# 首次运行浏览器回归时安装 Chromium
npx playwright install --with-deps chromium
npm run test:e2e
```

## Windows 构建

在 Windows 安装 Rust stable、Visual Studio C++ 构建工具及 WebView2 Runtime：

```sh
npm ci --legacy-peer-deps
npm run native:icons
npm run portable:win
```

EXE 位于 `src-tauri/target/release/aegis-vault-portable.exe`。Tauri 会自动构建前端。

## Android 构建

需要 Java 21 和 Android SDK：

```sh
npm ci --legacy-peer-deps
npm run android:init
cd android
./gradlew assembleDebug
```

APK 位于 `android/app/build/outputs/apk/debug/app-debug.apk`。已生成 Android 工程后，可通过 `npm run android:sync` 更新前端。Android 工程由锁定版本的 Capacitor 生成，不提交构建产物。

## 自动构建与发布

[原生发布工作流](.github/workflows/build-portable-and-android.yml) 在推送 `v*` 标签时运行测试、Windows 构建与启动检查、Android 构建与 APK 签名验证；两平台均成功后发布 GitHub 预发布版本和校验文件。手动运行可只构建临时产物。

发布前同步修改 `package.json`、`src-tauri/Cargo.toml` 和 `src-tauri/tauri.conf.json` 的版本；标签须对应同一版本，例如 `v2.0.1-preview.3`。正式 Android 发布需要配置并长期保存发布签名密钥。

GitHub Pages 工作流保留为手动触发；Cloudflare 同步后端的部署见 [worker/README.md](worker/README.md)。API Token 使用 Cloudflare Secret 配置，不能提交到仓库。

## 项目结构

- `src/`：界面、加密引擎、同步和回归测试
- `shared/`：前后端共用的密文信封校验
- `worker/`：可选的云同步后端
- `src-tauri/`：Windows 原生外壳
- `public/`：PWA 静态资源
- `scripts/`：生成 Android 版本、图标和启动资源
- `docs/`：安全审阅记录

许可证：[Apache-2.0](LICENSE)。
