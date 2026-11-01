# AegisVault V2 — 零知识个人密码管理器 (Web Crypto + PWA 离线优先 + Cloudflare Durable Objects)

AegisVault V2 是一款面向个人使用的零知识 (Zero-Knowledge) Web 端密码与银行卡管理器，采用 **React 19 + TypeScript + Vite + Web Crypto API** 构建，具备完整的 **PWA 离线冷启动能力**、**中国大陆网络零第三方阻塞优化**，并配备基于 **Cloudflare Worker + SQLite Durable Objects** 的强一致多设备密文同步架构。

---

## 核心安全与架构特性 (V2)

### 1. V2 零知识密码学设计 (`formatVersion: 2`)
- **高强度密钥派生 (KDF)**：使用浏览器原生 Web Crypto API `PBKDF2-HMAC-SHA256`，默认 **600,000 次迭代** 与 128-bit CSPRNG 随机盐值 (`kdf.salt`)，派生的 256-bit `CryptoKey` 标记为不可导出 (`extractable: false`)，仅驻留运行时内存。
- **独立密码库身份标识 (`vaultId`)**：创建密码库时生成独立于 `kdf.salt` 的 CSPRNG UUID `vaultId`。修改主密码或轮换密钥时，`vaultId` 保持不变，而 `kdf.salt`、派生密钥与全部密文重新生成。
- **AES-256-GCM + AAD 关联数据认证绑定**：
  - `verifier` 绑定 `vaultId`、`formatVersion`、`kdf.iterations` 与 `kdf.salt`。
  - `encryptedMetadata` 将用户自定义分类与标签完整加密存储在密文信封内（绑定 `vaultId` 与 `formatVersion`），绝不在 `localStorage` 中保存任何明文分类键。
  - `encryptedRecords` 每条记录使用独立 96-bit 随机 IV 加密，并通过 AAD 绑定 `vaultId`、`recordId`、`recordType`、`createdAt` 与 `updatedAt`，防止跨库密文替换或外层元数据篡改。

### 2. 中国大陆网络兼容与零第三方隐私保护
- **移除全部 Google 外部依赖**：
  - **字体全面本地化**：`Plus Jakarta Sans Variable` 与 `JetBrains Mono Variable` 通过 `@fontsource-variable/*` 随构建打包为本地 WOFF2 资源，配合 `PingFang SC`、`Microsoft YaHei` 等中文系统字体回退栈，彻底消除 `fonts.googleapis.com` 与 `fonts.gstatic.com` 在大陆直连环境下的连接挂起。
  - **零外部网站图标请求**：彻底移除 `https://www.google.com/s2/favicons` 请求。密码库解锁与浏览时全部采用内置本地矢量品牌图标（GitHub、Cloudflare、Apple、支付宝、微信、淘宝、京东、Bilibili、主流银行等）与确定性本地首字母徽标，既杜绝向第三方泄露用户保存的站点域名，又避免弱网下图片请求超时。
- **PWA 离线冷启动与安全更新**：
  - 配备 `manifest.webmanifest`、多尺寸离线图标与构建期注入资源清单的 `sw.js` Service Worker，同时兼容根路径 (`/`) 与 GitHub Pages 子路径 (`/AegisVault/`)。
  - **严格缓存安全边界**：仅预缓存前端静态壳资源（HTML/JS/CSS/WOFF2/SVG/PNG），所有 `/api/*`、跨源 Cloudflare Worker 请求及含 `Authorization` 头的请求强制走 `NetworkOnly`，绝不写入 Cache Storage。
  - **非侵入式更新机制**：检测到新版本 Service Worker 时绝不在用户已解锁或编辑记录期间强制刷新页面，而是通过顶部更新横幅由用户主动确认切换。

### 3. 本地权威持久化 (IndexedDB 原子事务) 与 7 态同步状态机
- **IndexedDB 权威存储与 `localStorage` 一致性对账**：
  - 加密密码库信封 (`EncryptedVaultPayload`)、同步状态 (`LocalSyncStateV2`) 与单调递增写入序列号 (`writeSequence`)、重置代数 (`resetEpoch`) 在同一 IndexedDB 事务 (`tx.oncomplete`) 中原子提交。
  - 捕获配额不足 (`QuotaExceededError`) 或事务中止错误：写入失败时绝不静默丢弃内存中已解密记录，并在顶部弹出告警横幅支持**重试本地保存**与**导出加密 JSON 备份**。
  - 重置密码库 (`clearLocalVaultAsync`) 原子清除 IndexedDB 与 `localStorage` 中的 AegisVault V2 键并递增 `resetEpoch`（绝不调用 `localStorage.clear()`），确保刷新页面后已重置的旧库不会复活。
- **弱网云端同步与幂等重试**：
  - **直连 `PUT` / `GET` 无前置 `HEAD` 阻塞**：日常上传与拉取直接发送 `PUT /api/vault`（15s 超时）与 `GET /api/vault`（12s 超时），减少跨境链路一半的往返次数；保留独立的手动“检测连接 (HEAD)”按钮（5s 超时）。
  - **快照绑定的幂等 `mutationId`**：`pendingMutationId` 与当前密文快照签名 (`computePayloadContentSignature`) 严格绑定。若服务端已完成写入但响应在跨境弱网中丢失，客户端重试相同快照时沿用同一 `mutationId`，由 Durable Object 幂等识别并返回成功；若用户在同步期间继续修改了本地记录，则自动保留 `sync_pending` 状态并生成新 `mutationId`，绝不误清最新未同步标记。

---

## 本地开发与验证

```bash
# 安装依赖
npm install

# 运行 V2 密码学、IndexedDB 一致性、弱网幂等同步与 SQLite Durable Object 自动化测试套件 (10 大测试集)
npm test

# 运行 TypeScript 类型检查
npm run lint

# 启动本地开发服务器 (http://localhost:3000)
npm run dev

# 构建生产版本（自动注入 PWA Service Worker 预缓存清单）
npm run build
```

## 部署 Cloudflare Durable Objects 同步后端

详见 [`worker/README.md`](./worker/README.md)：
```bash
cd worker
npx wrangler deploy
npx wrangler secret put API_TOKEN
```

---

## 打包 Windows 绿色便携版 (`.exe`) 与 Android 基础版 (`.apk`)

项目已内置完整的 **Windows 绿色便携版 (`src-tauri/`)**、**Android 基础版 (`capacitor.config.json`)** 与 **GitHub Actions 云端一键打包流水线 (`.github/workflows/build-portable-and-android.yml`)**。

### 1. Windows 真正的绿色便携版 (`AegisVault-Portable.exe`)
- **零注册表/零 C 盘残留设计**：在 [`src-tauri/src/main.rs`](./src-tauri/src/main.rs) 中，程序启动时自动定位 `.exe` 所在目录并创建同级 `./aegis-data/` 文件夹，通过 `WEBVIEW2_USER_DATA_FOLDER` 与 `WebviewWindowBuilder::data_directory` 将所有加密 `IndexedDB` 与 `localStorage` 数据强制绑定在 `./aegis-data/` 内，可放入 U 盘或移动硬盘随身携带。
- **本地构建命令**（需安装 Rust 工具链）：
  ```bash
  npx @tauri-apps/cli@^2.0.0 icon public/icon-512.png
  npm run portable:win
  # 产物路径：src-tauri/target/release/aegis-vault-portable.exe
  ```

### 2. Android 基础版 APP (`AegisVault-Android-v2.0.0.apk`) 与后续自动填充桥接
- **基础版直接可用**：通过 [`capacitor.config.json`](./capacitor.config.json) 配置 `androidScheme: "https"`，确保 Android WebView 原生启用 Web Crypto API (`crypto.subtle`) 与 `IndexedDB`，并由 [`src/services/nativePlatformBridge.ts`](./src/services/nativePlatformBridge.ts) 自动适配安卓端原生文件分享/导出加密备份。
- **已预留后续「自动填充 & 询问保存密码」桥接接口**：
  - **询问保存新账号密码**：当未来安卓端 `AutofillService` 捕获新登录凭证时，只需在 WebView 触发 `window.dispatchEvent(new CustomEvent('aegis:android-save-credential', { detail: { title, username, password, androidPackageName } }))`，前端会自动弹出预填好账号密码与包名的「新建记录」弹窗（若当前处于锁定状态，会在用户输入主密码解锁后立即自动弹出保存窗口）。
  - **查询匹配当前应用密码**：触发 `aegis:android-autofill-query` 事件即可按域名或安卓包名 (`android://<package>`) 检索候选凭证并通过 `window.AegisAndroidBridge.onAutofillCandidatesReady` 回传。
- **本地初始化与构建命令**：
  ```bash
  npm run android:init
  cd android && ./gradlew assembleDebug
  ```

### 3. 免配置云端一键打包 (GitHub Actions)
无需在本地安装 Rust、Visual Studio C++ 或 Android SDK：将仓库推送至 GitHub 后，进入 **Actions -> Build Windows Portable EXE & Android Base APK -> Run workflow**，即可直接下载编译好的 `AegisVault-Windows-Portable-x64.zip` 与 `AegisVault-Android-Base-APK`。

