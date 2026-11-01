# AegisVault 代码审阅

审阅日期：2026-11-01。来源：用户上传的 AegisVault V2 压缩包。

本次包括加密引擎、本地持久化及云同步主路径、Cloudflare Worker、原生桥接、PWA、构建与发布配置。审阅依据是实际代码、自动化测试和浏览器行为；这不是独立安全审计或生产安全认证。

## 已修复

| 优先级 | 问题与影响 | 修复位置与行为 |
| --- | --- | --- |
| P1 | 其他标签页轮换主密码后，当前标签页仍保留旧密钥，后续编辑可能产生不可解密的混合信封。异步解密也可能在锁定后恢复明文。 | `src/App.tsx`：遇到库标识或盐值变化时锁定；以会话代数阻止过期解密回调重新解锁；跨标签页读取只采用最新结果。同步广播标记来源，忽略本页自身广播。 |
| P1 | 记录、导入与主密码弹窗关闭后仍保持挂载，其 React 状态可能保留明文；锁定也未清理预填草稿。 | 弹窗只在已解锁且打开时挂载；锁定清理草稿并关闭相关弹窗。JavaScript 无法保证立即物理擦除 GC 管理的内存。 |
| P1 | 安卓匹配使用应用标题、包名子串和任意父子域关系，可能向不相关目标返回密码。 | `nativePlatformBridge.ts`：只接受精确主机名或明确的 `android://完整包名`；提供包名时不通过域名绕过包名检查。原生端仍须验证调用来源和用户授权。 |
| P1 | Worker 在检查实际大小前调用 `request.text()`，没有 Content-Length 的超大请求可先耗尽内存。 | `VaultDurableObject.ts`：流式计数，超过 1 MiB 立即取消读取并返回 413。 |
| P1 | 客户端和服务端对额外字段检查不足，导入的“密文”信封可能携带并持久化明文扩展字段。 | `shared/vaultEnvelopeSchema.ts`：前后端共用字段白名单，覆盖顶层、KDF、cipher、verifier、metadata 和各条记录。V2 不接受未声明扩展字段。 |
| P2 | 同步指纹忽略信封时间戳及记录顺序，可能为服务端视作不同的请求复用 mutationId。 | 指纹覆盖实际序列化的完整信封。它用于客户端重试判定，不承担密码学认证。 |
| P2 | PWA 安装忽略部分静态资源下载失败，更新后可能删除仍可用的旧离线缓存；版本只依据文件名。 | 预缓存全部成功后才完成安装，构建版本同时包含资源内容。 |
| P2 | JavaScript 字节循环的执行时间不具备原生恒定时间保证，原文档也错误声称已经使用 SHA-256。 | Bearer Token 比较改为原生 Web Crypto HMAC-SHA-256 验证。 |
| P2 | 便携目录创建失败时静默使用平台默认目录，违背便携存储约定。 | `src-tauri/src/main.rs`：目录不可创建则明确退出，避免静默回落。该原生改动尚未在 Windows 编译验证。 |
| P3 | 密码生成器存在模偏差及非有限长度输入异常；新记录 ID 使用 Math.random。 | 拒绝采样、长度兜底和 CSPRNG UUID。 |
| P3 | 缺少 npm 锁文件和 PR 验证流程，构建权限及忽略规则过宽或不完整。 | 添加锁文件、CI、`npm ci`、最小 contents 权限及原生构建/本地密码库忽略规则；修正文档图标路径。 |

## 尚未解决的设计限制

1. **P1：整份记录清单与新鲜度未被认证。** `buildMetadataAAD` 只绑定 vaultId 和版本，`unlockEncryptedVaultPayload` 逐条解密当前收到的记录。已用合成密码库复现：删除唯一的 encryptedRecord 后仍能成功解锁为空库。拥有存储写权限的攻击者也可以回放旧的有效密文。Worker 的 CAS revision 防止正常客户端的旧版本覆盖，并不能抵御恶意存储端。需要升级协议，为整份记录清单提供认证，并设计独立可信的新鲜度检查；本次保留 V2 兼容性，没有悄悄更换文件格式。
2. **P2：本地多标签页并发编辑不等同于事务合并。** localStorage 镜像和 IndexedDB 的写入队列不构成跨标签页的编辑锁；同时编辑仍可能覆盖彼此。建议使用单标签页编辑，后续引入 Web Locks/跨标签页 CAS 和明确的冲突处理。
3. **P2：Worker 限流是隔离实例内存状态。** 不提供全局限流，IP 桶没有集中持久化或全局配额；生产应使用 Cloudflare 的边缘限流能力。单个 Worker 同步端点只服务一个密码库，不能直接作为多用户服务。
4. **部署和凭证边界。** 显式勾选记住 Token 后会把同步 Token 保存在 localStorage；主密码轮换不会撤销 Token，也不会删除已有本地回滚备份或用户导出的旧备份。应配置高熵 API_TOKEN 和明确的 ALLOWED_ORIGINS。

## 验证证据

- 现有 10 项加密、SQLite Durable Object、同步、恢复及持久化测试通过。
- 新增 6 项回归测试通过：Token 验证、精确原生匹配、明文字段拒绝、超限流中止、密码生成边界、PWA 不完整安装拒绝。
- `npm run lint` 和 `npm run build` 通过。构建仍提示主 JavaScript 包大于 500 kB，这属于性能优化事项。
- Chromium：创建密码库、保存合成记录、锁定、刷新、重新解锁、本地存储不含合成记录密码、生产 PWA 离线冷启动通过，无未捕获页面错误。
- Chromium：真实的两标签页主密码轮换，旧会话锁定、新主密码解锁，以及自动锁定后未保存明文草稿丢弃均通过。
- 依据 `@cloudflare/workers-types@5.20261101.1` 验证现有 Worker handler、Durable Object namespace/state 结构兼容，类型检查通过；未对线上 Cloudflare 运行时进行部署测试。
- `npm audit`（含开发依赖）报告 0 个已知漏洞。常见 GitHub/AWS/API 密钥与私钥格式扫描未命中，代码中的 DemoOnly 和测试凭证为示例数据。此扫描不能证明不存在任何秘密。
- 后续原生发布验证：[`v2.0.1-preview.3`](https://github.com/RS-Imagine/AegisVault/releases/tag/v2.0.1-preview.3) 的 Windows/Android 构建均通过；Windows EXE 启动与便携目录检查、Android APK 签名与包版本验证通过，发布下载文件的 SHA-256 已复核。[构建记录](https://github.com/RS-Imagine/AegisVault/actions/runs/41310407035)。Android 为调试签名测试版，尚未进行真实设备或系统级自动填充验证。

## 复现常规检查

使用 Node.js >= 22.13：

```sh
npm ci --legacy-peer-deps
npm test
npm run lint
npm run build
npm audit
```

上传只包含源码、配置、锁文件和审阅资料。依赖目录、生产构建产物、执行环境配置、上传压缩包和任何真实密码库数据均不纳入仓库。
