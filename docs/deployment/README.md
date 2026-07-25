# ⚠️ 本目录内容已废弃（2026-07 核对）

这里的 6 份文档描述的是一套**已经从项目中移除的授权 / 许可后端**
（`api.lovelyres.com`、JWT 认证、设备绑定、License 校验）。

佐证：`src/main.ts` 的 `removeLegacyAccessArtifacts()` 至今还在主动清理它的残留——
删除 `lovelyres-access-token` / `lovelyres-refresh-token` / `lovelyres-user-info`
这几个 localStorage 键，并移除 `#login-modal` / `.license-card` 等 DOM 节点。
`src-tauri/src/crypto_keys.rs` 与 `get_rsa_public_key` 命令也随之闲置。

**不要按这里的内容开发或部署。** 当前的构建与打包方式见根目录 [AGENTS.md](../AGENTS.md)。

保留这些文件只是为了历史追溯，随时可以整体删除。
