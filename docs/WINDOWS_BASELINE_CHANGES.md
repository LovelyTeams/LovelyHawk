# Windows 基线一键配置与恢复

更新：2026-10-26。状态：**已接通，真实管理员目标写入仍为实验性 / NOT_RUN**。

现有 69 项检测继续保留。一键配置首批覆盖 19 个固定注册表 DWORD 策略值：RDP 的 NLA/加密级别/TLS 安全层、WDigest、四项 UAC、空口令远程访问、匿名共享/账户枚举、NTLM 级别、LM 摘要、两项 WinRM、机器/当前账户的高权限 MSI 安装、自动运行、PowerShell 脚本块日志。新增的 37 项检测仍只读。LSA PPL、口令策略、审计策略、Defender、服务和防火墙等尚不进入批量写入；原有无备份的直接修复接口已移除。

## 用户流程与边界

1. 基线页的“一键配置…”选择本次不通过的支持项，也可从单项详情进入。
2. core 读取目标身份、账户、系统版本/启动时间、注册表原值与 ACL，生成 5 分钟有效、绑定本次会话的固定计划；页面只获得目标、差异、影响和计划编号。
3. 用户核对具体差异后确认。执行时消费一次性计划，再读全部原状态；任何变化均拒绝旧计划。
4. 每次写入之前先把原值、ACL、目标身份和执行状态保存到便携目录的 `data/LovelyHawk-windows-baseline-history.json`。保存失败则停止；历史达到 100 次/4 MiB 不丢弃旧记录。
5. 每项写入前再次比较，写入后另发只读请求独立回读。界面显示正在处理的数量与阶段；“中止后续项”不会声称当前远端写入立即终止。
6. 失败时停止后续，尝试恢复已有完整修改后观察的本次修改，并再次回读。超时或结果不明的项不猜测成功、不盲目恢复或重试。
7. 配置历史可预览恢复差异，需新的固定计划和本次确认。恢复比较主机/账户/系统版本、当前值和 ACL，不覆盖之后的业务变更。新建的空策略键保留，不删除整棵键树。

写入候选限定 Windows 10/11 或 Server 2016+、本机管理员、非域成员且非域控制器。版本前提来自现有策略语义，**不代表这些版本均已验证**。32 位采集进程也使用明确的 Registry64 视图。HKCU 只针对采集账户，不遍历其他用户。不会静默提权、刷新组策略、关闭安全机制或重启服务/系统。

注册表检查和写入并非原子事务。回读通过只证明所列配置值；MDM/策略刷新、运行组件、重启和业务连接仍需独立验证。RDP/NTLM/WinRM 兼容影响、UAC 重启条件与脚本日志秘密暴露均在计划中说明。不能用“完成一键配置”宣称无入侵或完整合规。

## 实现与契约

`windows_incident/baseline_change.rs` / `baseline_change.ps1` → backend `windows.incident` 的有限 plan/apply/discard/cancel/progress/history/restore 动作 → shared 严格 DTO → 现有宿主白名单与 `ui/src/host` → `WinIrBaselineChanges`。

固定目录不接受客户端提供注册表路径、值、脚本或备份内容。PowerShell 参数通过 JSON 的 Base64 数据传递，不拼接执行文本。读取分组限制为 6 项，注册表 ACL 限 2 KiB；编码后的进程命令限 30,000 UTF-16 字符。单次远程调用限 45 秒，新增项执行阶段限 3 分钟，失败恢复阶段超过 5 分钟不再启动后续恢复项；当前调用仍受单次时限约束。页面执行等待上限 10 分钟，进度和取消独立查询。应用导航与正常关闭等待 Windows 任务结束。

## 参考与验证范围

参考 [WindowsBaselineAssistant 的交互实现](https://github.com/DeEpinGh0st/WindowsBaselineAssistant/blob/master/Main.cs) 的选择检查项和一键配置流程。没有复制它的 XML 策略或执行代码，也没有沿用“忽略项计为通过”和直接执行后要求手工复扫的结果语义。

策略语义参考微软 [UAC 配置](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration?tabs=reg)、[LAN Manager 身份验证级别](https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level)，其他既有检测依据见 [检测覆盖](WINDOWS_BASELINE_COVERAGE.md)。目录是产品建议，不是某份认证标准的完整实现。

本机 Windows 11 专业版 10.0.26200 x64 / PowerShell 5.1、非管理员已执行实际读取与故意不匹配身份的拒绝探针：两个值及 ACL 前后观察一致，没有实际策略修改。最终脚本证据：`target/windows-redesign-ebb23754-b2a6-4be5-8af2-dfcda3431c5a/read-denial.json`；文件 SHA256 为 `84b10e14d65ac1ed38f0d300f2afc8fe71efdb164b4e4380f0fef4c5a273636f`。

同一次计划中多个值共用一个新建键时，只沿用本次已独立回读的键存在性和 ACL；其他值仍须匹配各自原状态。回归同时覆盖新键完整配置/恢复和中途外部修改不被覆盖。宿主把只读状态、进度和取消放入既有控制队列，实际写入仍按主队列排序；宿主测试持有主队列时核查这些控制请求能够返回。预览最多等待 4 分钟，以容纳分组读取，不缩短远端单次 45 秒边界。

core 测试使用独立内存目标与临时便携目录覆盖原值备份、确认变化零写入、部分失败恢复、取消后续、结果不明不重试、恢复并发保护、幂等及一次性/过期计划。它们不替代真实注册表写入。Windows Server、域成员、域控、ARM64、管理员正向写入/恢复、断电、实际 RDP 断连、MDM/GPO 覆盖和业务健康仍为 NOT_RUN；域成员/域控自动配置明确拒绝。正式发布验收仍未完成。
