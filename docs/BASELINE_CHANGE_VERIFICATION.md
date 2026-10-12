# 基线快捷修改的验证范围

此文说明桌面端“配置 → 检查这台主机”中，对单项 Linux 安全基线的修改与放回，以及 sshd 实际读取哪个文件的判断。它只覆盖可写的单项设置；Nginx、Redis、PostgreSQL 和只检查“是否配置”的项目仍只读，见各自的验证文档。

## 用户流程

1. 扫描后选中一项。右侧“修改这一项”显示当前值，默认选中建议值，并提供两种生效方式：写入后先用程序自己的检查核对再重载，或只写入、稍后手动重载。
2. “查看修改计划…”只生成计划，不改动主机。确认对话框列出要改的文件、旧值 → 新值、生效方式、检查不通过时的恢复办法；涉及 sshd_config 时提示新登录会按新规则执行，已打开的会话不受影响。焦点默认在“取消”，计划 5 分钟内有效，只能执行一次。
3. 确认后先完整备份原文件，再写入、由程序检查（sshd 用 `sshd -t`）、按计划重载，并独立读回。检查不通过时从备份放回并读回核对。回执说明是否完成并核对；页面随后重新扫描并刷新历史，回执由页面保留，不会随列表刷新消失。
4. “变更历史”中，带有修改后完整文件证据的记录可以“放回改动前的文件…”。放回前核对文件仍与当时改完时完全一致；之后又被改过就拒绝放回，不覆盖别人的改动。缺少这类证据的旧记录只能查看。每条记录写明改动前后的值（如“禁止 root 直接登录（yes → no）”），状态为“已应用”或“已撤销”，时间按本机时区显示。

以下情况不提供修改，并说明原因：只检查不修改的项目、尚未扫描、软件未安装、实际值无法核实、只在 Match 条件块里设置、值超出该项允许的范围，或已经是这个值。

## 调用链

`baseline.action.plan / confirm / execute / cancel`（`crates/lovelyhawk-backend/src/baseline_write_api.rs`）只接受目录和扫描结果给出的句柄，不接受文件路径或命令。计划绑定当前 SSH 连接，确认一次、执行一次，过期、断开或取消后失效。页面通过 `ui/src/host` 的四个方法调用，确认使用应用内对话框（`useConfirmDialog` / `DialogHost`）。

## sshd 实际读取的文件

sshd 按 `Include` 行所在的位置读入其他文件，并且每个设置采用最先读到的值。扫描现在按同样的方式判断：

- 从 `/etc/ssh/sshd_config` 开始，逐行跟随 `Include`，在该行的位置读入匹配的文件，按 sshd 的规则把相对路径放在 `/etc/ssh` 下。被包含的文件中的 `Include` 也会跟随，深度上限与 sshd 相同（16 层）。
- 主文件没有 `Include` 时，`sshd_config.d` 里的文件不计入。此前扫描总是先读所有附加文件：在一台 sshd_config 没有 Include、附加文件里写着 `PermitRootLogin yes` 的 AlmaLinux 9 实验主机上，扫描把那个被忽略的文件当成生效位置，修改写进去后 `sshd -T` 仍然是 yes。
- `Match` 之后的 `Include` 属于条件块，不跟随；条件块里的值仍按原规则报告为“只对部分连接生效”。
- 生效值来自本工具不管理的位置（`/etc/ssh/sshd_config` 和 `/etc/ssh/sshd_config.d/*.conf` 以外）时报告“无法判断”，不提供修改，以免把修改写到 sshd 不会读的文件；来自符号链接或特殊文件时报告“不支持”。`Include` 参数带引号、文件名含特殊字符或包含层数过深时也报告“无法判断”。

右侧文件查看同样打开扫描找到的那个文件（例如胜出的附加文件），并标出其中 sshd 采用的那一行；扫描无法判断时只列出提及，不标任何一行为生效。

修改写入扫描找到的那个文件。sshd 的写入只改动第一个 `Match` 之前的内容：条件块里的同名设置原样保留；文件里没有这项时，新行插在第一个 `Match` 之前，而不是追加到可能属于条件块的文件末尾。此前通用写入会把条件块里的同名行当成重复项删除，或把新行追加进末尾的条件块。

## 验证

```powershell
cargo test --locked --package lovelyhawk-core baseline::
cargo build --locked --package lovelyhawk-backend
# 九个发行版：每种 Include 布局先由 sshd -T 给出答案，扫描结果和来源文件必须一致
LAB=<ubuntu|alpine|debian|rocky|alma|suse|openeuler|anolis|deepin> node tools/lab/probe-baseline.mjs
# 写入程序：真实 sshd_config 与三种 Match 布局，由 sshd -t / sshd -T（含 -C 指定连接）核对
node tools/lab/probe-baseline-write.mjs <arena|alpine|rocky>
# 计划、确认、执行、放回：每次新建带本次标签、限资源的容器，结束时核对身份后删除
BASELINE=<deb|el> node tools/lab/probe-baseline-actions.mjs
# 桌面窗口中的同一流程
pnpm desktop:build
BASELINE=<deb|el> node tools/lab/probe-ui-baseline-actions.mjs
```

`probe-baseline.mjs` 在 `lab-*` 容器上临时替换 sshd_config 与 sshd_config.d，结束时放回原文件。新增的 I–N 用例覆盖：Include 在前且附加文件放行 root、没有 Include、Include 在主文件设置之后、相对路径、嵌套 Include，以及生效值来自本工具不管理的位置。每个用例先问 `sshd -T`，扫描读到的值和来源文件必须与之相符；I 与 N 还核对文件查看打开的文件和标出的生效行。

`probe-baseline-write.mjs` 中的 Match 用例在新写入程序上全部通过，在原通用写入程序上全部失败（全局值未变，或条件块被改写），说明用例确实能发现原缺陷。

`probe-baseline-actions.mjs` 每次检查 25 项：计划不改动主机、未确认不执行、写入后 `sshd -T` 为 no、重载后原会话可用、计划不能重复执行、非法值 / 已是该值 / 只检查的项目 / 伪造句柄 / 文件路径均被拒绝、放回后文件逐字节一致、已放回的记录不能再放回，以及之后被手工改过的文件拒绝放回且手工内容保留。证据在 `target/lab-baseline-actions/<deb|el>/<runId>/report.json`。

2026-10-12 在同一份构建上（门禁 `desktop-quality-gate-2026-10-12i`）：九个发行版的读法探针各 37 项通过；写入探针 arena 39 项，Alpine、Rocky 各 23 项（这两台只装了 sshd，其余格式跳过）；改动链路 Debian 与 AlmaLinux 各 25/25；真实窗口两者各 11/11，无控制台错误。桌面证据在 `target/lab-ui-baseline-actions/<deb|el>/<runId>/`。

## 尚未覆盖

- 只在容器中验证。容器内没有 systemd，重载走 `service` 或 pidfile 发送 SIGHUP 的后备方式；systemd 主机上的 `systemctl reload`、真实虚拟机和实机仍待验证，参见 `SSH_COMPATIBILITY.md`。
- `Match` 块中的 `Include` 不跟随：被它包含的文件中的设置不会被标为条件设置。
- Shell 中的核对不是原子事务；检查与写入之间仍有并发窗口，见 `BASELINE_RESTORE_VERIFICATION.md`。
- 修改只说明配置文件已写入、程序检查通过并完成重载，不代表业务已恢复健康，也不证明主机没有其他登录途径。
