# SSH 兼容性与安全策略

LovelyHawk 的“已支持”以自动化契约为准，不以协议实现理论兼容性代替实测结论。版本化
实验矩阵保存在 `tests/ssh-compat/matrix.json`；Core 的兼容性清单是
`lovelyhawk_core::ssh_compat::SSH_COMPATIBILITY_CONTRACT`（序列化 schema 仍沿用
`lovelyres-ssh-compatibility/v1`，以保持兼容）。两者只定义必须覆盖的格子，
不能代替真实 Linux/OpenSSH/Dropbear 实验室结果。

## 当前契约

- 服务端：OpenSSH 7.x、8.x、9.x、10.x，以及 Dropbear。
- 系统：Ubuntu 20.04/24.04、Debian 12、Rocky Linux 9、Alpine 3.20、
  openEuler 22.03 LTS SP4、Anolis OS 8.9、openSUSE Leap 15.6。
- 网络：IPv4、原始 IPv6 地址、DNS 多地址回退、300ms 高延迟、执行中断连。
- 认证：密码、Ed25519 私钥、ECDSA 私钥、OpenSSH 用户证书、
  keyboard-interactive/MFA、OpenSSH Agent/Pageant、通过 Agent 使用 RSA、
  堡垒机 direct-tcpip（ProxyJump）。
- 降级：无 SFTP、无 PTY、受限账号、主机密钥变更均必须返回明确状态，不能伪装成功。

每个正常目标至少验证：主机指纹确认、认证、命令成功退出码、非零退出码、能力预检、
SFTP（可用时）及有限时 PCAP（显式启用时）。

## RSA 策略

RSA 私钥文件、RSA 用户证书和 Agent 中的 RSA 身份都支持（2026-10-12 起；此前
RSA 私钥文件按下述漏洞安全失败，Agent 中的 RSA 身份也被一并拒绝，与本节旧文
"通过 Agent 使用 RSA"不符）。

签名算法由服务端 `server-sig-algs` 决定：列出 rsa-sha2-512/256 时用 SHA-2；
只支持 `ssh-rsa` 时用 SHA-1；什么都不声明时先试 rsa-sha2-256、再试 SHA-1
（OpenSSH 7.2–7.3 支持 SHA-2 但不声明，更老的只有 SHA-1）。OpenSSH 8.8+ 拒绝
SHA-1，所以 RSA 证书不走 russh 内置的证书登录（只能声明
`ssh-rsa-cert-v01`），而是由进程内签名器按 `rsa-sha2-*-cert-v01` 签。

**已知风险**：RSA 私钥文件在进程内由 RustCrypto `rsa` 签名，它有
`RUSTSEC-2023-0071`（时间侧信道，尚无修复版本）。利用它需要精确测量大量私钥运算
的耗时；SSH 客户端每次登录只签一次且隔着网络，取得这些测量的条件不具备，因此为
让大量仍在用 RSA 密钥的主机能够登录而接受该风险。对风险敏感的环境仍可改用：

1. Ed25519 或 ECDSA 私钥；
2. SSH Agent/Pageant 托管 RSA 私钥并代签（私钥与签名运算不进入 LovelyHawk 进程）。

## 登录方式实测（2026-10-12）

`tests/ssh-compat/login-methods-lab.sh up <fixture-dir>` 在 Docker 里起四台一次性目标
（标签 `lovelyhawk.test=login-methods`，`down` 只删它们）并生成一次性密钥与证书，
输出 `live_openssh_every_login_method` 与 `live_openssh_keyboard_interactive_contract`
所需的环境变量。Windows 上用 `wsl -u root -e bash tests/ssh-compat/login-methods-lab.sh up …`，
目标发布在 WSL 自身地址。结果（客户端 Windows 11，core 进程内 SSH）：

| 登录方式 | 目标 | 结果 |
| --- | --- | --- |
| 密码 | OpenSSH 9.7 (alpine 3.20) | 已验证（含 PTY） |
| Ed25519 私钥（带口令） | OpenSSH 9.7 | 已验证 |
| ECDSA P-256 私钥 | OpenSSH 9.7 | 已验证 |
| RSA 3072 私钥文件 | OpenSSH 9.7 | 已验证（rsa-sha2，按 server-sig-algs） |
| Ed25519 用户证书 | OpenSSH 9.7 | 已验证（证书密钥本身未授权，只经 CA） |
| RSA 用户证书 | OpenSSH 8.6 (alpine 3.14) | 已验证（ssh-rsa-cert-v01） |
| RSA 用户证书 | OpenSSH 9.7 | **不支持**：russh 0.62 只能以 `ssh-rsa-cert-v01`（SHA-1）出示 RSA 证书，8.8+ 拒绝；界面给出 `ssh-rsa-certificate-refused` 并建议改用 Ed25519/ECDSA 证书或 RSA 私钥。上游较新的 russh 已修复，需单独评估升级 |
| Agent：Ed25519 | OpenSSH 9.7 | 已验证 |
| Agent：RSA | OpenSSH 9.7 | 已验证（rsa-sha2 标志） |
| keyboard-interactive（PAM） | OpenSSH 9.7 (`sshd.pam`) | 已验证 |
| ProxyJump（堡垒机 + 目标均为密码） | OpenSSH 9.7 ×2 | 已验证（含 PTY） |

Agent 的缺口：本机 `ssh-agent` 服务被禁用，以普通进程运行需要写 HKLM，测试改为在
`\\.\pipe\openssh-ssh-agent` 上由测试自带的最小 Agent（按 OpenSSH 规则处理
rsa-sha2-256/512 标志）提供身份，所以验证的是 LovelyHawk 的 Agent 客户端与协议，
**不是** Windows 自带 Agent 或 Pageant 本身。russh 自带的 Agent 服务端对 RSA 一律用
SHA-1 签名，不能用来测这一项。

修复同日暴露的实验室问题：Alpine 的 PAM 版 sshd 是单独的 `/usr/sbin/sshd.pam`，
`configure-target.sh` 以前总启动不认 `UsePAM` 的 `/usr/sbin/sshd`，keyboard-interactive
目标在 Alpine 上从未真正可用。

## 目标能力预检

连接成功后，客户端按会话探测 OS、init、`/proc`、提权能力、PTY、SFTP 和关键工具。
结果与目标会话绑定；切换目标不会复用旧结果。页面必须按能力显示不可用原因和替代路径，
不适用的检查项使用 N/A，不计入安全分数。

## 本地运行实机契约

矩阵依赖 Linux Docker 网络与 `NET_ADMIN`。在 Linux runner 上由工作流执行；单个目标也可用：

```bash
mkdir -p /tmp/lovelyhawk-ssh-fixtures
ssh-keygen -q -t ed25519 -N '' -f /tmp/lovelyhawk-ssh-fixtures/user_key
bash scripts/start-ssh-compat-target.sh ubuntu:24.04 lovelyhawk-ssh 2222 password /tmp/lovelyhawk-ssh-fixtures
```

然后设置测试注释列出的 `LOVELYHAWK_TEST_*` 环境变量并运行 Core 的忽略实机测试：

```bash
cargo test --locked -p lovelyhawk-core live_openssh_end_to_end_contract -- --ignored --nocapture
cargo test --locked -p lovelyhawk-core live_openssh_keyboard_interactive_contract -- --ignored --nocapture
cargo test --locked -p lovelyhawk-core live_sftp_crud_atomic_restore_archive_matrix -- --ignored --nocapture
```

MFA 合约额外要求 `LOVELYHAWK_TEST_SSH_MFA_{HOST,PORT,USERNAME,HOST_KEY}` 与
`LOVELYHAWK_TEST_SSH_MFA_RESPONSES_JSON`；后者是按服务端提示顺序排列的 JSON 字符串数组。
所有账号、因素和远端目录必须是一次性靶场资源。

Windows 开发机若没有 Docker，只能运行编译、单元测试和静态矩阵门禁，不能把它们描述成
“实机矩阵已通过”。
