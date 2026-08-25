# SSH 兼容性与安全策略

LovelyRes 的“已支持”以自动化契约为准，不以协议实现理论兼容性代替实测结论。版本化
实验矩阵保存在 `tests/ssh-compat/matrix.json`；Core 的兼容性清单是
`lovelyres_core::ssh_compat::SSH_COMPATIBILITY_CONTRACT`。两者只定义必须覆盖的格子，
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

LovelyRes 不在进程内加载 RSA 私钥。RustCrypto `rsa` 的
`RUSTSEC-2023-0071` 尚无修复版本，因此直接选择 RSA 私钥会安全失败，并提示改用：

1. Ed25519 或 ECDSA 私钥；
2. SSH Agent/Pageant 托管 RSA 私钥并代签；
3. 在受控环境使用系统 OpenSSH。

该限制不等于拒绝 RSA 服务端。RSA 身份通过 Agent 使用时，私钥和签名秘密不进入
LovelyRes 进程。

## 目标能力预检

连接成功后，客户端按会话探测 OS、init、`/proc`、提权能力、PTY、SFTP 和关键工具。
结果与目标会话绑定；切换目标不会复用旧结果。页面必须按能力显示不可用原因和替代路径，
不适用的检查项使用 N/A，不计入安全分数。

## 本地运行实机契约

矩阵依赖 Linux Docker 网络与 `NET_ADMIN`。在 Linux runner 上由工作流执行；单个目标也可用：

```bash
mkdir -p /tmp/lovelyres-ssh-fixtures
ssh-keygen -q -t ed25519 -N '' -f /tmp/lovelyres-ssh-fixtures/user_key
bash scripts/start-ssh-compat-target.sh ubuntu:24.04 lovelyres-ssh 2222 password /tmp/lovelyres-ssh-fixtures
```

然后设置测试注释列出的 `LOVELYRES_TEST_*` 环境变量并运行 Core 的忽略实机测试：

```bash
cargo test --locked -p lovelyres-core live_openssh_end_to_end_contract -- --ignored --nocapture
cargo test --locked -p lovelyres-core live_openssh_keyboard_interactive_contract -- --ignored --nocapture
cargo test --locked -p lovelyres-core live_sftp_crud_atomic_restore_archive_matrix -- --ignored --nocapture
```

MFA 合约额外要求 `LOVELYRES_TEST_SSH_MFA_{HOST,PORT,USERNAME,HOST_KEY}` 与
`LOVELYRES_TEST_SSH_MFA_RESPONSES_JSON`；后者是按服务端提示顺序排列的 JSON 字符串数组。
所有账号、因素和远端目录必须是一次性靶场资源。

Windows 开发机若没有 Docker，只能运行编译、单元测试和静态矩阵门禁，不能把它们描述成
“实机矩阵已通过”。
