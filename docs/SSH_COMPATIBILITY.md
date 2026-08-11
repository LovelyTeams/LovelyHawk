# SSH 兼容性与安全策略

LovelyRes 的“已支持”以自动化契约为准，不以协议实现理论兼容性代替实测结论。可执行矩阵在
`tests/ssh-compat/matrix.json`，GitHub Actions 入口为
`.github/workflows/ssh-compatibility.yml`。

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
快速检测中的不适用项目使用 N/A，不计入安全分数。

## 本地运行实机契约

矩阵依赖 Linux Docker 网络与 `NET_ADMIN`。在 Linux runner 上由工作流执行；单个目标也可用：

```bash
mkdir -p /tmp/lovelyres-ssh-fixtures
ssh-keygen -q -t ed25519 -N '' -f /tmp/lovelyres-ssh-fixtures/user_key
bash scripts/start-ssh-compat-target.sh ubuntu:24.04 lovelyres-ssh 2222 password /tmp/lovelyres-ssh-fixtures
```

然后设置 `LOVELYRES_TEST_SSH_*` 环境变量并运行忽略的实机测试：

```bash
cargo test --locked --manifest-path src-tauri/Cargo.toml real_linux_ssh_contract -- --ignored --nocapture
```

Windows 开发机若没有 Docker，只能运行编译、单元测试和静态矩阵门禁，不能把它们描述成
“实机矩阵已通过”。
