//! Additional bounded Windows baseline observations. Thresholds are product
//! review criteria, not a claim of compliance with an entire external standard.
use super::{WindowsBaselineItem, WindowsRiskLevel};
use serde_json::{Map, Value};

#[derive(Clone, Copy)]
enum Check {
    Boolean,
    Range(u64, u64, &'static str),
    Choices(&'static [u64]),
    Audit(u64),
    DefenderBoolean,
    SignatureAge,
    SecurityService(u64),
    Firewall(&'static str),
}

type Spec = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Check,
    &'static str,
    &'static str,
);

const SAM_SCOPE: &str = "来源：NetUserModalsGet 的本机 SAM 策略。仅适用于工作站或成员服务器的本地账户，不代表域账户、细粒度口令策略或现有口令强度。";
const AUDIT_SCOPE: &str = "来源：AuditQuerySystemPolicy，按固定子类别 GUID 读取成功/失败位。仅观察系统审计策略，不覆盖逐用户排除，也不证明事件已写入或转发。";
const FIREWALL_SCOPE: &str = "来源：Get-NetFirewallProfile -PolicyStore ActiveStore。需同时取得 Domain、Private、Public 的有效字段；未配置不推断默认值，也不代表某个业务端口已受控。";
const DEFENDER_SCOPE: &str = "来源：Get-MpComputerStatus。仅在报告 Normal 运行模式时按 Defender 主防护评估；被动模式、其他防病毒产品与管理策略需单独核实。";
const DEVICE_GUARD_SCOPE: &str = "来源：root/Microsoft/Windows/DeviceGuard 的 Win32_DeviceGuard。只观察运行状态；缺少类或权限时无法判断，未运行时需评估版本、硬件、驱动与虚拟化兼容性。";

const RULES: &[Spec] = &[
    (
        "password-length",
        "口令与锁定",
        "本地账户最短口令长度",
        "passwordLength",
        Check::Range(14, 128, "字符"),
        "至少 14 字符",
        "建议采用长口令；本检查不读取口令，不要求立即重置账户。",
    ),
    (
        "password-history",
        "口令与锁定",
        "本地账户口令历史",
        "passwordHistory",
        Check::Range(24, 1024, "次"),
        "至少 24 次",
        "防止重复使用旧口令；历史配置不能证明已有口令从未复用。",
    ),
    (
        "password-min-age",
        "口令与锁定",
        "本地账户最短口令使用期",
        "passwordMinAgeSeconds",
        Check::Range(86400, u32::MAX as u64 - 1, "秒"),
        "至少 1 天（86400 秒）",
        "限制反复改密绕过历史；管理员强制重置与紧急改密流程需单独评估。",
    ),
    (
        "lockout-threshold",
        "口令与锁定",
        "本地账户锁定阈值",
        "lockoutThreshold",
        Check::Range(1, 10, "次"),
        "1–10 次，结合拒绝服务风险评估",
        "0 表示不按失败次数锁定；锁定可能被滥用为拒绝服务，需结合其他认证保护。",
    ),
    (
        "lockout-duration",
        "口令与锁定",
        "本地账户锁定持续时间",
        "lockoutDurationSeconds",
        Check::Range(900, u32::MAX as u64, "秒"),
        "至少 15 分钟，或仅由管理员解锁",
        "仅在锁定阈值大于 0 时适用；原生值 4294967295 表示不自动解锁。",
    ),
    (
        "lockout-reset",
        "口令与锁定",
        "失败登录计数重置窗口",
        "lockoutResetSeconds",
        Check::Range(900, u32::MAX as u64 - 1, "秒"),
        "至少 15 分钟，且不超过有限锁定时间",
        "仅在锁定阈值大于 0 时适用；持续时间和重置窗口需一起核对。",
    ),
    (
        "audit-logon",
        "高级审计",
        "登录成功与失败审计",
        "auditLogon",
        Check::Audit(3),
        "成功和失败",
        "子类别 {0cce9215-69ae-11d9-bed3-505054503030}；关联 4624、4625 等登录事件。",
    ),
    (
        "audit-lockout",
        "高级审计",
        "账户锁定失败审计",
        "auditLockout",
        Check::Audit(2),
        "失败",
        "子类别 {0cce9217-69ae-11d9-bed3-505054503030}；关注已锁定账户的登录尝试，不能代替账户管理审计。",
    ),
    (
        "audit-special-logon",
        "高级审计",
        "特殊权限登录审计",
        "auditSpecialLogon",
        Check::Audit(1),
        "成功",
        "子类别 {0cce921b-69ae-11d9-bed3-505054503030}；用于关联具有特殊权限的登录。",
    ),
    (
        "audit-process-creation",
        "高级审计",
        "进程创建审计",
        "auditProcessCreation",
        Check::Audit(1),
        "成功",
        "子类别 {0cce922b-69ae-11d9-bed3-505054503030}；4688 中的完整命令行还依赖单独策略。",
    ),
    (
        "audit-policy-change",
        "高级审计",
        "审计策略变更审计",
        "auditPolicyChange",
        Check::Audit(1),
        "成功",
        "子类别 {0cce922f-69ae-11d9-bed3-505054503030}；需与安全日志留存和转发共同核对。",
    ),
    (
        "audit-user-account",
        "高级审计",
        "用户账户管理审计",
        "auditUserAccount",
        Check::Audit(3),
        "成功和失败",
        "子类别 {0cce9235-69ae-11d9-bed3-505054503030}；用于观察账户创建、禁用、口令等管理活动。",
    ),
    (
        "audit-security-group",
        "高级审计",
        "安全组管理审计",
        "auditSecurityGroup",
        Check::Audit(1),
        "成功",
        "子类别 {0cce9237-69ae-11d9-bed3-505054503030}；关注本地或域安全组成员变化。",
    ),
    (
        "audit-credential-validation",
        "高级审计",
        "凭据验证成功与失败审计",
        "auditCredentialValidation",
        Check::Audit(3),
        "成功和失败",
        "子类别 {0cce923f-69ae-11d9-bed3-505054503030}；不覆盖全部 Kerberos 或其他认证协议。",
    ),
    (
        "security-log-enabled",
        "日志留存",
        "Security 日志通道",
        "securityLogEnabled",
        Check::Boolean,
        "启用",
        "来源：Get-WinEvent -ListLog Security 的 IsEnabled。需另外核对读取权限、实际事件与转发。",
    ),
    (
        "system-log-enabled",
        "日志留存",
        "System 日志通道",
        "systemLogEnabled",
        Check::Boolean,
        "启用",
        "来源：Get-WinEvent -ListLog System 的 IsEnabled。仅说明通道开关，不证明服务和系统事件完整。",
    ),
    (
        "application-log-enabled",
        "日志留存",
        "Application 日志通道",
        "applicationLogEnabled",
        Check::Boolean,
        "启用",
        "来源：Get-WinEvent -ListLog Application 的 IsEnabled。应用自身日志还需按产品检查。",
    ),
    (
        "powershell-log-enabled",
        "日志留存",
        "PowerShell Operational 日志通道",
        "powershellLogEnabled",
        Check::Boolean,
        "启用",
        "来源：Get-WinEvent -ListLog Microsoft-Windows-PowerShell/Operational 的 IsEnabled。脚本块与模块日志策略需另行核对。",
    ),
    (
        "security-log-size",
        "日志留存",
        "Security 日志容量",
        "securityLogMaxBytes",
        Check::Range(192 * 1024 * 1024, u32::MAX as u64 * 1024, "字节"),
        "建议至少 192 MiB，按事件量调整",
        "来源：Get-WinEvent -ListLog Security 的 MaximumSizeInBytes。容量仅为本工具建议，不证明实际留存天数、覆盖方式或集中归档有效。",
    ),
    (
        "system-log-size",
        "日志留存",
        "System 日志容量",
        "systemLogMaxBytes",
        Check::Range(32 * 1024 * 1024, u32::MAX as u64 * 1024, "字节"),
        "建议至少 32 MiB，按事件量调整",
        "来源：Get-WinEvent -ListLog System 的 MaximumSizeInBytes。需结合覆盖速度和日志收集平台确认保留期。",
    ),
    (
        "process-command-line",
        "日志审计",
        "进程创建事件记录命令行",
        "processCommandLine",
        Check::Choices(&[1]),
        "1",
        "来源：HKLM/Software/Microsoft/Windows/CurrentVersion/Policies/System/Audit/ProcessCreationIncludeCmdLine_Enabled。还需启用进程创建审计；命令行可能包含秘密，应限制日志访问。",
    ),
    (
        "firewall-inbound",
        "防火墙",
        "各网络配置文件默认入站阻止",
        "firewallProfiles",
        Check::Firewall("inbound"),
        "三种配置文件均为 Block",
        "有效允许规则仍可能放行连接；默认动作不能代替规则与监听检查。",
    ),
    (
        "firewall-dropped-log",
        "防火墙",
        "各网络配置文件记录丢弃连接",
        "firewallProfiles",
        Check::Firewall("logBlocked"),
        "三种配置文件均记录丢弃连接",
        "记录丢弃连接有助于排查；需核对日志写入权限、实际文件与保留量。",
    ),
    (
        "firewall-log-size",
        "防火墙",
        "各网络配置文件日志容量",
        "firewallProfiles",
        Check::Firewall("logSizeKb"),
        "建议每种配置文件至少 16384 KiB",
        "此容量为本工具建议；没有启用日志时，容量设置不会自动产生记录。",
    ),
    (
        "defender-antivirus",
        "防病毒",
        "Defender 防病毒运行状态",
        "defenderAntivirus",
        Check::DefenderBoolean,
        "开启",
        "观察 AntivirusEnabled；不能据此推断已检测到所有恶意程序。",
    ),
    (
        "defender-behavior",
        "防病毒",
        "Defender 行为监控",
        "defenderBehavior",
        Check::DefenderBoolean,
        "开启",
        "观察 BehaviorMonitorEnabled；排除项与防篡改状态需共同核对。",
    ),
    (
        "defender-on-access",
        "防病毒",
        "Defender 文件访问保护",
        "defenderOnAccess",
        Check::DefenderBoolean,
        "开启",
        "观察 OnAccessProtectionEnabled；不等于所有文件均已扫描。",
    ),
    (
        "defender-signature-age",
        "防病毒",
        "Defender 安全情报更新时效",
        "defenderSignatureAge",
        Check::SignatureAge,
        "建议不超过 7 天",
        "观察 AntivirusSignatureAge；7 天为本工具关注阈值，离线更新方案需人工核实，未知时间不当作刚更新。",
    ),
    (
        "vbs-running",
        "虚拟化保护",
        "基于虚拟化的安全正在运行",
        "vbsStatus",
        Check::Choices(&[2]),
        "2（正在运行）",
        "观察 VirtualizationBasedSecurityStatus；0 为未启用，1 为已启用但未运行。",
    ),
    (
        "credential-guard-running",
        "虚拟化保护",
        "Credential Guard 正在运行",
        "securityServicesRunning",
        Check::SecurityService(1),
        "运行列表包含 1",
        "依据 SecurityServicesRunning 数组，不以 LsaIso.exe 存在代替运行状态。",
    ),
    (
        "memory-integrity-running",
        "虚拟化保护",
        "内存完整性正在运行",
        "securityServicesRunning",
        Check::SecurityService(2),
        "运行列表包含 2",
        "依据 SecurityServicesRunning 数组；修改前需评估驱动兼容性与重启条件。",
    ),
    (
        "uac-standard-prompt",
        "权限控制",
        "标准用户提权方式",
        "uacStandardPrompt",
        Check::Choices(&[0, 1]),
        "0（拒绝）或 1（安全桌面输入凭据）",
        "来源：HKLM/Software/Microsoft/Windows/CurrentVersion/Policies/System/ConsentPromptBehaviorUser。适用于标准用户提权，仍需核对 UAC 主开关。",
    ),
    (
        "remote-token-filter",
        "权限控制",
        "本地账户远程管理令牌过滤",
        "remoteTokenFilter",
        Check::Choices(&[0]),
        "0",
        "来源：HKLM/Software/Microsoft/Windows/CurrentVersion/Policies/System/LocalAccountTokenFilterPolicy。只观察本地账户远程 UAC 过滤策略，不代表域账户权限或防火墙策略。",
    ),
    (
        "everyone-anonymous",
        "账户安全",
        "Everyone 权限不扩展给匿名用户",
        "everyoneAnonymous",
        Check::Choices(&[0]),
        "0",
        "来源：HKLM/SYSTEM/CurrentControlSet/Control/Lsa/EveryoneIncludesAnonymous。仍需核对匿名共享和对象 ACL；缺失值不推断系统默认。",
    ),
    (
        "winrm-client-basic",
        "远程管理",
        "WinRM 客户端 Basic 认证策略",
        "winrmClientBasic",
        Check::Choices(&[0]),
        "0",
        "来源：HKLM/Software/Policies/Microsoft/Windows/WinRM/Client/AllowBasic。仅观察客户端策略，缺失不等于启用或关闭；需结合实际连接方式核实。",
    ),
    (
        "winrm-client-cleartext",
        "远程管理",
        "WinRM 客户端非加密流量策略",
        "winrmClientUnencrypted",
        Check::Choices(&[0]),
        "0",
        "来源：HKLM/Software/Policies/Microsoft/Windows/WinRM/Client/AllowUnencryptedTraffic。策略观察不代替运行配置和端到端传输复核。",
    ),
    (
        "llmnr",
        "名称解析",
        "关闭 LLMNR 多播名称解析策略",
        "llmnr",
        Check::Choices(&[0]),
        "0",
        "来源：HKLM/Software/Policies/Microsoft/Windows NT/DNSClient/EnableMulticast。用于降低名称解析欺骗面；不覆盖 mDNS、NetBIOS 或 DNS 解析安全，变更需评估旧设备依赖。",
    ),
];

fn number(value: Option<&Value>) -> Option<u64> {
    value?.as_u64()
}

fn missing_reason(raw: &Map<String, Value>, field: &str, category: &str) -> &'static str {
    let section = match category {
        "防病毒" => "defender",
        "防火墙" => "firewall",
        "虚拟化保护" => "deviceGuard",
        _ if field.starts_with("securityLog") => "Security",
        _ if field.starts_with("systemLog") => "System",
        _ if field.starts_with("applicationLog") => "Application",
        _ if field == "powershellLogEnabled" => "Microsoft-Windows-PowerShell/Operational",
        _ => field,
    };
    let error = raw
        .get(&format!("{field}Error"))
        .or_else(|| {
            raw.get("readErrors")
                .and_then(|v| v.get(field).or_else(|| v.get(section)))
        })
        .or_else(|| {
            raw.get(if field.starts_with("password") {
                "passwordPolicyError"
            } else if field.starts_with("lockout") {
                "lockoutPolicyError"
            } else {
                return None;
            })
        })
        .or_else(|| {
            matches!(category, "口令与锁定" | "高级审计")
                .then(|| raw.get("nativePolicyError"))
                .flatten()
        })
        .and_then(Value::as_str);
    match error {
        Some("permission-denied") => "当前账户缺少读取权限；未自动提权",
        Some("not-configured") => "未显式配置；需结合版本核对默认行为",
        Some("unavailable") => "读取接口或组件不可用；需核对系统版本和执行环境",
        Some("identity-mismatch") => "返回的审计子类别与请求不一致",
        Some("query-failed") => "读取失败；需核对权限、组件和系统版本",
        _ => "未取得有效值；缺失、无效数据或未支持的版本不能算通过",
    }
}

fn firewall(raw: Option<&Value>, field: &str) -> (Option<bool>, String) {
    let Some(rows) = raw.and_then(Value::as_array).filter(|v| v.len() == 3) else {
        return (None, "未完整取得三种网络配置文件".to_owned());
    };
    let mut result = Some(true);
    let mut display = Vec::new();
    for name in ["Domain", "Private", "Public"] {
        let matches: Vec<_> = rows
            .iter()
            .filter(|v| v.get("name").and_then(Value::as_str) == Some(name))
            .collect();
        if matches.len() != 1 {
            return (None, "网络配置文件缺失、重复或名称不受支持".to_owned());
        }
        let value = matches[0].get(field);
        let (valid, text) = match field {
            "inbound" => match value.and_then(Value::as_str) {
                Some("Block") => (Some(true), "Block".to_owned()),
                Some("Allow") => (Some(false), "Allow".to_owned()),
                _ => (None, "未取得 / 未配置".to_owned()),
            },
            "logBlocked" => match value.and_then(Value::as_str) {
                Some("True") => (Some(true), "记录".to_owned()),
                Some("False") => (Some(false), "不记录".to_owned()),
                _ => (None, "未取得 / 未配置".to_owned()),
            },
            _ => match number(value).filter(|n| *n <= u32::MAX as u64) {
                Some(n) => (Some(n >= 16384), format!("{n} KiB")),
                None => (None, "未取得有效容量".to_owned()),
            },
        };
        result = result.zip(valid).map(|(a, b)| a && b);
        display.push(format!("{name}：{text}"));
    }
    (result, display.join("；"))
}

pub(super) fn append_checks(raw: &Map<String, Value>, items: &mut Vec<WindowsBaselineItem>) {
    for &(id, category, title, field, check, expected, note) in RULES {
        let value = raw.get(field);
        let (mut pass, mut current) = match check {
            Check::Boolean | Check::DefenderBoolean => match value.and_then(Value::as_bool) {
                Some(v) => (Some(v), if v { "开启" } else { "关闭" }.to_owned()),
                None => (None, String::new()),
            },
            Check::Range(min, max, unit) => match number(value) {
                Some(n) if n <= u32::MAX as u64 || unit == "字节" => (
                    Some(n >= min && n <= max),
                    if id == "lockout-duration" && n == u32::MAX as u64 {
                        "仅由管理员解锁（原生值 4294967295）".to_owned()
                    } else {
                        format!("{n} {unit}")
                    },
                ),
                _ => (None, String::new()),
            },
            Check::Choices(allowed) => match number(value).filter(|n| match id {
                "vbs-running" => *n <= 2,
                "uac-standard-prompt" => matches!(*n, 0 | 1 | 3),
                _ => *n <= 1,
            }) {
                Some(n) => (Some(allowed.contains(&n)), n.to_string()),
                None => (None, String::new()),
            },
            Check::Audit(required) => match number(value) {
                Some(n @ 0..=4) => (
                    Some(n & required == required),
                    match n {
                        1 => "成功",
                        2 => "失败",
                        3 => "成功和失败",
                        _ => "未启用成功/失败审计",
                    }
                    .to_owned(),
                ),
                _ => (None, String::new()),
            },
            Check::SignatureAge => match number(value).filter(|n| *n < 65535) {
                Some(n) => (Some(n <= 7), format!("{n} 天")),
                None => (None, String::new()),
            },
            Check::SecurityService(service) => match value.and_then(Value::as_array).filter(|v| {
                !v.is_empty()
                    && v.len() <= 16
                    && v.iter().all(|n| n.as_u64().is_some_and(|n| n <= 64))
                    && (v.len() == 1 || !v.contains(&Value::from(0)))
                    && v.iter().enumerate().all(|(i, n)| !v[..i].contains(n))
            }) {
                Some(values) => (
                    Some(values.iter().any(|v| v.as_u64() == Some(service))),
                    format!(
                        "运行服务编号：{}",
                        values
                            .iter()
                            .map(Value::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                ),
                None => (None, String::new()),
            },
            Check::Firewall(field) => firewall(value, field),
        };
        let mut not_applicable = false;
        if category == "口令与锁定" {
            match number(raw.get("productType")) {
                Some(1 | 3) => {}
                Some(2) => {
                    not_applicable = true;
                    current = "当前为域控制器；本项限定本地 SAM 账户，应单独核查域与细粒度策略"
                        .to_owned();
                }
                _ => {
                    pass = None;
                    current = "系统角色未核实，不能将策略当作本地 SAM 账户策略".to_owned();
                }
            }
            if matches!(number(raw.get("productType")), Some(1 | 3))
                && matches!(id, "lockout-duration" | "lockout-reset")
            {
                match number(raw.get("lockoutThreshold")) {
                    Some(0) => {
                        not_applicable = true;
                        current = "锁定阈值为 0，本项尚不生效；请先复核锁定阈值".to_owned();
                    }
                    Some(n) if n <= u32::MAX as u64 => {}
                    _ => {
                        pass = None;
                        current = "未取得有效锁定阈值，无法判断本项是否生效".to_owned();
                    }
                }
            }
            if id == "lockout-reset" && !not_applicable && pass == Some(true) {
                pass = number(raw.get("lockoutDurationSeconds"))
                    .filter(|n| *n <= u32::MAX as u64)
                    .map(|duration| {
                        duration == u32::MAX as u64
                            || number(value).is_some_and(|reset| reset <= duration)
                    });
                if pass == Some(false) {
                    current.push_str("；超过锁定持续时间");
                }
            }
        }
        let defender_review = matches!(check, Check::DefenderBoolean | Check::SignatureAge)
            && match raw.get("defenderMode").and_then(Value::as_str) {
                Some("Normal") => false,
                Some("Passive Mode" | "EDR Block Mode" | "SxS Passive Mode" | "Not running") => {
                    true
                }
                _ => {
                    pass = None;
                    current = "Defender 运行模式未核实，需确认主防病毒产品".to_owned();
                    false
                }
            };
        if defender_review {
            current.push_str(
                if raw.get("defenderMode").and_then(Value::as_str) == Some("Not running") {
                    "；Defender 未运行，需核实是否由其他防病毒产品提供保护"
                } else {
                    "；Defender 为被动或辅助防护模式，需核实主防病毒产品"
                },
            );
        }
        if id == "vbs-running" && number(value).is_some_and(|n| n > 2) {
            pass = None;
            current = "未识别的虚拟化安全状态".to_owned();
        }
        if pass.is_none() && !not_applicable {
            let reason = missing_reason(raw, field, category);
            current = if current.is_empty() {
                reason.to_owned()
            } else {
                format!("{current}；{reason}")
            };
        }
        let status = if not_applicable {
            "not-applicable"
        } else if pass.is_none() {
            "unknown"
        } else if defender_review {
            "warn"
        } else if pass == Some(true) {
            "pass"
        } else if category == "虚拟化保护"
            || matches!(
                id,
                "security-log-size"
                    | "system-log-size"
                    | "firewall-log-size"
                    | "defender-signature-age"
                    | "lockout-threshold"
            )
        {
            "warn"
        } else {
            "fail"
        };
        let scope = match category {
            "口令与锁定" => SAM_SCOPE,
            "高级审计" => AUDIT_SCOPE,
            "防病毒" => DEFENDER_SCOPE,
            "防火墙" => FIREWALL_SCOPE,
            "虚拟化保护" => DEVICE_GUARD_SCOPE,
            _ => "",
        };
        items.push(WindowsBaselineItem {
            id: id.to_owned(), category: category.to_owned(), title: title.to_owned(),
            current_value: current, expected_value: expected.to_owned(), status: status.to_owned(),
            severity: match status { "pass" | "not-applicable" => WindowsRiskLevel::Normal, "unknown" => WindowsRiskLevel::Low, _ => WindowsRiskLevel::Medium },
            description: format!("{scope}{note}"),
            recommendation: if status == "unknown" { "补齐读取权限、组件及适用范围后重新检查；不要把未取得的数据当作通过。" } else if status == "not-applicable" { "本项不计为通过；请按当前主机角色与前置策略核查对应范围。" } else { "先评估组织要求、业务依赖与采集影响，再制定具体变更、备份和恢复计划；变更后独立读取并验证实际行为。" }.to_owned(),
            remediation_available: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse_baseline_json;
    use super::*;
    use serde_json::json;

    fn item(raw: Value, id: &str) -> WindowsBaselineItem {
        parse_baseline_json(&raw.to_string())
            .unwrap()
            .items
            .into_iter()
            .find(|i| i.id == id)
            .unwrap()
    }

    #[test]
    fn catalog_has_unique_ids_and_unknown_is_never_a_pass_or_repair() {
        let snapshot = parse_baseline_json("{}").unwrap();
        assert_eq!(snapshot.total_checks, 69);
        assert_eq!(snapshot.unknown_count, 69);
        assert_eq!(snapshot.not_applicable_count, 0);
        let ids: std::collections::HashSet<_> = snapshot.items.iter().map(|i| &i.id).collect();
        assert_eq!(ids.len(), 69);
        assert!(snapshot.items.iter().all(|i| !i.remediation_available));
        assert!(
            snapshot
                .items
                .iter()
                .skip(32)
                .all(|i| i.description.contains("来源："))
        );
    }

    #[test]
    fn local_password_thresholds_require_local_sam_scope() {
        assert_eq!(
            item(
                json!({"productType":1,"passwordLength":13}),
                "password-length"
            )
            .status,
            "fail"
        );
        assert_eq!(
            item(
                json!({"productType":3,"passwordLength":14}),
                "password-length"
            )
            .status,
            "pass"
        );
        assert_eq!(
            item(
                json!({"productType":1,"passwordMinAgeSeconds":86399}),
                "password-min-age"
            )
            .status,
            "fail"
        );
        assert_eq!(
            item(
                json!({"productType":1,"passwordMinAgeSeconds":86400}),
                "password-min-age"
            )
            .status,
            "pass"
        );
        for value in [json!(-1), json!(14.5), json!("14"), Value::Null] {
            assert_eq!(
                item(
                    json!({"productType":1,"passwordLength":value}),
                    "password-length"
                )
                .status,
                "unknown"
            );
        }
        let dc =
            parse_baseline_json(r#"{"productType":2,"passwordLength":14,"lockoutThreshold":10}"#)
                .unwrap();
        assert_eq!(dc.not_applicable_count, 6);
        assert_eq!(dc.passed_count, 0);
        assert_eq!(
            item(json!({"passwordLength":14}), "password-length").status,
            "unknown"
        );
        assert_eq!(
            item(json!({"lockoutThreshold":0}), "lockout-duration").status,
            "unknown"
        );
    }

    #[test]
    fn lockout_dependencies_and_native_infinite_duration_are_explicit() {
        let disabled = json!({"productType":1,"lockoutThreshold":0,"lockoutDurationSeconds":900});
        assert_eq!(item(disabled.clone(), "lockout-threshold").status, "warn");
        assert_eq!(item(disabled, "lockout-duration").status, "not-applicable");
        for (seconds, expected) in [
            (0, "fail"),
            (899, "fail"),
            (900, "pass"),
            (u32::MAX, "pass"),
        ] {
            assert_eq!(
                item(
                    json!({"productType":1,"lockoutThreshold":10,"lockoutDurationSeconds":seconds}),
                    "lockout-duration"
                )
                .status,
                expected
            );
        }
        assert_eq!(item(json!({"productType":1,"lockoutThreshold":10,"lockoutDurationSeconds":900,"lockoutResetSeconds":1200}), "lockout-reset").status, "fail");
        assert_eq!(
            item(
                json!({"productType":1,"lockoutThreshold":10,"lockoutResetSeconds":900}),
                "lockout-reset"
            )
            .status,
            "unknown"
        );
    }

    #[test]
    fn audit_checks_use_required_bits_and_keep_denied_or_invalid_results_unknown() {
        for (flags, expected) in [
            (0, "fail"),
            (1, "fail"),
            (2, "fail"),
            (3, "pass"),
            (4, "fail"),
            (5, "unknown"),
            (8, "unknown"),
        ] {
            assert_eq!(
                item(json!({"auditLogon":flags}), "audit-logon").status,
                expected
            );
        }
        assert_eq!(
            item(json!({"auditProcessCreation":3}), "audit-process-creation").status,
            "pass"
        );
        assert_eq!(
            item(json!({"auditLockout":1}), "audit-lockout").status,
            "fail"
        );
        let denied = item(
            json!({"auditLogonError":"permission-denied"}),
            "audit-logon",
        );
        assert_eq!(denied.status, "unknown");
        assert!(denied.current_value.contains("缺少读取权限"));
        assert!(!denied.remediation_available);
        assert_eq!(
            item(json!({"auditLogon":"3"}), "audit-logon").status,
            "unknown"
        );
    }

    fn profiles() -> Value {
        json!({"firewallProfiles": [
            {"name":"Domain","inbound":"Block","logBlocked":"True","logSizeKb":16384},
            {"name":"Private","inbound":"Block","logBlocked":"True","logSizeKb":16384},
            {"name":"Public","inbound":"Block","logBlocked":"True","logSizeKb":16384}
        ]})
    }

    #[test]
    fn firewall_needs_distinct_profiles_and_concrete_effective_values() {
        assert_eq!(item(profiles(), "firewall-inbound").status, "pass");
        let mut data = profiles();
        data["firewallProfiles"][2]["inbound"] = json!("Allow");
        assert_eq!(item(data.clone(), "firewall-inbound").status, "fail");
        data["firewallProfiles"][2]["inbound"] = json!("NotConfigured");
        assert_eq!(item(data.clone(), "firewall-inbound").status, "unknown");
        data["firewallProfiles"][2]["name"] = json!("Private");
        assert_eq!(item(data, "firewall-inbound").status, "unknown");
        let mut data = profiles();
        data["firewallProfiles"][2]["logBlocked"] = json!(false);
        assert_eq!(item(data.clone(), "firewall-dropped-log").status, "unknown");
        data["firewallProfiles"][2]["logSizeKb"] = json!(4096);
        assert_eq!(item(data, "firewall-log-size").status, "warn");
    }

    #[test]
    fn defender_mode_and_unknown_signature_age_do_not_look_healthy() {
        let stopped = item(
            json!({"defenderMode":"Not running","defenderAntivirus":false}),
            "defender-antivirus",
        );
        assert_eq!(stopped.status, "warn");
        assert!(stopped.current_value.contains("未运行"));
        assert!(!stopped.current_value.contains("辅助防护模式"));
        assert_eq!(
            item(
                json!({"defenderMode":"Normal","defenderAntivirus":true}),
                "defender-antivirus"
            )
            .status,
            "pass"
        );
        assert_eq!(
            item(
                json!({"defenderMode":"Passive Mode","defenderAntivirus":true}),
                "defender-antivirus"
            )
            .status,
            "warn"
        );
        assert_eq!(
            item(json!({"defenderAntivirus":true}), "defender-antivirus").status,
            "unknown"
        );
        for (age, expected) in [
            (7, "pass"),
            (8, "warn"),
            (65535, "unknown"),
            (u32::MAX, "unknown"),
        ] {
            assert_eq!(
                item(
                    json!({"defenderMode":"Normal","defenderSignatureAge":age}),
                    "defender-signature-age"
                )
                .status,
                expected
            );
        }
    }

    #[test]
    fn device_guard_uses_running_states_and_rejects_contradictory_arrays() {
        assert_eq!(item(json!({"vbsStatus":1}), "vbs-running").status, "warn");
        assert_eq!(item(json!({"vbsStatus":2}), "vbs-running").status, "pass");
        assert_eq!(
            item(json!({"vbsStatus":3}), "vbs-running").status,
            "unknown"
        );
        assert_eq!(
            item(
                json!({"securityServicesRunning":[1,2]}),
                "credential-guard-running"
            )
            .status,
            "pass"
        );
        assert_eq!(
            item(
                json!({"securityServicesRunning":[0]}),
                "memory-integrity-running"
            )
            .status,
            "warn"
        );
        for values in [
            json!([]),
            json!([0, 1]),
            json!([1, 1]),
            json!(["1"]),
            json!(1),
        ] {
            assert_eq!(
                item(
                    json!({"securityServicesRunning":values}),
                    "credential-guard-running"
                )
                .status,
                "unknown"
            );
        }
    }

    #[test]
    fn registry_missing_values_and_new_rules_do_not_offer_unimplemented_repairs() {
        let missing = item(
            json!({"nativePolicyError":"unavailable","readErrors":{"llmnr":"not-configured"}}),
            "llmnr",
        );
        assert_eq!(missing.status, "unknown");
        assert!(missing.current_value.contains("未显式配置"));
        assert_eq!(item(json!({"llmnr":0}), "llmnr").status, "pass");
        assert_eq!(item(json!({"llmnr":1}), "llmnr").status, "fail");
        assert_eq!(item(json!({"llmnr":99}), "llmnr").status, "unknown");
        assert!(!item(json!({"llmnr":1}), "llmnr").remediation_available);
        assert!(item(json!({"wdigest":1}), "wdigest").remediation_available);
        assert!(!item(json!({}), "wdigest").remediation_available);
        assert!(!item(json!({"defenderTamper":0}), "defender-tamper").remediation_available);
    }

    #[cfg(windows)]
    #[test]
    fn native_baseline_v3_reads_local_sam_and_preserves_audit_permission_gaps() {
        let response = lovelyhawk_win_dvc::native_collect::handle_native_collect("baseline-v3");
        let text = super::super::strip_exit_prefix(&response).unwrap();
        let raw: Value = serde_json::from_str(&text).unwrap();
        // The local read must actually exercise the native reader, not silently
        // degrade to the old registry-only collector or an unavailable compiler.
        assert!(
            raw.get("nativePolicyError").is_none(),
            "native reader unavailable: {raw}"
        );
        assert!(raw.get("passwordLength").is_some() || raw.get("passwordPolicyError").is_some());
        for name in [
            "auditLogon",
            "auditLockout",
            "auditSpecialLogon",
            "auditProcessCreation",
            "auditPolicyChange",
            "auditUserAccount",
            "auditSecurityGroup",
            "auditCredentialValidation",
        ] {
            assert!(raw.get(name).is_some() || raw.get(format!("{name}Error")).is_some());
        }
        let snapshot = parse_baseline_json(&text).unwrap();
        assert_eq!(snapshot.total_checks, 69);
        assert_eq!(
            snapshot.total_checks,
            snapshot.passed_count
                + snapshot.failed_count
                + snapshot.warning_count
                + snapshot.unknown_count
                + snapshot.not_applicable_count
        );
        println!(
            "Windows baseline v3: {} checks, {} passed, {} failed, {} review, {} unknown, {} not applicable; local read only",
            snapshot.total_checks,
            snapshot.passed_count,
            snapshot.failed_count,
            snapshot.warning_count,
            snapshot.unknown_count,
            snapshot.not_applicable_count
        );
        if raw["auditLogonError"] == "permission-denied" {
            assert_eq!(
                snapshot
                    .items
                    .iter()
                    .find(|i| i.id == "audit-logon")
                    .unwrap()
                    .status,
                "unknown"
            );
        }
    }
}
