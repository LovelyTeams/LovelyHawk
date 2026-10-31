//! Attribute-only authentication repairs and a closed set of audit watches.
//! These use the baseline's existing confirmation, journal and history; neither
//! the account files nor arbitrary audit commands are exposed to the page.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};

pub(super) const PERMISSION_SAFE: &str = "权限符合策略";
pub(super) const AUDIT_READY: &str = "规则已保存并载入";
pub(super) fn is_attribute_label(value: &str) -> bool {
    let Some((mode, rest)) = value
        .strip_prefix("权限 ")
        .and_then(|s| s.split_once("，属主 UID "))
    else {
        return false;
    };
    let Some((uid, gid)) = rest.split_once("，属组 GID ") else {
        return false;
    };
    mode.len() == 4
        && mode.bytes().all(|b| matches!(b, b'0'..=b'7'))
        && [uid, gid].iter().all(|id| {
            !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && id.parse::<u32>().is_ok()
        })
}
const AUTH_FILES: [&str; 4] = ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"];
const AUDIT_FILE: &str = "/etc/audit/rules.d/70-lovelyhawk-auth.rules";
const AUDIT_KEY: &str = "lovelyhawk_auth";

pub(super) const fn permission_definition(
    id: &'static str,
    file: &'static str,
    title: &'static str,
) -> BaselineDefinition {
    BaselineDefinition {
        id,
        file,
        title,
        category: BaselineCategory::FilePermissions,
        component: BaselineComponent::System,
        risk: BaselineRisk::High,
        description: "检查普通文件的属主、属组、权限与 ACL。保留 root/shadow 组的现有用途，只移除多余权限；未知属组或扩展 ACL 须人工核对。读取摘要可能更新访问时间，不显示账号或口令正文。",
        recommendation: PERMISSION_SAFE,
        value_kind: BaselineValueKind::Choice(&[PERMISSION_SAFE]),
        reading: Reading::HostState,
        implicit: None,
        key: "auth_permissions",
        format: FileFormat::Whitespace,
        reload: ReloadGroup::None,
    }
}

pub(super) const AUDIT_DEFINITION: BaselineDefinition = BaselineDefinition {
    id: "logging-auth-file-watches",
    file: AUDIT_FILE,
    title: "认证文件的 auditd 监控",
    category: BaselineCategory::Logging,
    component: BaselineComponent::System,
    risk: BaselineRisk::High,
    description: "记录 passwd、group、shadow、gshadow 的写入和属性变化。分别核对受管规则片段与内核运行规则；不会安装或启动 auditd、清空其他规则或重载整个规则集。规则存在不证明事件已落盘，也不证明重启后会自动加载。",
    recommendation: AUDIT_READY,
    value_kind: BaselineValueKind::Choice(&[AUDIT_READY]),
    reading: Reading::HostState,
    implicit: None,
    key: "auth_watches",
    format: FileFormat::Whitespace,
    reload: ReloadGroup::None,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Guard {
    Permissions {
        before: BaselineBackupEvidence,
        desired_mode: u32,
        desired_gid: u32,
        group_hash: String,
    },
    Audit {
        before: BaselineBackupEvidence,
        boot: String,
        daemon_pid: u32,
        watched_hash: String,
        runtime_before: String,
        runtime_after: String,
    },
}

#[derive(Debug, Clone)]
struct PermissionProbe {
    file: BaselineBackupEvidence,
    root_gid: u32,
    shadow_gid: Option<u32>,
    group_hash: String,
}
#[derive(Debug, Clone)]
struct AuditProbe {
    file: BaselineBackupEvidence,
    boot: String,
    daemon_pid: u32,
    watched_hash: String,
    rules: String,
}

// All files are fixed by the catalogue. The caller's environment cannot choose
// programs. Extended ACLs require a separate policy, so refuse them instead of
// interpreting mode bits as the whole access decision.
const PROBE: &str = r#"
PATH=/usr/sbin:/usr/bin:/sbin:/bin; LC_ALL=C; export PATH LC_ALL
lh_path() {
  lh_p=$1
  while [ "$lh_p" != / ]; do
    [ ! -L "$lh_p" ] || return 1
    lh_p=${lh_p%/*}; [ -n "$lh_p" ] || lh_p=/
  done
}
lh_hash() { lh_h=$(sha256sum -- "$1") || return 1; printf '%s' "${lh_h%% *}"; }
lh_safe_dir() {
  lh_parent=$1
  while [ "$lh_parent" != / ]; do
    lh_path "$lh_parent" || return 1
    if [ -e "$lh_parent" ]; then
      [ -d "$lh_parent" ] && [ "$(stat -c %u -- "$lh_parent")" = 0 ] || return 1
      lh_mode=$(stat -c %a -- "$lh_parent") || return 1
      [ "$((0$lh_mode & 022))" = 0 ] || return 1
    fi
    lh_parent=${lh_parent%/*}; [ -n "$lh_parent" ] || lh_parent=/
  done
}
lh_file() {
  lh_path "$1" && [ -f "$1" ] && [ -r "$1" ] || return 1
  [ "$(stat -c %h -- "$1")" = 1 ] || return 1
  [ "$(stat -c %s -- "$1")" -le 1048576 ] || return 1
  lh_attrs=$(stat -c '%a:%u:%g:%d:%i:%h' -- "$1") || return 1
  lh_digest=$(lh_hash "$1") || return 1
  [ "$(stat -c '%a:%u:%g:%d:%i:%h' -- "$1")" = "$lh_attrs" ] || return 1
}
lh_perm() {
  lh_f=$1
  for lh_tool in stat sha256sum awk getfacl; do command -v "$lh_tool" >/dev/null 2>&1 || return 1; done
  lh_file "$lh_f" || return 1
  lh_a=$lh_attrs lh_d=$lh_digest
  lh_acl=$(getfacl -cp -- "$lh_f" 2>/dev/null) || return 1
  printf '%s\n' "$lh_acl" | awk '
    /^user::[rwx-][rwx-][rwx-]$/ {u++; next}
    /^group::[rwx-][rwx-][rwx-]$/ {g++; next}
    /^other::[rwx-][rwx-][rwx-]$/ {o++; next}
    /^$/ {next} {bad=1} END {exit !(u==1 && g==1 && o==1 && !bad)}' || return 1
  lh_file /etc/group || return 1
  lh_g=$lh_digest
  lh_groups=$(awk -F: '$1=="root" {r++; rg=$3} $1=="shadow" {s++; sg=$3} END {if(r!=1 || s>1) exit 1; print rg "|" (s==1 ? sg : "-")}' /etc/group) || return 1
  [ "$(lh_hash /etc/group)" = "$lh_g" ] || return 1
  [ "$(stat -c '%a:%u:%g:%d:%i:%h' -- "$lh_f")" = "$lh_a" ] || return 1
  printf 'PERM|%s|%s|%s|%s|%s\n' "$lh_f" "$lh_a" "$lh_d" "$lh_groups" "$lh_g"
}
lh_audit() {
  for lh_tool in auditctl stat sha256sum base64 head wc sort tr awk uname systemd-detect-virt; do command -v "$lh_tool" >/dev/null 2>&1 || return 1; done
  # A container shares its kernel's audit subsystem; it is not a host target.
  [ ! -e /.dockerenv ] && [ ! -e /run/.containerenv ] && [ ! -e /.containerenv ] || return 1
  lh_virt_status=0
  lh_virt=$(systemd-detect-virt --container 2>/dev/null) || lh_virt_status=$?
  [ "$lh_virt_status" = 1 ] && [ "$lh_virt" = none ] || return 1
  case "$(uname -r)" in *[Mm]icrosoft*|*WSL*) return 1;; esac
  lh_path /etc/audit/rules.d && [ -d /etc/audit/rules.d ] || return 1
  lh_status=$(auditctl -s 2>/dev/null) || return 1
  lh_enabled=$(printf '%s\n' "$lh_status" | awk '$1=="enabled" {print $2}')
  lh_pid=$(printf '%s\n' "$lh_status" | awk '$1=="pid" {print $2}')
  [ "$lh_enabled" = 1 ] && [ "${lh_pid:-0}" -gt 0 ] || return 1
  lh_boot=$(head -c 64 /proc/sys/kernel/random/boot_id) || return 1
  lh_objects=$(for lh_watch in /etc/passwd /etc/group /etc/shadow /etc/gshadow; do
    lh_path "$lh_watch" && [ -f "$lh_watch" ] && [ "$(stat -c %h -- "$lh_watch")" = 1 ] || exit 1
    stat -c '%d:%i' -- "$lh_watch" || exit 1
  done) || return 1
  lh_watched=$(printf '%s' "$lh_objects" | sha256sum); lh_watched=${lh_watched%% *}
  lh_rules=$({ auditctl -l 2>/dev/null; printf '\nLH_AUDIT_STATUS:%s' "$?"; } | head -c 65537)
  [ "${#lh_rules}" -lt 65536 ] || return 1
  lh_end=${lh_rules##*'
LH_AUDIT_STATUS:'}; [ "$lh_end" = 0 ] || return 1
  lh_rules=${lh_rules%'
LH_AUDIT_STATUS:'*}
  lh_rule_data=$(printf '%s' "$lh_rules" | base64 | tr -d '\n')
  lh_f=/etc/audit/rules.d/70-lovelyhawk-auth.rules
  lh_path "$lh_f" || return 1
  if [ -e "$lh_f" ]; then
    lh_file "$lh_f" || return 1
    lh_fa=$lh_attrs lh_fd=$lh_digest
  else lh_fa=- lh_fd=-; fi
  printf 'AUDIT|%s|%s|%s|%s|%s|%s\n' "$lh_fa" "$lh_fd" "$lh_boot" "$lh_pid" "$lh_rule_data" "$lh_watched"
}
"#;

fn error(message: impl Into<String>) -> CoreError {
    CoreError::validation("authentication baseline", message)
}
fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn attributes(file: &BaselineBackupEvidence) -> CoreResult<Vec<u64>> {
    validate_applied_files(std::slice::from_ref(&file.file), std::slice::from_ref(file))?;
    file.attributes
        .as_ref()
        .ok_or_else(|| error("missing attributes"))?
        .split(':')
        .enumerate()
        .map(|(i, value)| {
            if i == 0 {
                u64::from_str_radix(value, 8)
            } else {
                value.parse()
            }
            .map_err(|_| error("invalid attributes"))
        })
        .collect()
}
fn evidence(file: &str, attrs: &str, hash: &str) -> CoreResult<BaselineBackupEvidence> {
    let item = BaselineBackupEvidence {
        file: file.to_owned(),
        attributes: (attrs != "-").then(|| attrs.to_owned()),
        sha256: (hash != "-").then(|| hash.to_owned()),
    };
    validate_backups(&[file.to_owned()], std::slice::from_ref(&item))?;
    if item.sha256.is_some() != item.attributes.is_some() {
        return Err(error("incomplete file state"));
    }
    Ok(item)
}
fn parse_permission(line: &str) -> CoreResult<PermissionProbe> {
    let p: Vec<_> = line.split('|').collect();
    if p.len() != 7 || p[0] != "PERM" || !AUTH_FILES.contains(&p[1]) || !digest(p[6]) {
        return Err(error("invalid permission observation"));
    }
    let result = PermissionProbe {
        file: evidence(p[1], p[2], p[3])?,
        root_gid: p[4].parse().map_err(|_| error("root group unavailable"))?,
        shadow_gid: if p[5] == "-" {
            None
        } else {
            Some(
                p[5].parse()
                    .map_err(|_| error("shadow group unavailable"))?,
            )
        },
        group_hash: p[6].to_owned(),
    };
    attributes(&result.file)?;
    Ok(result)
}

fn permission_policy(probe: &PermissionProbe) -> CoreResult<(u32, u32)> {
    let a = attributes(&probe.file)?;
    let gid = u32::try_from(a[2]).map_err(|_| error("invalid gid"))?;
    let secret = matches!(probe.file.file.as_str(), "/etc/shadow" | "/etc/gshadow");
    let (mask, wanted_gid) = if !secret {
        (0o644, probe.root_gid)
    } else if gid == probe.root_gid {
        (0o600, gid)
    } else if Some(gid) == probe.shadow_gid {
        (0o640, gid)
    } else {
        return Err(error(
            "口令文件属于未知用户组，请核对本机认证程序的访问需求后处理。",
        ));
    };
    Ok((a[0] as u32 & mask, wanted_gid))
}
fn wanted_rules() -> Vec<String> {
    AUTH_FILES
        .iter()
        .map(|file| format!("-w {file} -p wa -k {AUDIT_KEY}"))
        .collect()
}
fn rules_file() -> String {
    format!(
        "# LovelyHawk authentication watches v1\n{}\n",
        wanted_rules().join("\n")
    )
}
fn canonical_rules(raw: &str) -> CoreResult<String> {
    if raw.len() > 65536
        || raw
            .chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(error("audit rule output exceeded bounds"));
    }
    let mut lines: Vec<_> = raw
        .lines()
        .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|s| !s.is_empty() && s != "No rules")
        .collect();
    if lines.len() > 1024 {
        return Err(error("too many audit rules"));
    }
    lines.sort();
    if lines.windows(2).any(|p| p[0] == p[1]) {
        return Err(error("duplicate audit rules require review"));
    }
    Ok(lines.join("\n"))
}
fn parse_audit(line: &str) -> CoreResult<AuditProbe> {
    let p: Vec<_> = line.split('|').collect();
    if p.len() != 7 || p[0] != "AUDIT" || Uuid::parse_str(p[3]).is_err() || !digest(p[6]) {
        return Err(error("audit status unavailable"));
    }
    let daemon_pid = p[4]
        .parse::<u32>()
        .map_err(|_| error("audit daemon unavailable"))?;
    if daemon_pid == 0 {
        return Err(error("audit daemon not running"));
    }
    let raw = String::from_utf8(
        STANDARD
            .decode(p[5])
            .map_err(|_| error("invalid audit encoding"))?,
    )
    .map_err(|_| error("invalid audit output"))?;
    Ok(AuditProbe {
        file: evidence(AUDIT_FILE, p[1], p[2])?,
        boot: p[3].to_owned(),
        daemon_pid,
        watched_hash: p[6].to_owned(),
        rules: canonical_rules(&raw)?,
    })
}
fn audit_policy(probe: &AuditProbe) -> CoreResult<String> {
    if let Some(hash) = &probe.file.sha256 {
        let a = attributes(&probe.file)?;
        if *hash != sha256_hex(rules_file()) || a[0] != 0o600 || a[1] != 0 || a[2] != 0 {
            return Err(error("同名 auditd 文件不是完整的受管规则，拒绝覆盖。"));
        }
    }
    let wanted = wanted_rules();
    let mut rules: BTreeSet<String> = probe.rules.lines().map(str::to_owned).collect();
    for rule in &rules {
        if wanted.contains(rule) {
            continue;
        }
        if rule.contains(AUDIT_KEY)
            || rule.contains("never")
            || rule.contains("exclude")
            || rule.contains("task")
            || AUTH_FILES.iter().any(|p| rule.contains(p))
            || rule.contains("dir=/etc")
            || rule.contains("dir=/ ")
            || rule.ends_with("dir=/")
            || rule.starts_with("-w /etc ")
            || rule.starts_with("-w / ")
        {
            return Err(error(
                "已有重叠或排除审计规则，需先核对其覆盖范围；没有添加重复监控。",
            ));
        }
    }
    rules.extend(wanted);
    Ok(rules.into_iter().collect::<Vec<_>>().join("\n"))
}

pub(super) fn scan_item(definition: &BaselineDefinition) -> String {
    format!(
        "printf 'ITEM=%s\\t__unverified__\\t%s\\n' {} {}; ",
        shq(definition.id),
        shq(definition.file)
    )
}
async fn run(
    service: &BaselineService,
    session: &BoundSshSession,
    body: &str,
) -> CoreResult<String> {
    let result = successful_output(
        "认证文件与审计状态核对",
        service
            .ssh
            .execute_bound(session, format!("{PROBE}\n{body}"), COMMAND_TIMEOUT)
            .await?,
    )?;
    service.target.validate(session.target())?;
    if result.len() > 128 * 1024 {
        return Err(error("host observation exceeded bounds"));
    }
    Ok(result)
}
pub(super) fn scan_script() -> String {
    format!(
        "\n{PROBE}\nfor lh_target in {}; do (lh_perm \"$lh_target\") 2>/dev/null || printf 'GAP|%s\\n' \"$lh_target\"; done; (lh_audit) 2>/dev/null || printf 'GAP|audit\\n'",
        AUTH_FILES
            .iter()
            .map(|p| shq(p))
            .collect::<Vec<_>>()
            .join(" ")
    )
}
pub(super) fn scan_from_output(output: &str) -> CoreResult<Vec<BaselineStatus>> {
    BASELINE_CATALOG
        .iter()
        .filter(|d| matches!(d.reading, Reading::HostState))
        .map(|d| {
            let observed = if d.file == AUDIT_FILE {
                output
                    .lines()
                    .find(|s| s.starts_with("AUDIT|"))
                    .and_then(|line| parse_audit(line).ok())
                    .and_then(|probe| {
                        audit_policy(&probe).ok().map(|wanted| {
                            if probe.rules == wanted && probe.file.sha256.is_some() {
                                BaselineObservedValue::Value(AUDIT_READY.to_owned())
                            } else {
                                BaselineObservedValue::Value(
                                    if probe.file.sha256.is_some() {
                                        "persistent-only"
                                    } else if probe
                                        .rules
                                        .lines()
                                        .any(|line| line.contains(AUDIT_KEY))
                                    {
                                        "runtime-only"
                                    } else {
                                        "not-configured"
                                    }
                                    .to_owned(),
                                )
                            }
                        })
                    })
            } else {
                output
                    .lines()
                    .find(|s| s.starts_with(&format!("PERM|{}|", d.file)))
                    .and_then(|line| parse_permission(line).ok())
                    .and_then(|probe| {
                        permission_policy(&probe).ok().and_then(|(mode, gid)| {
                            attributes(&probe.file).ok().map(|a| {
                                BaselineObservedValue::Value(
                                    if a[0] == u64::from(mode)
                                        && a[1] == 0
                                        && a[2] == u64::from(gid)
                                    {
                                        PERMISSION_SAFE.to_owned()
                                    } else {
                                        format!(
                                            "权限 {:04o}，属主 UID {}，属组 GID {}",
                                            a[0], a[1], a[2]
                                        )
                                    },
                                )
                            })
                        })
                    })
            }
            .unwrap_or(BaselineObservedValue::Unverified);
            Ok(BaselineStatus {
                item_id: d.id.to_owned(),
                compliant: observed == BaselineObservedValue::Value(d.recommendation.to_owned()),
                observed,
                source_file: d.file.to_owned(),
            })
        })
        .collect()
}
pub(super) async fn capture(
    service: &BaselineService,
    session: &BoundSshSession,
    definition: &BaselineDefinition,
) -> CoreResult<Guard> {
    capture_state(service, session, definition, true).await
}

async fn capture_state(
    service: &BaselineService,
    session: &BoundSshSession,
    definition: &BaselineDefinition,
    require_root: bool,
) -> CoreResult<Guard> {
    let permission = if require_root {
        "[ \"$(id -u)\" = 0 ]"
    } else {
        "true"
    };
    if definition.file == AUDIT_FILE {
        let output = run(service, session, &format!("{permission} && lh_audit")).await?;
        let probe = parse_audit(output.trim())?;
        let after = audit_policy(&probe)?;
        let guard = Guard::Audit {
            before: probe.file,
            boot: probe.boot,
            daemon_pid: probe.daemon_pid,
            watched_hash: probe.watched_hash,
            runtime_before: probe.rules,
            runtime_after: after,
        };
        guard.validate(definition)?;
        Ok(guard)
    } else {
        let output = run(
            service,
            session,
            &format!("{permission} && lh_perm {}", shq(definition.file)),
        )
        .await?;
        let probe = parse_permission(output.trim())?;
        let (desired_mode, desired_gid) = permission_policy(&probe)?;
        Ok(Guard::Permissions {
            before: probe.file,
            desired_mode,
            desired_gid,
            group_hash: probe.group_hash,
        })
    }
}
pub(super) async fn read_view(
    service: &BaselineService,
    session: &BoundSshSession,
    definition: &BaselineDefinition,
) -> CoreResult<BaselineFileView> {
    let text = match capture_state(service, session, definition, false).await {
        Ok(Guard::Permissions {
            before,
            desired_mode,
            desired_gid,
            ..
        }) => {
            let a = attributes(&before)?;
            format!(
                "当前权限 {:04o}，属主 UID {}，属组 GID {}。\n策略目标：权限 {desired_mode:04o}，属主 UID 0，属组 GID {desired_gid}。\n已核对普通文件、内容摘要、身份及基础 ACL；正文不返回页面。需要修改时先查看具体计划并确认。",
                a[0], a[1], a[2]
            )
        }
        Ok(Guard::Audit {
            before,
            runtime_before,
            ..
        }) => {
            let count = wanted_rules()
                .iter()
                .filter(|rule| runtime_before.lines().any(|line| line == rule.as_str()))
                .count();
            format!(
                "本工具规则片段：{}。\n运行中匹配的认证文件监控：{count} / 4。\n未核实事件落盘或重启自动加载；当前核对未执行修改。\n{}",
                if before.sha256.is_some() {
                    "已保存并核对"
                } else {
                    "尚未保存"
                },
                wanted_rules().join("\n")
            )
        }
        Err(_) => {
            if definition.file == AUDIT_FILE {
                "无法核实 auditd：可能未安装、未运行、规则已锁定、权限不足、处于容器/WSL，或存在重叠规则及非受管文件。请在真实主机核对 auditctl -s、auditctl -l 和规则文件；未执行修改。".to_owned()
            } else {
                "无法核实文件属性、完整摘要或 ACL：可能缺少 getfacl/stat/sha256sum、权限不足、存在扩展 ACL、未知属组、链接或文件在读取时变化。仅支持本次能完整核实的普通文件；账号和口令正文不会返回页面。".to_owned()
            }
        }
    };
    Ok(BaselineFileView {
        path: definition.file.to_owned(),
        key: if definition.file == AUDIT_FILE {
            "认证文件监控"
        } else {
            "文件属主与权限"
        },
        exists: !text.starts_with("无法核实"),
        text,
        mentions: Vec::new(),
        truncated: false,
    })
}

impl Guard {
    fn before(&self) -> &BaselineBackupEvidence {
        match self {
            Self::Permissions { before, .. } | Self::Audit { before, .. } => before,
        }
    }
    pub(super) fn validate(&self, definition: &BaselineDefinition) -> CoreResult<()> {
        if self.before().file != definition.file {
            return Err(error("guard does not match the selected file"));
        }
        validate_backups(
            &[definition.file.to_owned()],
            std::slice::from_ref(self.before()),
        )?;
        match self {
            Self::Permissions {
                before,
                desired_mode,
                desired_gid: _,
                group_hash,
            } => {
                if !AUTH_FILES.contains(&definition.file)
                    || *desired_mode > 0o644
                    || !digest(group_hash)
                {
                    return Err(error("invalid permission plan"));
                }
                let a = attributes(before)?;
                if u64::from(*desired_mode) & !a[0] != 0 {
                    return Err(error("permission repair cannot add access"));
                }
            }
            Self::Audit {
                before,
                boot,
                daemon_pid,
                watched_hash,
                runtime_before,
                runtime_after,
            } => {
                if definition.file != AUDIT_FILE
                    || Uuid::parse_str(boot).is_err()
                    || *daemon_pid == 0
                    || !digest(watched_hash)
                    || canonical_rules(runtime_before)? != *runtime_before
                {
                    return Err(error("invalid audit plan"));
                }
                let probe = AuditProbe {
                    file: before.clone(),
                    boot: boot.clone(),
                    daemon_pid: *daemon_pid,
                    watched_hash: watched_hash.clone(),
                    rules: runtime_before.clone(),
                };
                if audit_policy(&probe)? != *runtime_after {
                    return Err(error("audit plan changed"));
                }
            }
        }
        Ok(())
    }
    pub(super) fn summary(&self, file: &str) -> CoreResult<String> {
        match self {
            Self::Permissions {
                before,
                desired_mode,
                desired_gid,
                ..
            } => {
                let a = attributes(before)?;
                Ok(format!(
                    "仅修改 {file} 的属性：权限 {:04o} → {desired_mode:04o}，UID {} → 0，GID {} → {desired_gid}。保留文件正文及 inode，先在受管私有目录备份；权限立即生效，依赖多余权限的程序可能无法再访问。放回前核对完整内容与身份，只放回原权限和属主，不覆盖后来修改的正文。",
                    a[0], a[1], a[2]
                ))
            }
            Self::Audit { runtime_before, .. } => Ok(format!(
                "为 /etc/passwd、/etc/group、/etc/shadow、/etc/gshadow 增加写入及属性变化监控。规则片段：{file}（root:root，0600）；运行中只添加缺失的 {} 条本工具规则，不重载其他规则或重启服务。会增加审计事件量。保存片段不证明启动加载，规则存在不证明日志成功落盘，须独立产生测试事件并检查留存。恢复只撤销本次新增规则并放回原片段，遇到后续变化即停止。\n{}",
                wanted_rules()
                    .iter()
                    .filter(|rule| !runtime_before.lines().any(|line| line == rule.as_str()))
                    .count(),
                wanted_rules().join("\n")
            )),
        }
    }
}

fn guard_assertion(guard: &Guard, restored: bool) -> CoreResult<String> {
    let before = guard.before();
    match guard {
        Guard::Permissions {
            desired_mode,
            desired_gid,
            group_hash,
            ..
        } => {
            let mut expected = before.clone();
            if !restored {
                let a = attributes(before)?;
                expected.attributes = Some(format!(
                    "{desired_mode:o}:0:{desired_gid}:{}:{}:1",
                    a[3], a[4]
                ));
            }
            Ok(format!(
                "{} [ \"$(lh_hash /etc/group)\" = {} ] || exit 42; lh_perm {} >/dev/null || exit 42; ",
                assert_file_evidence(&expected),
                shq(group_hash),
                shq(&before.file)
            ))
        }
        Guard::Audit {
            boot,
            daemon_pid,
            watched_hash,
            runtime_before,
            runtime_after,
            ..
        } => {
            let runtime = if restored {
                runtime_before
            } else {
                runtime_after
            };
            // Reuse the same bounded parser on the target. Normalized rule order
            // is irrelevant; all unrelated rules must still match the plan.
            Ok(format!(
                "lh_audit >/dev/null || exit 42; [ \"$lh_boot\" = {} ] && [ \"$lh_pid\" = {} ] && [ \"$lh_watched\" = {} ] || exit 42; lh_normal=$(printf '%s\\n' \"$lh_rules\" | awk 'NF && $0 != \"No rules\" {{$1=$1; print}}' | LC_ALL=C sort); [ \"$lh_normal\" = {} ] || exit 42; ",
                shq(boot),
                shq(&daemon_pid.to_string()),
                shq(watched_hash),
                shq(runtime)
            ))
        }
    }
}
fn change_attrs(file: &str, mode: u64, uid: u64, gid: u64) -> String {
    format!(
        "chown -- {} {}; chmod -- {} {}; ",
        shq(&format!("{uid}:{gid}")),
        shq(file),
        shq(&format!("{mode:o}")),
        shq(file)
    )
}
fn watch_delta(guard: &Guard, undo: bool) -> String {
    let Guard::Audit { runtime_before, .. } = guard else {
        return String::new();
    };
    AUTH_FILES
        .iter()
        .zip(wanted_rules())
        .filter(|(_, rule)| !runtime_before.lines().any(|line| line == rule))
        .map(|(path, _)| {
            format!(
                "auditctl {} {} -p wa -k {AUDIT_KEY} || exit 43; ",
                if undo { "-W" } else { "-w" },
                shq(path)
            )
        })
        .collect()
}

pub(super) fn apply_command(plan: &BaselineChangePlan) -> CoreResult<String> {
    let change = &plan.changes[0];
    let guard = change
        .host_guard
        .as_ref()
        .ok_or_else(|| error("missing plan"))?;
    guard.validate(definition(&change.item_id)?)?;
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    command.push_str(&guard_assertion(guard, true)?);
    command.push_str(&assert_file_evidence(guard.before()));
    // Verify parent ownership before creating a backup namespace or rule file.
    command.push_str(&format!(
        "lh_safe_dir /etc && lh_safe_dir {} || exit 41; ",
        shq(BASELINE_ROOT)
    ));
    if matches!(guard, Guard::Audit { .. }) {
        command.push_str("lh_safe_dir /etc/audit/rules.d || exit 41; ");
    }
    command.push_str(&backup_prelude(&plan.remote_root, &plan.files)?);
    // Attribute records are part of the immutable plan. The generic backup
    // row lacks them; replace it with an exact second marker used below.
    command.push_str(&files_read_body(
        &plan.files,
        "HOST_BACKUP=",
        guard.before().sha256.is_some(),
    )?);
    match guard {
        Guard::Permissions {
            before,
            desired_mode,
            desired_gid,
            ..
        } => {
            command.push_str(&assert_file_evidence(before));
            command.push_str(&change_attrs(
                &before.file,
                u64::from(*desired_mode),
                0,
                u64::from(*desired_gid),
            ));
        }
        Guard::Audit { before, .. } => {
            if before.sha256.is_none() {
                command.push_str(&format!("(set -C; umask 077; printf '%s' {} > {}) || exit 41; chown 0:0 {}; stat -c '%a:%u:%g:%d:%i:%h' -- {} > {}; ", shq(&rules_file()), shq(AUDIT_FILE), shq(AUDIT_FILE), shq(AUDIT_FILE), shq(&format!("{}/audit-created.attrs", plan.remote_root))));
            }
            command.push_str(&watch_delta(guard, false));
        }
    }
    command.push_str(&guard_assertion(guard, false)?);
    command.push_str(&files_read_body(&plan.files, "APPLIED_FILE=", true)?);
    command.push_str(&format!("printf '%s\\n' {APPLY_MARKER}"));
    Ok(command)
}

pub(super) fn restore_command(
    change: &PlannedBaselineChange,
    remote_root: &str,
    backups: &[BaselineBackupEvidence],
    applied: Option<&[BaselineBackupEvidence]>,
) -> CoreResult<String> {
    let guard = change
        .host_guard
        .as_ref()
        .ok_or_else(|| error("missing host plan"))?;
    guard.validate(definition(&change.item_id)?)?;
    validate_remote_root(remote_root)?;
    validate_backups(std::slice::from_ref(&change.file), backups)?;
    if backups != std::slice::from_ref(guard.before()) {
        return Err(error("backup state differs from the approved plan"));
    }
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    command.push_str(&guard_assertion(guard, false)?);
    if let Some(applied) = applied {
        validate_applied_files(std::slice::from_ref(&change.file), applied)?;
        command.push_str(&assert_file_evidence(&applied[0]));
    }
    if let Guard::Audit { before, .. } = guard {
        if before.sha256.is_some() {
            command.push_str(&assert_file_evidence(before));
        } else {
            let marker = format!("{remote_root}/audit-created.attrs");
            command.push_str(&format!("lh_file {} && [ \"$lh_digest\" = {} ] && lh_path {} && [ \"$(cat {})\" = \"$lh_attrs\" ] || exit 42; ", shq(AUDIT_FILE), shq(&sha256_hex(rules_file())), shq(&marker), shq(&marker)));
        }
    }
    let backup = format!("{remote_root}/file-0.before");
    if let Some(hash) = &guard.before().sha256 {
        command.push_str(&format!(
            "lh_path {} && [ -f {} ] && [ \"$(lh_hash {})\" = {} ] || exit 42; ",
            shq(&backup),
            shq(&backup),
            shq(&backup),
            shq(hash)
        ));
    }
    match guard {
        Guard::Permissions { before, .. } => {
            let a = attributes(before)?;
            command.push_str(&change_attrs(&before.file, a[0], a[1], a[2]));
        }
        Guard::Audit { before, .. } => {
            command.push_str(&watch_delta(guard, true));
            if before.sha256.is_none() {
                command.push_str(&format!(
                    "[ \"$(lh_hash {})\" = {} ] || exit 42; rm -- {}; ",
                    shq(AUDIT_FILE),
                    shq(&sha256_hex(rules_file())),
                    shq(AUDIT_FILE)
                ));
            }
        }
    }
    command.push_str(&assert_file_evidence(guard.before()));
    command.push_str(&guard_assertion(guard, true)?);
    command.push_str(&format!("printf '%s\\n' {RESTORE_MARKER}"));
    Ok(command)
}
pub(super) async fn verify(
    service: &BaselineService,
    session: &BoundSshSession,
    change: &PlannedBaselineChange,
    restored: bool,
) -> CoreResult<VerificationResult> {
    let guard = change
        .host_guard
        .as_ref()
        .ok_or_else(|| error("missing host plan"))?;
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    command.push_str(&guard_assertion(guard, restored)?);
    if matches!(guard, Guard::Audit { .. }) {
        if restored {
            command.push_str(&assert_file_evidence(guard.before()));
        } else {
            command.push_str(&format!("lh_file {} || exit 42; [ \"$lh_digest\" = {} ] || exit 42; case \"$lh_attrs\" in 600:0:0:*) ;; *) exit 42;; esac; ", shq(AUDIT_FILE), shq(&sha256_hex(rules_file()))));
        }
    }
    command.push_str("printf 'HOST_VERIFIED\\n'");
    let output = service
        .ssh
        .execute_bound(session, command, COMMAND_TIMEOUT)
        .await?;
    service.target.validate(session.target())?;
    let passed = !output.timed_out
        && output.exit_code == Some(0)
        && output.output.lines().any(|line| line == "HOST_VERIFIED");
    Ok(VerificationResult {
        passed,
        detail: if passed {
            match guard {
            Guard::Permissions { .. } => "已独立核对完整内容摘要、文件身份、属主、属组、权限与 ACL；文件正文未改动。",
            Guard::Audit { .. } => "已独立核对规则片段和内核规则，其他规则保持原状。尚未确认审计事件落盘或重启后的自动加载。",
        }.to_owned()
        } else {
            "独立复核未通过，请核对当前属性和运行规则；保留备份与操作记录，不能据此认定已恢复。"
                .to_owned()
        },
    })
}

fn partial_restore_command(
    guard: &Guard,
    remote_root: &str,
    observation: &str,
) -> CoreResult<String> {
    validate_remote_root(remote_root)?;
    let mut command = format!("set -eu; {PROBE}\n{FILE_EVIDENCE_PRELUDE}");
    match guard {
        Guard::Permissions {
            before,
            desired_mode,
            desired_gid,
            group_hash,
        } => {
            let now = parse_permission(observation.trim())?;
            let old = attributes(before)?;
            let actual = attributes(&now.file)?;
            if before.sha256 != now.file.sha256
                || old[3..] != actual[3..]
                || group_hash != &now.group_hash
                || !((actual[0] == old[0] && actual[1] == old[1] && actual[2] == old[2])
                    || (actual[1] == 0
                        && actual[2] == u64::from(*desired_gid)
                        && (actual[0] == old[0] || actual[0] == u64::from(*desired_mode))))
            {
                return Err(error("文件在失败后有其他变化，未自动放回"));
            }
            command.push_str(&assert_file_evidence(&now.file));
            command.push_str(&format!(
                "lh_path {} && [ \"$(lh_hash {})\" = {} ] || exit 42; ",
                shq(&format!("{}/file-0.before", remote_root)),
                shq(&format!("{}/file-0.before", remote_root)),
                shq(before
                    .sha256
                    .as_deref()
                    .ok_or_else(|| error("missing original hash"))?)
            ));
            command.push_str(&change_attrs(&before.file, old[0], old[1], old[2]));
        }
        Guard::Audit {
            before,
            boot,
            daemon_pid,
            watched_hash,
            runtime_before,
            runtime_after,
        } => {
            let now = parse_audit(observation.trim())?;
            audit_policy(&now)?;
            let old: BTreeSet<_> = runtime_before.lines().collect();
            let after: BTreeSet<_> = runtime_after.lines().collect();
            let current: BTreeSet<_> = now.rules.lines().collect();
            if now.boot != *boot
                || now.daemon_pid != *daemon_pid
                || now.watched_hash != *watched_hash
                || (before.sha256.is_some() && now.file != *before)
                || !old.is_subset(&current)
                || !current.is_subset(&after)
            {
                return Err(error("审计规则或主机状态发生其他变化，未自动放回"));
            }
            let current_guard = Guard::Audit {
                before: before.clone(),
                boot: boot.clone(),
                daemon_pid: *daemon_pid,
                watched_hash: watched_hash.clone(),
                runtime_before: now.rules.clone(),
                runtime_after: runtime_after.clone(),
            };
            command.push_str(&guard_assertion(&current_guard, true)?);
            command.push_str(&assert_file_evidence(&now.file));
            if before.sha256.is_none() && now.file.sha256.is_some() {
                let marker = format!("{}/audit-created.attrs", remote_root);
                command.push_str(&format!(
                    "lh_path {} && [ -f {} ] && [ \"$(cat {})\" = {} ] || exit 42; ",
                    shq(&marker),
                    shq(&marker),
                    shq(&marker),
                    shq(now
                        .file
                        .attributes
                        .as_deref()
                        .ok_or_else(|| error("missing created file identity"))?)
                ));
            }
            for file in AUTH_FILES {
                let rule = format!("-w {file} -p wa -k {AUDIT_KEY}");
                if !old.contains(rule.as_str()) && current.contains(rule.as_str()) {
                    command.push_str(&format!(
                        "auditctl -W {} -p wa -k {AUDIT_KEY} || exit 43; ",
                        shq(file)
                    ));
                }
            }
            if before.sha256.is_none() && now.file.sha256.is_some() {
                command.push_str(&format!("rm -- {}; ", shq(AUDIT_FILE)));
            }
        }
    }
    Ok(command)
}

/// A nonzero exit may follow a partial chmod or rule insertion. Journal it and
/// only undo states that are a prefix of this exact plan, preserving every
/// unrelated change. A lost connection never becomes a successful restore.
pub(super) async fn failed_execution(
    service: &BaselineService,
    session: &BoundSshSession,
    plan: &BaselineChangePlan,
) -> CoreError {
    let change = &plan.changes[0];
    let recovery = async {
        let guard = change
            .host_guard
            .as_ref()
            .ok_or_else(|| error("missing plan"))?;
        if verify(service, session, change, true)
            .await
            .is_ok_and(|r| r.passed)
        {
            return Ok::<_, CoreError>(true);
        }
        let observation = match guard {
            Guard::Permissions { before, .. } => {
                run(service, session, &format!("lh_perm {}", shq(&before.file))).await?
            }
            Guard::Audit { .. } => run(service, session, "lh_audit").await?,
        };
        let command = partial_restore_command(guard, &plan.remote_root, &observation)?;
        successful_output(
            "放回本次未完成的属性或审计变更",
            service
                .ssh
                .execute_bound(session, command, COMMAND_TIMEOUT)
                .await?,
        )?;
        Ok(verify(service, session, change, true).await?.passed)
    }
    .await;
    let detail = if recovery.is_ok_and(|ok| ok) {
        "执行未完成；已独立核对原有属性与规则，未留下本次变更。"
    } else {
        "执行未完成，可能已有部分变更；未能独立确认放回。请核对目标状态，保留受管备份与审计记录。"
    };
    let entry = crate::operations::OperationJournalEntry {
        entry_id: Uuid::new_v4().to_string(),
        operation_id: plan.operation.id.clone(),
        target: plan.operation.target.clone(),
        summary: plan.operation.summary.clone(),
        dangerous: true,
        source: "baseline".to_owned(),
        restore_description: plan.operation.restore_description.clone(),
        phase: crate::operations::JournalPhase::VerificationFailed,
        detail: detail.to_owned(),
        occurred_at: Utc::now(),
    };
    if let Err(journal_error) = service.journal.append(entry) {
        tracing::warn!(error = %journal_error, "authentication baseline failure journal could not be saved");
        return error(format!(
            "{detail} 本机操作记录保存失败，请检查便携数据目录的空间与写入权限。"
        ));
    }
    error(detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn permission(file: &str, mode: &str, uid: u32, gid: u32) -> PermissionProbe {
        parse_permission(&format!(
            "PERM|{file}|{mode}:{uid}:{gid}:2049:19:1|{}|0|42|{}",
            "a".repeat(64),
            "b".repeat(64)
        ))
        .unwrap()
    }
    fn audit(rules: &str) -> AuditProbe {
        parse_audit(&format!(
            "AUDIT|-|-|11111111-1111-4111-8111-111111111111|123|{}|{}",
            STANDARD.encode(rules),
            "c".repeat(64)
        ))
        .unwrap()
    }

    #[test]
    fn permission_policy_retains_shadow_group_and_never_adds_access() {
        assert_eq!(
            permission_policy(&permission("/etc/shadow", "666", 0, 42)).unwrap(),
            (0o640, 42)
        );
        assert_eq!(
            permission_policy(&permission("/etc/shadow", "666", 0, 0)).unwrap(),
            (0o600, 0)
        );
        assert_eq!(
            permission_policy(&permission("/etc/gshadow", "400", 0, 42)).unwrap(),
            (0o400, 42)
        );
        assert_eq!(
            permission_policy(&permission("/etc/passwd", "6777", 1000, 1000)).unwrap(),
            (0o644, 0)
        );
        assert!(permission_policy(&permission("/etc/shadow", "640", 0, 1000)).is_err());
    }

    #[test]
    fn malformed_metadata_and_missing_observations_do_not_pass() {
        assert!(is_attribute_label("权限 0666，属主 UID 0，属组 GID 42"));
        for invalid in [
            "权限 0999，属主 UID 0，属组 GID 42",
            "权限 0666，属主 UID 0，属组 GID 42;id",
            "权限 0666，属主 UID 0，属组 GID 42\n",
            "权限 0666，属主 UID 0，属组 GID 4294967296",
        ] {
            assert!(!is_attribute_label(invalid));
        }
        for line in [
            "PERM|/etc/shadow|640:0:0:1:2:2|a|0|42|b",
            "PERM|/etc/passwd;id|640:0:0:1:2:1|a|0|42|b",
            "GAP|/etc/shadow",
        ] {
            assert!(parse_permission(line).is_err());
        }
        let missing = scan_from_output("GAP|audit\nGAP|/etc/shadow").unwrap();
        assert_eq!(missing.len(), 5);
        assert!(missing.iter().all(
            |status| status.observed == BaselineObservedValue::Unverified && !status.compliant
        ));
        assert!(!PROBE.contains("cat /etc/shadow"));
        assert!(PROBE.contains("getfacl -cp"));
    }

    #[test]
    fn audit_refuses_overlaps_exclusions_and_unowned_persistence() {
        for rule in [
            "-w /etc/shadow -p wa -k existing",
            "-a never,task",
            "-a always,exclude -F msgtype=PATH",
            "-a always,exit -F dir=/ -F perm=wa",
            "-w /etc -p wa -k whole-directory",
        ] {
            assert!(audit_policy(&audit(rule)).is_err(), "{rule}");
        }
        let mut probe = audit("");
        probe.file = evidence(AUDIT_FILE, "600:0:0:2049:20:1", &"d".repeat(64)).unwrap();
        assert!(audit_policy(&probe).is_err());
        assert!(canonical_rules("-w /tmp/a -p wa\n-w /tmp/a -p wa").is_err());
    }

    #[test]
    fn audit_only_adds_missing_owned_rules_and_preserves_unrelated_rules() {
        let first = wanted_rules()[0].clone();
        let probe = audit(&format!("{first}\n-w /var/log -p wa -k previous"));
        let after = audit_policy(&probe).unwrap();
        assert_eq!(after.lines().count(), 5);
        let guard = Guard::Audit {
            before: probe.file,
            boot: probe.boot,
            daemon_pid: probe.daemon_pid,
            watched_hash: probe.watched_hash,
            runtime_before: probe.rules,
            runtime_after: after,
        };
        guard.validate(&AUDIT_DEFINITION).unwrap();
        let add = watch_delta(&guard, false);
        assert_eq!(add.matches("auditctl -w ").count(), 3);
        assert!(!add.contains("/etc/passwd"));
        let remove = watch_delta(&guard, true);
        assert_eq!(remove.matches("auditctl -W ").count(), 3);
        assert!(!remove.contains("/var/log"));
        assert!(!add.contains("-D"));
    }

    #[test]
    fn metadata_plans_bind_identity_and_refuse_the_generic_writer() {
        let probe = permission("/etc/shadow", "666", 0, 42);
        let guard = Guard::Permissions {
            before: probe.file.clone(),
            desired_mode: 0o640,
            desired_gid: 42,
            group_hash: probe.group_hash,
        };
        let change = PlannedBaselineChange {
            item_id: "permissions-auth-shadow".to_owned(),
            before: BaselineObservedValue::Value("mode:0666,uid:0,gid:42".to_owned()),
            after: PERMISSION_SAFE.to_owned(),
            file: "/etc/shadow".to_owned(),
            host_guard: Some(guard.clone()),
        };
        validate_changes(std::slice::from_ref(&change)).unwrap();
        assert!(edit_body(&change, "/tmp", 0).is_err());
        let assertion = guard_assertion(&guard, false).unwrap();
        assert!(assertion.contains("640:0:42:2049:19:1"));
        assert!(assertion.contains(&"a".repeat(64)) && assertion.contains(&"b".repeat(64)));
        let mut forged = change.clone();
        forged.host_guard = None;
        assert!(validate_changes(&[forged]).is_err());
        assert!(validate_changes(&[change.clone(), change]).is_err());
        let root = expected_remote_root("11111111-1111-4111-8111-111111111111").unwrap();
        let restore = restore_command(
            &PlannedBaselineChange {
                item_id: "permissions-auth-shadow".to_owned(),
                before: BaselineObservedValue::Missing,
                after: PERMISSION_SAFE.to_owned(),
                file: "/etc/shadow".to_owned(),
                host_guard: Some(guard),
            },
            &root,
            &[probe.file],
            None,
        )
        .unwrap();
        assert!(restore.contains("chown -- '0:42' '/etc/shadow'"));
        assert!(!restore.contains("cp -p") && !restore.contains("cat --"));
    }

    #[test]
    fn partial_audit_recovery_rejects_replacement_of_an_existing_fragment() {
        let probe = audit("");
        let hash = sha256_hex(rules_file());
        let guard = Guard::Audit {
            before: evidence(AUDIT_FILE, "600:0:0:2049:20:1", &hash).unwrap(),
            boot: probe.boot.clone(),
            daemon_pid: probe.daemon_pid,
            watched_hash: probe.watched_hash.clone(),
            runtime_before: probe.rules,
            runtime_after: canonical_rules(&wanted_rules().join("\n")).unwrap(),
        };
        let observation = format!(
            "AUDIT|600:0:0:2049:21:1|{hash}|{}|123|{}|{}",
            probe.boot,
            STANDARD.encode(&wanted_rules()[0]),
            probe.watched_hash
        );
        let root = expected_remote_root("11111111-1111-4111-8111-111111111111").unwrap();
        assert!(partial_restore_command(&guard, &root, &observation).is_err());
        assert!(
            partial_restore_command(&guard, &root, &observation.replace(":21:1", ":20:1")).is_ok()
        );
    }

    // A fixture runner supplies real stat/hash observations from its private
    // directory. Export the production commands, not a second implementation.
    #[test]
    #[ignore = "requires an explicitly owned shell fixture input"]
    fn export_owned_fixture_commands() {
        let input = std::env::var("LOVELYHAWK_HOST_BASELINE_FIXTURE").unwrap();
        let input_path = std::path::Path::new(&input);
        assert!(input_path.is_absolute() && input_path.file_name().unwrap() == "host-input.json");
        let data: serde_json::Value =
            serde_json::from_slice(&std::fs::read(input_path).unwrap()).unwrap();
        let line = data["observation"].as_str().unwrap();
        let (id, guard) = if line.starts_with("PERM|") {
            let p = parse_permission(line).unwrap();
            let (mode, gid) = permission_policy(&p).unwrap();
            (
                "permissions-auth-shadow",
                Guard::Permissions {
                    before: p.file,
                    desired_mode: mode,
                    desired_gid: gid,
                    group_hash: p.group_hash,
                },
            )
        } else {
            let p = parse_audit(line).unwrap();
            let after = audit_policy(&p).unwrap();
            (
                "logging-auth-file-watches",
                Guard::Audit {
                    before: p.file,
                    boot: p.boot,
                    daemon_pid: p.daemon_pid,
                    watched_hash: p.watched_hash,
                    runtime_before: p.rules,
                    runtime_after: after,
                },
            )
        };
        let definition = definition(id).unwrap();
        guard.validate(definition).unwrap();
        let change = PlannedBaselineChange {
            item_id: id.to_owned(),
            before: BaselineObservedValue::Missing,
            after: definition.recommendation.to_owned(),
            file: definition.file.to_owned(),
            host_guard: Some(guard.clone()),
        };
        let id = Uuid::new_v4().to_string();
        let remote_root = data["remoteRoot"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| expected_remote_root(&id).unwrap());
        validate_remote_root(&remote_root).unwrap();
        let plan = BaselineChangePlan {
            operation: OperationPlan::new(
                TargetGuard {
                    identity: TargetIdentity::new("owned-fixture").unwrap(),
                    generation: 1,
                },
                "fixture",
                true,
                Some("restore".to_owned()),
            )
            .unwrap(),
            changes: vec![change.clone()],
            files: vec![definition.file.to_owned()],
            remote_root: remote_root.clone(),
            reload_policy: BaselineReloadPolicy::ApplyNow,
            digest: String::new(),
        };
        let recovery = data["current"].as_str().map(|line| {
            partial_restore_command(&guard, &remote_root, line).map_err(|error| error.to_string())
        });
        let output = serde_json::json!({"recovery": recovery, "apply": apply_command(&plan).unwrap(), "restore": restore_command(&change, &remote_root, std::slice::from_ref(guard.before()), None).unwrap(), "root": remote_root});
        std::fs::write(
            input_path.with_file_name("host-commands.json"),
            serde_json::to_vec_pretty(&output).unwrap(),
        )
        .unwrap();
    }
}
