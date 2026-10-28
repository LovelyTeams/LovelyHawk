//! One directory inside a container or a pod, listed through the runtime's
//! own exec.
//!
//! Images differ in everything but `/bin/sh`: BusyBox or GNU, with or without
//! `stat`, with `ls` flags that disagree. So the listing is a POSIX `sh` loop
//! over the directory's own glob, asking `test` for the kind and `stat` for the
//! size, time and mode where `stat` exists, and saying "unknown" where it does
//! not. Each record ends in `/` and a newline: a name can hold a newline but
//! never a `/`, so no name can end a record early, and there is no NUL in the
//! output for a transport to mangle.

use serde::Serialize;

use crate::{CoreError, CoreResult, sftp::RemotePath, shell_escape::shq};

/// The most entries one listing carries. `/usr/bin` in a full image is a few
/// hundred; a directory past this is a place to search, not to scroll.
pub const MAX_EXEC_DIRECTORY_ENTRIES: usize = 1_000;
const MAX_NAME_BYTES: usize = 1_024;

const STATUS_PREFIX: &str = "lovelyhawk-dir=";
const TRUNCATED: &str = "lovelyhawk-truncated";
const END: &str = "lovelyhawk-end";

/// `$1` is the directory. `stat` without `-L` describes a link itself, as
/// `test -L` does, on GNU and BusyBox alike.
const LISTING_SCRIPT: &str = r#"d=$1
if [ ! -d "$d" ]; then printf 'lovelyhawk-dir=missing/\n'; exit 0; fi
cd -- "$d" 2>/dev/null || { printf 'lovelyhawk-dir=denied/\n'; exit 0; }
printf 'lovelyhawk-dir=ok/\n'
n=0
for f in .[!.]* ..?* *; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  n=$((n+1))
  if [ "$n" -gt LIMIT ]; then printf 'lovelyhawk-truncated/\n'; break; fi
  if [ -L "$f" ]; then t=l; elif [ -d "$f" ]; then t=d; elif [ -f "$f" ]; then t=f; else t=o; fi
  m=$(stat -c '%s %Y %a' -- "$f" 2>/dev/null) || m='- - -'
  [ -n "$m" ] || m='- - -'
  printf '%s %s %s/\n' "$t" "$m" "$f"
done
printf 'lovelyhawk-end/\n'"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecEntryKind {
    Directory,
    File,
    Symlink,
    /// A device, socket or pipe: listed, never opened.
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecDirectoryEntry {
    pub name: String,
    pub kind: ExecEntryKind,
    /// None where the image has no `stat`, or it could not describe the entry.
    pub size: Option<u64>,
    pub modified_unix: Option<i64>,
    /// Permission bits as `stat` prints them, e.g. `755`.
    pub mode: Option<String>,
    /// Whether the joined path is one this tool can name again. A name with a
    /// control character, a backslash or bytes that are not UTF-8 is listed
    /// as it reads, but cannot be opened or entered from here.
    pub openable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecDirectoryListing {
    pub path: RemotePath,
    pub entries: Vec<ExecDirectoryEntry>,
    pub truncated: bool,
}

/// `{exec}` is the runtime's exec up to and including its `--`, e.g.
/// `docker exec -- 'id'` or `kubectl exec 'pod' -n 'ns' --`.
pub(crate) fn listing_command(exec: &str, directory: &RemotePath) -> String {
    let script = LISTING_SCRIPT.replace("LIMIT", &MAX_EXEC_DIRECTORY_ENTRIES.to_string());
    format!(
        "{exec} /bin/sh -c {} lovelyhawk-list {}",
        shq(&script),
        shq(directory.as_str())
    )
}

pub(crate) fn parse_listing(
    directory: RemotePath,
    output: &str,
) -> CoreResult<ExecDirectoryListing> {
    // Only what a terminator closed is a record. Whatever follows the last one
    // is nothing (a whole listing) or half a record (a cut-off one).
    let closed = output.rfind("/\n").map_or("", |end| &output[..end]);
    let mut records = closed.split("/\n");
    // A runtime may greet the command with a warning line first; the status
    // record is the first one that is one.
    let status = records
        .by_ref()
        .find_map(|record| {
            record
                .rsplit('\n')
                .next()
                .and_then(|line| line.strip_prefix(STATUS_PREFIX))
        })
        .ok_or_else(|| {
            CoreError::validation(
                "exec directory listing",
                "the listing did not report whether the directory could be read",
            )
        })?;
    match status {
        "ok" => {}
        "missing" => {
            return Err(CoreError::validation(
                "exec directory listing",
                "这个目录不存在，或者不是目录",
            ));
        }
        "denied" => {
            return Err(CoreError::validation(
                "exec directory listing",
                "没有权限进入这个目录",
            ));
        }
        _ => {
            return Err(CoreError::validation(
                "exec directory listing",
                "the listing reported an unknown status",
            ));
        }
    }

    let mut entries = Vec::new();
    let mut truncated = false;
    let mut ended = false;
    for record in records {
        if record == END {
            ended = true;
            break;
        }
        if record == TRUNCATED {
            truncated = true;
            continue;
        }
        if entries.len() >= MAX_EXEC_DIRECTORY_ENTRIES {
            truncated = true;
            continue;
        }
        entries.push(parse_entry(&directory, record)?);
    }
    if !ended {
        // Cut off by the transport or a time limit: what came is real, but it
        // is not the whole directory, and saying so is the point.
        truncated = true;
    }
    entries.sort_by(|left, right| {
        (left.kind != ExecEntryKind::Directory)
            .cmp(&(right.kind != ExecEntryKind::Directory))
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(ExecDirectoryListing {
        path: directory,
        entries,
        truncated,
    })
}

fn parse_entry(directory: &RemotePath, record: &str) -> CoreResult<ExecDirectoryEntry> {
    let malformed = || CoreError::validation("exec directory listing", "a record was malformed");
    let mut fields = record.splitn(5, ' ');
    let kind = match fields.next().ok_or_else(malformed)? {
        "d" => ExecEntryKind::Directory,
        "f" => ExecEntryKind::File,
        "l" => ExecEntryKind::Symlink,
        "o" => ExecEntryKind::Other,
        _ => return Err(malformed()),
    };
    let size = fields.next().ok_or_else(malformed)?;
    let modified = fields.next().ok_or_else(malformed)?;
    let mode = fields.next().ok_or_else(malformed)?;
    let name = fields.next().ok_or_else(malformed)?;
    if name.is_empty() || name == "." || name == ".." || name.len() > MAX_NAME_BYTES {
        return Err(malformed());
    }
    let joined = if directory.as_str() == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", directory.as_str())
    };
    Ok(ExecDirectoryEntry {
        name: name.to_owned(),
        kind,
        size: size.parse().ok(),
        modified_unix: modified.parse().ok(),
        mode: (mode.len() <= 4
            && !mode.is_empty()
            && mode
                .bytes()
                .all(|byte| byte.is_ascii_digit() && byte < b'8'))
        .then(|| mode.to_owned()),
        openable: !name.contains('\u{FFFD}') && RemotePath::new(joined).is_ok(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(value: &str) -> RemotePath {
        RemotePath::new(value).unwrap()
    }

    #[test]
    fn the_command_quotes_the_directory_and_runs_one_fixed_script() {
        let command = listing_command("docker exec -- 'abc123'", &path("/etc/it's here"));
        assert!(command.starts_with("docker exec -- 'abc123' /bin/sh -c '"));
        assert!(command.ends_with(" lovelyhawk-list '/etc/it'\\''s here'"));
        assert!(command.contains(&format!("-gt {MAX_EXEC_DIRECTORY_ENTRIES}")));
        assert!(!command.contains("LIMIT"));
    }

    #[test]
    fn a_listing_reads_kinds_sizes_and_names_with_spaces_and_newlines() {
        let output = "WARNING: a runtime greeting\nlovelyhawk-dir=ok/\n\
            f 220 1700000000 644 .bashrc/\n\
            d 4096 1700000001 755 cron.d/\n\
            l 7 1700000002 777 mtab/\n\
            f - - - no stat here/\n\
            f 12 1700000003 600 two\nlines/\n\
            o 0 1700000004 660 initctl/\n\
            lovelyhawk-end/\n";
        let listing = parse_listing(path("/etc"), output).unwrap();
        assert!(!listing.truncated);
        let names: Vec<_> = listing
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        // Directories first, then by name.
        assert_eq!(
            names,
            [
                "cron.d",
                ".bashrc",
                "initctl",
                "mtab",
                "no stat here",
                "two\nlines"
            ]
        );
        let bashrc = &listing.entries[1];
        assert_eq!(bashrc.kind, ExecEntryKind::File);
        assert_eq!(bashrc.size, Some(220));
        assert_eq!(bashrc.modified_unix, Some(1_700_000_000));
        assert_eq!(bashrc.mode.as_deref(), Some("644"));
        assert!(bashrc.openable);
        let unknown = &listing.entries[4];
        assert_eq!(
            (unknown.size, unknown.modified_unix, unknown.mode.as_deref()),
            (None, None, None)
        );
        // Listed as it reads, but a path with a newline cannot be named again.
        assert!(!listing.entries[5].openable);
        assert_eq!(listing.entries[3].kind, ExecEntryKind::Symlink);
        assert_eq!(listing.entries[2].kind, ExecEntryKind::Other);
    }

    #[test]
    fn the_root_joins_without_a_double_slash() {
        let listing = parse_listing(
            path("/"),
            "lovelyhawk-dir=ok/\nd 4096 1 755 etc/\nlovelyhawk-end/\n",
        )
        .unwrap();
        assert!(listing.entries[0].openable);
    }

    #[test]
    fn missing_denied_cut_off_and_capped_listings_say_so() {
        assert!(parse_listing(path("/nope"), "lovelyhawk-dir=missing/\n").is_err());
        assert!(parse_listing(path("/root"), "lovelyhawk-dir=denied/\n").is_err());
        assert!(parse_listing(path("/etc"), "").is_err());
        assert!(parse_listing(path("/etc"), "lovelyhawk-dir=maybe/\n").is_err());

        // No end marker: whatever arrived is shown, as not the whole directory.
        let cut = parse_listing(path("/etc"), "lovelyhawk-dir=ok/\nf 1 1 644 a/\n").unwrap();
        assert!(cut.truncated);
        assert_eq!(cut.entries.len(), 1);
        // Cut in the middle of a record: the half is dropped, not misread.
        let half =
            parse_listing(path("/etc"), "lovelyhawk-dir=ok/\nf 1 1 644 a/\nf 2 2 64").unwrap();
        assert!(half.truncated);
        assert_eq!(half.entries.len(), 1);

        let mut many = String::from("lovelyhawk-dir=ok/\n");
        for index in 0..MAX_EXEC_DIRECTORY_ENTRIES {
            many.push_str(&format!("f 1 1 644 file-{index}/\n"));
        }
        many.push_str("lovelyhawk-truncated/\nlovelyhawk-end/\n");
        let capped = parse_listing(path("/usr/bin"), &many).unwrap();
        assert!(capped.truncated);
        assert_eq!(capped.entries.len(), MAX_EXEC_DIRECTORY_ENTRIES);
    }

    #[test]
    fn a_record_that_is_not_one_fails_the_listing_rather_than_inventing_an_entry() {
        for record in [
            "x 1 1 644 a",
            "f 1 1 644",
            "f 1 1 644 ",
            "d 1 1 755 ..",
            "f 1 1 644 .",
        ] {
            let output = format!("lovelyhawk-dir=ok/\n{record}/\nlovelyhawk-end/\n");
            assert!(parse_listing(path("/etc"), &output).is_err(), "{record}");
        }
        // A mode that is not octal digits is dropped, not trusted.
        let odd = parse_listing(
            path("/etc"),
            "lovelyhawk-dir=ok/\nf 1 1 9z9 a/\nlovelyhawk-end/\n",
        )
        .unwrap();
        assert_eq!(odd.entries[0].mode, None);
    }
}
