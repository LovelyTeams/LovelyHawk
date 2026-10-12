//! POSIX shell and SQL escaping shared by all core services.

use std::net::IpAddr;

/// Wrap an arbitrary value as one POSIX `sh` argument.
pub fn shq(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Escape single quotes without adding the outer pair of quotes.
pub fn shq_inner(value: &str) -> String {
    value.replace('\'', "'\\''")
}

/// Validate a Linux account name used in commands and `sed` expressions.
pub fn is_valid_username(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    value.len() <= 32
        && (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Validate an IPv4/IPv6 literal with an optional prefix length.
pub fn is_valid_ip_or_cidr(value: &str) -> bool {
    let value = value.trim();
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) if !address.contains('/') && !prefix.contains('/') => {
            (address, Some(prefix))
        }
        Some(_) => return false,
        None => (value, None),
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    match (address, prefix) {
        (_, None) => true,
        (IpAddr::V4(_), Some(prefix)) => prefix.parse::<u8>().is_ok_and(|p| p <= 32),
        (IpAddr::V6(_), Some(prefix)) => prefix.parse::<u8>().is_ok_and(|p| p <= 128),
    }
}

/// Validate a TCP/UDP port in its canonical decimal form.
pub fn is_valid_port(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Validate a Linux PID up to the kernel's maximum supported value.
pub fn is_valid_pid(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && value
            .parse::<u32>()
            .is_ok_and(|pid| (1..=4_194_304).contains(&pid))
}

/// Validate a small non-negative integer used by command builders.
pub fn is_valid_non_negative_int(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u32>().is_ok_and(|number| number <= 99_999)
}

/// Validate an SQL identifier for positions that cannot use a bound parameter.
pub fn is_valid_sql_ident(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Escape a MySQL/PostgreSQL string literal by doubling quotes.
pub fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_matches_existing_frontend_vectors() {
        assert_eq!(shq("root"), "'root'");
        assert_eq!(shq("a b"), "'a b'");
        assert_eq!(shq(""), "''");
        assert_eq!(shq("O'Brien"), "'O'\\''Brien'");
        assert_eq!(shq("''"), "''\\'''\\'''");

        for payload in [
            "a;rm -rf /",
            "a&&whoami",
            "a||whoami",
            "a|tee /etc/passwd",
            "a`id`",
            "a$(id)",
            "a$HOME",
            "a>/etc/passwd",
            "a</etc/shadow",
            "a*",
            "a?",
            "a\nwhoami",
            "-rf",
            "~root",
        ] {
            assert_eq!(
                shq(payload),
                format!("'{}'", payload.replace('\'', "'\\''"))
            );
        }
    }

    #[test]
    fn inner_form_differs_only_by_outer_quotes() {
        for value in ["", "plain", "a b", "O'Brien", "; rm -rf /", "$(id)"] {
            assert_eq!(format!("'{}'", shq_inner(value)), shq(value));
        }
    }

    #[test]
    fn whitelist_validators_match_security_vectors() {
        for value in ["root", "www-data", "user_1", "a", "_svc", &"A".repeat(32)] {
            assert!(is_valid_username(value), "should accept {value:?}");
        }
        for value in ["test'x", "a|b", "a.b", "-h", "1user", "a b", ""] {
            assert!(!is_valid_username(value), "should reject {value:?}");
        }

        for value in [
            "1.1.1.1",
            "192.168.0.0/16",
            "10.0.0.1/32",
            "fe80::1",
            "2001:db8::/32",
        ] {
            assert!(is_valid_ip_or_cidr(value), "should accept {value:?}");
        }
        for value in [
            "256.1.1.1",
            "1.1.1.1/33",
            "2001:db8::/129",
            "1.1.1.1;id",
            "notanip",
            "",
        ] {
            assert!(!is_valid_ip_or_cidr(value), "should reject {value:?}");
        }

        for value in ["1", "22", "65535"] {
            assert!(is_valid_port(value));
        }
        for value in ["0", "65536", "-1", "22/tcp", "22;id", ""] {
            assert!(!is_valid_port(value));
        }

        for value in ["1", "4194304", " 1234 "] {
            assert!(is_valid_pid(value));
        }
        for value in ["0", "-1", "4194305", "1;id", "1.5", ""] {
            assert!(!is_valid_pid(value));
        }

        for value in ["0", "7", "99999"] {
            assert!(is_valid_non_negative_int(value));
        }
        for value in ["-1", "1.5", "100000", "abc", "", "7;id"] {
            assert!(!is_valid_non_negative_int(value));
        }
    }

    #[test]
    fn sql_escaping_and_identifier_validation() {
        for value in ["users", "_tmp", "t1", "my_table$x", "A"] {
            assert!(is_valid_sql_ident(value));
        }
        for value in ["", "1table", "users; DROP DATABASE prod; --", "a.b", "a`b"] {
            assert!(!is_valid_sql_ident(value));
        }
        assert_eq!(escape_sql_literal("O'Brien"), "O''Brien");
        assert!(!escape_sql_literal("x'").contains('\\'));
    }
}
