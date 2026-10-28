#[path = "../src/diagnostic_log_api.rs"]
mod diagnostic_log_api;

#[test]
fn phase_zero_operation_surface_is_fixed_at_exactly_five() {
    let source = include_str!("../src/diagnostic_log_api.rs");
    let api_impl = source
        .split_once("impl DiagnosticLogApi {")
        .expect("diagnostic API implementation")
        .1
        .split_once("#[derive(Clone, Copy, Debug, Eq, PartialEq)]")
        .expect("diagnostic API implementation end")
        .0;

    for method in [
        "pub(crate) fn list(",
        "pub(crate) fn set_level(",
        "pub(crate) fn clear_buffer(",
        "pub(crate) fn preview(",
        "pub(crate) fn prepare_export(",
    ] {
        assert!(api_impl.contains(method), "missing fixed method {method}");
    }
    assert_eq!(api_impl.matches("    pub(crate) fn ").count(), 6);
    assert!(api_impl.contains("pub(crate) fn new("));
}

#[test]
fn phase_zero_source_has_no_stderr_shell_path_or_generic_forwarder() {
    let source = include_str!("../src/diagnostic_log_api.rs");
    for forbidden in [
        "std::io::stderr",
        "eprintln!",
        "std::process::Command",
        "pub(crate) path:",
        "generic_invoke",
        "run_command",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden source marker {forbidden}"
        );
    }
    assert!(source.contains("never backend stderr"));
    assert!(source.contains("composition root installs this layer into its single subscriber"));
    // The rolling file gets the very entry the ring keeps, after redaction, and the
    // overlay learns only which of three states the file is in, never where it is.
    assert!(source.contains("same redacted entries to a small rolling log"));
    assert!(source.contains("let line = log_file_line(&entry);"));
    assert!(source.contains("\"writing\""));
    assert!(source.contains("\"memory-only\""));
    assert!(source.contains("\"failed\""));
    assert!(!source.contains("log_file_path"));
}
