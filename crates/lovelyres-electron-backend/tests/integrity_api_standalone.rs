#![allow(dead_code)]

#[path = "../src/connections_api.rs"]
mod connections_api;
#[path = "../src/integrity_api.rs"]
mod integrity_api;
#[path = "../src/ssh_api.rs"]
mod ssh_api;

#[test]
fn source_boundary_has_no_renderer_supplied_path_or_generic_command_input() {
    let source = include_str!("../src/integrity_api.rs");
    assert!(!source.contains("pub(crate) path:"));
    assert!(!source.contains("pub(crate) command:"));
    assert!(!source.contains("pub(crate) session"));
    assert!(!source.contains("pub(crate) target"));
    assert!(!source.contains("pub(crate) generation"));
    assert!(!source.contains("pub(crate) digest"));
    assert!(!source.contains("pub(crate) quarantine_path"));
}
