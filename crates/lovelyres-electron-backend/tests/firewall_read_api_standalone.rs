#![allow(dead_code)]

#[path = "../src/connections_api.rs"]
mod connections_api;
#[path = "../src/firewall_read_api.rs"]
mod firewall_read_api;
#[path = "../src/ssh_api.rs"]
mod ssh_api;

#[test]
fn public_read_surface_has_only_inspection_and_history_without_remote_or_mutation_primitives() {
    let source = include_str!("../src/firewall_read_api.rs");
    assert!(source.contains(".firewall().inspect("));
    assert!(source.contains(".firewall().list_changes("));
    for forbidden in [
        ".plan_mutation(",
        ".execute_mutation(",
        ".plan_resolution(",
        ".execute_resolution(",
        ".reconcile(",
        "DangerousConfirmation",
        "OperationPlan",
        "pub(crate) session",
        "pub(crate) guard",
        "pub(crate) generation",
        "pub(crate) command",
        "pub(crate) remote_root",
        "pub(crate) object_name",
        "pub(crate) operation_id",
        "pub(crate) preflight_sha256",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}

#[test]
fn binding_close_is_an_internal_scope_cleanup_not_a_public_remote_primitive() {
    let source = include_str!("../src/firewall_read_api.rs");
    assert!(source.contains("pub(crate) fn close_binding(&self, binding_handle: &str)"));
    assert!(source.contains("entry.scope.binding_handle != binding_handle"));
    assert!(!source.contains("pub fn close_binding"));
}
