#![allow(dead_code)]

#[path = "../src/connections_api.rs"]
mod connections_api;
#[path = "../src/kubernetes_read_api.rs"]
mod kubernetes_read_api;
#[path = "../src/ssh_api.rs"]
mod ssh_api;

#[test]
fn public_read_surface_has_no_resource_identity_command_or_mutation_input() {
    let source = include_str!("../src/kubernetes_read_api.rs");
    assert!(!source.contains(".plan_mutation("));
    assert!(!source.contains(".execute_mutation("));
    assert!(!source.contains("KubernetesMutation"));
    assert!(!source.contains("pub(crate) namespace:"));
    assert!(!source.contains("pub(crate) name:"));
    assert!(!source.contains("pub(crate) uid:"));
    assert!(!source.contains("pub(crate) command:"));
    assert!(!source.contains("pub(crate) session"));
    assert!(!source.contains("pub(crate) generation"));
    for forbidden in [
        ".scale(",
        ".restart(",
        ".delete(",
        ".cordon(",
        ".drain(",
        ".exec(",
        ".read_file(",
        ".open_terminal(",
        ".export(",
        "GenericKubernetes",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden surface: {forbidden}"
        );
    }
}

#[test]
fn phase_zero_has_eager_binding_cleanup_and_bounded_scope_scrubbing() {
    let source = include_str!("../src/kubernetes_read_api.rs");
    for required in [
        "pub(crate) fn close_binding(&self, binding_handle: &str)",
        "snapshots.close_binding(binding_handle);",
        "fn project_public_multiline(",
        "[SENSITIVE KUBERNETES TEXT REDACTED]",
        "&scope.sensitive_literals()",
    ] {
        assert!(
            source.contains(required),
            "missing safety boundary: {required}"
        );
    }
}
