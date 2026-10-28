#![allow(dead_code)]

#[path = "../src/connections_api.rs"]
mod connections_api;
#[path = "../src/docker_read_api.rs"]
mod docker_read_api;
#[path = "../src/ssh_api.rs"]
mod ssh_api;

#[test]
fn phase_zero_closes_bindings_tokenizes_refreshes_and_scrubs_scope_literals() {
    let source = include_str!("../src/docker_read_api.rs");
    for required in [
        "pub(crate) fn close_binding(&self, binding_handle: &str)",
        "registry.close_binding(binding_handle);",
        "fn insert_refreshed(",
        "release_refresh(&self.binding_handle, self.token);",
        "[SENSITIVE DOCKER TEXT REDACTED]",
        "fn project_public_multiline(",
        "&scope.sensitive_literals()",
    ] {
        assert!(
            source.contains(required),
            "missing Docker boundary: {required}"
        );
    }
}
