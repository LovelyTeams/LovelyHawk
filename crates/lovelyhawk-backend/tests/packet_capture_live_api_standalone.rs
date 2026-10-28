#![allow(dead_code)]

#[path = "../src/connections_api.rs"]
mod connections_api;
#[path = "../src/packet_capture_live_api.rs"]
mod packet_capture_live_api;
#[path = "../src/ssh_api.rs"]
mod ssh_api;

#[test]
fn public_live_surface_has_no_interface_name_command_path_or_evidence_input() {
    let source = include_str!("../src/packet_capture_live_api.rs");
    let input = &source[source
        .find("pub(crate) struct PacketCaptureStartInput")
        .unwrap()
        ..source
            .find("pub(crate) struct PacketCaptureInterfaceListDto")
            .unwrap()];
    assert!(!input.contains("interface:"));
    assert!(!input.contains("session"));
    assert!(!input.contains("guard"));
    assert!(!input.contains("generation"));
    assert!(!input.contains("identity"));
    assert!(!input.contains("command"));
    assert!(!input.contains("path"));
    assert!(!input.contains("capture_id"));
    assert!(!source.contains("capture_evidence_remote("));
    assert!(!source.contains("capture_evidence_to_path("));
    assert!(!source.contains("cleanup_remote("));
    assert!(source.contains(".start_live("));
    assert!(source.contains("request_stop()"));
    assert!(source.contains(".stop()"));
}

#[test]
fn close_and_filter_boundaries_are_revocable_typed_and_non_generic() {
    let source = include_str!("../src/packet_capture_live_api.rs");
    assert!(source.contains("pub(crate) async fn close_binding(&self, binding_handle: &str)"));
    assert!(source.contains("interfaces.remove_binding(binding_handle)"));
    assert!(source.contains("operations.close_binding(binding_handle)"));
    assert!(source.contains("captures.close_binding(binding_handle, Instant::now())"));

    let start = source
        .split("pub(crate) async fn start(")
        .nth(1)
        .and_then(|value| value.split("pub(crate) async fn poll(").next())
        .unwrap();
    assert!(start.contains("let request = PcapCaptureRequest"));
    assert!(start.contains("request.validate()?"));
    assert!(start.contains(".start_live(&binding, request)"));
    for forbidden in ["shell_escape", "shq(", "CommandRunner", ".execute_bound("] {
        assert!(!start.contains(forbidden));
    }
}
