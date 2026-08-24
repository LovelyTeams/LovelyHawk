#[cfg(target_os = "windows")]
fn main() {
    println!("cargo:rerun-if-changed=assets/app.ico");
    let mut resource = winresource::WindowsResource::new();
    resource
        .set_icon("assets/app.ico")
        .set("ProductName", "LovelyRes")
        .set("FileDescription", "LovelyRes Linux Emergency Response Tool")
        .set("LegalCopyright", "LovelyRes contributors")
        .set("OriginalFilename", "LovelyRes.exe");
    resource
        .compile()
        .expect("failed to compile LovelyRes Windows resources");
}

#[cfg(not(target_os = "windows"))]
fn main() {
    println!("cargo:rerun-if-changed=assets/app.ico");
}
