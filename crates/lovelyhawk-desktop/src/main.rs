// A release build is a GUI program: no console window opens beside it.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> std::process::ExitCode {
    lovelyhawk_desktop::run()
}
