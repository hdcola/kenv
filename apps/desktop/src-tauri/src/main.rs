// Keep this in place for a future Windows desktop build so release binaries do not open an extra console window.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    kenv_desktop_lib::run()
}
