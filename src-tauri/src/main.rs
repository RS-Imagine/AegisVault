// Prevents an extra console window on Windows in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;
use tauri::{WebviewUrl, WebviewWindowBuilder};

/// Resolves `./aegis-data/` right next to `AegisVault-Portable.exe` so the entire
/// encrypted IndexedDB & localStorage vault travels with the portable directory or USB drive,
/// leaving zero vault traces in `C:\Users\<User>\AppData\Local`.
fn resolve_portable_data_dir() -> std::io::Result<PathBuf> {
    let exe_path = std::env::current_exe()?;
    let exe_dir = exe_path.parent().ok_or_else(|| {
        std::io::Error::other("Cannot resolve the portable executable directory")
    })?;
    let portable_dir = exe_dir.join("aegis-data");
    fs::create_dir_all(&portable_dir)?;
    Ok(portable_dir)
}

fn main() {
    // Abort when portable storage is unavailable; never silently fall back to AppData.
    let portable_data_dir = resolve_portable_data_dir()
        .expect("Cannot create aegis-data next to AegisVault; move it to a writable directory");

    // On Windows WebView2, setting WEBVIEW2_USER_DATA_FOLDER before window creation
    // guarantees all IndexedDB, localStorage, and cache stay inside ./aegis-data/
    #[cfg(target_os = "windows")]
    std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", portable_data_dir.as_os_str());

    tauri::Builder::default()
        .setup(move |app| {
            let win_builder =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("AegisVault — 零知识个人密码库 (便携版)")
                    .inner_size(1280.0, 820.0)
                    .min_inner_size(380.0, 600.0)
                    .center();

            win_builder.data_directory(portable_data_dir.clone()).build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running AegisVault Portable");
}
