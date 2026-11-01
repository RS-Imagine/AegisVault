// Prevents an extra console window on Windows in release builds
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::fs;
use std::path::PathBuf;
use tauri::{WebviewUrl, WebviewWindowBuilder};

/// Resolves `./aegis-data/` right next to `AegisVault-Portable.exe` so the entire
/// encrypted IndexedDB & localStorage vault travels with the portable directory or USB drive,
/// leaving zero vault traces in `C:\Users\<User>\AppData\Local`.
fn resolve_portable_data_dir() -> Option<PathBuf> {
    let exe_path = std::env::current_exe().ok()?;
    let exe_dir = exe_path.parent()?;
    let portable_dir = exe_dir.join("aegis-data");
    if fs::create_dir_all(&portable_dir).is_ok() {
        Some(portable_dir)
    } else {
        None
    }
}

fn main() {
    let portable_data_dir = resolve_portable_data_dir();

    // On Windows WebView2, setting WEBVIEW2_USER_DATA_FOLDER before window creation
    // guarantees all IndexedDB, localStorage, and cache stay inside ./aegis-data/
    #[cfg(target_os = "windows")]
    if let Some(ref dir) = portable_data_dir {
        std::env::set_var("WEBVIEW2_USER_DATA_FOLDER", dir.as_os_str());
    }

    tauri::Builder::default()
        .setup(move |app| {
            let mut win_builder =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .title("AegisVault — 零知识个人密码库 (便携版)")
                    .inner_size(1280.0, 820.0)
                    .min_inner_size(380.0, 600.0)
                    .center();

            if let Some(dir) = portable_data_dir.clone() {
                win_builder = win_builder.data_directory(dir);
            }

            win_builder.build()?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running AegisVault Portable");
}
