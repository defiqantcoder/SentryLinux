use sentrylinux_daemon::{
    collect_live_telemetry, save_spec_bundle_atomic, start_local_ipc_server,
    validate_and_resolve_export_dir, KeyringGuard,
};
use std::collections::HashMap;
use std::env;
use std::ffi::{c_char, c_int, c_ulong, c_void, CString};
use std::path::PathBuf;
use std::ptr;

#[cfg(target_os = "linux")]
#[link(name = "gtk-3")]
#[link(name = "webkit2gtk-4.1")]
#[link(name = "gobject-2.0")]
extern "C" {
    fn gtk_init_check(argc: *mut c_int, argv: *mut *mut *mut c_char) -> c_int;
    fn gtk_window_new(window_type: c_int) -> *mut c_void;
    fn gtk_window_set_title(window: *mut c_void, title: *const c_char);
    fn gtk_window_set_default_size(window: *mut c_void, width: c_int, height: c_int);
    fn gtk_container_add(container: *mut c_void, widget: *mut c_void);
    fn gtk_widget_show_all(widget: *mut c_void);
    fn gtk_main();
    fn gtk_main_quit();
    fn webkit_web_view_new() -> *mut c_void;
    fn webkit_web_view_load_uri(web_view: *mut c_void, uri: *const c_char);
    fn g_signal_connect_data(
        instance: *mut c_void,
        detailed_signal: *const c_char,
        c_handler: extern "C" fn(),
        data: *mut c_void,
        destroy_data: *mut c_void,
        connect_flags: c_int,
    ) -> c_ulong;
}

#[cfg(target_os = "linux")]
extern "C" fn on_window_destroy() {
    unsafe {
        gtk_main_quit();
    }
}

pub fn locate_ui_directory() -> PathBuf {
    if let Ok(custom) = env::var("SENTRYLINUX_UI_DIR") {
        let p = PathBuf::from(custom);
        if p.join("index.html").is_file() {
            return p;
        }
    }
    let candidates = [
        PathBuf::from("./dist"),
        PathBuf::from("../dist"),
        PathBuf::from("/usr/share/sentrylinux/ui"),
    ];
    for c in candidates {
        if c.join("index.html").is_file() {
            return c;
        }
    }
    PathBuf::from("/usr/share/sentrylinux/ui")
}

pub fn invoke_ipc_command(cmd: &str, arg: &str) -> Result<String, String> {
    match cmd {
        "get_system_telemetry" => Ok(collect_live_telemetry().to_json()),
        "validate_path" => {
            let p = validate_and_resolve_export_dir(arg)?;
            Ok(p.to_string_lossy().to_string())
        }
        "save_spec_bundle" => {
            let mut files = HashMap::new();
            files.insert(
                "spec.md".to_string(),
                "# SentryLinux Specification\n".to_string(),
            );
            let out = save_spec_bundle_atomic(arg, &files)?;
            Ok(out.to_string_lossy().to_string())
        }
        "keyring_roundtrip" => {
            let kr = KeyringGuard::new();
            kr.set_key(arg);
            Ok(kr.get_key())
        }
        _ => Err(format!("Unknown IPC command: {cmd}")),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if let Some(flag) = args.get(1).map(|s| s.as_str()) {
        match flag {
            "--version" | "-v" => {
                println!("SentryLinux Desktop v2.4.1 (Ubuntu 24.04 LTS / Tauri v2 + WebKit2GTK)");
                return;
            }
            "--telemetry" => {
                println!("{}", collect_live_telemetry().to_json());
                return;
            }
            "--headless-check" => {
                let ui_dir = locate_ui_directory();
                let port = start_local_ipc_server(0, ui_dir.clone())
                    .expect("Failed to start local IPC server");
                let snap = collect_live_telemetry();
                println!(
                    "SentryLinux Headless Self-Test OK | UI={} | IPC=http://127.0.0.1:{} | Kernel={}",
                    ui_dir.display(),
                    port,
                    snap.kernel_version
                );
                return;
            }
            _ => {}
        }
    }

    let ui_dir = locate_ui_directory();
    let port =
        start_local_ipc_server(0, ui_dir).expect("Failed to bind local SentryLinux IPC server");
    let url = format!("http://127.0.0.1:{port}/");

    #[cfg(target_os = "linux")]
    unsafe {
        let mut argc: c_int = 0;
        let mut argv: *mut *mut c_char = ptr::null_mut();
        if gtk_init_check(&mut argc, &mut argv) != 0 {
            let window = gtk_window_new(0);
            let title = CString::new(
                "SentryLinux — Ubuntu 24.04 LTS Endpoint Security & Telemetry Console",
            )
            .unwrap();
            gtk_window_set_title(window, title.as_ptr());
            gtk_window_set_default_size(window, 1440, 900);

            let webview = webkit_web_view_new();
            let c_url = CString::new(url.clone()).unwrap();
            webkit_web_view_load_uri(webview, c_url.as_ptr());

            gtk_container_add(window, webview);

            let destroy_sig = CString::new("destroy").unwrap();
            g_signal_connect_data(
                window,
                destroy_sig.as_ptr(),
                on_window_destroy,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            );

            gtk_widget_show_all(window);
            gtk_main();
            return;
        }
    }

    println!("SentryLinux running in headless console mode at {url}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipc_telemetry_command() {
        let out = invoke_ipc_command("get_system_telemetry", "").unwrap();
        assert!(out.contains("\"kernelVersion\""));
    }

    #[test]
    fn test_ipc_path_guard_blocks_dotdot() {
        assert!(invoke_ipc_command("validate_path", "../etc/shadow").is_err());
        assert!(invoke_ipc_command("validate_path", "/etc/passwd").is_err());
        assert!(invoke_ipc_command("validate_path", "~/Projects/CrateBench-BOMs").is_ok());
    }

    #[test]
    fn test_ipc_keyring_roundtrip() {
        let val = invoke_ipc_command("keyring_roundtrip", "secret-token-xyz").unwrap();
        assert_eq!(val, "secret-token-xyz");
    }
}
