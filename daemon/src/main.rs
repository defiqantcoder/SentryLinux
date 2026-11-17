use sentrylinux_daemon::{
    collect_live_telemetry, scan_deleted_shared_objects, start_local_ipc_server,
    validate_and_resolve_export_dir,
};
use std::env;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("--telemetry");

    match cmd {
        "--version" | "-v" => {
            println!("sentrylinux-daemon 2.4.1 (Ubuntu 24.04 LTS Noble Numbat)");
        }
        "--telemetry" => {
            let snap = collect_live_telemetry();
            println!("{}", snap.to_json());
        }
        "--scan-stale" => {
            let deleted = scan_deleted_shared_objects();
            println!(
                "{{\"staleMappingsCount\":{},\"items\":{:?}}}",
                deleted.len(),
                deleted
            );
        }
        "--validate-path" => {
            let raw = args.get(2).map(|s| s.as_str()).unwrap_or("");
            match validate_and_resolve_export_dir(raw) {
                Ok(p) => println!("{{\"valid\":true,\"normalized\":\"{}\"}}", p.display()),
                Err(e) => {
                    eprintln!("{{\"valid\":false,\"error\":\"{e}\"}}");
                    std::process::exit(1);
                }
            }
        }
        "--serve" => {
            let port = args
                .get(2)
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(37890);
            let ui_dir = args
                .get(3)
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/share/sentrylinux/ui"));
            match start_local_ipc_server(port, ui_dir) {
                Ok(bound) => {
                    println!("SentryLinux IPC & Telemetry Server listening on http://127.0.0.1:{bound}");
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(3600));
                    }
                }
                Err(e) => {
                    eprintln!("Failed to bind IPC server: {e}");
                    std::process::exit(1);
                }
            }
        }
        _ => {
            println!("SentryLinux Telemetry Daemon v2.4.1");
            println!("Usage: sentrylinux-daemon [--telemetry | --scan-stale | --validate-path <dir> | --serve [port] [ui_dir]]");
        }
    }
}
