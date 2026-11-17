# SentryLinux (v2.4.1-lts)

> **AI-augmented endpoint security hub, automated hardening console, and network sentry for Ubuntu 24.04 LTS (Noble Numbat).**

SentryLinux unifies Ubuntu's CLI security ecosystem—`auditd`, `AppArmor`, `Lynis`, `UFW`, `OpenSnitch`, `Fail2ban`, `Suricata`, `ClamAV`, `LMD`, `RKhunter`, `AIDE`, `Debsums`, `USBGuard`, `needrestart`, `WireGuard`, and `NextDNS`—into a native desktop workstation powered by a low-overhead Rust telemetry daemon (`sentrylinux-daemon`) and a native GTK/WebKit2GTK Libadwaita desktop shell (`sentrylinux`).

---

## Core Architecture & Screens

1. **Overview Telemetry & Defense Scorecard**: Composite posture score (0–100), live incident feed with eBPF/auditd MITRE ATT&CK tags, Pre-Execution Blast Radius mapper, Systemd Service Isolation & Exposure pipeline (`systemd-analyze security` + AI Drop-In `99-hardening.conf` generator), and `needrestart` stale library banner.
2. **DNS Sentry (NextDNS SSE Stream)**: Live query stream over DoH/DoT with regex filtering, 1-click inline Allow/Deny gating, CNAME & CDN Dependency Untangler warning modal, and Rescue DNS Watchdog.
3. **Outbound Socket Intercepts & Policy Compiler**: Interactive Simplewall/OpenSnitch-style connection intercept popover with SHA-256 package provenance verification, plus a Natural-Language-to-Native Policy Compiler (UFW + Fail2ban).
4. **USG & Lynis CIS Benchmark Compliance Audit**: 3-column CIS Level 2 workbench with granular rule staging, AI vulnerability deep dives, Adversarial Dual-Model Safety Critic verification gate, and atomic `/etc` Git/Btrfs rollback checkpoints.
5. **Malware & Rootkit Double-Check Sweep**: ClamAV, LMD, RKhunter, and Debsums multi-engine scanner with Two-Stage Rootkit Double-Check (Canonical GPG manifest check + Gemini forensic correlation) and 1-click `apt-get install --reinstall` package healing.
6. **Daemon Restarts & `needrestart` Memory Inspector**: Scans `/proc/[pid]/maps` for unlinked/superseded shared libraries (`libssl.so.3`, `libc.so.6`) with virtual memory diff inspection and graceful Polkit batch restarts.
7. **Network Profiles & WireGuard Co-Existence Manager**: Three-state network switcher (`NextDNS Only`, `Proton VPN Only`, `Co-Existence: Proton + NextDNS`) managing WireGuard `fwmark 51820` and `resolvectl` link-scoped `~.` routing without DNS leaks.
8. **Rules & Quarantine Vault**: Permission-stripped (`0000 +i`) inode vault with `shred -u -z` DoD wiping, ELF/Hex inspection, AppArmor profile studio (`Enforce`/`Complain`), Landlock sandbox launcher, and `cgroup v2` resource slices.
9. **Settings, Polkit Auth & Spec Bundle Exporter**: Polkit-1 action matrix (`org.sentrylinux.*`), PAM-U2F hardware token (`YubiKey`) controls, GNOME Keyring (`libsecret` / `secret-tool`) credential vault, `/boot/sentry-rescue.sh` generator, and canonical-path-guarded Specification Bundle Exporter (`Alt+S`).

---

## Building, Testing & Packaging (.deb)

```bash
# 1. Type-check and build the frontend UI
npm run build

# 2. Run Rust & Node unit test suites
cargo test --manifest-path daemon/Cargo.toml
cargo test --manifest-path src-tauri/Cargo.toml
npm test

# 3. Build the installable Ubuntu 24.04 Debian package (sentrylinux_2.4.1_amd64.deb)
npm run build:deb

# 4. Install or inspect the .deb package
dpkg-deb --info sentrylinux_2.4.1_amd64.deb
sudo dpkg -i sentrylinux_2.4.1_amd64.deb
```
