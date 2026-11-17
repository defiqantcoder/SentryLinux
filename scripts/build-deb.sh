#!/usr/bin/env bash
set -euo pipefail

VERSION="2.4.1"
ARCH="amd64"
PKG_NAME="sentrylinux_${VERSION}_${ARCH}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE_DIR="${ROOT_DIR}/build/deb-staging/${PKG_NAME}"

echo "[1/5] Running TypeScript verification & Vite production build..."
cd "${ROOT_DIR}"
npm run build

echo "[2/5] Building native Rust telemetry daemon & GTK/WebKit2GTK desktop shell..."
cargo build --release --manifest-path "${ROOT_DIR}/daemon/Cargo.toml"
cargo build --release --manifest-path "${ROOT_DIR}/src-tauri/Cargo.toml"

echo "[3/5] Assembling Debian package filesystem hierarchy..."
rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}/DEBIAN"
mkdir -p "${STAGE_DIR}/usr/bin"
mkdir -p "${STAGE_DIR}/usr/share/sentrylinux/ui"
mkdir -p "${STAGE_DIR}/usr/share/applications"
mkdir -p "${STAGE_DIR}/usr/share/polkit-1/actions"
mkdir -p "${STAGE_DIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${STAGE_DIR}/lib/systemd/system"

# Copy compiled native binaries
cp "${ROOT_DIR}/src-tauri/target/release/sentrylinux" "${STAGE_DIR}/usr/bin/sentrylinux"
cp "${ROOT_DIR}/daemon/target/release/sentrylinux-daemon" "${STAGE_DIR}/usr/bin/sentrylinux-daemon"
chmod 0755 "${STAGE_DIR}/usr/bin/sentrylinux" "${STAGE_DIR}/usr/bin/sentrylinux-daemon"

# Copy compiled frontend assets
cp -r "${ROOT_DIR}/dist/"* "${STAGE_DIR}/usr/share/sentrylinux/ui/"

# Create desktop launcher entry
cat > "${STAGE_DIR}/usr/share/applications/sentrylinux.desktop" << 'EOF'
[Desktop Entry]
Name=SentryLinux
GenericName=Endpoint Security & Telemetry Hub
Comment=AI-augmented endpoint security hub, automated hardening console, and network sentry for Ubuntu 24.04 LTS
Exec=/usr/bin/sentrylinux
Icon=sentrylinux
Terminal=false
Type=Application
Categories=System;Security;Monitor;GTK;
Keywords=security;firewall;ufw;apparmor;nextdns;wireguard;cis;lynis;ebpf;
StartupNotify=true
EOF

# Create SVG application icon
cat > "${STAGE_DIR}/usr/share/icons/hicolor/scalable/apps/sentrylinux.svg" << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" width="128" height="128">
  <rect width="128" height="128" rx="28" fill="#121221"/>
  <path d="M64 16L22 34v30c0 27.6 17.9 53.3 42 62 24.1-8.7 42-34.4 42-62V34L64 16z" fill="#f85e2a"/>
  <path d="M64 28L32 42v22c0 21.2 13.6 41.1 32 48 18.4-6.9 32-26.8 32-48V42L64 28z" fill="#1e1e2e"/>
  <circle cx="64" cy="64" r="14" fill="#45dfa4"/>
</svg>
EOF

# Create least-privilege Polkit-1 action profile
cat > "${STAGE_DIR}/usr/share/polkit-1/actions/org.sentrylinux.policy" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>SentryLinux</vendor>
  <vendor_url>https://github.com/defiqantcoder/SentryLinux</vendor_url>

  <action id="org.sentrylinux.quarantine.shred">
    <description>Permanently shred quarantined malware inode</description>
    <message>Authentication is required to permanently shred a quarantined binary.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
  </action>

  <action id="org.sentrylinux.network.killswitch">
    <description>Engage emergency nftables/UFW network kill-switch</description>
    <message>Authentication is required to toggle SentryLinux Emergency Lockdown Mode.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_self_keep</allow_active>
    </defaults>
  </action>

  <action id="org.sentrylinux.cis.applybenchmark">
    <description>Apply staged USG/CIS benchmark hardening diffs</description>
    <message>Authentication is required to apply staged CIS hardening rules to /etc.</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
  </action>
</policyconfig>
EOF

# Create hardened systemd service unit
cat > "${STAGE_DIR}/lib/systemd/system/sentrylinux-daemon.service" << 'EOF'
[Unit]
Description=SentryLinux Telemetry & Endpoint Security Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/sentrylinux-daemon --serve 37890 /usr/share/sentrylinux/ui
Restart=on-failure
RestartSec=5
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
RestrictRealtime=yes

[Install]
WantedBy=multi-user.target
EOF

# Calculate installed size in KB
INSTALLED_KB=$(du -sk "${STAGE_DIR}/usr" "${STAGE_DIR}/lib" | awk '{sum += $1} END {print sum}')

cat > "${STAGE_DIR}/DEBIAN/control" << EOF
Package: sentrylinux
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_KB}
Depends: libc6 (>= 2.38), libgtk-3-0t64 | libgtk-3-0, libwebkit2gtk-4.1-0, libglib2.0-0t64 | libglib2.0-0
Recommends: polkitd, libsecret-tools, ufw, apparmor-utils, debsums
Maintainer: SentryLinux Security Team <security@sentrylinux.org>
Homepage: https://github.com/defiqantcoder/SentryLinux
Description: AI-augmented endpoint security hub and hardening console for Ubuntu 24.04 LTS
 SentryLinux unifies Ubuntu's CLI security ecosystem (auditd, AppArmor, Lynis,
 UFW, OpenSnitch, Fail2ban, ClamAV, RKhunter, Debsums, WireGuard, and NextDNS)
 into a native Libadwaita desktop workstation with Dual-Model Gemini 4 triage.
EOF

cat > "${STAGE_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
exit 0
EOF
chmod 0755 "${STAGE_DIR}/DEBIAN/postinst"

echo "[4/5] Building .deb archive with dpkg-deb..."
DEB_OUT_ROOT="${ROOT_DIR}/${PKG_NAME}.deb"
TAURI_BUNDLE_DIR="${ROOT_DIR}/src-tauri/target/release/bundle/deb"
mkdir -p "${TAURI_BUNDLE_DIR}"

dpkg-deb --build --root-owner-group "${STAGE_DIR}" "${DEB_OUT_ROOT}"
cp "${DEB_OUT_ROOT}" "${TAURI_BUNDLE_DIR}/${PKG_NAME}.deb"

echo "[5/5] Verifying built .deb package metadata and contents..."
dpkg-deb --info "${DEB_OUT_ROOT}"
dpkg-deb --contents "${DEB_OUT_ROOT}"
ls -lh "${DEB_OUT_ROOT}"
