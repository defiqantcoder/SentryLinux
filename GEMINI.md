# SentryLinux — Gemini CLI Workspace Instructions

Always follow the project specifications and rules in:
- [spec.md](./spec.md)
- [plan.md](./plan.md)
- [tasks.md](./tasks.md)
- [AGENTS.md](./AGENTS.md)
- [USER_GUIDE.md](./USER_GUIDE.md)

## Workspace Overview
- **Application Name**: SentryLinux
- **Tagline**: AI-augmented endpoint security hub, automated hardening console, and network sentry for Ubuntu 24.04 LTS.
- **Target Platform**: Native Ubuntu Desktop Application (Tauri v2 + React 19)
- **Coding Language**: Rust + Tauri v2 (GTK4 / Libadwaita UI layout; Rust telemetry daemon (eBPF/auditd, tokio, aya-rs); Python 3.12 bindings; google-genai SDK for Gemini 3.8 Flash triage and Gemini 3.1 Pro forensic reasoning; D-Bus / polkit execution bridge.)
- **Architecture**: Low-overhead Rust root daemon monitoring kernel syscalls and log sockets, communicating via D-Bus and polkit with a sandboxed GTK4/Libadwaita user desktop shell, querying Gemini via structured Pydantic JSON contracts.
- **Security Boundary**: All API keys stored in GNOME Keyring via libsecret; file exports canonicalized with ../ traversal rejection; least-privilege polkit action profiles for UFW/AppArmor rule manipulation.

## Core Features
- Inspect system health scores, active intrusion alerts, and unhandled daemon restarts from a unified Libadwaita dashboard
- Filter and live-tail NextDNS queries over Server-Sent Events with instant 1-click domain allow and deny gating
- Authorize or reject process outbound connections via interactive desktop popovers backed by OpenSnitch and UFW
- Switch between NextDNS Only, Proton VPN Only, and Co-Existence modes with automated WireGuard and resolvectl route scoping
- Audit CIS benchmarks via granular Yes/No toggles in USG and inspect side-by-side config diffs before applying fixes
- Run double-checked rootkit and malware sweeps combining ClamAV, LMD, RKhunter, and Debsums package healing
- Trigger 1-click Emergency Lockdown from the system tray to sever untrusted sockets and force AppArmor enforcement

## Gemini CLI Execution Invariants
- Execute tasks incrementally following the task sequence in `tasks.md`. Do not skip verification steps.
- Maintain strict local privacy: never leak API keys, system paths, or uncommitted credentials.
- After every file edit or feature implementation, execute the relevant verification command:
  - Type checking & compilation
  - Linter & formatting checks
  - Unit & integration tests
- Check git status and keep working copy clean before transitioning between tasks.

## CLI Usage Examples
```bash
# Bootstrap the project according to plan.md:
gemini "Read GEMINI.md, spec.md, and plan.md. Set up project scaffolding."

# Implement a specific task slice:
gemini "Read tasks.md and implement Task 1.1 with tests. Verify compilation before finishing."
```
