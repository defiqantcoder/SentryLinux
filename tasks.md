# Implementation Tasks: SentryLinux

> **Execution Strategy:** `balanced-slices` · **Target OS:** `Ubuntu 24.04 LTS`
> **Legend:** `(HITL)` = Human-in-the-Loop checkpoint · `(AFK)` = Autonomous background execution · `[P]` = Safe to parallelize

- [x] **T001: Project Scaffolding & IPC Foundation (HITL)**
  - Initialize Rust (`daemon/` & `src-tauri/`), React 19 + TypeScript + Tailwind v4 Libadwaita UI, systemd/auditd/OpenSnitch/NextDNS APIs, `@google/genai` (Gemini 4 Hydrogen & Gemini 4 Carbon), and GNOME Keyring (`libsecret` / `secret-tool`) guard.
  - Configure least-privilege permissions and typed command bridges for `~/Projects/CrateBench-BOMs`.
  - Verification: Run `npx tsc --noEmit` and confirm the application boots cleanly on port 3000 / native desktop shell.

- [x] **T002: Design Tokens & Glassmorphic Surface Theme (AFK) [P]**
  - Implement the Adwaita Telemetry Console night-violet palette (`#121221` / `#1E1E2E`), frosted card surfaces, and `#F85E2A` / `#E95420` primary action styles.
  - Build reusable UI primitives: `Tooltip`, `GnomeSwitch`, `ModeSwitcher`, and `CodeViewer`.
  - Verification: Render workspace cards and verify 12px backdrop blur, 1px hairline borders, and tabular numerals.

- [x] **T003: Universal Hover Explainer System (AFK) [P]**
  - Implement `Tooltip` primitives with a 100ms hover delay and `role="tooltip"` accessibility semantics.
  - Connect central plain-English dictionary covering all section badges, switches, and exporters.
  - Verification: Hover over any section label and confirm the lilac-bordered explainer callout appears cleanly.

- [x] **T004: Feature Slice — Inspect system health scores, active intrusion alerts, and unhandled daemon restarts from a unified Libadwaita dashboard (HITL)**
  - Implement UI controls, state handlers, and plain-English hover tooltip explainers for: *Inspect system health scores, active intrusion alerts, and unhandled daemon restarts from a unified Libadwaita dashboard*.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [x] **T005: Feature Slice — Filter and live-tail NextDNS queries over Server-Sent Events with instant 1-click domain allow and deny gating (AFK) [P]**
  - Implement UI controls, state handlers, CNAME Dependency Untangler modal, and plain-English hover tooltip explainers for: *Filter and live-tail NextDNS queries over Server-Sent Events with instant 1-click domain allow and deny gating*.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [x] **T006: Feature Slice — Authorize or reject process outbound connections via interactive desktop popovers backed by OpenSnitch and UFW (HITL)**
  - Implement UI controls, Simplewall/OpenSnitch modal popover, Natural-Language-to-Native Policy Compiler, and Blast Radius mapper for: *Authorize or reject process outbound connections via interactive desktop popovers backed by OpenSnitch and UFW*.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [x] **T007: Feature Slice — Switch between NextDNS Only, Proton VPN Only, and Co-Existence modes with automated WireGuard and resolvectl route scoping (AFK) [P]**
  - Implement UI controls, USG/Lynis CIS audit matrix, Malware/Rootkit Two-Stage sweep, `needrestart` memory inspector, Quarantine Vault, AppArmor studio, and WireGuard + `resolvectl` route scoping.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [x] **T008: Contract Compiler, Multi-Platform Exporter & Native Save Modal (HITL)**
  - Compile `ProjectState` into `spec.md`, `plan.md`, `tasks.md`, `AGENTS.md`, `COLLABORATION.md`, `.continuerules`, and `SHA256SUMS.txt`.
  - Wire the Ubuntu directory export modal with canonical path validation (`../` rejection) and native/browser downloads, plus package native Linux `.deb` (`sentrylinux_2.4.1_amd64.deb`).
  - Verification: Click "Save to Computer", verify file sizes, confirm all specification files export cleanly, and verify `.deb` build.
