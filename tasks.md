# Implementation Tasks: SentryLinux

> **Execution Strategy:** `balanced-slices` · **Target OS:** `Ubuntu 24.04 LTS`
> **Legend:** `(HITL)` = Human-in-the-Loop checkpoint · `(AFK)` = Autonomous background execution · `[P]` = Safe to parallelize

- [ ] **T001: Project Scaffolding & IPC Foundation (HITL)**
  - Initialize Rust (eBPF aya-rs, tokio, reqwest), Python 3.12 (PyGObject, GTK4, Libadwaita), systemd/auditd/OpenSnitch/NextDNS APIs, @google/genai (Gemini 3.8 Flash & Gemini 3.1 Pro), libsecret-1 keyring..
  - Configure least-privilege permissions and typed command bridges for `~/Projects/CrateBench-BOMs`.
  - Verification: Run `npx tsc --noEmit` and confirm the application boots cleanly on port 3000 / desktop shell.

- [ ] **T002: Design Tokens & Glassmorphic Surface Theme (AFK) [P]**
  - Implement the night-violet palette (`#0F0C1B`), frosted card surfaces, and `#E95420` primary action styles.
  - Build reusable UI primitives: `Card`, `Tooltip`, `ModeSwitcher`, and `CodeViewer`.
  - Verification: Render workspace cards and verify 12px backdrop blur, 1px lilac borders, and tabular numerals.

- [ ] **T003: Universal Hover Explainer System (AFK) [P]**
  - Wrap Radix UI Tooltip primitives with a 100ms hover delay and `role="tooltip"` accessibility semantics.
  - Connect central plain-English dictionary covering all section badges, switches, and exporters.
  - Verification: Hover over any section label and confirm the lilac-bordered explainer callout appears cleanly.

- [ ] **T004: Feature Slice — Inspect system health scores, active intrusion alerts, and... (HITL)**
  - Implement UI controls, state handlers, and plain-English hover tooltip explainers for: *Inspect system health scores, active intrusion alerts, and unhandled daemon restarts from a unified Libadwaita dashboard*.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [ ] **T005: Feature Slice — Filter and live-tail NextDNS queries over Server-Sent Even... (AFK) [P]**
  - Implement UI controls, state handlers, and plain-English hover tooltip explainers for: *Filter and live-tail NextDNS queries over Server-Sent Events with instant 1-click domain allow and deny gating*.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [ ] **T006: Feature Slice — Authorize or reject process outbound connections via inter... (HITL)**
  - Implement UI controls, state handlers, and plain-English hover tooltip explainers for: *Authorize or reject process outbound connections via interactive desktop popovers backed by OpenSnitch and UFW*.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [ ] **T007: Feature Slice — Switch between NextDNS Only, Proton VPN Only, and Co-Exist... (AFK) [P]**
  - Implement UI controls, state handlers, and plain-English hover tooltip explainers for: *Switch between NextDNS Only, Proton VPN Only, and Co-Existence modes with automated WireGuard and resolvectl route scoping*.
  - Verification: Interact with the control in the live workspace and confirm state updates immediately without console errors.

- [ ] **T008: Contract Compiler, Multi-Platform Exporter & Native Save Modal (HITL)**
  - Compile `ProjectState` into `spec.md`, `plan.md`, `tasks.md`, and 10-section `AGENTS.md`.
  - Wire the Ubuntu directory export modal with canonical path validation (`../` rejection) and direct file downloads.
  - Verification: Click "Save to Computer", verify file sizes, and confirm all 4 specification files export cleanly.
