# Multi-Agent Collaboration & File Boundary Board — SentryLinux

> **Purpose:** Shared coordination ledger for parallel AI coding agents working on **SentryLinux** (Rust + Tauri v2 (GTK4 / Libadwaita UI layout; Rust telemetry daemon (eBPF/auditd, tokio, aya-rs); Python 3.12 bindings; google-genai SDK for Gemini 3.8 Flash triage and Gemini 3.1 Pro forensic reasoning; D-Bus / polkit execution bridge.)).
> Read this file before touching any code, claim your active lane, respect **Stay Away From** boundaries, and record handoff notes when done.

## 1. Status Overview (MULTI-AGENT MODE ACTIVE)

| Agent | Focus Area | Work On (Allowed Paths) | Stay Away From (Restricted) | Status | Handoff Note |
| --- | --- | --- | --- | --- | --- |
| daemon and kernal telemetry | Screens, Stitch integration, accessibility & CSS | `daemon/src/, ebpf/ |` | `server/, src-tauri/src/` | **IN-PROGRESS** | Wait for typed API payloads from Agent B before wiring live calls. |
| Agent B · Backend & Native IPC | Express API routes, Rust Tauri IPC & security guards | `server.ts, server/, src-tauri/src/` | `src/decks/, src/components/` | **READY** | Publish request/response shapes in COLLABORATION.md when changed. |
| Agent C · QA, Specs & Release | Unit tests, verification commands, docs & packaging | `tests/, server.test.ts, README.md` | `src/decks/, server/archiveRoute.ts` | **READY** | Run npx tsc --noEmit, npm test, and cargo test after lane handoffs. |

## 2. Detailed Agent Boundaries

### Lane 1: daemon and kernal telemetry
- **Focus Area:** Screens, Stitch integration, accessibility & CSS
- **Current Status:** `in-progress`
- **WORK ON (Owned Scope):** `daemon/src/, ebpf/ |`
- **STAY AWAY FROM (Do Not Modify):** `server/, src-tauri/src/`
- **Handoff & Coordination Note:** Wait for typed API payloads from Agent B before wiring live calls.

### Lane 2: Agent B · Backend & Native IPC
- **Focus Area:** Express API routes, Rust Tauri IPC & security guards
- **Current Status:** `ready`
- **WORK ON (Owned Scope):** `server.ts, server/, src-tauri/src/`
- **STAY AWAY FROM (Do Not Modify):** `src/decks/, src/components/`
- **Handoff & Coordination Note:** Publish request/response shapes in COLLABORATION.md when changed.

### Lane 3: Agent C · QA, Specs & Release
- **Focus Area:** Unit tests, verification commands, docs & packaging
- **Current Status:** `ready`
- **WORK ON (Owned Scope):** `tests/, server.test.ts, README.md`
- **STAY AWAY FROM (Do Not Modify):** `src/decks/, server/archiveRoute.ts`
- **Handoff & Coordination Note:** Run npx tsc --noEmit, npm test, and cargo test after lane handoffs.

## 3. Shared Coordination Protocol
Update COLLABORATION.md Status & Claims before editing shared contracts (src/types/project.ts) and never touch files listed in another agent lane Stay Away From boundary.

### Mandatory Merge & Handoff Checklist
1. **Before Starting:** Check the status table above and set your lane status to `in-progress`. Do not edit files listed under another agent's **Work On** column without leaving a note here first.
2. **Contract Changes:** If a shared domain type (`src/types/project.ts` or IPC schema) must change, update the contract summary in Section 4 below before downstream agents consume it.
3. **Before Marking Done:** Run `npx tsc --noEmit`, `npm test`, and `cargo test --manifest-path src-tauri/Cargo.toml` (if Rust changed), update your **Handoff Note**, and switch status to `done`.

## 4. Shared Contract Notes & Active Locks
- **Active Project**: `SentryLinux` (`desktop`, language: `rust-tauri`)
- **Features Locked for Build**: 7 defined features
- **Verification Owner**: Last lane touching integration tests confirms full suite green.
