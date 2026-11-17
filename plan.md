# Technical Implementation Plan: SentryLinux

> **Summary:** AI-augmented endpoint security hub, automated hardening console, and network sentry for Ubuntu 24.04 LTS.
> **Target Platform:** Native Ubuntu Desktop Application (Tauri v2 + React 19)
> **Preferred Coding Language:** Rust + Tauri v2 (GTK4 / Libadwaita UI layout; Rust telemetry daemon (eBPF/auditd, tokio, aya-rs); Python 3.12 bindings; google-genai SDK for Gemini 3.8 Flash triage and Gemini 3.1 Pro forensic reasoning; D-Bus / polkit execution bridge.)

---

## 1. System Architecture & Data Flow
SentryLinux enforces a strict separation between the sandboxed UI layer, deterministic specification/validation logic, AI synthesis adapters (`gemini-3.8-flash`), and local OS/filesystem boundaries on `Ubuntu 24.04 LTS`.

```
[User Interface & Multi-Screen Views]
    │  (Typed Domain State + Optimistic Updates)
    ▼
[State Manager & Live Contract Compiler]
    ├──► [Offline Validation & Persistence] ──► localStorage / Disk Exports
    ├──► [Cloud Gemini Service (gemini-3.8-flash)] ──► Express / Tauri Proxy (30s timeout)
    ├──► [Local AI Runtime (qwen2.5-coder:14b @ http://127.0.0.1:11434)]
    └──► [Tauri IPC / Native Layer]
             ├──► Canonical Path Guard + Atomic Spec Bundle Writer
             └──► System Keyring Credential Guard
```

- **Tech Stack Summary:** Rust (eBPF aya-rs, tokio, reqwest), Python 3.12 (PyGObject, GTK4, Libadwaita), systemd/auditd/OpenSnitch/NextDNS APIs, @google/genai (Gemini 3.8 Flash & Gemini 3.1 Pro), libsecret-1 keyring.
- **Architecture Style:** Low-overhead Rust root daemon monitoring kernel syscalls and log sockets, communicating via D-Bus and polkit with a sandboxed GTK4/Libadwaita user desktop shell, querying Gemini via structured Pydantic JSON contracts.
- **Slicing Strategy:** `balanced-slices`

---

## 2. Feature-to-Module Architecture Matrix

| Feature ID | User Capability | Execution Path |
| --- | --- | --- |
| F-01 | Inspect system health scores, active intrusion alerts, and unhandled daemon restarts from a unified Libadwaita dashboard | UI Component -> State Store -> Validation -> Rust IPC / Local Storage |
| F-02 | Filter and live-tail NextDNS queries over Server-Sent Events with instant 1-click domain allow and deny gating | UI Component -> State Store -> Validation -> Rust IPC / Local Storage |
| F-03 | Authorize or reject process outbound connections via interactive desktop popovers backed by OpenSnitch and UFW | UI Component -> State Store -> Validation -> Rust IPC / Local Storage |
| F-04 | Switch between NextDNS Only, Proton VPN Only, and Co-Existence modes with automated WireGuard and resolvectl route scoping | UI Component -> State Store -> Validation -> Rust IPC / Local Storage |
| F-05 | Audit CIS benchmarks via granular Yes/No toggles in USG and inspect side-by-side config diffs before applying fixes | UI Component -> State Store -> Validation -> Rust IPC / Local Storage |
| F-06 | Run double-checked rootkit and malware sweeps combining ClamAV, LMD, RKhunter, and Debsums package healing | UI Component -> State Store -> Validation -> Rust IPC / Local Storage |
| F-07 | Trigger 1-click Emergency Lockdown from the system tray to sever untrusted sockets and force AppArmor enforcement | UI Component -> State Store -> Validation -> Rust IPC / Local Storage |

---

## 3. UI Surfaces & Multi-Screen Hierarchy
- **Global Visual Direction:** Native Ubuntu 24.04 desktop application built with GTK4 and Libadwaita. Dark-mode foundation adhering to GNOME Human Interface Guidelines. Neutral charcoal background (#1E1E2E / #141120) with frosted card surfaces, subtle 1px hairline borders (#363243), and distinct semantic accents: Ubuntu Orange (#E95420) for primary actions, Mint Emerald (#34D399) for verified states, Coral Red (#EF4444) for critical intrusions, and Electric Violet (#8B5CF6) for AI reasoning badges. Clean typography using Inter and JetBrains Mono for tabular log telemetry.
- **Defined Screens & Menus:**
1. **Screen 1** (`screen`) — Design the primary overview window for SentryLinux. Top bar features a System Health Gauge (0-100), active network profile pill (Co-Existence: Proton + NextDNS), and an emergency 1-click 'Lockdown Mode' switch. The central canvas displays three frosted cards: Live Incident Feed (with Gemini severity badges), Active Services Health (UFW, AppArmor, Fail2ban, USBGuard), and a needrestart status banner indicating updated libraries.
2. **Screen 2** (`screen`) — Design a real-time DNS monitoring console. Displays a streaming log table of outgoing domain queries ingested via SSE, showing timestamp, client process, domain, and tracker block status. Each row includes inline 'Allow' and 'Deny' action buttons, with a top search bar and DNSSEC encryption status pill.
3. **Screen 3** (`screen`) — Design a compliance audit view for Ubuntu Security Guide (USG) and Lynis. Left rail displays a CIS Benchmark category selector; central panel shows an itemized checklist of security rules with individual Yes/No toggle switches, risk badges (High/Medium/Low), an 'AI Explain Vulnerability' button, and an interactive 'Review & Apply Diff' drawer.
4. **Screen 4** (`component`) — Design an interactive security toast/popover for an intercepted outbound connection. Shows process icon, binary path (/usr/bin/curl), PID, target IP/domain, and port. Includes three distinct buttons: 'Allow Once', 'Allow Always (Create Rule)', and 'Block Connection', plus a subtle 'Inspect Process Lineage with Gemini' link.
5. **Screen 5** (`screen`) — Follow global visual direction
6. **Screen 6** (`screen`) — Follow global visual direction
7. **Screen 7** (`screen`) — Follow global visual direction
8. **Screen 8** (`screen`) — Follow global visual direction
- **Uploaded Stitch Artifact**: `stitch_sentrylinux_ubuntu_security_hub.zip`
- **Stitch Handoff Guidance**: Wire interactive state, form validation, and loading/error states onto imported Stitch layout.

---

## 4. Key Domain Models & Validation Rules

```typescript
export type TargetPlatform = 'desktop';
export type CodingLanguageId = 'rust-tauri';

export interface ProjectState {
  id: string;
  appName: string; // "SentryLinux"
  tagline: string;
  coreIdea: string;
  targetPlatform: TargetPlatform;
  codingLanguage?: CodingLanguageId;
  features: string[]; // 7 defined features
  groundRules: {
    offlineFirst: true;
    highPerformance: true;
    localPrivacy: true;
    darkModeDefault: true;
  };
  clarifications: Array<{ id: string; category: string; question: string; selectedAnswer?: string }>;
}
```

- **Input Validation Rules**: Reject empty directory paths, block `..` path traversal, validate request payloads before hitting AI SDKs, and enforce O(n) linear scanning on template token inspection.

---

## 5. Native IPC & Backend API Contracts
1. **`save_spec_bundle(target_dir: String, files: HashMap<String, String>) -> Result<bool, String>`**
   - Expands `~/`, verifies directory boundaries, enforces symlink-escape rejection, atomically renames temporary writes for `AGENTS.md`, `spec.md`, `plan.md`, `tasks.md`, `COLLABORATION.md`, and `.continuerules`.
2. **`get_secure_key` / `set_secure_key` / `has_secure_key`**
   - Reads and persists Gemini API keys via OS keyring without writing credentials to repo files or logs.
3. **`POST /api/gemini/*` & `gemini_proxy_request`**
   - Supports `expand`, `random-idea`, `grill`, `fill-field`, `mini-grill`, `stitch-surprise`, and `recommend-language` with explicit model selection (`gemini-3.8-flash`), fast thinking budgets (`LOW`/`MINIMAL`), and 30-second AbortController timeouts.
4. **`POST /api/export/bundle` & `POST /api/specs/validate`**
   - Deterministic ZIP + `SHA256SUMS.txt` archive generator and offline spec-readiness auditor.

---

## 6. Offline Resilience, Performance & Error Recovery
- **Offline First (Required)**: Form edits and recent blueprints save locally in `localStorage`; deterministic compilation and offline checks run without network access.
- **Latency Budget (<200ms UI)**: Use low/minimal model thinking presets on Flash/Lite models for quick interactive AI actions; retain user text non-destructively when upstream AI calls time out or fail.
- **Accessibility**: Every interactive control, header, blank input, and card mounts plain-English `role="tooltip"` explainers.

---

## 7. Security Boundaries, Phased Milestones & Verification Matrix
- **Security Boundary:** All API keys stored in GNOME Keyring via libsecret; file exports canonicalized with ../ traversal rejection; least-privilege polkit action profiles for UFW/AppArmor rule manipulation.
- **Testing Strategy:** Unit tests for log parser regexes and resolvectl state machines; mock auditd telemetry test harnesses; path canonicalization security assertions; verification of zero plaintext key storage in files.

| Milestone Phase | Deliverable | Required Verification Gate |
| --- | --- | --- |
| Phase 1 · Core Models & UI | Multi-screen Stitch layout + domain types | `npx tsc --noEmit` (0 errors) |
| Phase 2 · Backend & IPC | Rate-limited Express routes + Rust IPC guards | `npm test` + `cargo test` |
| Phase 3 · Packaging & Polish | Production Vite build + Ubuntu Tauri bundle | `npm run build` + `cargo clippy -- -D warnings` |

---

### 8. Optional Local AI Workflow (OLLAMA)
- **Ollama Endpoint**: `http://127.0.0.1:11434`
- **Model**: `qwen2.5-coder:14b`
- **Configuration Artifact**: `.continuerules` & `.continue/config.yaml` rules synced from specification invariants.
- **Usage Note**: Use local Ollama models for offline regex refinement, log parsing unit tests, and AppArmor profile syntax linting.

### 9. Multi-Agent Coordination Boundaries
See `COLLABORATION.md` for full file-claim rules. Active ownership lanes:
- **daemon and kernal telemetry** (in-progress): Work On `daemon/src/, ebpf/ |` | Stay Away From `server/, src-tauri/src/`
- **Agent B · Backend & Native IPC** (ready): Work On `server.ts, server/, src-tauri/src/` | Stay Away From `src/decks/, src/components/`
- **Agent C · QA, Specs & Release** (ready): Work On `tests/, server.test.ts, README.md` | Stay Away From `src/decks/, server/archiveRoute.ts`

### 10. End-to-End Implementation Workflow Plan
1. **Phase 1 · UI Blueprint & Visual Tokens (Google Stitch)**
   - Generate high-fidelity visual layout and component hierarchy using the Stitch UI Contract in Stage 1.
   - Refine component hierarchy, WCAG AA contrast tokens, and responsive dimensions.
   - Upload the resulting HTML, screenshot, or ZIP archive back to PromptForge to lock in visual requirements.

2. **Phase 2 · Application Scaffolding & State Wiring (Google Antigravity (AGY))**
   - Import the PromptForge specification bundle (AGENTS.md, spec.md, plan.md, tasks.md) into Google Antigravity (AGY).
   - Scaffold the domain state models and core interactive handlers for: Inspect system health scores, active intrusion alerts, and unhandled daemon restarts from a unified Libadwaita dashboard, Filter and live-tail NextDNS queries over Server-Sent Events with instant 1-click domain allow and deny gating, Authorize or reject process outbound connections via interactive desktop popovers backed by OpenSnitch and UFW.
   - Wire server/IPC boundaries and ensure form text persists non-destructively.

3. **Phase 3 · Feature Slices & Behavioral Verification
   - Implement remaining feature requirements in ordered slices (balanced-slices).
   - Enforce ground rules: Offline resilience, local key storage, and sub-200ms latency budget.
   - Run typechecks and unit tests to ensure zero regressions.

4. **Phase 4 · Packaging, Polish & Freemium Offline Alternative**
   - Execute production bundle build (Tauri native package).
   - For offline/free execution: toggle Local AI Agents (Ollama) to refactor code without paid API keys.
