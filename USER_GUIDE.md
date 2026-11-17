# SentryLinux — Master User Implementation Handbook & Prompt Playbook

> **Audience**: This guide is written directly for **you, the developer/creator**, rather than an AI agent. It details exactly **when**, **where**, and **how** to use each prompt, where to place each generated file, and how to drive the build from initial UI sketches to production deployment.

---

## 1. File Placement & Repository Directory Layout

When exporting or extracting your PromptForge specification bundle, place the files in your project repository as follows:

```text
sentrylinux/
├── spec.md                   # Product scope, user personas & EARS functional requirements
├── plan.md                   # System architecture, data schemas, IPC contracts & testing matrix
├── tasks.md                  # Numbered step-by-step implementation tasks & verification steps
├── AGENTS.md                 # Universal coding instructions, repository rules & constraints
├── GEMINI.md                 # Gemini CLI workspace instructions & terminal rules
├── USER_GUIDE.md             # (This file) Human developer handbook & prompt runbook
├── COLLABORATION.md          # Multi-agent coordination board & directory ownership boundaries
├── .continuerules            # Local AI / Continue IDE assistant configuration
└── src/                      # Your application source code
```

---

## 2. The 4-Stage Build Workflow: When & Where to Use Prompts

PromptForge generates specialized contracts tailored for each phase of your build. Follow this sequence:

### Stage 1: Visual Design with Google Stitch
- **When**: Start here BEFORE writing backend code or complex state logic.
- **Where**: Open [Google Stitch](https://stitch.withgoogle.com/).
- **How to Use**:
  1. In PromptForge, open the **Exporter Deck** or **Stitch UI Studio** (Deck 05).
  2. Select the **Google Stitch** prompt tab and click **Copy Complete Google Stitch UI Prompt**.
  3. Paste the prompt into Google Stitch to generate high-fidelity glassmorphic screens and components.
  4. Download the generated HTML/CSS/ZIP export or capture visual screenshots.
  5. Back in PromptForge, drop your Stitch export into Stage 1b **"Upload What Stitch Built"** so subsequent builder prompts inherit the exact markup and classes.

### Stage 2: Full-Stack Implementation with Your Primary Builder
Choose your primary builder tool:
- **Option A: Google Gemini CLI**
  - **When**: When you want interactive terminal coding with direct command execution and file edits.
  - **Where**: Terminal / shell where `gemini` CLI is installed.
  - **How**: Run `gemini "Read GEMINI.md, spec.md, plan.md, and tasks.md. Implement Task 1."` or copy the **Gemini CLI Prompt** from the Exporter Deck.
- **Option B: Google Antigravity (AGY)**
  - **When**: When you want an autonomous multi-file terminal agent that writes code and runs verification gates.
  - **Where**: Terminal / Antigravity CLI or Antigravity IDE.
  - **How**: Run your Antigravity agent in the repository root. Antigravity reads `AGENTS.md`, `spec.md`, `plan.md`, and `tasks.md` automatically.
- **Option C: Google AI Studio**
  - **When**: When building a web application with full-stack React + Express + server-side `@google/genai` routes.
  - **Where**: [Google AI Studio](https://aistudio.google.com/).
  - **How**: Paste the **AI Studio Full-Stack Contract** into AI Studio's Build workspace.
- **Option D: GitHub Copilot / Cursor**
  - **When**: When coding inside VS Code / JetBrains / Cursor.
  - **Where**: Place `AGENTS.md` or `.github/copilot-instructions.md` in the project root.
  - **How**: Open Copilot Edits or Cursor Composer and reference `@tasks.md` and `@plan.md`.

### Stage 3: Offline & Local AI Refactoring (Ollama + Continue)
- **When**: For offline coding, zero-cost refactoring, documentation generation, or private enterprise work.
- **Where**: Local IDE with the **Continue** extension connected to local **Ollama** (`http://localhost:11434`).
- **How**: Ensure `.continuerules` is in the root directory. Continue automatically loads your project ground rules and context.

### Stage 4: Multi-Agent Parallel Handoffs
- **When**: When running multiple AI coding agents simultaneously on different parts of the project.
- **Where**: Reference `COLLABORATION.md`.
- **How**: Assign each agent to its designated **Work-On Path** (e.g., Agent 1 on UI components, Agent 2 on backend IPC). Verify that neither agent touches the other's **Stay-Away Paths** to prevent git merge conflicts.

---

## 3. Step-by-Step Execution Checklist

1. [ ] **Export the Bundle**: In PromptForge, click **"Export Spec Bundle"** (Alt+S) and save files to your repository root.
2. [ ] **Inspect `tasks.md`**: Review the ordered implementation milestones.
3. [ ] **Run Initial Verification**: Confirm baseline compiler / linter commands work (e.g., `npm run build` or `cargo check`).
4. [ ] **Execute Tasks Sequentially**: Feed one task slice at a time to your builder agent.
5. [ ] **Verify After Each Task**: Run the specified automated verification commands in `tasks.md` before marking any task as complete.

---

## 4. Key Security & Quality Rules

- **Offline-First & Local Privacy**: Do not hardcode API keys or credentials in source code. Use system keyring or environment variables (`GEMINI_API_KEY`).
- **Path Canonicalization**: When reading or writing user files, reject path traversal attempts containing `..`.
- **Latency Standards**: Maintain responsive UI feedback (under 200ms) with tabular numerals for data metrics.
