---
name: Adwaita Telemetry Console
colors:
  surface: '#121221'
  surface-dim: '#121221'
  surface-bright: '#383849'
  surface-container-lowest: '#0d0d1c'
  surface-container-low: '#1a1a2a'
  surface-container: '#1e1e2e'
  surface-container-high: '#292839'
  surface-container-highest: '#333344'
  on-surface: '#e3e0f7'
  on-surface-variant: '#e2bfb4'
  inverse-surface: '#e3e0f7'
  inverse-on-surface: '#2f2f40'
  outline: '#aa8a80'
  outline-variant: '#5a4139'
  surface-tint: '#ffb59e'
  primary: '#ffb59e'
  on-primary: '#5e1700'
  primary-container: '#f85e2a'
  on-primary-container: '#521300'
  inverse-primary: '#ae3200'
  secondary: '#d0bcff'
  on-secondary: '#3c0091'
  secondary-container: '#571bc1'
  on-secondary-container: '#c4abff'
  tertiary: '#45dfa4'
  on-tertiary: '#003825'
  tertiary-container: '#00a574'
  on-tertiary-container: '#003120'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#ffdbd0'
  primary-fixed-dim: '#ffb59e'
  on-primary-fixed: '#3a0b00'
  on-primary-fixed-variant: '#852400'
  secondary-fixed: '#e9ddff'
  secondary-fixed-dim: '#d0bcff'
  on-secondary-fixed: '#23005c'
  on-secondary-fixed-variant: '#5516be'
  tertiary-fixed: '#68fcbf'
  tertiary-fixed-dim: '#45dfa4'
  on-tertiary-fixed: '#002114'
  on-tertiary-fixed-variant: '#005137'
  background: '#121221'
  on-background: '#e3e0f7'
  surface-variant: '#333344'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '700'
    lineHeight: 40px
  headline-lg:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '600'
    lineHeight: 24px
  title-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '600'
    lineHeight: 20px
  label-md:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
  label-sm:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 14px
  body-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 22px
  body-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-dense: 0.5rem
  margin: 1.5rem
  margin-compact: 0.75rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
---

## Brand & Style

This design system establishes a high-performance, developer-grade desktop interface grounded in canonical GNOME and Ubuntu 24.04 Libadwaita patterns. Engineered for system engineers, security operators, and infrastructure architects, the aesthetic merges technical rigor with modern operating system refinement.

The experience is centered on reliability, instantaneous legibility under operational pressure, and tactile desktop ergonomics:
- **Canonical Utility:** Prioritizes desktop conventions—header bars, integrated controls, and distinct system states—avoiding generic web-app paradigms.
- **Architectural Depth:** Employs charcoal base canvases layered with translucent, structured surfaces that mimic modern Linux compositor rendering.
- **Technical Telemetry:** Elevates log streams, IP data, and system metrics with monospace precision, framed within clean structural cards and explicit hairline delimiters.

## Colors

The color system delivers high-contrast legibility against a deep terminal-inspired backdrop, balancing core Ubuntu identity with specialized security and telemetry semantics.

### Palette Architecture
- **Primary (`#E95420` - Ubuntu Brand Orange):** The primary signal for focused elements, primary action triggers, active tabs, and system focus rings.
- **Secondary (`#8B5CF6` - Electric Violet):** Reserved for telemetry streams, automated reasoning pipelines, and synthetic intelligence badges.
- **Tertiary (`#34D399` - Mint Emerald):** Dedicated to nominal system states, cryptographic verification, healthy service units, and safe network flows.
- **Critical / Intrusion (`#EF4444` - Coral Red):** Emphasized for firewall triggers, unauthorized intrusion attempts, error exceptions, and destructive actions.
- **Neutral Canvas (`#141120` to `#1E1E2E`):** The foundational substrate representing window background layers and header bars.

### Layer & Surface Tokens
- **Window Base:** `#141120`
- **Surface Level 1 (Card & Pane):** `rgba(30, 30, 46, 0.75)`
- **Surface Level 2 (Elevated Popovers & Modals):** `rgba(40, 38, 58, 0.90)`
- **Hairline Structural Border:** `#363243`
- **Subtle Inset Divider:** `rgba(255, 255, 255, 0.06)`
- **Text High-Emphasis:** `#F5F5F7`
- **Text Medium-Emphasis:** `#A6A1B8`
- **Text Disabled / Dimmed:** `#625D73`

## Typography

The type scale combines proportional modern sans-serif for interface navigation and dense tabular monospaced letterforms for content-heavy operational feeds.

- **Interface Framework (`Inter`):** Drives structural UI elements, window titles, dialog actions, segment switchers, and group labels. It retains high legibility at micro scales (11px–12px) without visual clutter.
- **Telemetry & Systems (`JetBrains Mono`):** Applied systematically to log records, diff engines, PID references, IPv4/IPv6 matrices, memory addresses, and data grids. It enforces tabular alignment across dynamic streaming data.
- **Type Pairing Principle:** Structural headers never use monospaced fonts; data containers never use proportional sans. The division between control surface and machine data remains strict.

## Layout & Spacing

The layout model adopts Libadwaita desktop conventions, utilizing a pane-and-stack architecture configured along an 8px base rhythm with 4px sub-intervals.

### Structural Panes & Grids
- **Header Bar (Window Titlebar):** Fixed 48px height accommodating window control buttons, global segmented views, and the unified search bar.
- **Primary Navigation Sidebar:** Fixed 240px width or collapsible to an 48px icon rail under condensed viewports.
- **Workspace Canvas:** Fluid container hosting multi-column inspector grids and tabular telemetry sheets.
- **Margins & Gutters:** Global margins conform to 24px (`1.5rem`) on full-width desktop monitors, tightening to 12px (`0.75rem`) within compact side-panes and modal inspectors.

### Density Tiers
- **Standard UI Spacing:** Employs `space-md` (12px) for card body padding and standard form layouts.
- **Telemetry Density:** Employs `space-xs` (4px) and `space-sm` (8px) gaps between terminal rows and key-value monitors to maximize vertical information yield.

## Elevation & Depth

This system avoids heavy drop shadows, relying instead on GTK4-style backdrop filters, subtle top highlights, and calibrated hairline borders.

### Surface Tiers
- **Tier 0 (Window Substrate):** Completely opaque canvas at `#141120`.
- **Tier 1 (Cards, Tabular Panels, Sidebars):** Translucent fill `rgba(30, 30, 46, 0.75)` paired with a backdrop blur of `12px` and a uniform 1px solid border at `#363243`.
- **Tier 2 (Popovers, Tooltips, Menus):** `rgba(40, 38, 58, 0.95)` with a 1px border at `#474259` and an ambient perimeter shadow (`0 8px 24px rgba(0, 0, 0, 0.45)`).
- **Tier 3 (Modal Shells):** Solid background `#1E1E2E` with a high-contrast 1px border at `#E95420` (if urgent) or `#363243` (standard), complemented by an operating-system level dimming scrim (`rgba(10, 8, 16, 0.65)`).

### Lighting & Outlines
Every card and container utilizes an inner highlight line: an explicit `box-shadow: inset 0 1px 0 0 rgba(255, 255, 255, 0.05)` to emulate the top-lit beveled edges characteristic of native desktop toolkits.

## Shapes

The geometry adheres to Libadwaita standard radii, providing an approachable yet precise desktop finish.

### Radius Assignments
- **Top-Level App Window:** Outer boundary corners utilize `rounded-lg` (12px/1rem). Titlebars smoothly match this curve along the top edges.
- **Cards, Panels, & Group Containers:** Built strictly at `rounded` (8px/0.5rem).
- **Interactive Controls (Inputs, Buttons, Segmented Blocks):** Default to `rounded` (8px/0.5rem) to ensure uniform touch targets and cohesive click regions.
- **Telemetry Tags & Pill Badges:** Full capsule rounding (`rounded-full` / 9999px) to visually distinguish immutable status labels from interactive rectangular controls.
- **Window Management Triggers:** Circular close, minimize, and maximize buttons (16px base diameter) seated inside the header bar.

## Components

### Buttons & Segmented Controls
- **Suggested Primary Button:** Background `#E95420`, text `#FFFFFF`, border `1px solid rgba(0, 0, 0, 0.15)`. On hover, background shifts to `#D64515`. On active/pressed, `#BF3D13`. Focused via an outer 2px `#E95420` halo with 2px offset.
- **Secondary / Flat Button:** Translucent fill `rgba(255, 255, 255, 0.05)`, border `1px solid #363243`, text `#F5F5F7`. Hover shifts to `rgba(255, 255, 255, 0.08)`.
- **Segmented Control:** Enclosed container using `rgba(20, 17, 32, 0.6)` with 4px internal padding. The active toggle indicator slides underneath using a solid `#363243` background and sharp white text.

### Inputs & Search Bars
- **Text Inputs:** Background `rgba(20, 17, 32, 0.8)`, border `1px solid #363243`, text `#F5F5F7`, placeholder `#625D73`. Focus transitions the border to `#E95420` with zero layout shift.
- **Headerbar Search Bar:** Pill-style input containing an inline terminal lens icon and an integrated shortcut label (`Ctrl+K`) styled in monospace.

### Badges & Pill Indicators
- **Telemetry Badges:** Pill-shaped capsules (padding `2px 8px`, font `label-sm`).
  - *Verified Nominal:* Border `rgba(52, 211, 153, 0.3)`, background `rgba(52, 211, 153, 0.1)`, text `#34D399`.
  - *Critical Intrusion:* Border `rgba(239, 68, 68, 0.3)`, background `rgba(239, 68, 68, 0.1)`, text `#EF4444`.
  - *AI Inference / Reasoning:* Border `rgba(139, 92, 246, 0.3)`, background `rgba(139, 92, 246, 0.1)`, text `#8B5CF6`.

### Cards & Structured Groups
- **Adwaita Preferences Group:** Solid list card with grouped rows separated by 1px hairline dividers (`rgba(255, 255, 255, 0.04)`). No divider after the final row. Each row features a title, optional subtitle, and trailing action (switch, dropdown, or chevron).

### Checkboxes, Switches, & Radios
- **GNOME Switch:** Pill track (44px × 24px) in `#363243`, sliding knob (20px) in white. Active state shifts the entire track to `#E95420`.
- **Checkboxes:** 18px square with a 4px corner radius. Inactive border `#363243`; selected state fills with `#E95420` with a sharp check icon.

### Telemetry Logs & Terminal Diffs
- Full-bleed monospaced tables featuring zebra-striping via alternating rows of `transparent` and `rgba(255, 255, 255, 0.02)`. Hovering a row highlights it with `rgba(233, 84, 32, 0.08)` and reveals contextual action icons (copy hash, isolate IP).