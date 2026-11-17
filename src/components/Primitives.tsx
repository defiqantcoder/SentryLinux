import React, { useState, useRef } from 'react';
import type { NetworkMode } from '../types/project';

export const EXPLAINER_DICTIONARY: Record<string, { title: string; body: string }> = {
  'lockdown-mode': {
    title: 'Zero-Trust Emergency Lockdown',
    body: 'Immediately sets UFW/nftables to drop all non-loopback sockets, forces all 72 AppArmor profiles into strict Enforce mode, and arms a 5-minute auto-revert watchdog.',
  },
  'coexistence-mode': {
    title: 'Proton VPN + NextDNS Co-Existence',
    body: 'Tunnels all system traffic through WireGuard (wg0-proton) while scoping systemd-resolved (~.) exclusively to your encrypted NextDNS DoH profile without leaks.',
  },
  'health-scorecard': {
    title: 'System Defense Scorecard (0–100)',
    body: 'Composite posture index calculated from USG CIS Level 2 compliance rules, AppArmor confinement ratio, needrestart memory cleanliness, and active eBPF hooks.',
  },
  'cname-untangler': {
    title: 'NextDNS CNAME & CDN Dependency Untangler',
    body: 'Inspects CNAME chains before blocking a domain so shared OAuth/CDN endpoints do not accidentally break login flows.',
  },
  'safety-critic': {
    title: 'Adversarial Dual-Model Safety Critic',
    body: 'Every staged configuration diff is audited for user lockouts, credential wipes, or boot target regressions before Polkit authorization.',
  },
  'blast-radius': {
    title: 'Pre-Execution Blast Radius Mapper',
    body: 'Analyzes process ancestry (pstree), shared libraries, and Wayland/PipeWire sockets before terminating or freezing a suspicious PID.',
  },
  'snapshot-etc': {
    title: 'Atomic /etc Git & Btrfs Checkpoint',
    body: 'Captures an immutable pre-remediation snapshot so any sysctl, SSH, or PAM change can be rolled back in one click.',
  },
  'polkit-token': {
    title: 'Polkit-1 Least-Privilege Token',
    body: 'Temporary privilege escalation lease verified via PAM-U2F hardware token (YubiKey) or sudo password.',
  },
};

interface TooltipProps {
  explainerKey?: string;
  title?: string;
  content?: string;
  children: React.ReactNode;
  className?: string;
}

export const Tooltip: React.FC<TooltipProps> = ({
  explainerKey,
  title,
  content,
  children,
  className = '',
}) => {
  const [visible, setVisible] = useState(false);
  const timerRef = useRef<number | null>(null);

  const entry = explainerKey ? EXPLAINER_DICTIONARY[explainerKey] : undefined;
  const resolvedTitle = title || entry?.title || 'SentryLinux Explainer';
  const resolvedBody = content || entry?.body || '';

  const handleEnter = () => {
    timerRef.current = window.setTimeout(() => setVisible(true), 100);
  };

  const handleLeave = () => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setVisible(false);
  };

  if (!resolvedBody) {
    return <>{children}</>;
  }

  return (
    <div
      className={`relative inline-flex ${className}`}
      onMouseEnter={handleEnter}
      onMouseLeave={handleLeave}
      onFocus={handleEnter}
      onBlur={handleLeave}
    >
      {children}
      {visible && (
        <div
          role="tooltip"
          className="pointer-events-none absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-64 p-2.5 rounded-lg bg-[#28263a]/95 backdrop-blur-md border border-[#8B5CF6]/40 shadow-[0_8px_24px_rgba(0,0,0,0.55)] text-left z-50 animate-in fade-in duration-150"
        >
          <div className="font-title-sm text-[12px] text-primary font-semibold flex items-center gap-1">
            <span className="material-symbols-outlined text-[14px] text-secondary">info</span>
            <span>{resolvedTitle}</span>
          </div>
          <p className="font-code-sm text-[11px] text-on-surface/90 mt-1 leading-relaxed">
            {resolvedBody}
          </p>
        </div>
      )}
    </div>
  );
};

export const MaterialIcon: React.FC<{ name: string; className?: string }> = ({
  name,
  className = 'text-[18px]',
}) => <span className={`material-symbols-outlined select-none ${className}`}>{name}</span>;

export const GnomeSwitch: React.FC<{
  checked: boolean;
  onChange: (next: boolean) => void;
  label?: string;
  ariaLabel?: string;
}> = ({ checked, onChange, label, ariaLabel }) => (
  <label className="inline-flex items-center gap-2.5 cursor-pointer select-none">
    {label && <span className="font-label-md text-label-md text-on-surface">{label}</span>}
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel || label || 'Toggle switch'}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full p-0.5 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-primary-container ${
        checked ? 'bg-primary-container' : 'bg-surface-container-highest'
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transition-transform duration-200 ${
          checked ? 'translate-x-5' : 'translate-x-0'
        }`}
      />
    </button>
  </label>
);

export const ModeSwitcher: React.FC<{
  mode: NetworkMode;
  onChange: (mode: NetworkMode) => void;
}> = ({ mode, onChange }) => {
  const options: Array<{ id: NetworkMode; label: string; badge: string }> = [
    { id: 'nextdns', label: 'NextDNS Only', badge: 'DoH/DoT' },
    { id: 'proton', label: 'Proton VPN Only', badge: 'NetShield' },
    { id: 'coexist', label: 'Co-Existence: Proton + NextDNS', badge: 'wg0 + ~.' },
  ];

  return (
    <div className="inline-flex items-center bg-surface-container-lowest/90 p-1 rounded-xl border border-[#363243] gap-1">
      {options.map((opt) => {
        const active = mode === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            onClick={() => onChange(opt.id)}
            className={`px-3 py-1.5 rounded-lg font-label-md text-label-md transition-all flex items-center gap-1.5 ${
              active
                ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                : 'text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high/50'
            }`}
          >
            <span>{opt.label}</span>
            <span
              className={`font-code-sm text-[10px] px-1.5 py-0.2 rounded-full ${
                active
                  ? 'bg-black/25 text-white'
                  : 'bg-surface-container-highest text-on-surface-variant'
              }`}
            >
              {opt.badge}
            </span>
          </button>
        );
      })}
    </div>
  );
};

export const CodeViewer: React.FC<{
  filePath: string;
  removedLines?: string[];
  addedLines?: string[];
  rawCode?: string;
}> = ({ filePath, removedLines = [], addedLines = [], rawCode }) => (
  <div className="flex flex-col gap-1 bg-surface-container-lowest rounded-lg p-3 font-code-sm text-code-sm border border-[#363243] overflow-x-auto">
    <div className="flex items-center justify-between text-on-surface-variant pb-1 border-b border-white/5">
      <span className="text-primary font-semibold truncate">{filePath}</span>
      <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-container-high text-on-surface-variant">
        diff: +{addedLines.length} -{removedLines.length}
      </span>
    </div>
    {rawCode ? (
      <pre className="text-on-surface whitespace-pre-wrap leading-relaxed pt-1">{rawCode}</pre>
    ) : (
      <div className="flex flex-col gap-0.5 pt-1">
        <div className="text-on-surface-variant/40">
          @@ -1,{Math.max(1, removedLines.length)} +1,{Math.max(1, addedLines.length)} @@
        </div>
        {removedLines.map((line, idx) => (
          <div
            key={`rem-${idx}`}
            className="bg-error-container/25 text-error px-1.5 py-0.5 rounded-sm flex items-center gap-2"
          >
            <span>-</span>
            <span>{line}</span>
          </div>
        ))}
        {addedLines.map((line, idx) => (
          <div
            key={`add-${idx}`}
            className="bg-tertiary-container/25 text-tertiary px-1.5 py-0.5 rounded-sm flex items-center gap-2"
          >
            <span>+</span>
            <span>{line}</span>
          </div>
        ))}
      </div>
    )}
  </div>
);
