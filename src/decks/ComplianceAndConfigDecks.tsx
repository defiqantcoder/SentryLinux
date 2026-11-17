import React, { useState } from 'react';
import type {
  AppArmorProfileItem,
  CisBenchmarkRule,
  NetworkMode,
  PolkitActionRule,
  ProjectState,
  QuarantinedArtifact,
  SafetyCriticVerdict,
  StaleDaemonItem,
  SweepFinding,
  WireGuardTunnel,
} from '../types/project';
import { CodeViewer, GnomeSwitch, MaterialIcon, ModeSwitcher, Tooltip } from '../components/Primitives';
import { AiSectionExplainer } from '../components/AiSectionExplainer';
import { runSafetyCriticAudit } from '../services/geminiService';
import {
  generateEmergencyRescueScript,
  setSecureKey,
} from '../services/sentryBridge';

// ============================================================================
// SCREEN 4: USG & Lynis CIS Benchmark Compliance Audit
// ============================================================================
interface UsgCisAuditDeckProps {
  rules: CisBenchmarkRule[];
  onToggleRuleStage: (id: string) => void;
  onApplyStagedFixes: () => void;
  snapshotId: string;
  onRevertSnapshot: () => void;
  onRunFullUsgScan: () => void;
}

export const UsgCisAuditDeck: React.FC<UsgCisAuditDeckProps> = ({
  rules,
  onToggleRuleStage,
  onApplyStagedFixes,
  snapshotId,
  onRevertSnapshot,
  onRunFullUsgScan,
}) => {
  const [selectedSection, setSelectedSection] = useState<number | 'ALL'>('ALL');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'FAILED' | 'PASSED' | 'MANUAL'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedAiRuleId, setExpandedAiRuleId] = useState<string | null>('cis-523');
  const [hardeningProfileLevel, setHardeningProfileLevel] = useState<number>(2);
  const [criticVerdict, setCriticVerdict] = useState<SafetyCriticVerdict | null>(null);
  const [criticLoading, setCriticLoading] = useState(false);
  const [scanningUsg, setScanningUsg] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const notify = (msg: string) => {
    setToast(msg);
    window.setTimeout(() => setToast(null), 3500);
  };

  const domainSections = [
    { id: 1, title: '1. Initial Setup', subtitle: 'Filesystems & Updates', passText: '24/25 pass', pct: 96 },
    { id: 2, title: '2. Services & Daemons', subtitle: 'SSH, Cups, RPC', passText: '15/17 pass', pct: 88 },
    { id: 3, title: '3. Network Configuration', subtitle: 'Firewall, Sysctl, IPv6', passText: '32/34 pass', pct: 94 },
    { id: 4, title: '4. Logging & Auditing', subtitle: 'auditd, rsyslog', passText: '21/23 pass', pct: 91 },
    { id: 5, title: '5. Access, Auth & PAM', subtitle: 'su, sudo, password hashing', passText: '17/20 pass', pct: 85 },
    { id: 6, title: '6. Maintenance & Perms', subtitle: 'File ownership & stickies', passText: '18/18 pass', pct: 100 },
  ];

  const stagedRules = rules.filter((r) => r.stagedForFix);

  const filteredRules = rules.filter((r) => {
    if (selectedSection !== 'ALL' && r.sectionId !== selectedSection) return false;
    if (statusFilter === 'FAILED' && r.status === 'Passed') return false;
    if (statusFilter === 'PASSED' && r.status !== 'Passed') return false;
    if (statusFilter === 'MANUAL' && r.status !== 'Manual') return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        r.title.toLowerCase().includes(q) ||
        r.code.toLowerCase().includes(q) ||
        r.serviceTag.toLowerCase().includes(q) ||
        r.targetFile.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleDryRun = async () => {
    setCriticLoading(true);
    const summary = stagedRules
      .map((r) => `${r.code} (${r.targetFile}): ${r.diffAdded.join(', ')}`)
      .join('\n');
    const verdict = await runSafetyCriticAudit(summary);
    setCriticVerdict(verdict);
    setCriticLoading(false);
    notify('Adversarial Safety Critic verified all staged CIS diffs.');
  };

  const handleExportReport = () => {
    const htmlReport = `# SentryLinux CIS Ubuntu 24.04 LTS Audit Report\nSnapshot: #${snapshotId}\n\n` +
      rules.map((r) => `- [${r.status === 'Passed' ? 'x' : ' '}] ${r.code}: ${r.title} (${r.currentValue})`).join('\n');
    const blob = new Blob([htmlReport], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SentryLinux-CIS-Audit-${snapshotId}.md`;
    a.click();
    URL.revokeObjectURL(url);
    notify('Exported CIS Benchmark Compliance Report.');
  };

  const handleTriggerUsgScan = () => {
    setScanningUsg(true);
    window.setTimeout(() => {
      onRunFullUsgScan();
      setScanningUsg(false);
      notify('Completed full USG 24.04.1 + Lynis 3.1.2 compliance evaluation.');
    }, 1000);
  };

  return (
    <div className="flex flex-col w-full gap-space-lg select-text">
      {toast && (
        <div className="fixed bottom-5 right-6 z-50 px-4 py-2.5 rounded-xl bg-surface-container-high border border-tertiary/40 text-on-surface shadow-2xl flex items-center gap-2 font-code-sm text-code-sm">
          <MaterialIcon name="verified" className="text-tertiary text-[18px]" />
          <span>{toast}</span>
        </div>
      )}

      {/* Sub-Header & Libadwaita Control Bar */}
      <div className="flex flex-wrap items-center justify-between gap-space-md bg-surface-container-low/80 backdrop-blur-md p-space-md rounded-xl border border-[#363243] shadow-sm">
        <div className="flex flex-col gap-0.5">
          <div className="flex items-center gap-space-xs text-on-surface-variant">
            <span className="font-label-sm text-label-sm uppercase tracking-wider">
              Compliance & Hardening
            </span>
            <MaterialIcon name="chevron_right" className="text-[14px]" />
            <span className="font-code-sm text-code-sm text-primary">
              USG & Lynis CIS Benchmark
            </span>
          </div>
          <div className="flex items-center gap-space-md mt-1 flex-wrap">
            <div className="flex items-center gap-space-xs bg-surface-container px-space-md py-1.5 rounded-lg shadow-inner">
              <MaterialIcon name="verified" className="text-[16px] text-tertiary" />
              <span className="font-title-sm text-title-sm text-on-surface">
                CIS Ubuntu 24.04 LTS Server/Workstation v1.0.0 — Level {hardeningProfileLevel}
              </span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1 rounded-lg bg-surface-container">
              <span className="font-label-sm text-label-sm text-on-surface-variant">
                Profile Slider:
              </span>
              <input
                type="range"
                min={1}
                max={3}
                step={1}
                value={hardeningProfileLevel}
                onChange={(e) => setHardeningProfileLevel(Number(e.target.value))}
                className="w-24 accent-primary-container cursor-pointer"
                aria-label="Hardening profile level"
              />
              <span className="font-code-sm text-code-sm text-tertiary font-semibold">
                {hardeningProfileLevel === 1
                  ? 'Dev Friendly'
                  : hardeningProfileLevel === 2
                    ? 'CIS Level 2'
                    : 'Strict Lockdown'}
              </span>
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-space-xs flex-wrap">
          <Tooltip explainerKey="snapshot-etc">
            <button
              type="button"
              onClick={() => {
                onRevertSnapshot();
                notify(`Reverted /etc configuration tree to atomic snapshot #${snapshotId}.`);
              }}
              className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-colors shadow-sm"
            >
              <MaterialIcon name="history" className="text-[16px] text-on-surface-variant" />
              <span className="font-label-md text-label-md">
                Revert Snapshot (<span className="font-code-sm text-primary">#{snapshotId}</span>)
              </span>
            </button>
          </Tooltip>
          <button
            type="button"
            onClick={handleExportReport}
            className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-colors shadow-sm"
          >
            <MaterialIcon name="picture_as_pdf" className="text-[16px]" />
            <span className="font-label-md text-label-md">Generate Report</span>
          </button>
          <button
            type="button"
            disabled={scanningUsg}
            onClick={handleTriggerUsgScan}
            className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 transition-all font-semibold shadow-md"
          >
            <MaterialIcon
              name={scanningUsg ? 'sync' : 'play_arrow'}
              className={`text-[18px] ${scanningUsg ? 'animate-spin' : ''}`}
            />
            <span className="font-title-sm text-title-sm">
              {scanningUsg ? 'Auditing USG...' : 'Run Full USG Scan'}
            </span>
          </button>
        </div>
      </div>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="usg-and-lynis-cis-audit"
        onExecuteRecommendedAction={handleDryRun}
        customActionLabel="Run Safety Critic & Apply Staged Fixes"
        defaultExpanded={false}
      />

      {/* 3-Column Cockpit Grid: Categories Rail, Rules Checklist, Atomic Diff Drawer */}
      <div className="grid grid-cols-12 gap-space-lg items-start">
        {/* Column 1: CIS Benchmark Sections Rail (Span 3) */}
        <div className="col-span-12 xl:col-span-3 flex flex-col gap-space-md">
          <div className="bg-surface-container-low/90 backdrop-blur-md rounded-xl p-space-md border border-[#363243] flex flex-col gap-space-sm shadow-md">
            <div className="flex items-center justify-between pb-space-xs">
              <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
                CIS Domain Sections
              </span>
              <button
                type="button"
                onClick={() => setSelectedSection('ALL')}
                className="font-code-sm text-code-sm text-tertiary hover:underline"
              >
                Show All (6)
              </button>
            </div>
            {domainSections.map((sec) => {
              const isSelected = selectedSection === sec.id;
              return (
                <div
                  key={sec.id}
                  onClick={() =>
                    setSelectedSection(selectedSection === sec.id ? 'ALL' : sec.id)
                  }
                  className={`p-space-sm rounded-lg transition-colors cursor-pointer flex flex-col gap-1 relative overflow-hidden ${
                    isSelected
                      ? 'bg-surface-container-high/90 shadow-inner'
                      : 'hover:bg-surface-container'
                  }`}
                >
                  {isSelected && (
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-primary-container" />
                  )}
                  <div className="flex items-center justify-between pl-1">
                    <span className="font-title-sm text-title-sm text-on-surface truncate">
                      {sec.title}
                    </span>
                    <span className="font-code-sm text-code-sm text-tertiary font-bold">
                      {sec.pct}%
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-on-surface-variant font-code-sm text-code-sm pl-1">
                    <span>{sec.subtitle}</span>
                    <span>{sec.passText}</span>
                  </div>
                  <div className="w-full bg-surface-container-highest h-1.5 rounded-full overflow-hidden mt-0.5">
                    <div
                      className="bg-tertiary h-full rounded-full"
                      style={{ width: `${sec.pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Hardening Score Ring Card */}
          <div className="bg-surface-container-low/90 backdrop-blur-md rounded-xl p-space-md border border-[#363243] flex flex-col gap-space-sm shadow-md">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Lynis & USG Summary
            </span>
            <div className="flex items-center justify-between gap-space-md">
              <div className="flex flex-col">
                <div className="flex items-baseline gap-1">
                  <span className="font-display-lg text-display-lg font-bold text-on-surface tabular-nums">
                    {rules.filter((r) => r.status === 'Passed').length * 4 + 64}
                  </span>
                  <span className="font-title-sm text-title-sm text-on-surface-variant">/100</span>
                </div>
                <span className="font-label-sm text-label-sm text-on-surface-variant">
                  Lynis Hardening Index
                </span>
              </div>
              <div className="relative w-16 h-16 flex items-center justify-center shrink-0">
                <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                  <path
                    className="text-surface-container-highest"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="3.5"
                  />
                  <path
                    className="text-primary-container"
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke="currentColor"
                    strokeDasharray="84, 100"
                    strokeLinecap="round"
                    strokeWidth="3.5"
                  />
                </svg>
                <span className="absolute font-code-sm text-code-sm text-primary font-bold">
                  84
                </span>
              </div>
            </div>
            <div className="flex flex-col gap-space-xs pt-space-xs font-code-sm text-code-sm">
              <div className="flex items-center justify-between">
                <span className="text-on-surface-variant">USG Ubuntu Baseline</span>
                <span className="text-tertiary font-semibold">91.2%</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-on-surface-variant">Staged Remediations</span>
                <span className="px-space-xs py-0.5 rounded bg-primary-container/30 text-primary font-medium">
                  {stagedRules.length} Items
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-on-surface-variant">Audit Tooling</span>
                <span className="text-on-surface">usg 24.04.1 + lynis 3.1.2</span>
              </div>
            </div>
          </div>
        </div>

        {/* Column 2: Center Compliance Rules Checklist (Span 5) */}
        <div className="col-span-12 xl:col-span-5 flex flex-col gap-space-md">
          <div className="bg-surface-container-low/90 backdrop-blur-md rounded-xl p-space-md border border-[#363243] flex flex-col gap-space-sm shadow-md">
            <div className="relative w-full">
              <MaterialIcon
                name="search"
                className="absolute left-3 top-2.5 text-[18px] text-on-surface-variant"
              />
              <input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-surface-container-lowest/80 text-on-surface font-body-md text-body-md pl-9 pr-16 py-2 rounded-lg border border-[#363243] focus:outline-none focus:ring-1 focus:ring-primary-container placeholder:text-on-surface-variant/50 transition-all"
                placeholder="Filter rules, CVEs, or sysctl keys..."
                type="text"
              />
              <span className="absolute right-3 top-2.5 font-code-sm text-code-sm text-on-surface-variant px-1 rounded bg-surface-container-high">
                Ctrl+F
              </span>
            </div>
            <div className="flex items-center gap-space-xs overflow-x-auto pb-0.5">
              {[
                { id: 'ALL', label: `All (${rules.length})` },
                {
                  id: 'FAILED',
                  label: `Failed / Queued (${rules.filter((r) => r.status !== 'Passed').length})`,
                },
                {
                  id: 'PASSED',
                  label: `Passed (${rules.filter((r) => r.status === 'Passed').length})`,
                },
              ].map((pill) => (
                <button
                  key={pill.id}
                  type="button"
                  onClick={() => setStatusFilter(pill.id as typeof statusFilter)}
                  className={`px-space-sm py-1 rounded-full font-label-sm text-label-sm whitespace-nowrap transition-colors ${
                    statusFilter === pill.id
                      ? 'bg-primary-container text-white font-semibold'
                      : 'bg-surface-container-high text-on-surface-variant hover:text-on-surface'
                  }`}
                >
                  {pill.label}
                </button>
              ))}
            </div>
          </div>

          {/* Itemized Rules List */}
          <div className="flex flex-col gap-space-sm">
            {filteredRules.map((rule) => {
              const isExpanded = expandedAiRuleId === rule.id;
              return (
                <div
                  key={rule.id}
                  className="bg-surface-container-low/95 rounded-xl p-space-md border border-[#363243] shadow-sm flex flex-col gap-space-sm relative overflow-hidden"
                >
                  <div
                    className={`absolute left-0 top-0 bottom-0 w-1 ${
                      rule.status === 'Passed'
                        ? 'bg-tertiary'
                        : rule.stagedForFix
                          ? 'bg-primary-container'
                          : 'bg-error'
                    }`}
                  />
                  <div className="flex items-start justify-between gap-space-sm pl-1">
                    <div className="flex flex-col gap-0.5">
                      <div className="flex items-center gap-space-xs flex-wrap">
                        <span className="font-code-sm text-code-sm text-primary font-bold">
                          {rule.code}
                        </span>
                        <span
                          className={`px-space-xs py-0.5 rounded font-label-sm text-label-sm ${
                            rule.status === 'Passed'
                              ? 'bg-tertiary/15 text-tertiary'
                              : 'bg-error-container/80 text-on-error-container'
                          }`}
                        >
                          {rule.status === 'Passed' ? 'PASS' : rule.risk}
                        </span>
                        <span className="px-space-xs py-0.5 rounded bg-surface-container-high text-on-surface-variant font-code-sm text-code-sm">
                          {rule.serviceTag}
                        </span>
                      </div>
                      <h3 className="font-title-sm text-title-sm text-on-surface mt-0.5">
                        {rule.title}
                      </h3>
                    </div>

                    {rule.status !== 'Passed' ? (
                      <GnomeSwitch
                        checked={rule.stagedForFix}
                        onChange={() => onToggleRuleStage(rule.id)}
                        label="Stage Fix"
                        ariaLabel={`Stage fix for ${rule.code}`}
                      />
                    ) : (
                      <span className="font-code-sm text-code-sm text-tertiary flex items-center gap-1 shrink-0">
                        <MaterialIcon name="check_circle" className="text-[15px]" />
                        Compliant
                      </span>
                    )}
                  </div>

                  <div className="bg-surface-container-lowest/80 rounded-lg p-space-xs font-code-sm text-code-sm flex items-center justify-between text-on-surface-variant pl-2 flex-wrap gap-2">
                    <span>
                      Current:{' '}
                      <span
                        className={rule.status === 'Passed' ? 'text-tertiary' : 'text-error'}
                      >
                        {rule.currentValue}
                      </span>
                    </span>
                    <span>
                      Target: <span className="text-tertiary">{rule.targetValue}</span>
                    </span>
                  </div>

                  <div className="flex items-center justify-between pl-1 pt-1">
                    <button
                      type="button"
                      onClick={() =>
                        setExpandedAiRuleId(isExpanded ? null : rule.id)
                      }
                      className="flex items-center gap-space-xs px-space-sm py-1 rounded-md bg-secondary-container/30 hover:bg-secondary-container/50 text-secondary transition-colors"
                    >
                      <MaterialIcon name="auto_awesome" className="text-[14px]" />
                      <span className="font-label-sm text-label-sm font-semibold">
                        {isExpanded ? 'Hide AI Explanation' : 'AI: Explain Threat & Recommend Action'}
                      </span>
                    </button>
                    <span className="font-code-sm text-code-sm text-on-surface-variant">
                      {rule.targetFile}
                    </span>
                  </div>

                  {isExpanded && (
                    <div className="mt-2 p-3 rounded-xl bg-surface-container border border-secondary/40 flex flex-col gap-2.5 animate-in fade-in">
                      <div className="flex items-center gap-1.5 text-secondary font-title-sm text-[12px] font-bold uppercase font-code-sm">
                        <MaterialIcon name="psychology" className="text-[16px]" />
                        <span>AI Plain-English Threat & Remediation Guide</span>
                      </div>
                      
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[12px]">
                        <div className="p-2.5 rounded-lg bg-surface-container-low border border-white/5">
                          <span className="font-bold text-on-surface block mb-1">1. What this checks:</span>
                          <span className="text-on-surface-variant leading-relaxed">
                            {rule.title}. Currently set to <code className="text-error">{rule.currentValue}</code>.
                          </span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-surface-container-low border border-error/20">
                          <span className="font-bold text-error block mb-1">2. Where threat comes from:</span>
                          <span className="text-on-surface-variant leading-relaxed">
                            Hackers scan for default unhardened settings in <code className="text-on-surface">{rule.targetFile}</code> to bypass authentication or gain root privileges.
                          </span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-surface-container-low border border-tertiary/20 flex flex-col justify-between">
                          <div>
                            <span className="font-bold text-tertiary block mb-1">3. How to handle it:</span>
                            <span className="text-on-surface-variant leading-relaxed">
                              {rule.aiVulnerabilityExplanation}
                            </span>
                          </div>
                          {rule.status !== 'Passed' && (
                            <button
                              type="button"
                              onClick={() => onToggleRuleStage(rule.id)}
                              className="mt-2 py-1 px-2 rounded bg-primary text-white text-[11px] font-semibold hover:brightness-110 flex items-center justify-center gap-1"
                            >
                              <MaterialIcon name="tune" className="text-[13px]" />
                              <span>{rule.stagedForFix ? 'Unstage Fix' : 'Stage AI Fix Now'}</span>
                            </button>
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Column 3: Interactive 'Review & Apply Diff' Drawer / Panel (Span 4) */}
        <div className="col-span-12 xl:col-span-4 flex flex-col gap-space-md sticky top-20">
          <div className="bg-surface-container-low/95 backdrop-blur-md rounded-xl p-space-md border border-[#363243] flex flex-col gap-space-md shadow-xl">
            <div className="flex items-center justify-between pb-space-xs">
              <div className="flex items-center gap-space-xs">
                <MaterialIcon name="difference" className="text-primary text-[20px]" />
                <span className="font-title-sm text-title-sm text-on-surface font-semibold">
                  Atomic Remediation Staging
                </span>
              </div>
              <span className="px-space-xs py-0.5 rounded-full bg-primary-container/20 text-primary font-code-sm text-code-sm">
                {stagedRules.length} Queued
              </span>
            </div>
            <p className="font-body-md text-body-md text-on-surface-variant -mt-1">
              Review generated configuration diffs before invoking Polkit authentication. Atomic
              commit writes with rollback journaling.
            </p>

            <div className="flex flex-col gap-space-sm max-h-80 overflow-y-auto">
              {stagedRules.length === 0 ? (
                <div className="p-4 rounded-lg bg-surface-container-lowest text-center font-code-sm text-code-sm text-on-surface-variant">
                  All selected CIS rules are compliant or un-staged. Toggle a rule to preview its
                  diff.
                </div>
              ) : (
                stagedRules.map((sr) => (
                  <CodeViewer
                    key={sr.id}
                    filePath={sr.targetFile}
                    removedLines={sr.diffRemoved}
                    addedLines={sr.diffAdded}
                  />
                ))
              )}
            </div>

            {/* Dual-Model Safety Critic Gate */}
            <div className="p-space-sm rounded-lg bg-surface-container border border-secondary/30 flex flex-col gap-1.5 shadow-sm">
              <div className="flex items-center justify-between">
                <Tooltip explainerKey="safety-critic">
                  <div className="flex items-center gap-space-xs text-secondary cursor-help">
                    <MaterialIcon name="auto_awesome" className="text-[18px]" />
                    <span className="font-title-sm text-title-sm font-semibold">
                      Adversarial Safety Critic Gate
                    </span>
                  </div>
                </Tooltip>
                {criticVerdict && (
                  <span className="px-1.5 py-0.5 rounded bg-tertiary/15 text-tertiary font-code-sm text-[10px] font-bold">
                    APPROVED
                  </span>
                )}
              </div>
              <p className="font-code-sm text-code-sm text-on-surface leading-relaxed">
                {criticVerdict
                  ? criticVerdict.summary
                  : `Staged diffs will be committed to atomic branch #${snapshotId} after verifying zero SSH/PAM lockouts.`}
              </p>
            </div>

            <div className="flex flex-col gap-space-sm pt-space-xs">
              <div className="flex items-center gap-space-xs">
                <button
                  type="button"
                  disabled={criticLoading || stagedRules.length === 0}
                  onClick={handleDryRun}
                  className="w-1/2 py-2 px-space-sm rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-title-sm text-title-sm transition-colors text-center shadow-sm disabled:opacity-50"
                >
                  {criticLoading ? 'Auditing...' : 'Simulate Dry-Run'}
                </button>
                <button
                  type="button"
                  disabled={stagedRules.length === 0}
                  onClick={() => {
                    onApplyStagedFixes();
                    notify(
                      `Applied ${stagedRules.length} CIS remediations via single Polkit batch transaction.`,
                    );
                  }}
                  className="w-1/2 py-2 px-space-sm rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 font-title-sm text-title-sm font-semibold transition-all flex items-center justify-center gap-1 shadow-md disabled:opacity-50"
                >
                  <MaterialIcon name="security" className="text-[18px]" />
                  <span>Apply Fixes</span>
                </button>
              </div>
              <div className="flex items-center gap-space-xs text-on-surface-variant text-[11px] font-label-sm">
                <MaterialIcon name="restore" className="text-[14px] text-tertiary" />
                <span>
                  Snapshot Safety: Automatic Btrfs & Git checkpoint #{snapshotId} armed prior to
                  disk write.
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// SCREEN 5: Malware & Rootkit Sweep Console
// ============================================================================
interface MalwareSweepDeckProps {
  findings: SweepFinding[];
  onHealFinding: (id: string) => void;
  onPurgeFinding: (id: string) => void;
  onNavigateQuarantine: () => void;
}

export const MalwareSweepDeck: React.FC<MalwareSweepDeckProps> = ({
  findings,
  onHealFinding,
  onPurgeFinding,
  onNavigateQuarantine,
}) => {
  const [selectedFindingId, setSelectedFindingId] = useState<string>(findings[0]?.id ?? 'sw-1');
  const [filterTab, setFilterTab] = useState<'ALL' | 'QUARANTINED' | 'CHECKSUM'>('ALL');
  const [search, setSearch] = useState('');
  const [fanotifyActive, setFanotifyActive] = useState(true);
  const [sweeping, setSweeping] = useState(false);
  const [terminalLines, setTerminalLines] = useState<string[]>([
    '[14:18:02] freshclam: Database updated successfully (daily.cvd: 27210, main.cvd: 62). Signatures: 8,742,109',
    '[14:20:15] rkhunter: Checking system binaries for known signatures and hidden rootkit vectors...',
    '[14:20:44] rkhunter: Checking LKM modules and /proc table against sys_call_table... [PASS] No hooks found',
    '[14:21:40] debsums: Scanning 1,420 deb-installed packages via md5sums registry...',
    "[14:21:48] debsums: [WARN] Checksum mismatch in package 'coreutils': /usr/bin/dir",
    '[14:22:04] clamscan: Real-time Fanotify triggered on /tmp/.x11-unix/.cache/srv_mon',
    '[14:22:04] [ALERT] clamscan: /tmp/.x11-unix/.cache/srv_mon: Unix.Trojan.Mirai-1002 FOUND',
    '[14:22:05] sentry-daemon: Isolating inode #91823 -> /var/lib/sentry/quarantine/91823.isolated (chmod 0000 +i)',
  ]);

  const selectedFinding =
    findings.find((f) => f.id === selectedFindingId) || findings[0];

  const appendLog = (line: string) => {
    const ts = new Date().toTimeString().split(' ')[0];
    setTerminalLines((prev) => [...prev, `[${ts}] ${line}`]);
  };

  const handleRunSweep = () => {
    setSweeping(true);
    appendLog(
      'sentry-orchestrator: Initiated multi-engine sweep (ClamAV + LMD + RKhunter + Debsums) on /bin, /usr/bin, /tmp...',
    );
    window.setTimeout(() => {
      appendLog(
        'sentry-orchestrator: Stage 1 (debsums -c) & Stage 2 (Gemini 4 Carbon rootkit hook check) completed in 0.84s.',
      );
      setSweeping(false);
    }, 900);
  };

  const visibleFindings = findings.filter((f) => {
    if (filterTab === 'QUARANTINED' && f.status !== 'Quarantined') return false;
    if (filterTab === 'CHECKSUM' && f.category !== 'Checksum Anomaly') return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        f.name.toLowerCase().includes(q) ||
        f.path.toLowerCase().includes(q) ||
        f.sha256.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="flex flex-col w-full gap-space-lg select-text">
      {/* Sub-Header / Action Strip */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md">
        <div className="flex flex-col gap-space-xs">
          <div className="flex items-center gap-space-xs text-on-surface-variant font-code-sm text-code-sm">
            <span>HARDENING & COMPLIANCE</span>
            <span>/</span>
            <span className="text-primary font-medium">MALWARE & ROOTKIT SWEEP</span>
          </div>
          <div className="flex flex-wrap items-center gap-space-xs pt-0.5">
            <span className="inline-flex items-center gap-1.5 px-space-sm py-0.5 rounded-full bg-surface-container-high text-tertiary font-code-sm text-code-sm">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary animate-pulse" />
              ClamAV 1.3.1 (daily.cvd #27210)
            </span>
            <span className="inline-flex items-center gap-1.5 px-space-sm py-0.5 rounded-full bg-surface-container-high text-on-surface font-code-sm text-code-sm">
              <MaterialIcon name="check_circle" className="text-[12px] text-tertiary" />
              RKhunter 1.4.6 (Hashes verified)
            </span>
            <span className="inline-flex items-center gap-1.5 px-space-sm py-0.5 rounded-full bg-surface-container-high text-on-surface font-code-sm text-code-sm">
              <MaterialIcon name="inventory_2" className="text-[12px] text-tertiary" />
              Debsums 3.0.2 (dpkg md5)
            </span>
            <span className="inline-flex items-center gap-1.5 px-space-sm py-0.5 rounded-full bg-surface-container-high text-on-surface font-code-sm text-code-sm">
              <MaterialIcon name="security" className="text-[12px] text-tertiary" />
              LMD v1.6.5
            </span>
          </div>
        </div>

        <div className="flex items-center gap-space-sm flex-wrap">
          <button
            type="button"
            onClick={onNavigateQuarantine}
            className="relative flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-label-md text-label-md transition-colors border border-[#363243]"
          >
            <MaterialIcon name="folder_supervised" className="text-[16px] text-primary" />
            <span>Quarantine Vault ({findings.filter((f) => f.status === 'Quarantined').length})</span>
          </button>
          <button
            type="button"
            onClick={() =>
              appendLog('freshclam: Checked mirrors; daily.cvd #27210 is already up to date.')
            }
            className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container hover:bg-surface-container-high text-on-surface font-label-md text-label-md transition-colors border border-[#363243]"
          >
            <MaterialIcon name="sync" className="text-[16px]" />
            <span>freshclam Signatures</span>
          </button>
          <button
            type="button"
            disabled={sweeping}
            onClick={handleRunSweep}
            className="flex items-center gap-space-xs px-space-lg py-2 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 font-label-md text-label-md font-semibold transition-all shadow-md"
          >
            <MaterialIcon
              name="radar"
              className={`text-[18px] ${sweeping ? 'animate-spin' : ''}`}
            />
            <span>{sweeping ? 'Running Multi-Engine Sweep...' : 'Start Multi-Engine Sweep'}</span>
          </button>
        </div>
      </div>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="malware-and-sweep"
        onExecuteRecommendedAction={handleRunSweep}
        customActionLabel="Start Two-Stage Deep Scan & Heal"
        defaultExpanded={false}
      />

      {/* Sweep Telemetry & Heuristics Hero Card */}
      <div className="rounded-xl bg-surface-container border border-[#363243] p-space-lg shadow-md">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-space-md mb-space-md">
          <div className="flex items-center gap-space-md">
            <div className="w-12 h-12 rounded-xl bg-surface-container-highest flex items-center justify-center text-primary-container shadow-inner">
              <MaterialIcon name="biotech" className="text-[28px]" />
            </div>
            <div>
              <div className="flex items-center gap-space-xs flex-wrap">
                <span className="font-headline-md text-headline-md text-on-surface">
                  Two-Stage Rootkit & Malware Double-Check Sweep
                </span>
                <span className="px-space-xs py-0.5 rounded bg-tertiary-container text-on-tertiary-container font-code-sm text-code-sm uppercase">
                  Nominal eBPF
                </span>
              </div>
              <span className="font-code-sm text-code-sm text-on-surface-variant">
                Stage 1: Canonical Debsums GPG Manifests • Stage 2: Gemini 4 Carbon Backport vs Hook
                Forensics
              </span>
            </div>
          </div>
          <div className="flex items-center gap-space-lg">
            <div className="text-right">
              <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant block">
                Integrity Index
              </span>
              <span className="font-display-lg text-display-lg text-tertiary font-bold leading-tight tabular-nums">
                98.4%
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-space-sm">
          <div className="p-space-md rounded-lg bg-surface-container-low flex flex-col justify-between">
            <span className="font-label-sm text-label-sm text-on-surface-variant">
              Scanned Objects
            </span>
            <div className="flex items-baseline gap-space-xs mt-1">
              <span className="font-headline-lg text-headline-lg text-on-surface font-bold tabular-nums">
                482,914
              </span>
              <span className="font-code-sm text-code-sm text-on-surface-variant">files & pkgs</span>
            </div>
            <span className="font-code-sm text-code-sm text-tertiary mt-1">2,420 obj/sec</span>
          </div>
          <div className="p-space-md rounded-lg bg-surface-container-low flex flex-col justify-between">
            <span className="font-label-sm text-label-sm text-error">Infected / Flagged</span>
            <div className="flex items-baseline gap-space-xs mt-1">
              <span className="font-headline-lg text-headline-lg text-error font-bold tabular-nums">
                {findings.filter((f) => f.status === 'Active' || f.status === 'Quarantined').length}
              </span>
              <span className="font-code-sm text-code-sm text-error">Anomalies</span>
            </div>
            <span className="font-code-sm text-code-sm text-on-surface-variant mt-1">
              1 Trojan • 1 Debsum Diff
            </span>
          </div>
          <div className="p-space-md rounded-lg bg-surface-container-low flex flex-col justify-between">
            <span className="font-label-sm text-label-sm text-on-surface-variant">
              Active Kernel Hooks
            </span>
            <div className="flex items-baseline gap-space-xs mt-1">
              <span className="font-headline-lg text-headline-lg text-tertiary font-bold tabular-nums">
                0
              </span>
              <span className="font-code-sm text-code-sm text-tertiary">Clean</span>
            </div>
            <span className="font-code-sm text-code-sm text-on-surface-variant mt-1">
              No LKM rootkits found
            </span>
          </div>
          <div className="p-space-md rounded-lg bg-surface-container-low flex flex-col justify-between">
            <span className="font-label-sm text-label-sm text-on-surface-variant">
              Package Checksums
            </span>
            <div className="flex items-baseline gap-space-xs mt-1">
              <span className="font-headline-lg text-headline-lg text-primary font-bold tabular-nums">
                {findings.some((f) => f.status === 'Active') ? '1,419/1,420' : '1,420/1,420'}
              </span>
            </div>
            <span className="font-code-sm text-code-sm text-primary mt-1">
              {findings.some((f) => f.status === 'Active')
                ? '1 mismatch in coreutils'
                : 'All packages healed'}
            </span>
          </div>
        </div>
      </div>

      {/* 3-Column Engine Architecture Status Strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
        <div className="p-space-md rounded-xl bg-surface-container border border-[#363243] flex flex-col justify-between shadow-sm">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-space-sm">
              <MaterialIcon name="bug_report" className="text-[20px] text-tertiary" />
              <div>
                <span className="font-title-sm text-title-sm text-on-surface block">
                  ClamAV & LMD
                </span>
                <span className="font-code-sm text-code-sm text-on-surface-variant">
                  clamd (daemonized PID 894)
                </span>
              </div>
            </div>
            <span className="px-space-xs py-0.5 rounded bg-tertiary-container text-on-tertiary-container font-code-sm text-code-sm">
              Active
            </span>
          </div>
          <div className="my-space-md flex flex-col gap-1 font-code-sm text-code-sm">
            <div className="flex justify-between">
              <span className="text-on-surface-variant">Signature Database:</span>
              <span className="text-on-surface">8,742,109 hashes</span>
            </div>
            <div className="flex justify-between">
              <span className="text-on-surface-variant">Hot Ingestion Paths:</span>
              <span className="text-tertiary">~/Downloads, /tmp</span>
            </div>
          </div>
          <div className="flex items-center justify-between bg-surface-container-low p-2 rounded-lg">
            <span className="font-label-sm text-label-sm text-on-surface">
              Fanotify On-Access Hook
            </span>
            <GnomeSwitch
              checked={fanotifyActive}
              onChange={setFanotifyActive}
              ariaLabel="Toggle fanotify on-access malware scanning"
            />
          </div>
        </div>

        <div className="p-space-md rounded-xl bg-surface-container border border-[#363243] flex flex-col justify-between shadow-sm">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-space-sm">
              <MaterialIcon name="shield" className="text-[20px] text-secondary" />
              <div>
                <span className="font-title-sm text-title-sm text-on-surface block">
                  RKhunter & chkrootkit
                </span>
                <span className="font-code-sm text-code-sm text-on-surface-variant">
                  DPkg::Post-Invoke --propupd
                </span>
              </div>
            </div>
            <span className="px-space-xs py-0.5 rounded bg-tertiary-container text-on-tertiary-container font-code-sm text-code-sm">
              Nominal
            </span>
          </div>
          <div className="my-space-md flex flex-col gap-1 font-code-sm text-code-sm">
            <div className="flex justify-between">
              <span className="text-on-surface-variant">Hidden Process Check:</span>
              <span className="text-tertiary">0 Hidden PIDs</span>
            </div>
            <div className="flex justify-between">
              <span className="text-on-surface-variant">Kernel Module Taint:</span>
              <span className="text-tertiary">Zero Unsigned LKMs</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() =>
              appendLog(
                'rkhunter: Deep Clean sequence finished. 0 hidden processes or LKM hooks found.',
              )
            }
            className="w-full py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-label-md text-label-md transition-colors flex items-center justify-center gap-1"
          >
            <MaterialIcon name="refresh" className="text-[14px]" />
            <span>Re-run Rootkit Test</span>
          </button>
        </div>

        <div className="p-space-md rounded-xl bg-surface-container border border-[#363243] flex flex-col justify-between shadow-sm">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-space-sm">
              <MaterialIcon name="verified" className="text-[20px] text-primary" />
              <div>
                <span className="font-title-sm text-title-sm text-on-surface block">
                  Debsums Package Healer
                </span>
                <span className="font-code-sm text-code-sm text-on-surface-variant">
                  Canonical Mirrors Checked
                </span>
              </div>
            </div>
            <span className="px-space-xs py-0.5 rounded bg-primary-container/20 text-primary font-code-sm text-code-sm font-semibold">
              apt --reinstall
            </span>
          </div>
          <div className="my-space-md flex flex-col gap-1 font-code-sm text-code-sm">
            <div className="flex justify-between">
              <span className="text-on-surface-variant">Installed Debs Total:</span>
              <span className="text-on-surface">1,420 Packages</span>
            </div>
            <div className="flex justify-between">
              <span className="text-on-surface-variant">Signature Validity:</span>
              <span className="text-tertiary">Valid GPG Keyrings</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => {
              onHealFinding('sw-2');
              appendLog(
                'apt-get install --reinstall coreutils: Restored verified Canonical binary /usr/bin/dir.',
              );
            }}
            className="w-full py-1.5 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 font-label-md text-label-md font-semibold transition-colors flex items-center justify-center gap-1"
          >
            <MaterialIcon name="build" className="text-[14px]" />
            <span>Heal Tampered Package (coreutils)</span>
          </button>
        </div>
      </div>

      {/* Flagged Findings & Gemini Forensic Split Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-space-lg">
        <div className="xl:col-span-7 flex flex-col gap-space-sm bg-surface-container border border-[#363243] rounded-xl p-space-md shadow-md">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-space-sm pb-space-xs">
            <div className="flex items-center gap-space-xs flex-wrap">
              {[
                { id: 'ALL', label: `All Detections (${findings.length})` },
                { id: 'QUARANTINED', label: 'Quarantined' },
                { id: 'CHECKSUM', label: 'Checksum Anomalies' },
              ].map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setFilterTab(t.id as typeof filterTab)}
                  className={`px-space-sm py-1 rounded font-label-md text-label-md transition-colors ${
                    filterTab === t.id
                      ? 'bg-surface-container-highest text-on-surface font-semibold'
                      : 'text-on-surface-variant hover:text-on-surface'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="px-3 py-1 rounded bg-surface-container-lowest border border-[#363243] text-on-surface font-code-sm text-code-sm"
              placeholder="Filter by hash, path..."
              type="text"
            />
          </div>

          <div className="overflow-x-auto rounded-lg bg-surface-container-low">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-surface-container-high/60 text-on-surface-variant font-label-sm text-label-sm uppercase tracking-wider">
                  <th className="py-2.5 px-space-md">Severity / Threat</th>
                  <th className="py-2.5 px-space-md">Target File & Package</th>
                  <th className="py-2.5 px-space-md">Engine</th>
                  <th className="py-2.5 px-space-md text-right">Status</th>
                </tr>
              </thead>
              <tbody className="font-body-md text-body-md text-on-surface divide-y divide-white/5">
                {visibleFindings.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    className={`cursor-pointer transition-colors ${
                      selectedFinding?.id === f.id
                        ? 'bg-surface-container-highest/50'
                        : 'hover:bg-surface-container-highest/30'
                    }`}
                  >
                    <td className="py-3 px-space-md">
                      <span
                        className={`inline-flex items-center gap-1 px-space-xs py-0.5 rounded font-code-sm text-[10px] font-semibold ${
                          f.severity === 'Critical'
                            ? 'bg-error-container text-on-error-container'
                            : 'bg-surface-container-highest text-primary'
                        }`}
                      >
                        {f.category}
                      </span>
                      <span className="block font-title-sm text-title-sm text-on-surface mt-1">
                        {f.name}
                      </span>
                    </td>
                    <td className="py-3 px-space-md font-code-sm text-code-sm">
                      <div className="text-primary">{f.path}</div>
                      <div className="text-[10px] text-on-surface-variant">{f.packageOwner}</div>
                    </td>
                    <td className="py-3 px-space-md font-code-sm text-code-sm">{f.engine}</td>
                    <td className="py-3 px-space-md text-right font-code-sm text-code-sm">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                          f.status === 'Healed' || f.status === 'Verified Backport'
                            ? 'bg-tertiary/15 text-tertiary'
                            : 'bg-error-container text-on-error-container'
                        }`}
                      >
                        {f.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Gemini Forensic & Two-Stage Rootkit Triage Panel (Right / 5 cols) */}
        {selectedFinding && (
          <div className="xl:col-span-5 flex flex-col justify-between bg-surface-container border border-[#363243] rounded-xl p-space-md shadow-md">
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-space-xs">
                  <MaterialIcon name="psychology" className="text-[20px] text-secondary" />
                  <span className="font-headline-md text-headline-md text-on-surface">
                    Two-Stage Rootkit Forensics
                  </span>
                </div>
                <span className="px-space-xs py-0.5 rounded bg-secondary-container text-on-secondary-container font-code-sm text-code-sm">
                  Gemini 4 Carbon
                </span>
              </div>

              <div className="p-space-sm rounded-lg bg-surface-container-low font-code-sm text-code-sm">
                <div className="text-on-surface-variant">TARGET PATH</div>
                <div className="text-primary font-semibold">{selectedFinding.path}</div>
                <div className="text-on-surface-variant text-[10px] mt-1">
                  Stage 1 (debsums -c): {selectedFinding.stage1DebsumsResult}
                </div>
              </div>

              <div className="p-space-md rounded-lg bg-surface-container-high/60 space-y-1">
                <div className="flex items-center gap-1 text-secondary font-title-sm text-title-sm font-semibold">
                  <MaterialIcon name="auto_awesome" className="text-[16px]" />
                  <span>Stage 2 Forensic Correlation</span>
                </div>
                <p className="font-code-sm text-code-sm text-on-surface leading-relaxed">
                  {selectedFinding.stage2GeminiForensics}
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-space-xs pt-space-md">
              <button
                type="button"
                onClick={() => {
                  onPurgeFinding(selectedFinding.id);
                  appendLog(
                    `polkitd: Purged ${selectedFinding.path} and cleaned associated persistence hooks.`,
                  );
                }}
                className="w-full py-2 px-space-md rounded-lg bg-error-container hover:bg-error text-on-error-container font-label-md text-label-md font-semibold transition-colors flex items-center justify-center gap-space-xs"
              >
                <MaterialIcon name="delete_sweep" className="text-[18px]" />
                <span>Purge Inode & Clean Crontab (Polkit Auth)</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  onHealFinding(selectedFinding.id);
                  appendLog(
                    `apt-get install --reinstall: Healed ${selectedFinding.path} from verified Canonical mirror.`,
                  );
                }}
                className="w-full py-1.5 px-space-sm rounded-lg bg-surface-container-high hover:bg-surface-bright text-tertiary font-label-md text-label-md transition-colors flex items-center justify-center gap-1"
              >
                <MaterialIcon name="healing" className="text-[16px]" />
                <span>Heal Package via Debsums Reinstall</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Real-time Telemetry & Terminal Drawer */}
      <div className="rounded-xl bg-surface-container border border-[#363243] overflow-hidden shadow-lg flex flex-col">
        <div className="flex items-center justify-between px-space-md py-2 bg-surface-container-high">
          <div className="flex items-center gap-space-sm">
            <MaterialIcon name="terminal" className="text-[16px] text-primary" />
            <span className="font-code-sm text-code-sm text-on-surface font-medium">
              sentry-sweep.log — Telemetry Terminal Stream
            </span>
          </div>
          <button
            type="button"
            onClick={() => setTerminalLines(['[Log stream cleared. Watching fanotify queue...]'])}
            className="text-on-surface-variant hover:text-on-surface font-code-sm text-code-sm"
          >
            Clear Log
          </button>
        </div>
        <div className="p-space-md bg-surface-container-lowest font-code-sm text-code-sm text-on-surface leading-relaxed max-h-44 overflow-y-auto space-y-1">
          {terminalLines.map((line, idx) => (
            <div key={idx} className="text-on-surface-variant">
              {line}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// SCREEN 6: Daemon Restarts & needrestart Stale Memory Inspector
// ============================================================================
interface DaemonRestartsDeckProps {
  daemons: StaleDaemonItem[];
  onRestartDaemon: (id: string) => void;
  onRestartAllStale: () => void;
}

export const DaemonRestartsDeck: React.FC<DaemonRestartsDeckProps> = ({
  daemons,
  onRestartDaemon,
  onRestartAllStale,
}) => {
  const [scopeFilter, setScopeFilter] = useState<'ALL' | 'System' | 'Session'>('ALL');
  const [search, setSearch] = useState('');
  const [safeAutoRestart, setSafeAutoRestart] = useState(true);
  const [inspectedDaemon, setInspectedDaemon] = useState<StaleDaemonItem | null>(null);
  const [scanningMem, setScanningMem] = useState(false);

  const staleCount = daemons.filter((d) => d.status === 'Stale').length;
  const cleanlinessPct = staleCount === 0 ? 100 : Math.max(70, 100 - staleCount * 6);

  const filtered = daemons.filter((d) => {
    if (scopeFilter !== 'ALL' && d.scope !== scopeFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        d.unitName.toLowerCase().includes(q) ||
        d.supersededObject.toLowerCase().includes(q) ||
        String(d.pid).includes(q)
      );
    }
    return true;
  });

  return (
    <div className="flex flex-col w-full gap-space-lg select-text">
      {/* Top Breadcrumb & Engine Status Bar */}
      <div className="w-full flex flex-col xl:flex-row xl:items-center justify-between gap-space-md">
        <div className="flex flex-col gap-space-xs">
          <div className="flex items-center gap-space-xs text-on-surface-variant font-code-sm text-code-sm uppercase tracking-widest">
            <span>Hardening & Compliance</span>
            <MaterialIcon name="chevron_right" className="text-[14px]" />
            <span className="text-primary font-semibold">Daemon Restarts & needrestart</span>
          </div>
          <div className="flex flex-wrap items-center gap-space-sm pt-0.5 font-code-sm text-code-sm">
            <span className="px-space-sm py-1 rounded bg-surface-container-low text-on-surface flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-tertiary" />
              needrestart 3.6 (eBPF /proc/pid/maps scanner)
            </span>
            <span className="px-space-sm py-1 rounded bg-surface-container-low text-tertiary">
              Kernel ABI Synchronized (No Reboot Required)
            </span>
          </div>
        </div>

        <div className="flex items-center gap-space-sm shrink-0">
          <button
            type="button"
            onClick={() => {
              setScanningMem(true);
              window.setTimeout(() => setScanningMem(false), 700);
            }}
            className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-bright transition-colors text-label-md font-label-md"
          >
            <MaterialIcon
              name="sync"
              className={`text-[17px] text-primary ${scanningMem ? 'animate-spin' : ''}`}
            />
            <span>{scanningMem ? 'Scanning /proc/*/maps...' : 'Scan Memory Now'}</span>
          </button>
          <button
            type="button"
            disabled={staleCount === 0}
            onClick={onRestartAllStale}
            className="flex items-center gap-space-xs px-space-lg py-2 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 font-label-md text-label-md font-semibold shadow-md transition-all disabled:opacity-50"
          >
            <MaterialIcon name="bolt" className="text-[18px]" />
            <span>
              {staleCount === 0
                ? 'All Daemons Remapped'
                : `Batch Restart Flagged Daemons (${staleCount})`}
            </span>
          </button>
        </div>
      </div>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="daemon-restarts-and-needrestart"
        onExecuteRecommendedAction={onRestartAllStale}
        customActionLabel="Restart Outdated Services (Zero Downtime)"
        defaultExpanded={false}
      />

      {/* Summary Telemetry Header Card */}
      <div className="w-full bg-surface-container/80 backdrop-blur-xl rounded-xl p-space-lg border border-[#363243] shadow-sm">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-space-lg items-center">
          <div className="lg:col-span-4 flex flex-col gap-space-xs">
            <div className="flex items-center gap-space-xs">
              <MaterialIcon name="memory" className="text-primary text-[22px]" />
              <h2 className="font-headline-md text-headline-md text-on-surface font-semibold">
                Stale Process Memory & ABI Inspector
              </h2>
            </div>
            <p className="font-body-md text-body-md text-on-surface-variant">
              Identifies background daemons holding superseded dynamic objects (.so) or deleted file
              descriptors following apt security upgrades.
            </p>
          </div>

          <div className="lg:col-span-5 grid grid-cols-2 sm:grid-cols-4 gap-space-sm">
            <div className="flex flex-col p-space-md rounded-lg bg-surface-container-low">
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">
                Stale .so Objects
              </span>
              <span className="font-headline-lg text-headline-lg text-error font-bold mt-1 tabular-nums">
                {staleCount}
              </span>
              <span className="font-code-sm text-code-sm text-on-surface-variant truncate mt-0.5">
                libssl, libc
              </span>
            </div>
            <div className="flex flex-col p-space-md rounded-lg bg-surface-container-low">
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">
                Monitored Units
              </span>
              <span className="font-headline-lg text-headline-lg text-primary font-bold mt-1 tabular-nums">
                {daemons.length}
              </span>
              <span className="font-code-sm text-code-sm text-on-surface-variant truncate mt-0.5">
                resolved, cron, pipewire
              </span>
            </div>
            <div className="flex flex-col p-space-md rounded-lg bg-surface-container-low">
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">
                Kernel Reboot
              </span>
              <span className="font-headline-lg text-headline-lg text-tertiary font-bold mt-1">
                No
              </span>
              <span className="font-code-sm text-code-sm text-tertiary truncate mt-0.5">
                ABI Synced
              </span>
            </div>
            <div className="flex flex-col p-space-md rounded-lg bg-surface-container-low">
              <span className="font-label-sm text-label-sm text-on-surface-variant uppercase">
                Memory Cleanliness
              </span>
              <span className="font-headline-lg text-headline-lg text-tertiary font-bold mt-1 tabular-nums">
                {cleanlinessPct}%
              </span>
              <span className="font-code-sm text-code-sm text-on-surface-variant mt-0.5">
                In-RAM pages
              </span>
            </div>
          </div>

          <div className="lg:col-span-3 flex items-center justify-end">
            <GnomeSwitch
              checked={safeAutoRestart}
              onChange={setSafeAutoRestart}
              label="Safe Auto-Restart"
            />
          </div>
        </div>
      </div>

      {/* Main 2-Column Split Workspace */}
      <div className="w-full grid grid-cols-1 xl:grid-cols-12 gap-space-lg items-start">
        <div className="xl:col-span-7 flex flex-col gap-space-md">
          <div className="w-full flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-space-sm bg-surface-container-low p-space-sm rounded-xl border border-[#363243]">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="flex-1 bg-surface-container-lowest px-space-md py-1.5 rounded-lg text-on-surface font-code-sm text-code-sm outline-none"
              placeholder="Filter processes, superseded .so, PID, or unit..."
              type="text"
            />
            <div className="flex items-center bg-surface-container-lowest p-1 rounded-lg gap-1">
              {(['ALL', 'System', 'Session'] as const).map((sc) => (
                <button
                  key={sc}
                  type="button"
                  onClick={() => setScopeFilter(sc)}
                  className={`px-space-sm py-1 rounded font-label-sm text-label-sm ${
                    scopeFilter === sc
                      ? 'bg-surface-container-high text-on-surface font-semibold'
                      : 'text-on-surface-variant hover:text-on-surface'
                  }`}
                >
                  {sc}
                </button>
              ))}
            </div>
          </div>

          {filtered.map((d) => (
            <div
              key={d.id}
              className="p-space-lg rounded-xl bg-surface-container/90 border border-[#363243] shadow-sm flex flex-col gap-space-sm"
            >
              <div className="flex items-start justify-between gap-space-md">
                <div>
                  <div className="flex items-center gap-space-sm flex-wrap">
                    <span className="font-title-sm text-title-sm text-on-surface font-semibold">
                      {d.unitName}
                    </span>
                    <span className="font-code-sm text-code-sm px-space-xs py-0.5 rounded bg-surface-container-lowest text-on-surface-variant">
                      PID {d.pid}
                    </span>
                    <span
                      className={`font-label-sm text-label-sm px-space-xs py-0.5 rounded font-semibold ${
                        d.status === 'Remapped'
                          ? 'bg-tertiary/15 text-tertiary'
                          : 'bg-error-container text-on-error-container'
                      }`}
                    >
                      {d.status === 'Remapped' ? 'Remapped & Verified' : d.badgeLabel}
                    </span>
                  </div>
                  <span className="font-body-md text-body-md text-on-surface-variant mt-0.5 block">
                    {d.description}
                  </span>
                </div>
                <div className="text-right font-code-sm text-code-sm">
                  <div className="text-on-surface">RSS: {d.rssMemory}</div>
                  <div className="text-on-surface-variant text-[11px]">Uptime: {d.uptime}</div>
                </div>
              </div>

              <div className="p-space-md rounded-lg bg-surface-container-lowest flex flex-col gap-1 font-code-sm text-code-sm">
                <div className="flex items-center justify-between">
                  <span className="text-on-surface-variant uppercase text-[10px]">
                    Resident Shared Object Mapping
                  </span>
                  {d.cveId && <span className="text-error font-semibold">{d.cveId}</span>}
                </div>
                <code className="text-primary truncate">{d.supersededObject}</code>
                <p className="text-on-surface-variant text-[11px] mt-1">{d.impactAssessment}</p>
              </div>

              <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    disabled={d.status === 'Remapped'}
                    onClick={() => onRestartDaemon(d.id)}
                    className="flex items-center gap-1 px-space-md py-1.5 rounded-lg bg-primary-container text-white font-label-md text-label-md font-semibold hover:brightness-110 transition-all disabled:opacity-50"
                  >
                    <MaterialIcon name="restart_alt" className="text-[16px]" />
                    <span>
                      {d.status === 'Remapped' ? 'Unit Remapped' : 'Graceful SIGHUP/Restart'}
                    </span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setInspectedDaemon(d)}
                    className="flex items-center gap-1 px-space-sm py-1.5 rounded-lg bg-surface-container-high text-on-surface font-label-md text-label-md hover:bg-surface-bright"
                  >
                    <MaterialIcon name="terminal" className="text-[16px]" />
                    <span>Inspect /proc/{d.pid}/maps</span>
                  </button>
                </div>
                <span className="font-code-sm text-code-sm text-on-surface-variant">
                  Scope: {d.scope}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Right Column: Gemini Memory Remap Intelligence */}
        <div className="xl:col-span-5 flex flex-col gap-space-md">
          <div className="p-space-lg rounded-xl bg-surface-container/90 border border-[#363243] shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-space-xs">
                <MaterialIcon name="auto_awesome" className="text-secondary text-[20px]" />
                <h3 className="font-title-sm text-title-sm text-on-surface font-semibold">
                  Gemini Process Memory Forensics
                </h3>
              </div>
              <span className="font-code-sm text-code-sm px-2 py-0.5 rounded-full bg-secondary-container/40 text-secondary">
                CVE-2024-5535
              </span>
            </div>
            <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
              Canonical security update patched <code className="text-primary">libssl.so.3</code> on
              disk, but long-running daemons retain anonymous mmap descriptors to the unlinked
              inode. Restarting via systemd socket activation preserves active DNS/SSH descriptors
              with zero packet loss.
            </p>
            {inspectedDaemon && (
              <div className="p-3 rounded-lg bg-surface-container-lowest border border-primary/30 space-y-1 font-code-sm text-code-sm">
                <div className="flex items-center justify-between text-primary font-semibold">
                  <span>/proc/{inspectedDaemon.pid}/maps ({inspectedDaemon.unitName})</span>
                  <button
                    type="button"
                    onClick={() => setInspectedDaemon(null)}
                    className="text-on-surface-variant hover:text-on-surface"
                  >
                    Close
                  </button>
                </div>
                {inspectedDaemon.memoryMaps.map((m, i) => (
                  <div key={i} className="text-[11px] text-on-surface-variant break-all">
                    {m}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// SCREEN 7: Network Profiles & WireGuard Co-Existence Manager
// ============================================================================
interface NetworkProfilesDeckProps {
  networkMode: NetworkMode;
  onChangeNetworkMode: (mode: NetworkMode) => void;
  tunnels: WireGuardTunnel[];
  onToggleTunnel: (id: string) => void;
}

export const NetworkProfilesDeck: React.FC<NetworkProfilesDeckProps> = ({
  networkMode,
  onChangeNetworkMode,
  tunnels,
  onToggleTunnel,
}) => {
  const [killSwitchStrict, setKillSwitchStrict] = useState(true);
  const [blockLan, setBlockLan] = useState(true);
  const [ipv6Blackhole, setIpv6Blackhole] = useState(true);
  const [leakTestResult, setLeakTestResult] = useState<string | null>(null);
  const [splitRules, setSplitRules] = useState([
    {
      id: 'sp-1',
      app: 'Steam / Proton Gaming Engine',
      cgroup: '/sys/fs/cgroup/games.slice',
      policy: 'Bypass to Physical wlan0',
    },
    {
      id: 'sp-2',
      app: 'Docker Swarm / Local Podman Bridges',
      cgroup: 'CIDR: 172.17.0.0/16, 10.88.0.0/16',
      policy: 'Retain in Bridge veth',
    },
  ]);

  const runSyntheticLeakTest = () => {
    setLeakTestResult(
      'SYNTHETIC LEAK TEST PASSED (0 Leaks): Queried whoami.ds.akahelp.net viawg0-proton link 4 (~.). Resolver: NextDNS Anycast 45.90.28.0 (DoH TLS 1.3). Plaintext UDP/53 blocked by nftables rule #88.',
    );
  };

  return (
    <div className="flex flex-col w-full gap-space-lg select-text">
      {/* Top Sub-Header & Three-State Mode Switcher */}
      <section className="flex flex-col xl:flex-row xl:items-center justify-between gap-space-md p-space-md rounded-xl bg-surface-container-low border border-[#363243] shadow-sm">
        <div className="flex flex-col gap-space-xs">
          <div className="flex items-center gap-space-xs text-on-surface-variant font-label-sm text-label-sm uppercase tracking-wider">
            <span>Configuration</span>
            <MaterialIcon name="chevron_right" className="text-[12px]" />
            <span className="text-primary font-semibold">
              Proton VPN & NextDNS Co-Existence Engine
            </span>
          </div>
          <div className="pt-1">
            <Tooltip explainerKey="coexistence-mode">
              <ModeSwitcher mode={networkMode} onChange={onChangeNetworkMode} />
            </Tooltip>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-space-xs">
          <button
            type="button"
            onClick={() =>
              setLeakTestResult(
                'Flushed systemd-resolved link 4 caches & verified WireGuard fwmark 51820.',
              )
            }
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-container hover:bg-surface-bright text-on-surface text-label-md font-label-md transition-colors border border-[#363243]"
          >
            <MaterialIcon name="sync" className="text-[16px] text-tertiary" />
            <span>Flush DNS & Route Cache</span>
          </button>
          <button
            type="button"
            onClick={runSyntheticLeakTest}
            className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-primary-container text-on-primary-container font-title-sm text-title-sm hover:brightness-110 transition-all shadow-sm"
          >
            <MaterialIcon name="troubleshoot" className="text-[18px]" />
            <span>Run Synthetic DNS Leak Check</span>
          </button>
        </div>
      </section>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="network-profiles-and-wireguard"
        onExecuteRecommendedAction={() => {
          onChangeNetworkMode('coexist');
          runSyntheticLeakTest();
        }}
        customActionLabel="Enforce Co-Existence Mode & Test Leak Shield"
        defaultExpanded={false}
      />

      {leakTestResult && (
        <div className="p-3 rounded-xl bg-tertiary-container/20 border border-tertiary text-tertiary font-code-sm text-code-sm flex items-center justify-between">
          <span>{leakTestResult}</span>
          <button type="button" onClick={() => setLeakTestResult(null)}>
            Dismiss
          </button>
        </div>
      )}

      {/* Main Split Interface */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-space-lg">
        {/* Left 7 cols: WireGuard Tunnels & Split Tunneling */}
        <div className="lg:col-span-7 flex flex-col gap-space-lg">
          <div className="flex flex-col rounded-xl bg-surface-container border border-[#363243] overflow-hidden shadow-sm">
            <div className="flex items-center justify-between px-space-md py-space-sm bg-surface-container-high">
              <div className="flex items-center gap-space-xs">
                <MaterialIcon name="vpn_key" className="text-primary text-[18px]" />
                <span className="font-title-sm text-title-sm text-on-surface">
                  WireGuard Interfaces & Endpoints
                </span>
              </div>
              <span className="font-code-sm text-code-sm text-tertiary">
                Linked IP Auto-Sync Armed
              </span>
            </div>

            <div className="flex flex-col p-space-md gap-space-md">
              {tunnels.map((tun) => (
                <div
                  key={tun.id}
                  className="flex flex-col gap-space-sm p-space-md rounded-lg bg-surface-container-low border border-white/5"
                >
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <div className="flex items-center gap-space-xs">
                      <span
                        className={`w-2.5 h-2.5 rounded-full ${
                          tun.status === 'ACTIVE DEFAULT' ? 'bg-tertiary' : 'bg-surface-bright'
                        }`}
                      />
                      <span className="font-title-sm text-title-sm text-on-surface font-bold">
                        {tun.interfaceName}
                      </span>
                      <span className="font-label-sm text-label-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-on-surface-variant">
                        {tun.location}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded-full font-label-sm text-label-sm font-semibold ${
                          tun.status === 'ACTIVE DEFAULT'
                            ? 'bg-tertiary-container/30 text-tertiary'
                            : 'bg-surface-container-highest text-on-surface-variant'
                        }`}
                      >
                        {tun.status}
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => onToggleTunnel(tun.id)}
                      className={`px-3 py-1 rounded font-label-md text-label-md transition-colors ${
                        tun.status === 'ACTIVE DEFAULT'
                          ? 'bg-error-container text-on-error-container'
                          : 'bg-primary-container text-white'
                      }`}
                    >
                      {tun.status === 'ACTIVE DEFAULT' ? 'Disconnect' : 'Engage Tunnel'}
                    </button>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-space-xs font-code-sm text-code-sm">
                    <div className="p-2 rounded bg-surface-container">
                      <div className="text-on-surface-variant text-[10px]">TUNNEL IP</div>
                      <div className="text-on-surface font-bold truncate">{tun.tunnelIp}</div>
                    </div>
                    <div className="p-2 rounded bg-surface-container">
                      <div className="text-on-surface-variant text-[10px]">ENDPOINT</div>
                      <div className="text-tertiary font-bold truncate">{tun.endpoint}</div>
                    </div>
                    <div className="p-2 rounded bg-surface-container">
                      <div className="text-on-surface-variant text-[10px]">ALLOWED IPS</div>
                      <div className="text-primary font-bold truncate">{tun.allowedIps}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Application Split-Tunneling (cgroups v2) */}
          <div className="flex flex-col rounded-xl bg-surface-container border border-[#363243] overflow-hidden shadow-sm">
            <div className="flex items-center justify-between px-space-md py-space-sm bg-surface-container-high">
              <div className="flex items-center gap-space-xs">
                <MaterialIcon name="call_split" className="text-primary text-[18px]" />
                <span className="font-title-sm text-title-sm text-on-surface">
                  Application Split-Tunneling (eBPF & cgroups v2)
                </span>
              </div>
              <button
                type="button"
                onClick={() =>
                  setSplitRules((prev) => [
                    ...prev,
                    {
                      id: `sp-${Date.now()}`,
                      app: 'Ollama Local Server (127.0.0.1:11434)',
                      cgroup: '/sys/fs/cgroup/ai-local.slice',
                      policy: 'Loopback Only (No Egress)',
                    },
                  ])
                }
                className="text-primary font-label-md text-label-md hover:underline"
              >
                + Add App Rule
              </button>
            </div>
            <div className="flex flex-col p-space-md gap-space-sm">
              {splitRules.map((sr) => (
                <div
                  key={sr.id}
                  className="flex items-center justify-between p-2.5 rounded bg-surface-container-low font-code-sm text-code-sm"
                >
                  <div>
                    <span className="text-on-surface font-semibold">{sr.app}</span>{' '}
                    <span className="text-on-surface-variant text-[11px]">({sr.cgroup})</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-tertiary">{sr.policy}</span>
                    <button
                      type="button"
                      onClick={() =>
                        setSplitRules((prev) => prev.filter((item) => item.id !== sr.id))
                      }
                      className="text-on-surface-variant hover:text-error"
                    >
                      <MaterialIcon name="delete" className="text-[16px]" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right 5 cols: Routing Inspector & Kill Switch */}
        <div className="lg:col-span-5 flex flex-col gap-space-lg">
          <div className="flex flex-col rounded-xl bg-surface-container border border-[#363243] overflow-hidden shadow-sm">
            <div className="flex items-center justify-between px-space-md py-space-sm bg-surface-container-high">
              <div className="flex items-center gap-space-xs">
                <MaterialIcon name="terminal" className="text-primary-container text-[18px]" />
                <span className="font-title-sm text-title-sm text-on-surface">
                  Kernel FIB Rules & D-Bus resolvectl Scoping
                </span>
              </div>
              <span className="font-code-sm text-code-sm text-tertiary">Table 51820</span>
            </div>
            <div className="p-space-md flex flex-col gap-space-md">
              <pre className="p-space-sm rounded-lg bg-surface-container-lowest font-code-sm text-code-sm text-on-surface overflow-x-auto leading-relaxed">
                {`# resolvectl status wg0-proton-ch
Link 4 (wg0-proton-ch)
  Current Scopes: DNS
       Protocols: +DefaultRoute -LLMNR -mDNS +DNSOverTLS
     DNS Servers: 45.90.28.0#dns.nextdns.io
      DNS Domain: ~.

# ip rule show
0:      from all lookup local
100:    from all fwmark 0xca6c lookup 51820
32766:  from all lookup main`}
              </pre>
            </div>
          </div>

          <div className="flex flex-col rounded-xl bg-surface-container border border-[#363243] overflow-hidden shadow-sm">
            <div className="flex items-center justify-between px-space-md py-space-sm bg-surface-container-high">
              <span className="font-title-sm text-title-sm text-on-surface">
                Kill Switch & Strict Leak Defenses
              </span>
              <span className="px-2 py-0.5 rounded bg-error-container text-on-error-container font-label-sm text-label-sm font-semibold">
                ENFORCED
              </span>
            </div>
            <div className="p-space-md flex flex-col gap-space-md">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-title-sm text-title-sm text-on-surface">
                    Hard Kill Switch (nftables)
                  </div>
                  <div className="font-code-sm text-code-sm text-on-surface-variant">
                    Drop all outbound non-wg0 packets on interface loss
                  </div>
                </div>
                <GnomeSwitch checked={killSwitchStrict} onChange={setKillSwitchStrict} />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-title-sm text-title-sm text-on-surface">
                    Block RFC1918 Local LAN Access
                  </div>
                  <div className="font-code-sm text-code-sm text-on-surface-variant">
                    Prevents rogue gateway interception on untrusted Wi-Fi
                  </div>
                </div>
                <GnomeSwitch checked={blockLan} onChange={setBlockLan} />
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-title-sm text-title-sm text-on-surface">
                    IPv6 Blackhole Mitigation
                  </div>
                  <div className="font-code-sm text-code-sm text-on-surface-variant">
                    Reject physical IPv6 router advertisements via sysctl
                  </div>
                </div>
                <GnomeSwitch checked={ipv6Blackhole} onChange={setIpv6Blackhole} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// ============================================================================
// SCREEN 8: Rules & Quarantine Vault + AppArmor & cgroups v2 Sandbox
// ============================================================================
interface RulesAndQuarantineDeckProps {
  quarantineItems: QuarantinedArtifact[];
  onShredArtifact: (id: string) => void;
  appArmorProfiles: AppArmorProfileItem[];
  onToggleAppArmorMode: (id: string) => void;
}

export const RulesAndQuarantineDeck: React.FC<RulesAndQuarantineDeckProps> = ({
  quarantineItems,
  onShredArtifact,
  appArmorProfiles,
  onToggleAppArmorMode,
}) => {
  const [vaultFilter, setVaultFilter] = useState<'ALL' | 'HIGH' | 'STAGED'>('ALL');
  const [hexModalItem, setHexModalItem] = useState<QuarantinedArtifact | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const visibleVault = quarantineItems.filter((q) => {
    if (vaultFilter === 'HIGH') return q.severity === 'High Alert';
    if (vaultFilter === 'STAGED') return q.severity === 'Staged Deletion';
    return true;
  });

  return (
    <div className="flex flex-col w-full gap-space-lg select-text">
      {toast && (
        <div className="fixed bottom-5 right-6 z-50 px-4 py-2.5 rounded-xl bg-surface-container-high border border-tertiary/40 text-on-surface shadow-2xl font-code-sm text-code-sm">
          {toast}
        </div>
      )}

      <header className="flex flex-col xl:flex-row xl:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-space-xs">
            <MaterialIcon name="security" className="text-primary-container text-[20px]" />
            <h1 className="font-headline-lg text-headline-lg tracking-tight text-on-surface">
              Rules & Quarantine Vault
            </h1>
          </div>
          <div className="flex flex-wrap items-center gap-space-xs pt-1 font-code-sm text-code-sm">
            <span className="bg-surface-container px-2.5 py-1 rounded-full">
              AppArmor 4.0 ({appArmorProfiles.filter((p) => p.mode === 'Enforce').length} enforce)
            </span>
            <span className="bg-surface-container px-2.5 py-1 rounded-full">
              Vault: /var/lib/sentry/quarantine (0000 +i)
            </span>
            <span className="bg-surface-container px-2.5 py-1 rounded-full text-tertiary">
              Landlock ABI v4 + Seccomp BPF Active
            </span>
          </div>
        </div>

        <div className="flex items-center gap-space-xs">
          <button
            type="button"
            onClick={() => {
              setToast('Launched untrusted binary in unprivileged Landlock + Bubblewrap sandbox.');
              window.setTimeout(() => setToast(null), 3000);
            }}
            className="px-space-md py-2 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-label-md text-label-md"
          >
            Run with Landlock Sandbox
          </button>
        </div>
      </header>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="rules-and-quarantine"
        onExecuteRecommendedAction={() => {
          if (quarantineItems[0]) onShredArtifact(quarantineItems[0].id);
        }}
        customActionLabel="Securely Shred Quarantined Files"
        defaultExpanded={false}
      />

      {/* Quarantine Vault Section */}
      <section className="flex flex-col gap-space-md">
        <div className="flex items-center gap-space-xs bg-surface-container-low p-space-sm rounded-xl border border-[#363243]">
          {[
            { id: 'ALL', label: `All Quarantined (${quarantineItems.length})` },
            { id: 'HIGH', label: 'High Alert ELF/Scripts' },
            { id: 'STAGED', label: 'Staged for DoD Shred' },
          ].map((b) => (
            <button
              key={b.id}
              type="button"
              onClick={() => setVaultFilter(b.id as typeof vaultFilter)}
              className={`px-space-md py-1.5 rounded-full font-label-md text-label-md transition-all ${
                vaultFilter === b.id
                  ? 'bg-surface-bright text-on-surface font-semibold'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              {b.label}
            </button>
          ))}
        </div>

        <div className="flex flex-col gap-space-md">
          {visibleVault.map((item) => (
            <article
              key={item.id}
              className="bg-surface-container-low border border-[#363243] p-space-md rounded-xl flex flex-col xl:flex-row items-start xl:items-center justify-between gap-space-md shadow-sm"
            >
              <div className="flex flex-col gap-space-xs">
                <div className="flex flex-wrap items-center gap-space-xs">
                  <span className="font-headline-md text-headline-md text-on-surface font-mono">
                    {item.binaryName}
                  </span>
                  <span className="font-label-sm text-label-sm px-2 py-0.5 rounded bg-error-container text-on-error-container font-semibold">
                    {item.severity}
                  </span>
                  <span className="font-code-sm text-code-sm text-primary">
                    {item.classification} (Inode #{item.inode})
                  </span>
                </div>
                <div className="font-code-sm text-code-sm text-on-surface-variant space-y-0.5">
                  <div>
                    Origin: <span className="text-on-surface">{item.originPath}</span> → Vault:{' '}
                    <span className="text-tertiary">{item.vaultPath}</span>
                  </div>
                  <div>
                    SHA256: <span className="text-primary">{item.sha256}</span> • Permissions:{' '}
                    <span className="text-error">{item.permissions}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => setHexModalItem(item)}
                  className="px-3 py-1.5 rounded-lg bg-surface-container-highest hover:bg-surface-bright text-on-surface font-label-md text-label-md"
                >
                  ELF / Hex View
                </button>
                <button
                  type="button"
                  onClick={() => {
                    onShredArtifact(item.id);
                    setToast(`Permanently wiped inode #${item.inode} via shred -u -z.`);
                    window.setTimeout(() => setToast(null), 3000);
                  }}
                  className="px-3 py-1.5 rounded-lg bg-error-container hover:bg-error text-on-error-container font-label-md text-label-md font-semibold"
                >
                  Permanently Shred (shred -u -z)
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* AppArmor Profile Studio & cgroup v2 Slices */}
      <section className="grid grid-cols-1 xl:grid-cols-2 gap-space-lg">
        <div className="bg-surface-container-low/95 border border-[#363243] p-space-lg rounded-xl flex flex-col gap-space-sm">
          <div className="flex items-center justify-between">
            <h2 className="font-headline-md text-headline-md text-on-surface">
              AppArmor Active Profiles (/etc/apparmor.d/)
            </h2>
            <span className="font-code-sm text-code-sm text-tertiary">aa-enforce / aa-complain</span>
          </div>
          <div className="flex flex-col gap-space-xs mt-1">
            {appArmorProfiles.map((prof) => (
              <div
                key={prof.id}
                className="flex items-center justify-between p-space-sm rounded-lg bg-surface-container"
              >
                <div className="flex flex-col">
                  <div className="flex items-center gap-2">
                    <span className="font-code-sm text-code-sm text-on-surface font-semibold">
                      {prof.profileName}
                    </span>
                    <span
                      className={`font-code-sm text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                        prof.mode === 'Enforce'
                          ? 'bg-tertiary/15 text-tertiary'
                          : 'bg-surface-container-highest text-on-surface-variant'
                      }`}
                    >
                      {prof.mode}
                    </span>
                  </div>
                  <span className="font-code-sm text-[11px] text-on-surface-variant">
                    {prof.binaryPath} • {prof.confinedProcesses} PIDs • {prof.cgroupSlice}
                  </span>
                </div>
                <GnomeSwitch
                  checked={prof.mode === 'Enforce'}
                  onChange={() => onToggleAppArmorMode(prof.id)}
                  ariaLabel={`Toggle AppArmor mode for ${prof.profileName}`}
                />
              </div>
            ))}
          </div>
        </div>

        <div className="bg-surface-container-low/95 border border-[#363243] p-space-lg rounded-xl flex flex-col gap-space-sm">
          <div className="flex items-center justify-between">
            <h2 className="font-headline-md text-headline-md text-on-surface">
              cgroup v2 Sandbox Slices & Flatpak Portal Guard
            </h2>
            <span className="font-code-sm text-code-sm text-secondary">Wayland XDG Guard</span>
          </div>
          <div className="p-space-md rounded-lg bg-surface-container font-code-sm text-code-sm space-y-2">
            <div className="flex justify-between">
              <span className="text-on-surface font-semibold">sentry-jail-untrusted.slice</span>
              <span className="text-tertiary">CPUMax=5% • MemoryMax=192M</span>
            </div>
            <div className="text-on-surface-variant">
              XDG Desktop Portal Watchdog: Blocking unauthorized Wayland Screencast, RemoteDesktop,
              and global clipboard polling requests.
            </div>
            <div className="text-tertiary">
              Package Provenance & Cosign Verifier: All /etc/apt/sources.list.d/*.sources pinned to
              /etc/apt/keyrings/ GPG manifests.
            </div>
          </div>
        </div>
      </section>

      {hexModalItem && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-xl bg-surface-container border border-primary-container p-space-lg space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-headline-md text-headline-md text-on-surface">
                Static ELF Header & Hex Inspection ({hexModalItem.binaryName})
              </span>
              <button type="button" onClick={() => setHexModalItem(null)}>
                <MaterialIcon name="close" />
              </button>
            </div>
            <pre className="p-3 rounded bg-surface-container-lowest font-code-sm text-code-sm text-tertiary overflow-x-auto">
              {`00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
00000010: 0200 3e00 0100 0000 b014 4000 0000 0000  ..>.......@.....
00000020: 4000 0000 0000 0000 5550 5821 0d16 0800  @.......UPX!....
Section: .text packed with UPX 4.22 | C2 Socket Literal: 185.162.251.10:443`}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// SCREEN 9: Settings, Polkit Auth, Keyring & Spec Bundle Exporter
// ============================================================================
interface SettingsAndPolkitDeckProps {
  polkitRules: PolkitActionRule[];
  onTogglePolkitRule: (id: string) => void;
  projectState: ProjectState;
  onOpenExportModal: () => void;
  onOpenSubAppInstaller?: () => void;
}

export const SettingsAndPolkitDeck: React.FC<SettingsAndPolkitDeckProps> = ({
  polkitRules,
  onTogglePolkitRule,
  onOpenExportModal,
  onOpenSubAppInstaller,
}) => {
  const [categoryFilter, setCategoryFilter] = useState<
    'ALL' | 'Quarantine' | 'Network' | 'CIS Audit' | 'System'
  >('ALL');
  const [adminTtlMinutes, setAdminTtlMinutes] = useState(15);
  const [fidoEnforced, setFidoEnforced] = useState(true);
  const [pinCaching, setPinCaching] = useState(true);
  const [aiProvider, setAiProvider] = useState<'gemini' | 'ollama' | 'airgap'>('gemini');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [keyringSavedMsg, setKeyringSavedMsg] = useState<string | null>(null);
  const [rescuePreviewOpen, setRescuePreviewOpen] = useState(false);

  const visibleRules = polkitRules.filter((r) =>
    categoryFilter === 'ALL' ? true : r.category === categoryFilter,
  );

  const handleSaveApiKey = async () => {
    await setSecureKey(apiKeyInput);
    setApiKeyInput('');
    setKeyringSavedMsg(
      'Stored Gemini API credential in GNOME Keyring (libsecret Secret Service API). Zero plaintext written to disk.',
    );
    window.setTimeout(() => setKeyringSavedMsg(null), 4000);
  };

  const handleDownloadRescueScript = () => {
    const script = generateEmergencyRescueScript();
    const blob = new Blob([script], { type: 'text/x-shellscript;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentry-rescue.sh';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col w-full gap-space-lg select-text">
      {/* Header & Top Action Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div>
          <div className="flex items-center gap-space-xs">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Configuration
            </span>
            <MaterialIcon name="chevron_right" className="text-[14px]" />
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-primary">
              Settings & Polkit Auth
            </span>
          </div>
          <div className="flex items-center gap-space-md flex-wrap mt-1">
            <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight">
              Privilege, GNOME Keyring & Spec Bundle Administration
            </h1>
            <span className="font-code-sm text-code-sm bg-surface-container-high px-2.5 py-0.5 rounded-full text-tertiary">
              polkitd 124 + pam_u2f.so armed
            </span>
          </div>
        </div>

        <div className="flex items-center gap-space-sm flex-wrap">
          {onOpenSubAppInstaller && (
            <button
              type="button"
              onClick={onOpenSubAppInstaller}
              className="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-colors border border-primary/30"
            >
              <MaterialIcon name="apps" className="text-[16px] text-tertiary" />
              <span className="font-title-sm text-title-sm">1-Click Tool Installer</span>
            </button>
          )}
          <button
            type="button"
            onClick={() => setRescuePreviewOpen(!rescuePreviewOpen)}
            className="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-colors"
          >
            <MaterialIcon name="medical_services" className="text-[16px] text-tertiary" />
            <span className="font-title-sm text-title-sm">/boot/sentry-rescue.sh</span>
          </button>
          <button
            type="button"
            onClick={onOpenExportModal}
            className="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 transition-all shadow-md font-semibold"
          >
            <MaterialIcon name="folder_zip" className="text-[18px]" />
            <span className="font-title-sm text-title-sm">Save Spec Bundle to Computer</span>
          </button>
        </div>
      </div>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="settings-and-polkit-auth"
        onExecuteRecommendedAction={handleDownloadRescueScript}
        customActionLabel="Generate /boot/sentry-rescue.sh Rescue Script"
        defaultExpanded={false}
      />

      {/* 1-Click Sub-Application Provisioning Banner Card */}
      <div className="p-space-md rounded-xl bg-gradient-to-r from-surface-container via-surface-container-high to-surface-container border border-primary/40 shadow-md flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-primary/20 text-primary border border-primary/30 shrink-0">
            <MaterialIcon name="build_circle" className="text-[26px]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-title-md text-title-md text-on-surface font-bold">
                Security Sub-Applications & Subsystem Provisioning
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-code-sm bg-tertiary/20 text-tertiary font-semibold">
                1-Click Setup
              </span>
            </div>
            <p className="font-body-md text-[13px] text-on-surface-variant mt-0.5">
              Automate installation for Fail2ban, Suricata, ClamAV, Lynis, UFW, RKhunter, needrestart, USBGuard & all security backends.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {onOpenSubAppInstaller && (
            <button
              type="button"
              onClick={onOpenSubAppInstaller}
              className="px-4 py-2 rounded-lg bg-gradient-to-r from-primary to-primary-container text-white font-title-sm text-[13px] font-semibold flex items-center gap-2 shadow-md hover:brightness-110 active:scale-98 transition-all"
            >
              <MaterialIcon name="auto_fix_high" className="text-[16px]" />
              <span>Open 1-Click Tool Installer</span>
            </button>
          )}
        </div>
      </div>

      {rescuePreviewOpen && (
        <div className="p-space-md rounded-xl bg-surface-container border border-tertiary/40 space-y-2">
          <div className="flex items-center justify-between">
            <span className="font-title-sm text-title-sm text-tertiary">
              Air-Gapped Emergency Rescue Script (/boot/sentry-rescue.sh)
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleDownloadRescueScript}
                className="px-3 py-1 rounded bg-primary-container text-white font-label-sm"
              >
                Download sentry-rescue.sh
              </button>
              <button
                type="button"
                onClick={() => setRescuePreviewOpen(false)}
                className="text-on-surface-variant"
              >
                Close
              </button>
            </div>
          </div>
          <pre className="p-3 rounded bg-surface-container-lowest font-code-sm text-code-sm text-on-surface overflow-x-auto">
            {generateEmergencyRescueScript()}
          </pre>
        </div>
      )}

      {/* GNOME Keyring / libsecret API Key Vault */}
      <div className="p-space-md rounded-xl bg-surface-container border border-[#363243] shadow-sm flex flex-col gap-space-sm">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <MaterialIcon name="vpn_key" className="text-primary text-[20px]" />
            <span className="font-title-sm text-title-sm text-on-surface font-semibold">
              GNOME Keyring / libsecret Credential Vault (Zero Plaintext Storage)
            </span>
          </div>
          <span className="font-code-sm text-code-sm text-tertiary">
            org.freedesktop.secrets / login.keyring
          </span>
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <input
            type="password"
            value={apiKeyInput}
            onChange={(e) => setApiKeyInput(e.target.value)}
            placeholder="Enter Gemini API Key (stored strictly in OS Keyring via libsecret)..."
            className="flex-1 bg-surface-container-lowest border border-[#363243] rounded-lg px-3 py-2 font-code-sm text-code-sm text-on-surface"
          />
          <button
            type="button"
            onClick={handleSaveApiKey}
            className="px-4 py-2 rounded-lg bg-primary-container text-white font-label-md font-semibold hover:brightness-110"
          >
            Seal in GNOME Keyring
          </button>
        </div>
        {keyringSavedMsg && (
          <div className="font-code-sm text-code-sm text-tertiary">{keyringSavedMsg}</div>
        )}
      </div>

      {/* Polkit Action Rules Matrix */}
      <div className="flex flex-col rounded-xl bg-surface-container border border-[#363243] shadow-sm overflow-hidden">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-md p-space-md bg-surface-container-high">
          <div>
            <span className="font-title-sm text-title-sm text-on-surface block">
              Registered Polkit Action Matrix (/etc/polkit-1/rules.d/50-sentry.rules)
            </span>
            <span className="font-label-sm text-label-sm text-on-surface-variant">
              Least-privilege actions under org.sentrylinux.*
            </span>
          </div>
          <div className="flex items-center p-0.5 bg-surface-container-low rounded-lg gap-0.5">
            {(['ALL', 'Quarantine', 'Network', 'CIS Audit', 'System'] as const).map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setCategoryFilter(cat)}
                className={`px-space-sm py-1 rounded font-label-sm text-label-sm ${
                  categoryFilter === cat
                    ? 'bg-surface-container-highest text-on-surface font-semibold'
                    : 'text-on-surface-variant hover:text-on-surface'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-col divide-y divide-surface-container-highest/20">
          {visibleRules.map((rule) => (
            <div
              key={rule.id}
              className="flex flex-col sm:flex-row sm:items-center justify-between p-space-md gap-space-md hover:bg-surface-container-high/40 transition-colors"
            >
              <div className="flex items-start gap-space-md">
                <div className="p-2 rounded-lg bg-surface-container-highest text-primary">
                  <MaterialIcon name={rule.icon} className="text-[20px]" />
                </div>
                <div>
                  <div className="flex items-center gap-space-xs flex-wrap">
                    <span className="font-code-sm text-code-sm font-semibold text-on-surface">
                      {rule.actionId}
                    </span>
                    <span className="px-space-xs py-0.5 rounded bg-surface-container-highest text-tertiary font-code-sm text-[10px]">
                      {rule.policyLevel}
                    </span>
                    <span className="px-space-xs py-0.5 rounded bg-primary-container/20 text-primary font-code-sm text-[10px]">
                      {rule.ttlLabel}
                    </span>
                  </div>
                  <span className="font-body-md text-body-md text-on-surface-variant">
                    {rule.description}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-space-md shrink-0">
                <span className="font-label-sm text-label-sm text-on-surface-variant">
                  {rule.promptMode}
                </span>
                <GnomeSwitch
                  checked={rule.enabled}
                  onChange={() => onTogglePolkitRule(rule.id)}
                  ariaLabel={`Toggle Polkit rule ${rule.actionId}`}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Hardware Tokens & Session Grace Tuning */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-space-lg">
        <div className="flex flex-col rounded-xl bg-surface-container border border-[#363243] p-space-md gap-space-md">
          <div className="flex items-center justify-between">
            <span className="font-title-sm text-title-sm text-on-surface">
              Hardware Tokens & PAM-U2F (YubiKey 5C NFC)
            </span>
            <span className="font-code-sm text-code-sm text-tertiary">User Present</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="font-label-md text-label-md text-on-surface">
              Enforce FIDO2 for CIS Remediations
            </span>
            <GnomeSwitch checked={fidoEnforced} onChange={setFidoEnforced} />
          </div>
          <div className="flex items-center justify-between">
            <span className="font-label-md text-label-md text-on-surface">
              Flush PIN Cache on GNOME Screen Lock
            </span>
            <GnomeSwitch checked={pinCaching} onChange={setPinCaching} />
          </div>
        </div>

        <div className="flex flex-col rounded-xl bg-surface-container border border-[#363243] p-space-md gap-space-md">
          <div className="flex items-center justify-between">
            <span className="font-title-sm text-title-sm text-on-surface">
              Polkit Token Lifetime & AI Engine Selector
            </span>
            <span className="font-code-sm text-code-sm text-primary">
              TTL: {adminTtlMinutes} Minutes
            </span>
          </div>
          <input
            type="range"
            min={0}
            max={60}
            value={adminTtlMinutes}
            onChange={(e) => setAdminTtlMinutes(Number(e.target.value))}
            className="w-full accent-primary-container cursor-pointer"
            aria-label="Polkit Admin Token Lifetime"
          />
          <div className="grid grid-cols-3 gap-2 pt-1">
            {[
              { id: 'gemini', label: 'Gemini 4 Dual-Tier' },
              { id: 'ollama', label: 'Ollama (127.0.0.1:11434)' },
              { id: 'airgap', label: 'Air-Gapped Heuristics' },
            ].map((prov) => (
              <button
                key={prov.id}
                type="button"
                onClick={() => setAiProvider(prov.id as typeof aiProvider)}
                className={`p-2 rounded-lg font-label-sm text-label-sm border transition-all ${
                  aiProvider === prov.id
                    ? 'border-primary-container bg-surface-container-high text-on-surface font-semibold'
                    : 'border-white/5 bg-surface-container-low text-on-surface-variant'
                }`}
              >
                {prov.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
