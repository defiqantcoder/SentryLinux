import React, { useState, useEffect } from 'react';
import type {
  BlastRadiusReport,
  DnsQueryRecord,
  IncidentEvent,
  InterceptSocketEvent,
  LiveSystemTelemetry,
  SystemdExposureUnit,
  TabId,
} from '../types/project';
import { MaterialIcon, Tooltip } from '../components/Primitives';
import { AiSectionExplainer } from '../components/AiSectionExplainer';
import { analyzeBlastRadius, queryAskSentry } from '../services/geminiService';

interface OverviewDeckProps {
  incidents: IncidentEvent[];
  onIsolateIncident: (id: string) => void;
  isLockdown: boolean;
  onToggleLockdown: () => void;
  snapshotId: string;
  onTakeSnapshot: () => void;
  staleCount: number;
  onRestartAllStale: () => void;
  onNavigate: (tab: TabId) => void;
  systemTelemetry: LiveSystemTelemetry;
  systemdUnits: SystemdExposureUnit[];
}

export const OverviewDeck: React.FC<OverviewDeckProps> = ({
  incidents,
  onIsolateIncident,
  isLockdown,
  onToggleLockdown,
  snapshotId,
  onTakeSnapshot,
  staleCount,
  onRestartAllStale,
  onNavigate,
  systemTelemetry,
  systemdUnits,
}) => {
  const [ufwEnabled, setUfwEnabled] = useState(true);
  const [debsumsStatus, setDebsumsStatus] = useState<'idle' | 'scanning' | 'clean'>('idle');
  const [restartingDaemons, setRestartingDaemons] = useState(false);
  const [blastModal, setBlastModal] = useState<BlastRadiusReport | null>(null);
  const [lineageIncident, setLineageIncident] = useState<IncidentEvent | null>(null);
  const [selectedDropIn, setSelectedDropIn] = useState<SystemdExposureUnit | null>(null);
  const [severityFilter, setSeverityFilter] = useState<'ALL' | 'CRITICAL' | 'WARN'>('ALL');
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const [expandedAiIncidentId, setExpandedAiIncidentId] = useState<string | null>(null);

  const triggerToast = (msg: string) => {
    setToastMsg(msg);
    window.setTimeout(() => setToastMsg(null), 3500);
  };

  const handleDebsumsScan = () => {
    setDebsumsStatus('scanning');
    window.setTimeout(() => {
      setDebsumsStatus('clean');
      triggerToast('Debsums -c verified 1,419/1,420 packages against Canonical GPG manifests.');
      window.setTimeout(() => setDebsumsStatus('idle'), 3000);
    }, 1200);
  };

  const handleGracefulRestart = () => {
    setRestartingDaemons(true);
    window.setTimeout(() => {
      onRestartAllStale();
      setRestartingDaemons(false);
      triggerToast('Polkit authenticated: systemd-resolved & cron remapped to patched libssl.so.3.');
    }, 900);
  };

  const handleInspectBlastRadius = async (inc: IncidentEvent) => {
    const report = await analyzeBlastRadius(inc.pid, inc.binary);
    setBlastModal(report);
  };

  const filteredIncidents = incidents.filter((inc) =>
    severityFilter === 'ALL' ? true : inc.severity === severityFilter,
  );

  const defenseScore = isLockdown ? 99 : staleCount === 0 ? 97 : 94;

  return (
    <div className="flex flex-col w-full gap-space-md select-text">
      {toastMsg && (
        <div className="fixed bottom-5 right-6 z-50 px-4 py-2.5 rounded-xl bg-surface-container-high border border-tertiary/40 text-on-surface shadow-2xl flex items-center gap-2 font-code-sm text-code-sm">
          <MaterialIcon name="check_circle" className="text-tertiary text-[18px]" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* Desktop Top Control Bar & Live Banner */}
      <section className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-space-md p-space-md rounded-xl bg-surface-container/80 backdrop-blur-xl border border-[#363243] shadow-md">
        <div className="flex items-center gap-space-md">
          <Tooltip explainerKey="health-scorecard">
            <div className="relative flex items-center justify-center w-14 h-14 rounded-full bg-surface-container-high/80 shrink-0">
              <svg className="w-14 h-14 -rotate-90" viewBox="0 0 48 48">
                <circle
                  className="text-surface-container-highest"
                  cx="24"
                  cy="24"
                  fill="none"
                  r="20"
                  stroke="currentColor"
                  strokeWidth="3"
                />
                <circle
                  className="text-primary-container transition-all duration-500"
                  cx="24"
                  cy="24"
                  fill="none"
                  r="20"
                  stroke="currentColor"
                  strokeDasharray="125.6"
                  strokeDashoffset={125.6 - (125.6 * defenseScore) / 100}
                  strokeLinecap="round"
                  strokeWidth="3"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="font-headline-md text-headline-md text-on-surface leading-none tabular-nums">
                  {defenseScore}
                </span>
                <span className="font-code-sm text-[8px] text-tertiary uppercase font-bold">
                  SECURE
                </span>
              </div>
            </div>
          </Tooltip>
          <div className="flex flex-col">
            <div className="flex items-center gap-space-xs flex-wrap">
              <h2 className="font-title-sm text-title-sm text-on-surface">
                System Defense Scorecard
              </h2>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-tertiary/10 text-tertiary font-code-sm text-[10px]">
                <span className="w-1.5 h-1.5 rounded-full bg-tertiary" />
                CIS Level 2 Hardened
              </span>
            </div>
            <p className="font-code-sm text-code-sm text-outline">
              Last atomic snapshot: just synced (/etc git-backed tree #{snapshotId})
            </p>
          </div>
        </div>

        {/* Quick Action / Lockdown Switcher */}
        <div className="flex items-center flex-wrap gap-space-sm">
          <Tooltip explainerKey="lockdown-mode">
            <div className="flex items-center gap-space-sm px-space-md py-1.5 rounded-lg bg-surface-container-low border border-[#363243] shadow-sm">
              <div className="flex flex-col items-end">
                <span className="font-label-md text-label-md text-on-surface">
                  Auto-Revert Shield
                </span>
                <span className="font-code-sm text-code-sm text-outline">05:00 Watchdog</span>
              </div>
              <button
                type="button"
                aria-label="Toggle Lockdown"
                onClick={onToggleLockdown}
                className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full transition-colors duration-200 ease-in-out focus:outline-none ${
                  isLockdown ? 'bg-error-container' : 'bg-surface-container-highest'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-on-surface shadow transition duration-200 ease-in-out mt-0.5 ${
                    isLockdown ? 'translate-x-5' : 'translate-x-0.5'
                  }`}
                />
              </button>
            </div>
          </Tooltip>

          <button
            type="button"
            onClick={() => onNavigate('usg-and-lynis-cis-audit')}
            className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-all active:scale-95 shadow-sm"
          >
            <MaterialIcon name="policy" className="text-[16px] text-tertiary" />
            <span className="font-title-sm text-title-sm">Audit System</span>
          </button>

          <Tooltip explainerKey="snapshot-etc">
            <button
              type="button"
              onClick={() => {
                onTakeSnapshot();
                triggerToast('Captured atomic Btrfs & /etc Git checkpoint.');
              }}
              className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-primary-container text-on-primary-container hover:brightness-110 transition-all shadow-md active:scale-95 font-semibold"
            >
              <MaterialIcon name="sync_saved_locally" className="text-[16px]" />
              <span className="font-title-sm text-title-sm">Snapshot /etc</span>
            </button>
          </Tooltip>
        </div>
      </section>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="overview"
        onExecuteRecommendedAction={onTakeSnapshot}
        customActionLabel="Capture Safety Snapshot & Verify Health"
        defaultExpanded={false}
      />

      {/* Metric Quick Stats (Telemetry Grid) */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md">
        <div
          onClick={() => onNavigate('dns-sentry')}
          className="cursor-pointer flex flex-col justify-between p-space-md rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-sm hover:bg-surface-container-high/60 transition-all relative overflow-hidden"
        >
          <div className="flex items-start justify-between">
            <span className="font-label-md text-label-md text-on-surface-variant">
              DNS Queries Blocked
            </span>
            <MaterialIcon name="cloud_sync" className="text-tertiary text-[20px]" />
          </div>
          <div className="mt-space-md">
            <div className="flex items-baseline gap-space-xs">
              <span className="font-code-sm text-[28px] font-bold text-on-surface tracking-tight tabular-nums">
                4,281
              </span>
              <span className="font-code-sm text-code-sm text-tertiary">+12%</span>
            </div>
            <div className="flex items-center gap-1.5 mt-1">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary animate-pulse" />
              <span className="font-code-sm text-code-sm text-outline">
                NextDNS DoH Active (1.8ms)
              </span>
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-tertiary/40 to-transparent" />
        </div>

        <div
          onClick={() => onNavigate('outbound-intercepts')}
          className="cursor-pointer flex flex-col justify-between p-space-md rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-sm hover:bg-surface-container-high/60 transition-all relative overflow-hidden"
        >
          <div className="flex items-start justify-between">
            <span className="font-label-md text-label-md text-on-surface-variant">
              Unresolved Intercepts
            </span>
            <MaterialIcon name="filter_alt" className="text-secondary text-[20px]" />
          </div>
          <div className="mt-space-md">
            <div className="flex items-baseline gap-space-xs">
              <span className="font-code-sm text-[28px] font-bold text-on-surface tracking-tight tabular-nums">
                1
              </span>
              <span className="font-code-sm text-code-sm text-primary">Awaiting Triage</span>
            </div>
            <div className="flex items-center gap-1.5 mt-1">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary" />
              <span className="font-code-sm text-code-sm text-outline">
                eBPF OpenSnitch Filter Live
              </span>
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-secondary/40 to-transparent" />
        </div>

        <div
          onClick={() => onNavigate('rules-and-quarantine')}
          className="cursor-pointer flex flex-col justify-between p-space-md rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-sm hover:bg-surface-container-high/60 transition-all relative overflow-hidden"
        >
          <div className="flex items-start justify-between">
            <span className="font-label-md text-label-md text-on-surface-variant">
              AppArmor Integrity
            </span>
            <MaterialIcon name="verified" className="text-tertiary text-[20px]" />
          </div>
          <div className="mt-space-md">
            <div className="flex items-baseline gap-space-xs">
              <span className="font-code-sm text-[28px] font-bold text-on-surface tracking-tight">
                4 / 4
              </span>
              <span className="font-code-sm text-code-sm text-outline font-normal">Daemons</span>
            </div>
            <div className="flex items-center gap-1.5 mt-1">
              <span className="w-1.5 h-1.5 rounded-full bg-tertiary" />
              <span className="font-code-sm text-code-sm text-outline">
                Strict Enforcing (68 profiles)
              </span>
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-tertiary/40 to-transparent" />
        </div>

        <div
          onClick={() => onNavigate('daemon-restarts-and-needrestart')}
          className="cursor-pointer flex flex-col justify-between p-space-md rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-sm hover:bg-surface-container-high/60 transition-all relative overflow-hidden"
        >
          <div className="flex items-start justify-between">
            <span className="font-label-md text-label-md text-on-surface-variant">
              Pending needrestart
            </span>
            <MaterialIcon name="restart_alt" className="text-primary-container text-[20px]" />
          </div>
          <div className="mt-space-md">
            <div className="flex items-baseline gap-space-xs">
              <span className="font-code-sm text-[28px] font-bold text-primary-container tracking-tight tabular-nums">
                {staleCount}
              </span>
              <span className="font-code-sm text-code-sm text-primary font-medium">
                {staleCount > 0 ? 'CVE Alert' : 'All Clean'}
              </span>
            </div>
            <div className="flex items-center gap-1.5 mt-1">
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  staleCount > 0 ? 'bg-primary-container animate-ping' : 'bg-tertiary'
                }`}
              />
              <span className="font-code-sm text-code-sm text-outline">
                {staleCount > 0 ? 'libssl3 patched on disk' : 'In-RAM libraries synced'}
              </span>
            </div>
          </div>
          <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-primary-container/40 to-transparent" />
        </div>
      </section>

      {/* Critical Banner: needrestart & Kernel Telemetry */}
      <section className="rounded-xl bg-surface-container/85 backdrop-blur-xl border border-[#363243] shadow-md p-space-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
          <div className="flex items-start gap-space-md">
            <div className="w-10 h-10 rounded-lg bg-primary-container/20 flex items-center justify-center shrink-0">
              <MaterialIcon
                name={staleCount > 0 ? 'warning' : 'verified'}
                className="text-primary-container text-[22px]"
              />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-space-xs flex-wrap">
                <span className="font-title-sm text-title-sm text-on-surface">
                  {staleCount > 0
                    ? 'Stale Memory Modules Detected:'
                    : 'All Shared Object Mappings Synchronized:'}
                </span>
                <span className="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-primary">
                  libssl.so.3
                </span>
                <span className="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-primary">
                  libc.so.6
                </span>
                {staleCount > 0 && (
                  <span className="font-label-sm text-label-sm px-2 py-0.5 rounded-full bg-error-container text-on-error-container">
                    Critical CVE-2024-5535
                  </span>
                )}
              </div>
              <p className="font-body-md text-code-sm text-on-surface-variant mt-0.5">
                {staleCount > 0 ? (
                  <>
                    {staleCount} daemons run on superseded shared objects:{' '}
                    <span className="text-on-surface font-semibold">systemd-resolved</span>,{' '}
                    <span className="text-on-surface font-semibold">cron</span>. Memory remap
                    recommended.
                  </>
                ) : (
                  'All system and session daemons have been remapped to the latest canonical shared libraries.'
                )}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-space-xs self-end md:self-center shrink-0">
            <button
              type="button"
              onClick={() => triggerToast('Deferred needrestart reminder for 2 hours.')}
              className="px-space-md py-1.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-label-md text-label-md transition-colors"
            >
              Defer 2 Hours
            </button>
            <button
              type="button"
              disabled={restartingDaemons || staleCount === 0}
              onClick={handleGracefulRestart}
              className="flex items-center gap-space-xs px-space-md py-1.5 rounded-lg bg-primary-container text-on-primary-container font-title-sm text-title-sm hover:brightness-110 shadow-sm transition-all active:scale-95 disabled:opacity-50"
            >
              <MaterialIcon
                name="restart_alt"
                className={`text-[16px] ${restartingDaemons ? 'animate-spin' : ''}`}
              />
              <span>
                {restartingDaemons
                  ? 'Authenticating Polkit...'
                  : staleCount === 0
                    ? 'Daemons Remapped'
                    : 'Graceful Restart (Polkit)'}
              </span>
            </button>
          </div>
        </div>
        {/* Kernel & Boot Chain Attestation Footnote */}
        <div className="mt-space-md pt-space-xs border-t border-white/5 flex flex-wrap items-center justify-between gap-space-sm font-code-sm text-code-sm text-outline">
          <div className="flex items-center gap-space-xs flex-wrap">
            <MaterialIcon name="memory" className="text-[14px] text-tertiary" />
            <span>{systemTelemetry.kernelVersion}</span>
            <span>•</span>
            <span className="text-tertiary">Lockdown: {systemTelemetry.lockdownMode}</span>
            <span>•</span>
            <span>TPM 2.0: {systemTelemetry.tpmPcrStatus}</span>
            <span>•</span>
            <span>LUKS Keyslots: {systemTelemetry.luksKeyslotsActive} Armed</span>
          </div>
          <div className="flex items-center gap-space-xs">
            <MaterialIcon name="terminal" className="text-[14px]" />
            <span>/proc/sys/kernel/kptr_restrict: {systemTelemetry.kptrRestrict}</span>
          </div>
        </div>
      </section>

      {/* Central Grid: Live Feed & Service Health */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-space-md">
        {/* Left: AI-Augmented Real-time Incident Feed (7 cols) */}
        <div className="lg:col-span-7 flex flex-col rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-md p-space-md">
          <div className="flex items-center justify-between pb-space-sm">
            <div className="flex items-center gap-space-xs">
              <MaterialIcon name="bolt" className="text-secondary text-[20px]" />
              <h3 className="font-headline-md text-headline-md text-on-surface">
                Live Incident Feed
              </h3>
              <span className="font-code-sm text-code-sm px-1.5 py-0.5 rounded bg-surface-container-highest text-secondary">
                Gemini eBPF Hook
              </span>
            </div>
            <div className="flex items-center gap-1">
              {(['ALL', 'CRITICAL', 'WARN'] as const).map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setSeverityFilter(lvl)}
                  className={`px-2 py-0.5 rounded font-code-sm text-[10px] transition-colors ${
                    severityFilter === lvl
                      ? 'bg-primary-container text-white font-semibold'
                      : 'bg-surface-container-high text-on-surface-variant hover:text-on-surface'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-space-sm mt-space-xs">
            {filteredIncidents.map((inc) => (
              <div
                key={inc.id}
                className="p-space-sm rounded-lg bg-surface-container-low hover:bg-surface-container-high/70 border border-white/5 transition-colors"
              >
                <div className="flex items-start justify-between gap-space-xs flex-wrap">
                  <div className="flex items-center gap-space-xs">
                    <span className="font-code-sm text-code-sm text-outline">{inc.timestamp}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase ${
                        inc.severity === 'CRITICAL'
                          ? 'bg-error-container text-on-error-container'
                          : inc.severity === 'WARN' || inc.severity === 'MITIGATED'
                            ? 'bg-primary-container text-on-primary-container'
                            : 'bg-surface-container-highest text-tertiary'
                      }`}
                    >
                      {inc.isolated ? 'ISOLATED' : inc.severity}
                    </span>
                    <span className="font-title-sm text-title-sm text-on-surface">{inc.title}</span>
                  </div>
                  <span className="font-code-sm text-code-sm px-2 py-0.5 rounded-full bg-secondary-container text-on-secondary-container flex items-center gap-1">
                    <MaterialIcon name="auto_awesome" className="text-[12px]" />
                    <span>{inc.mitreTag}</span>
                  </span>
                </div>

                <div className="mt-space-xs font-code-sm text-code-sm text-on-surface-variant">
                  {inc.summary}
                </div>

                <div className="mt-2 p-2 rounded bg-surface-container/90 flex flex-col gap-1 shadow-inner border border-white/5">
                  <div className="flex items-center gap-1 text-secondary font-code-sm text-code-sm">
                    <MaterialIcon name="psychology" className="text-[14px]" />
                    <span>{inc.geminiInsight}</span>
                  </div>
                  <div className="flex items-center justify-between text-outline font-code-sm text-[11px] pt-1 flex-wrap gap-2">
                    <span>
                      Parent: {inc.parentProcess} → Target: {inc.targetSocket}
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() =>
                          setExpandedAiIncidentId(
                            expandedAiIncidentId === inc.id ? null : inc.id,
                          )
                        }
                        className="text-primary font-semibold hover:underline flex items-center gap-1"
                      >
                        <MaterialIcon name="auto_awesome" className="text-[14px]" />
                        <span>AI: Explain Threat & Recommend Action</span>
                      </button>
                      <span>•</span>
                      <Tooltip explainerKey="blast-radius">
                        <button
                          type="button"
                          onClick={() => handleInspectBlastRadius(inc)}
                          className="text-tertiary hover:underline font-semibold"
                        >
                          Blast Radius
                        </button>
                      </Tooltip>
                      <span>•</span>
                      <button
                        type="button"
                        onClick={() => {
                          onIsolateIncident(inc.id);
                          triggerToast(
                            `Frozen PID ${inc.pid} (${inc.binary}) in cgroup v2 /sentry.slice.`,
                          );
                        }}
                        className="text-primary hover:underline font-semibold"
                      >
                        {inc.isolated ? 'Isolated in cgroup' : 'Kill & Isolate PID'}
                      </button>
                      <span>•</span>
                      <button
                        type="button"
                        onClick={() => setLineageIncident(inc)}
                        className="text-secondary hover:underline"
                      >
                        View Lineage
                      </button>
                    </div>
                  </div>

                  {expandedAiIncidentId === inc.id && (
                    <div className="mt-2.5 p-3 rounded-xl bg-surface-container-highest/60 border border-primary/30 flex flex-col gap-2 animate-in fade-in">
                      <div className="flex items-center gap-1.5 text-primary font-semibold text-[12px] uppercase font-code-sm">
                        <MaterialIcon name="psychology" className="text-[16px]" />
                        <span>AI Plain-Language Threat Breakdown & Recommended Action</span>
                      </div>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[12px] font-body-md mt-1">
                        <div className="p-2.5 rounded-lg bg-surface-container border border-white/5">
                          <span className="font-bold text-on-surface block mb-1">1. What is this?</span>
                          <span className="text-on-surface-variant">
                            The program <code className="text-primary">{inc.binary}</code> (PID {inc.pid}) triggered a high-risk security alert ({inc.severity}).
                          </span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-surface-container border border-error/20">
                          <span className="font-bold text-error block mb-1">2. Where threat comes from:</span>
                          <span className="text-on-surface-variant">
                            Spawned by parent process <code className="text-on-surface">{inc.parentProcess}</code> attempting an outbound socket connection to <code className="text-on-surface">{inc.targetSocket}</code>.
                          </span>
                        </div>
                        <div className="p-2.5 rounded-lg bg-surface-container border border-tertiary/20 flex flex-col justify-between">
                          <div>
                            <span className="font-bold text-tertiary block mb-1">3. How to handle it:</span>
                            <span className="text-on-surface-variant">
                              Isolate this process in a frozen cgroup slice so it cannot transmit data, then verify the crontab or launcher.
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => {
                              onIsolateIncident(inc.id);
                              triggerToast(`Frozen PID ${inc.pid} in cgroup v2.`);
                            }}
                            className="mt-2 py-1 px-2.5 rounded bg-primary text-white font-semibold text-[11px] hover:brightness-110 flex items-center justify-center gap-1"
                          >
                            <MaterialIcon name="lock" className="text-[13px]" />
                            <span>{inc.isolated ? 'Already Isolated' : 'Freeze & Isolate Now'}</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Active Security Services Health (5 cols) */}
        <div className="lg:col-span-5 flex flex-col rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-md p-space-md">
          <div className="flex items-center justify-between pb-space-sm">
            <div className="flex items-center gap-space-xs">
              <MaterialIcon name="security" className="text-tertiary text-[20px]" />
              <h3 className="font-headline-md text-headline-md text-on-surface">
                Core Security Services
              </h3>
            </div>
            <span className="font-label-sm text-label-sm px-2 py-0.5 rounded bg-tertiary/10 text-tertiary font-mono">
              Ubuntu 24.04
            </span>
          </div>

          <div className="flex flex-col gap-space-xs mt-space-xs">
            <div className="flex items-center justify-between p-space-md rounded-lg bg-surface-container-low">
              <div className="flex items-center gap-space-md">
                <div className="w-8 h-8 rounded-full bg-surface-container-high flex items-center justify-center shrink-0">
                  <MaterialIcon
                    name="local_fire_department"
                    className="text-tertiary text-[18px]"
                  />
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-title-sm text-title-sm text-on-surface">
                      UFW (Firewall)
                    </span>
                    <span
                      className={`w-2 h-2 rounded-full ${ufwEnabled ? 'bg-tertiary' : 'bg-error'}`}
                    />
                  </div>
                  <span className="font-code-sm text-code-sm text-outline">
                    Default Deny Inbound • WireGuard/DNS Out
                  </span>
                </div>
              </div>
              <input
                aria-label="Toggle UFW"
                checked={ufwEnabled}
                onChange={(e) => setUfwEnabled(e.target.checked)}
                className="w-5 h-5 accent-primary-container cursor-pointer rounded"
                type="checkbox"
              />
            </div>

            <div
              onClick={() => onNavigate('rules-and-quarantine')}
              className="cursor-pointer flex items-center justify-between p-space-md rounded-lg bg-surface-container-low hover:bg-surface-container-high/50 transition-colors"
            >
              <div className="flex items-center gap-space-md">
                <div className="w-8 h-8 rounded-full bg-surface-container-high flex items-center justify-center shrink-0">
                  <MaterialIcon name="verified_user" className="text-tertiary text-[18px]" />
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-title-sm text-title-sm text-on-surface">
                      AppArmor LSM
                    </span>
                    <span className="w-2 h-2 rounded-full bg-tertiary" />
                  </div>
                  <span className="font-code-sm text-code-sm text-outline">
                    68 loaded • {isLockdown ? '0 in complain mode' : '4 in complain mode'}
                  </span>
                </div>
              </div>
              <span className="font-code-sm text-code-sm px-2 py-0.5 rounded bg-tertiary/10 text-tertiary">
                Enforce
              </span>
            </div>

            <div className="flex items-center justify-between p-space-md rounded-lg bg-surface-container-low">
              <div className="flex items-center gap-space-md">
                <div className="w-8 h-8 rounded-full bg-surface-container-high flex items-center justify-center shrink-0">
                  <MaterialIcon name="shield_person" className="text-tertiary text-[18px]" />
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-title-sm text-title-sm text-on-surface">
                      Fail2ban + CrowdSec
                    </span>
                    <span className="w-2 h-2 rounded-full bg-tertiary" />
                  </div>
                  <span className="font-code-sm text-code-sm text-outline">
                    sshd, nginx, sudo • 3 IP drops
                  </span>
                </div>
              </div>
              <span className="font-code-sm text-code-sm px-2 py-0.5 rounded bg-surface-container-highest text-on-surface">
                3 Bans
              </span>
            </div>

            <div className="flex items-center justify-between p-space-md rounded-lg bg-surface-container-low">
              <div className="flex items-center gap-space-md">
                <div className="w-8 h-8 rounded-full bg-surface-container-high flex items-center justify-center shrink-0">
                  <MaterialIcon name="usb" className="text-tertiary text-[18px]" />
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-title-sm text-title-sm text-on-surface">
                      USBGuard IPC
                    </span>
                    <span className="w-2 h-2 rounded-full bg-tertiary" />
                  </div>
                  <span className="font-code-sm text-code-sm text-outline">
                    BadUSB & MassStorage Blocked by Default
                  </span>
                </div>
              </div>
              <span className="font-code-sm text-code-sm px-2 py-0.5 rounded bg-tertiary/10 text-tertiary">
                Locked
              </span>
            </div>
          </div>

          <div className="mt-auto pt-space-md">
            <button
              type="button"
              disabled={debsumsStatus === 'scanning'}
              onClick={handleDebsumsScan}
              className="w-full flex items-center justify-center gap-space-xs p-2.5 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface transition-all active:scale-[0.99] shadow-sm"
            >
              <MaterialIcon
                name={
                  debsumsStatus === 'scanning'
                    ? 'refresh'
                    : debsumsStatus === 'clean'
                      ? 'done_all'
                      : 'manage_search'
                }
                className={`text-[16px] text-tertiary ${
                  debsumsStatus === 'scanning' ? 'animate-spin' : ''
                }`}
              />
              <span className="font-title-sm text-title-sm">
                {debsumsStatus === 'scanning'
                  ? 'Verifying /usr checksums...'
                  : debsumsStatus === 'clean'
                    ? 'Packages Verified via Debsums'
                    : 'Scan Package Integrity (debsums)'}
              </span>
            </button>
          </div>
        </div>
      </section>

      {/* Network Co-existence & Telemetry Inspector Tray */}
      <section className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
        <div className="p-space-md rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-title-sm text-title-sm text-on-surface">
              WireGuard (wg0-proton)
            </span>
            <MaterialIcon name="sync_alt" className="text-tertiary text-[18px]" />
          </div>
          <div className="my-space-sm space-y-1">
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Endpoint:</span>
              <span className="text-on-surface">185.159.157.34:51820</span>
            </div>
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Rx / Tx:</span>
              <span className="text-on-surface">4.82 GiB / 1.15 GiB</span>
            </div>
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">AllowedIPs:</span>
              <span className="text-tertiary">0.0.0.0/0, ::/0</span>
            </div>
          </div>
          <div className="w-full bg-surface-container-high rounded-full h-1.5 overflow-hidden">
            <div className="bg-tertiary h-1.5 rounded-full" style={{ width: '82%' }} />
          </div>
        </div>

        <div className="p-space-md rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-title-sm text-title-sm text-on-surface">
              NextDNS + Proton Routing
            </span>
            <MaterialIcon name="hub" className="text-secondary text-[18px]" />
          </div>
          <div className="my-space-sm space-y-1">
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Systemd-resolved:</span>
              <span className="text-tertiary">Link 4 (~. Exclusive)</span>
            </div>
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Crypt Engine:</span>
              <span className="text-on-surface">DNS-over-HTTPS (DoH)</span>
            </div>
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Leak Test:</span>
              <span className="text-tertiary font-semibold">0 Leaks Detected</span>
            </div>
          </div>
          <div className="w-full bg-surface-container-high rounded-full h-1.5 overflow-hidden">
            <div className="bg-secondary h-1.5 rounded-full" style={{ width: '100%' }} />
          </div>
        </div>

        <div className="p-space-md rounded-xl bg-surface-container/70 backdrop-blur-xl border border-[#363243] shadow-sm flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-title-sm text-title-sm text-on-surface">
              Lynis CIS Compliance
            </span>
            <MaterialIcon name="fact_check" className="text-primary-container text-[18px]" />
          </div>
          <div className="my-space-sm space-y-1">
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Hardening Index:</span>
              <span className="text-primary-container font-bold">84 / 100</span>
            </div>
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Suggestions:</span>
              <span className="text-on-surface">3 items queued</span>
            </div>
            <div className="flex justify-between font-code-sm text-code-sm">
              <span className="text-outline">Last Lynis Scan:</span>
              <span className="text-outline">Today, 06:00 UTC</span>
            </div>
          </div>
          <div className="w-full bg-surface-container-high rounded-full h-1.5 overflow-hidden">
            <div className="bg-primary-container h-1.5 rounded-full" style={{ width: '84%' }} />
          </div>
        </div>
      </section>

      {/* Feature 8: Systemd Service Isolation & Exposure Auditing Pipeline */}
      <section className="rounded-xl bg-surface-container/75 backdrop-blur-xl border border-[#363243] p-space-md shadow-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-space-sm">
          <div className="flex items-center gap-space-xs">
            <MaterialIcon name="shield_lock" className="text-secondary text-[20px]" />
            <h3 className="font-title-sm text-title-sm text-on-surface">
              Systemd Service Isolation & Exposure Pipeline (systemd-analyze security)
            </h3>
          </div>
          <span className="font-code-sm text-code-sm text-on-surface-variant">
            0.0 (Hardened) → 10.0 (Exposed) • AI Drop-In Generator Ready
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-space-sm">
          {systemdUnits.map((u) => (
            <div
              key={u.unit}
              className="p-space-sm rounded-lg bg-surface-container-low border border-white/5 flex flex-col justify-between gap-2"
            >
              <div className="flex items-center justify-between">
                <span className="font-code-sm text-code-sm text-on-surface font-semibold truncate">
                  {u.unit}
                </span>
                <span
                  className={`font-code-sm text-code-sm font-bold px-1.5 py-0.5 rounded ${
                    u.exposureScore < 3
                      ? 'bg-tertiary/15 text-tertiary'
                      : u.exposureScore < 5
                        ? 'bg-primary/15 text-primary'
                        : 'bg-error-container text-on-error-container'
                  }`}
                >
                  {u.exposureScore.toFixed(1)} {u.level}
                </span>
              </div>
              <div className="font-code-sm text-[10px] text-on-surface-variant space-y-0.5">
                <div>ProtectSystem={u.protectSystem}</div>
                <div>
                  ProtectHome={u.protectHome} • NoNewPrivs={u.noNewPrivileges ? 'yes' : 'no'}
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedDropIn(u)}
                className="w-full py-1 rounded bg-surface-container-high hover:bg-surface-bright text-secondary font-label-sm text-label-sm transition-colors"
              >
                Draft 99-hardening.conf
              </button>
            </div>
          ))}
        </div>
        {selectedDropIn && (
          <div className="mt-space-sm p-space-md rounded-lg bg-surface-container-lowest border border-secondary/40 flex flex-col gap-2">
            <div className="flex items-center justify-between">
              <span className="font-code-sm text-code-sm text-secondary font-semibold">
                /etc/systemd/system/{selectedDropIn.unit}.d/99-hardening.conf (AI Simulated Dry-Run
                Passed)
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    triggerToast(
                      `Applied drop-in override for ${selectedDropIn.unit} via systemctl daemon-reload.`,
                    );
                    setSelectedDropIn(null);
                  }}
                  className="px-2.5 py-1 rounded bg-primary-container text-white font-label-sm text-label-sm font-semibold"
                >
                  Apply Drop-In (Polkit)
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedDropIn(null)}
                  className="text-on-surface-variant hover:text-on-surface font-code-sm text-code-sm"
                >
                  Close
                </button>
              </div>
            </div>
            <pre className="font-code-sm text-code-sm text-tertiary whitespace-pre-wrap">
              {selectedDropIn.dropInDraft}
            </pre>
          </div>
        )}
      </section>

      {/* Blast Radius Modal */}
      {blastModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-xl rounded-xl bg-surface-container border border-primary-container p-space-lg shadow-2xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MaterialIcon name="neurology" className="text-secondary text-[22px]" />
                <h3 className="font-headline-md text-headline-md text-on-surface">
                  Pre-Execution Blast Radius Analysis (PID {blastModal.pid})
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setBlastModal(null)}
                className="text-on-surface-variant hover:text-on-surface"
              >
                <MaterialIcon name="close" />
              </button>
            </div>
            <p className="font-body-md text-body-md text-on-surface bg-surface-container-lowest p-3 rounded-lg">
              {blastModal.riskSummary}
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 font-code-sm text-code-sm">
              <div className="p-2.5 rounded bg-surface-container-low">
                <div className="text-outline uppercase text-[10px]">Dependent Processes</div>
                {blastModal.dependentProcesses.map((d, i) => (
                  <div key={i} className="text-on-surface mt-0.5">
                    • {d}
                  </div>
                ))}
              </div>
              <div className="p-2.5 rounded bg-surface-container-low">
                <div className="text-outline uppercase text-[10px]">Recommended Surgical Action</div>
                <div className="text-tertiary font-bold mt-1">{blastModal.recommendedAction}</div>
                <div className="text-on-surface-variant text-[10px] mt-0.5">
                  GNOME / Wayland / PipeWire Safe: {blastModal.desktopSessionSafe ? 'YES' : 'NO'}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setBlastModal(null)}
                className="px-4 py-1.5 rounded-lg bg-surface-container-high text-on-surface font-label-md"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={() => {
                  triggerToast(
                    `Executed ${blastModal.recommendedAction} on PID ${blastModal.pid}.`,
                  );
                  setBlastModal(null);
                }}
                className="px-4 py-1.5 rounded-lg bg-primary-container text-white font-label-md font-semibold"
              >
                Execute {blastModal.recommendedAction}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Lineage Call Tree Modal */}
      {lineageIncident && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-xl bg-surface-container border border-secondary p-space-lg shadow-2xl space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-headline-md text-headline-md text-on-surface">
                eBPF Syscall Execution Lineage (pstree)
              </span>
              <button
                type="button"
                onClick={() => setLineageIncident(null)}
                className="text-on-surface-variant hover:text-on-surface"
              >
                <MaterialIcon name="close" />
              </button>
            </div>
            <pre className="p-3 rounded-lg bg-surface-container-lowest font-code-sm text-code-sm text-tertiary overflow-x-auto">
              {`systemd (PID 1, root)
 └─ ${lineageIncident.parentProcess} (daemon)
     └─ /bin/sh -c "crontab worker"
         └─ ${lineageIncident.binary} (PID ${lineageIncident.pid})
             └─ socket -> ${lineageIncident.targetSocket} [${lineageIncident.mitreTag}]`}
            </pre>
            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => setLineageIncident(null)}
                className="px-4 py-1.5 rounded-lg bg-primary-container text-white font-label-md"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

interface DnsSentryDeckProps {
  queries: DnsQueryRecord[];
  onAllowDomain: (id: string) => void;
  onDenyDomain: (id: string) => void;
  onClearQueries: () => void;
  onAddSimulatedQuery: (q: DnsQueryRecord) => void;
}

export const DnsSentryDeck: React.FC<DnsSentryDeckProps> = ({
  queries,
  onAllowDomain,
  onDenyDomain,
  onClearQueries,
  onAddSimulatedQuery,
}) => {
  const [paused, setPaused] = useState(false);
  const [search, setSearch] = useState('');
  const [activeFilter, setActiveFilter] = useState<
    'ALL' | 'BLOCKED' | 'ALLOWED' | 'C2' | 'DOH'
  >('ALL');
  const [cnameAlert, setCnameAlert] = useState<DnsQueryRecord | null>(null);
  const [rescueStatus, setRescueStatus] = useState<string | null>(null);

  useEffect(() => {
    if (paused) return;
    const samplePool: Array<Omit<DnsQueryRecord, 'id' | 'timestamp'>> = [
      {
        process: '/usr/lib/firefox/firefox',
        pid: 8821,
        domain: 'metrics.icloud-analytics.com',
        recordType: 'A',
        cnameChain: 'edge-ingest.adtracker.net',
        resolvedIp: '0.0.0.0',
        category: 'Tracker / Telemetry',
        threatFeed: 'NextDNS HaGeZi PRO++',
        protocol: 'DoH (NextDNS)',
        dnssec: true,
        status: 'Blocked',
        latencyMs: 0.4,
      },
      {
        process: '/usr/bin/curl',
        pid: 14210,
        domain: 'crates.io',
        recordType: 'HTTPS',
        cnameChain: 'fastly.crates.io',
        resolvedIp: '151.101.1.194',
        category: 'Developer Package Registry',
        protocol: 'DoH (NextDNS)',
        dnssec: true,
        status: 'Allowed',
        latencyMs: 1.7,
        cnameDependencyWarning:
          'CAUTION: Blocking crates.io / fastly.crates.io will break Cargo builds.',
      },
      {
        process: '/usr/bin/python3',
        pid: 31022,
        domain: 'generativelanguage.googleapis.com',
        recordType: 'A',
        resolvedIp: '142.250.185.106',
        category: 'Google Gemini API',
        protocol: 'DoH (NextDNS)',
        dnssec: true,
        status: 'Allowed',
        latencyMs: 1.9,
      },
    ];

    const timer = window.setInterval(() => {
      const pick = samplePool[Math.floor(Math.random() * samplePool.length)];
      const now = new Date();
      const ts = `${now.toTimeString().split(' ')[0]}.${String(now.getMilliseconds()).padStart(3, '0')}`;
      onAddSimulatedQuery({
        ...pick,
        id: `dns-${Date.now()}`,
        timestamp: ts,
      });
    }, 3500);
    return () => clearInterval(timer);
  }, [paused, onAddSimulatedQuery]);

  const filtered = queries.filter((q) => {
    if (activeFilter === 'BLOCKED' && q.status !== 'Blocked') return false;
    if (activeFilter === 'ALLOWED' && q.status !== 'Allowed') return false;
    if (activeFilter === 'C2' && q.status !== 'C2 Flagged') return false;
    if (search.trim()) {
      try {
        const rx = new RegExp(search.trim(), 'i');
        return rx.test(q.domain) || rx.test(q.process) || rx.test(q.resolvedIp);
      } catch {
        const s = search.toLowerCase();
        return (
          q.domain.toLowerCase().includes(s) ||
          q.process.toLowerCase().includes(s) ||
          q.resolvedIp.toLowerCase().includes(s)
        );
      }
    }
    return true;
  });

  const handleDenyClick = (q: DnsQueryRecord) => {
    if (q.cnameDependencyWarning && q.cnameDependencyWarning.startsWith('CAUTION')) {
      setCnameAlert(q);
      return;
    }
    onDenyDomain(q.id);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(queries, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentrylinux-nextdns-stream.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col w-full gap-space-lg select-text">
      {/* Title & Stream Diagnostics Row */}
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-space-md">
        <div className="flex flex-col gap-space-xs">
          <div className="flex items-center gap-space-sm flex-wrap">
            <div className="flex items-center gap-space-xs bg-surface-container-high px-2.5 py-1 rounded-lg shadow-sm">
              <MaterialIcon name="stream" className="text-primary-container text-[18px]" />
              <h1 className="font-headline-md text-headline-md text-on-surface tracking-tight font-semibold">
                DNS Sentry — Live Query Stream
              </h1>
            </div>
            <span className="font-code-sm text-code-sm px-2 py-0.5 rounded-full bg-surface-container-high text-on-surface-variant">
              wg0-proton / resolvectl link 4
            </span>
          </div>
          <p className="font-body-md text-body-md text-on-surface-variant/80">
            Kernel socket hooks intercepting eBPF cgroup egress paired with NextDNS ultra-low
            latency DoH resolver and CNAME dependency untangling.
          </p>
        </div>

        <div className="flex items-center gap-space-sm flex-wrap">
          <div className="flex items-center gap-space-xs px-3 py-1.5 rounded-full bg-surface-container-low border border-[#363243]">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-tertiary opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-tertiary" />
            </span>
            <span className="font-label-md text-label-md text-on-surface">
              SSE Live Stream:{' '}
              <span className="font-code-sm text-tertiary-fixed-dim">NextDNS DoH (link 4)</span>
            </span>
          </div>
          <div className="flex items-center gap-space-xs px-3 py-1.5 rounded-full bg-surface-container-low border border-[#363243]">
            <MaterialIcon name="speed" className="text-[15px] text-tertiary" />
            <span className="font-label-md text-label-md text-on-surface">
              RTT: <span className="font-code-sm text-tertiary font-semibold">1.8ms</span>
            </span>
          </div>
          <button
            type="button"
            onClick={() => {
              setRescueStatus('Flushed systemd-resolved caches & verified DoH upstream.');
              window.setTimeout(() => setRescueStatus(null), 3500);
            }}
            className="flex items-center gap-space-xs px-3 py-1.5 rounded-full bg-surface-container-high hover:bg-surface-bright text-primary font-label-md"
          >
            <MaterialIcon name="medical_services" className="text-[15px]" />
            <span>Rescue DNS Watchdog</span>
          </button>
        </div>
      </div>

      {rescueStatus && (
        <div className="p-3 rounded-xl bg-tertiary-container/20 border border-tertiary text-tertiary font-code-sm text-code-sm flex items-center justify-between">
          <span>[Rescue DNS Watchdog] {rescueStatus}</span>
          <button type="button" onClick={() => setRescueStatus(null)}>
            Dismiss
          </button>
        </div>
      )}

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="dns-sentry"
        onExecuteRecommendedAction={() =>
          setRescueStatus(
            'Rescue DNS verified: 45.90.28.0 (DoH link 4) active with 0.0ms leak.',
          )
        }
        customActionLabel="Test Encrypted DNS & Block Trackers"
        defaultExpanded={false}
      />

      {/* Action Toolbar */}
      <div className="p-space-sm rounded-xl bg-surface-container-low border border-[#363243] shadow-md flex flex-col gap-space-sm">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-space-sm">
          <div className="relative flex-1 min-w-[280px]">
            <MaterialIcon
              name="search"
              className="absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-[18px]"
            />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-surface-container-lowest text-on-surface font-code-sm text-code-sm pl-9 pr-24 py-2 rounded-lg border border-[#363243] focus:outline-none focus:ring-1 focus:ring-primary-container placeholder:text-on-surface-variant/40"
              placeholder="Search domains, client processes (/usr/bin/curl), or IPs (supports regex ^.*)..."
              type="text"
            />
            <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1.5 pointer-events-none">
              <span className="font-code-sm text-[10px] text-on-surface-variant bg-surface-container px-1.5 py-0.5 rounded">
                .* REGEX
              </span>
            </div>
          </div>

          <div className="flex items-center gap-space-xs overflow-x-auto">
            <button
              type="button"
              onClick={() => setPaused(!paused)}
              className="flex items-center gap-space-xs px-3 py-1.5 rounded-lg bg-primary-container text-on-primary-container hover:opacity-90 transition-all shadow-sm"
            >
              <MaterialIcon name={paused ? 'play_arrow' : 'pause'} className="text-[16px]" />
              <span className="font-label-md text-label-md font-semibold">
                {paused ? 'Resume Stream' : 'Pause Stream'}
              </span>
            </button>
            <button
              type="button"
              onClick={onClearQueries}
              className="flex items-center gap-space-xs px-3 py-1.5 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-bright transition-all shadow-sm"
            >
              <MaterialIcon name="mop" className="text-[16px] text-on-surface-variant" />
              <span className="font-label-md text-label-md">Clear Buffer</span>
            </button>
            <button
              type="button"
              onClick={handleExportJson}
              className="flex items-center gap-space-xs px-3 py-1.5 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-bright transition-all shadow-sm"
            >
              <MaterialIcon name="download" className="text-[16px] text-on-surface-variant" />
              <span className="font-label-md text-label-md">Export PCAP/JSON</span>
            </button>
          </div>
        </div>

        {/* Quick Filter Pills */}
        <div className="flex items-center gap-space-xs overflow-x-auto pt-1">
          {[
            { id: 'ALL', label: `All Queries (${queries.length})` },
            {
              id: 'BLOCKED',
              label: `Blocked Trackers (${queries.filter((q) => q.status === 'Blocked').length})`,
            },
            {
              id: 'ALLOWED',
              label: `Allowed (${queries.filter((q) => q.status === 'Allowed').length})`,
            },
            {
              id: 'C2',
              label: `Malware / C2 Flagged (${queries.filter((q) => q.status === 'C2 Flagged').length})`,
            },
            { id: 'DOH', label: 'Encrypted DoH/DoT (99.4%)' },
          ].map((pill) => (
            <button
              key={pill.id}
              type="button"
              onClick={() => setActiveFilter(pill.id as typeof activeFilter)}
              className={`px-3 py-1 rounded-full text-label-sm font-label-sm transition-all ${
                activeFilter === pill.id
                  ? 'bg-primary-container text-on-primary-container font-semibold'
                  : 'bg-surface-container text-on-surface hover:bg-surface-container-high'
              }`}
            >
              {pill.label}
            </button>
          ))}
        </div>
      </div>

      {/* CNAME Dependency Untangler Warning Modal */}
      {cnameAlert && (
        <div className="p-space-md rounded-xl bg-surface-container-high border-2 border-primary-container shadow-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-md">
          <div className="flex items-start gap-3">
            <MaterialIcon name="auto_awesome" className="text-secondary text-[22px] shrink-0" />
            <div>
              <div className="font-title-sm text-title-sm text-primary font-bold">
                Gemini NextDNS CNAME & CDN Dependency Untangler
              </div>
              <p className="font-code-sm text-code-sm text-on-surface mt-0.5">
                {cnameAlert.cnameDependencyWarning}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => setCnameAlert(null)}
              className="px-3 py-1.5 rounded-lg bg-surface-container text-on-surface font-label-md"
            >
              Keep Allowed (Safe)
            </button>
            <button
              type="button"
              onClick={() => {
                onDenyDomain(cnameAlert.id);
                setCnameAlert(null);
              }}
              className="px-3 py-1.5 rounded-lg bg-error-container text-on-error-container font-label-md font-semibold"
            >
              Force Block Anyway
            </button>
          </div>
        </div>
      )}

      {/* KPI Metric Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-space-md">
        <div className="rounded-xl bg-surface-container border border-[#363243] p-space-md shadow-md flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Total Ingested (24h)
            </span>
            <MaterialIcon name="dns" className="text-[18px] text-tertiary" />
          </div>
          <div className="flex items-baseline gap-space-xs mt-space-sm">
            <span className="font-display-lg text-[28px] font-bold text-on-surface tracking-tight tabular-nums">
              1,284,912
            </span>
            <span className="font-code-sm text-code-sm text-tertiary">+12.4%</span>
          </div>
          <div className="mt-space-xs flex items-center gap-1.5">
            <div className="h-1.5 flex-1 bg-surface-container-highest rounded-full overflow-hidden">
              <div className="h-full bg-tertiary-container w-[99.4%]" />
            </div>
            <span className="font-code-sm text-[10px] text-on-surface-variant font-medium">
              99.4% DoH
            </span>
          </div>
        </div>

        <div className="rounded-xl bg-surface-container border border-[#363243] p-space-md shadow-md flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-error">
              Threats & C2 Neutralized
            </span>
            <MaterialIcon name="shield" className="text-[18px] text-error" />
          </div>
          <div className="flex items-baseline gap-space-xs mt-space-sm">
            <span className="font-display-lg text-[28px] font-bold text-error tracking-tight tabular-nums">
              1,402
            </span>
            <span className="font-label-sm text-label-sm text-on-surface-variant">quarantined</span>
          </div>
          <div className="mt-space-xs flex items-center justify-between text-on-surface-variant">
            <span className="font-code-sm text-[11px] text-error/90">NextDNS + ThreatFeed</span>
            <span className="font-code-sm text-[10px] bg-error-container text-on-error-container px-1.5 py-0.5 rounded font-semibold">
              100% Intercept
            </span>
          </div>
        </div>

        <div className="rounded-xl bg-surface-container border border-[#363243] p-space-md shadow-md flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Tracking Suppressed
            </span>
            <MaterialIcon name="filter_alt" className="text-[18px] text-primary" />
          </div>
          <div className="flex items-baseline gap-space-xs mt-space-sm">
            <span className="font-display-lg text-[28px] font-bold text-on-surface tracking-tight tabular-nums">
              38.6%
            </span>
            <span className="font-code-sm text-code-sm text-primary">overall egress</span>
          </div>
          <div className="mt-space-xs flex items-center gap-1.5">
            <div className="h-1.5 flex-1 bg-surface-container-highest rounded-full overflow-hidden">
              <div className="h-full bg-primary-container w-[38.6%]" />
            </div>
            <span className="font-code-sm text-[10px] text-on-surface-variant">496,170 Drops</span>
          </div>
        </div>

        <div className="rounded-xl bg-surface-container border border-[#363243] p-space-md shadow-md flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Avg Resolution Time
            </span>
            <MaterialIcon name="bolt" className="text-[18px] text-secondary" />
          </div>
          <div className="flex items-baseline justify-between mt-space-sm">
            <div className="flex items-baseline gap-1">
              <span className="font-display-lg text-[28px] font-bold text-on-surface tracking-tight tabular-nums">
                1.84
              </span>
              <span className="font-code-sm text-code-sm text-tertiary">ms</span>
            </div>
            <svg className="w-24 h-6 text-tertiary" fill="none" viewBox="0 0 100 24">
              <path
                d="M0,18 L12,16 L24,19 L36,12 L48,15 L60,8 L72,11 L84,5 L96,7 L100,6"
                stroke="currentColor"
                strokeLinecap="round"
                strokeWidth="2"
              />
            </svg>
          </div>
          <div className="mt-space-xs flex items-center justify-between">
            <span className="font-code-sm text-[11px] text-on-surface-variant">
              Anycast Edge: Frankfurt-FRA1
            </span>
            <span className="w-2 h-2 rounded-full bg-tertiary" />
          </div>
        </div>
      </div>

      {/* Real-Time SSE Stream Monospace Tabular Panel */}
      <div className="rounded-xl bg-surface-container border border-[#363243] overflow-hidden shadow-xl flex flex-col">
        <div className="px-space-md py-space-sm bg-surface-container-high flex items-center justify-between">
          <div className="flex items-center gap-space-sm">
            <MaterialIcon name="terminal" className="text-primary text-[18px]" />
            <span className="font-title-sm text-title-sm text-on-surface">
              Live Resolv Egress Socket Stream
            </span>
            <span className="font-code-sm text-code-sm px-2 py-0.5 rounded bg-surface-container text-tertiary">
              {filtered.length} buffered records
            </span>
          </div>
          <Tooltip explainerKey="cname-untangler">
            <span className="font-code-sm text-code-sm text-secondary flex items-center gap-1 cursor-help">
              <MaterialIcon name="auto_awesome" className="text-[14px]" />
              CNAME Untangler Active
            </span>
          </Tooltip>
        </div>

        <div className="overflow-x-auto w-full">
          <table className="w-full text-left font-code-sm text-code-sm border-collapse min-w-[960px]">
            <thead>
              <tr className="bg-surface-container-highest/60 text-on-surface-variant uppercase text-[10px] tracking-wider font-semibold">
                <th className="py-2.5 px-space-md">Timestamp</th>
                <th className="py-2.5 px-space-md">Client / Process</th>
                <th className="py-2.5 px-space-md">Domain & CNAME Chain</th>
                <th className="py-2.5 px-space-md">Category</th>
                <th className="py-2.5 px-space-md">Protocol</th>
                <th className="py-2.5 px-space-md">Status</th>
                <th className="py-2.5 px-space-md text-right">Inline Gate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-container-highest/30">
              {filtered.map((q) => (
                <tr
                  key={q.id}
                  className={`transition-colors ${
                    q.status === 'C2 Flagged'
                      ? 'bg-error-container/20 hover:bg-error-container/30'
                      : 'hover:bg-white/5'
                  }`}
                >
                  <td className="py-3 px-space-md text-on-surface-variant tabular-nums">
                    {q.timestamp}
                  </td>
                  <td className="py-3 px-space-md">
                    <div className="flex items-center gap-1.5">
                      <MaterialIcon name="terminal" className="text-[14px] text-primary" />
                      <span className="text-on-surface font-semibold">{q.process}</span>
                      <span className="text-on-surface-variant/70 text-[10px] bg-surface-container-low px-1 rounded">
                        PID {q.pid}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-space-md">
                    <div className="flex items-center gap-1.5 font-semibold">
                      <span
                        className={
                          q.status === 'C2 Flagged' ? 'text-error' : 'text-on-surface'
                        }
                      >
                        {q.domain}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-container-highest text-on-surface-variant">
                        {q.recordType}
                      </span>
                    </div>
                    {q.cnameChain && (
                      <div className="text-[10px] text-on-surface-variant/80">
                        CNAME → {q.cnameChain} ({q.resolvedIp})
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-space-md text-on-surface-variant">{q.category}</td>
                  <td className="py-3 px-space-md">
                    <span className="text-tertiary">{q.protocol}</span>
                  </td>
                  <td className="py-3 px-space-md">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                        q.status === 'Allowed'
                          ? 'bg-tertiary/15 text-tertiary'
                          : 'bg-error-container text-on-error-container'
                      }`}
                    >
                      {q.status}
                    </span>
                  </td>
                  <td className="py-3 px-space-md text-right space-x-1.5">
                    <button
                      type="button"
                      onClick={() => onAllowDomain(q.id)}
                      className="px-2.5 py-1 rounded bg-tertiary/15 hover:bg-tertiary/25 text-tertiary font-semibold transition-colors"
                    >
                      Allow
                    </button>
                    <button
                      type="button"
                      onClick={() => handleDenyClick(q)}
                      className="px-2.5 py-1 rounded bg-error-container/70 hover:bg-error-container text-on-error-container font-semibold transition-colors"
                    >
                      Deny
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

interface OutboundInterceptsDeckProps {
  intercepts: InterceptSocketEvent[];
  onResolveIntercept: (
    id: string,
    verdict: 'ALLOW_ONCE' | 'ALLOW_ALWAYS' | 'DENY',
  ) => void;
}

export const OutboundInterceptsDeck: React.FC<OutboundInterceptsDeckProps> = ({
  intercepts,
  onResolveIntercept,
}) => {
  const pendingIntercept = intercepts.find((i) => i.verdict === 'PENDING') ?? null;
  const [selectedModalId, setSelectedModalId] = useState<string | null>(
    pendingIntercept?.id ?? 'int-1',
  );
  const [countdown, setCountdown] = useState(42);
  const [nlPolicyPrompt, setNlPolicyPrompt] = useState(
    'Only allow my local subnet 192.168.1.0/24 to connect to port 8080, drop everything else, and limit failed attempts to 3 per minute.',
  );
  const [compiledRuleOutput, setCompiledRuleOutput] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);

  const activeModalEvent =
    intercepts.find((i) => i.id === selectedModalId) || pendingIntercept;

  useEffect(() => {
    if (!activeModalEvent) return;
    const t = window.setInterval(() => {
      setCountdown((c) => (c > 1 ? c - 1 : 42));
    }, 1000);
    return () => clearInterval(t);
  }, [activeModalEvent]);

  const handleCompilePolicy = async () => {
    const res = await queryAskSentry(nlPolicyPrompt);
    setCompiledRuleOutput(
      `# Validated UFW + Fail2ban Native Rules\n${res.translatedCommand}\n\n# Fail2ban Jail (/etc/fail2ban/jail.d/port-8080.local)\n[port-8080-sentry]\nenabled = true\nport = 8080\nmaxretry = 3\nfindtime = 60\nbantime = 3600`,
    );
  };

  return (
    <div className="flex flex-col w-full gap-space-lg relative select-text">
      {/* Header / Context Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-space-md">
        <div className="flex flex-col">
          <div className="flex items-center gap-space-xs text-on-surface-variant font-code-sm text-code-sm uppercase tracking-wider">
            <span>Kernel eBPF</span>
            <span>/</span>
            <span>OpenSnitch Probes</span>
            <span>/</span>
            <span className="text-tertiary">cgroup_skb/egress</span>
          </div>
          <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight mt-0.5">
            Outbound Socket Intercepts & UFW Policy Compiler
          </h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setSelectedModalId(intercepts[0]?.id ?? null)}
            className="px-space-md py-2 rounded-lg bg-primary-container text-white font-title-sm text-title-sm shadow-md hover:brightness-110 transition-all flex items-center gap-1.5"
          >
            <MaterialIcon name="crisis_alert" className="text-[18px]" />
            <span>Open Intercept Popover</span>
          </button>
        </div>
      </div>

      {/* AI Plain-English Threat Explainer & Action Recommender */}
      <AiSectionExplainer
        sectionKey="outbound-intercepts"
        onExecuteRecommendedAction={() =>
          setSelectedModalId(intercepts[0]?.id ?? null)
        }
        customActionLabel="Review Pending Intercepts & Deny Unknown"
        defaultExpanded={false}
      />

      {/* Quick Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-space-md">
        <div className="bg-surface-container-low border border-[#363243] p-space-md rounded-xl shadow-md flex items-center justify-between">
          <div className="flex flex-col">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Intercepts Today
            </span>
            <span className="font-headline-lg text-headline-lg text-on-surface font-semibold mt-1 tabular-nums">
              842
            </span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-surface-container-high flex items-center justify-center text-primary">
            <MaterialIcon name="swap_calls" className="text-[22px]" />
          </div>
        </div>

        <div className="bg-surface-container-low border border-[#363243] p-space-md rounded-xl shadow-md flex items-center justify-between">
          <div className="flex flex-col">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Active Block Rules
            </span>
            <span className="font-headline-lg text-headline-lg text-on-surface font-semibold mt-1 tabular-nums">
              148
            </span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-surface-container-high flex items-center justify-center text-error">
            <MaterialIcon name="gpp_bad" className="text-[22px]" />
          </div>
        </div>

        <div className="bg-surface-container-low border border-[#363243] p-space-md rounded-xl shadow-md flex items-center justify-between">
          <div className="flex flex-col">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              Pending Triage
            </span>
            <div className="flex items-center gap-space-xs mt-1">
              <span className="font-headline-lg text-headline-lg text-primary-container font-semibold tabular-nums">
                {intercepts.filter((i) => i.verdict === 'PENDING').length}
              </span>
              <span className="inline-flex w-2 h-2 rounded-full bg-primary-container animate-ping" />
            </div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-surface-container-high flex items-center justify-center text-primary-container">
            <MaterialIcon name="hourglass_top" className="text-[22px]" />
          </div>
        </div>

        <div className="bg-surface-container-low border border-[#363243] p-space-md rounded-xl shadow-md flex items-center justify-between">
          <div className="flex flex-col">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant">
              eBPF Filter Latency
            </span>
            <span className="font-headline-lg text-headline-lg text-tertiary font-semibold mt-1 font-body-lg">
              0.04ms
            </span>
          </div>
          <div className="w-10 h-10 rounded-lg bg-surface-container-high flex items-center justify-center text-tertiary">
            <MaterialIcon name="speed" className="text-[22px]" />
          </div>
        </div>
      </div>

      {/* Recent Intercept Decisions Table */}
      <div className="bg-surface-container-low border border-[#363243] rounded-xl shadow-md p-space-md flex flex-col gap-space-sm">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-space-xs">
            <span className="font-title-sm text-title-sm text-on-surface">
              Recent OpenSnitch & eBPF Socket Decisions
            </span>
            <span className="font-code-sm text-code-sm px-space-xs py-0.5 rounded bg-surface-container-highest text-on-surface-variant">
              v_egress_hook0
            </span>
          </div>
          <span className="font-code-sm text-code-sm text-outline">
            Click any row to inspect process lineage & socket telemetry
          </span>
        </div>

        <div className="w-full flex flex-col font-code-sm text-code-sm text-on-surface-variant">
          <div className="flex items-center py-2 px-space-sm bg-surface-container-high rounded-lg text-on-surface font-title-sm text-title-sm">
            <div className="w-28">TIME</div>
            <div className="w-56">PROCESS</div>
            <div className="flex-1">TARGET SOCKET</div>
            <div className="w-40">RULE APPLIED</div>
            <div className="w-28 text-right">VERDICT</div>
          </div>
          {intercepts.map((item) => (
            <div
              key={item.id}
              onClick={() => setSelectedModalId(item.id)}
              className="cursor-pointer flex items-center py-2.5 px-space-sm hover:bg-surface-container-high/60 border-b border-white/5 transition-colors"
            >
              <div className="w-28 text-on-surface-variant tabular-nums">{item.timestamp}</div>
              <div
                className={`w-56 font-semibold ${
                  item.verdict === 'DENY' || item.verdict === 'PENDING'
                    ? 'text-error'
                    : 'text-on-surface'
                }`}
              >
                {item.binary} (PID {item.pid})
              </div>
              <div className="flex-1 truncate">
                {item.remoteIp}:{item.remotePort} [{item.remoteDomain}]
              </div>
              <div className="w-40 text-on-surface-variant truncate">{item.ruleApplied}</div>
              <div className="w-28 text-right">
                <span
                  className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                    item.verdict === 'ALLOW_ALWAYS' || item.verdict === 'ALLOW_ONCE'
                      ? 'bg-tertiary/15 text-tertiary'
                      : item.verdict === 'PENDING'
                        ? 'bg-primary-container text-white'
                        : 'bg-error-container text-on-error-container'
                  }`}
                >
                  {item.verdict}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Natural-Language-to-Native Policy Compiler */}
      <div className="bg-surface-container border border-[#363243] rounded-xl p-space-md shadow-md flex flex-col gap-space-sm">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <MaterialIcon name="auto_awesome" className="text-secondary text-[20px]" />
            <span className="font-title-sm text-title-sm text-on-surface">
              Natural-Language-to-Native Policy Compiler (UFW + Fail2ban + AppArmor)
            </span>
          </div>
          <span className="font-code-sm text-code-sm text-secondary">Gemini 4 Hydrogen</span>
        </div>
        <div className="flex flex-col sm:flex-row gap-2">
          <input
            type="text"
            value={nlPolicyPrompt}
            onChange={(e) => setNlPolicyPrompt(e.target.value)}
            className="flex-1 bg-surface-container-lowest border border-[#363243] rounded-lg px-3 py-2 font-code-sm text-code-sm text-on-surface"
          />
          <button
            type="button"
            onClick={handleCompilePolicy}
            className="px-4 py-2 rounded-lg bg-primary-container text-white font-label-md font-semibold shrink-0 hover:brightness-110"
          >
            Compile & Stage Rule
          </button>
        </div>
        {compiledRuleOutput && (
          <pre className="p-3 rounded-lg bg-surface-container-lowest border border-tertiary/30 font-code-sm text-code-sm text-tertiary whitespace-pre-wrap">
            {compiledRuleOutput}
          </pre>
        )}
      </div>

      {/* LIBADWAITA MODAL POPOVER OVERLAY (Simplewall / OpenSnitch style) */}
      {activeModalEvent && (
        <div className="fixed inset-0 top-16 left-0 md:left-72 bg-surface-container-lowest/75 backdrop-blur-md z-40 flex items-center justify-center p-space-md overflow-y-auto">
          <div className="w-full max-w-4xl bg-surface-container border-2 border-primary-container rounded-xl shadow-2xl flex flex-col overflow-hidden my-auto">
            {/* Popover Warning Header with Urgent Timer */}
            <div className="bg-gradient-to-r from-primary-container via-surface-container to-surface-container-high p-space-md flex flex-wrap items-center justify-between gap-space-sm">
              <div className="flex items-center gap-space-md">
                <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-primary-container text-on-primary-container shadow-md">
                  <MaterialIcon name="crisis_alert" className="text-[24px]" />
                  <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-error animate-ping" />
                  <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-error" />
                </div>
                <div className="flex flex-col">
                  <div className="flex items-center gap-space-xs">
                    <span className="font-headline-md text-headline-md text-on-surface font-bold tracking-tight">
                      Outbound Connection Intercepted
                    </span>
                    <span className="px-space-xs py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-error text-on-error">
                      eBPF Socket Gate
                    </span>
                  </div>
                  <p className="font-label-sm text-label-sm text-on-surface-variant">
                    Socket creation halted by kernel cgroup egress probe. Immediate operator triage
                    required.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <div className="flex items-center gap-space-xs bg-surface-container-lowest px-space-md py-1.5 rounded-full shadow-inner">
                  <MaterialIcon
                    name="timelapse"
                    className="text-[16px] text-primary-container animate-spin"
                  />
                  <span className="font-label-sm text-label-sm text-on-surface-variant">
                    Default:
                  </span>
                  <span className="font-code-sm text-code-sm font-semibold text-primary tabular-nums">
                    Auto-blocking in {countdown}s
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedModalId(null)}
                  className="p-1.5 rounded-lg bg-surface-container-lowest text-on-surface-variant hover:text-on-surface"
                  title="Minimize Popover"
                >
                  <MaterialIcon name="close" />
                </button>
              </div>
            </div>

            {/* Main Popover Body Content */}
            <div className="p-space-lg flex flex-col gap-space-md max-h-[calc(85vh-140px)] overflow-y-auto">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-space-md">
                {/* Card 1: Target Process Information */}
                <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col gap-space-sm border border-white/5 shadow-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-space-xs">
                      <MaterialIcon name="terminal" className="text-primary text-[18px]" />
                      <span className="font-title-sm text-title-sm text-on-surface">
                        Target Process Information
                      </span>
                    </div>
                    <span className="px-space-xs py-0.5 rounded bg-surface-container-highest text-on-surface font-code-sm text-code-sm">
                      PID: {activeModalEvent.pid}
                    </span>
                  </div>
                  <div className="flex flex-col gap-1.5 pt-1">
                    <div className="flex items-center justify-between text-on-surface-variant font-label-md text-label-md">
                      <span>Executable Binary:</span>
                      <span className="font-body-md text-body-md text-on-surface font-bold">
                        {activeModalEvent.binary}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-on-surface-variant font-label-md text-label-md">
                      <span>Effective User:</span>
                      <span className="font-code-sm text-code-sm text-on-surface">
                        {activeModalEvent.uid}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-on-surface-variant font-label-md text-label-md">
                      <span>Parent Tree:</span>
                      <span className="font-code-sm text-code-sm text-on-surface-variant truncate">
                        {activeModalEvent.parentTree}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1 mt-1 bg-surface-container-lowest p-space-sm rounded-lg shadow-inner">
                      <span className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider">
                        Command Line Invocation:
                      </span>
                      <span className="font-code-sm text-code-sm text-primary break-all">
                        {activeModalEvent.cmdLine}
                      </span>
                    </div>
                    <div className="flex items-center justify-between bg-surface-container-highest/60 px-space-sm py-1.5 rounded-lg mt-0.5">
                      <div className="flex items-center gap-1.5 truncate mr-2">
                        <MaterialIcon name="verified" className="text-[15px] text-tertiary" />
                        <span className="font-code-sm text-code-sm text-on-surface-variant truncate">
                          SHA256: {activeModalEvent.sha256.slice(0, 14)}...
                          {activeModalEvent.sha256.slice(-8)}
                        </span>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          navigator.clipboard?.writeText(activeModalEvent.sha256);
                          setCopiedHash(true);
                          window.setTimeout(() => setCopiedHash(false), 1500);
                        }}
                        className="hover:text-on-surface text-on-surface-variant transition-colors p-1"
                        title="Copy Hash"
                      >
                        <MaterialIcon
                          name={copiedHash ? 'check' : 'content_copy'}
                          className="text-[16px]"
                        />
                      </button>
                    </div>
                    <span className="font-label-sm text-label-sm text-tertiary flex items-center gap-1">
                      <MaterialIcon name="check_circle" className="text-[13px]" />
                      {activeModalEvent.packageVerified}
                    </span>
                  </div>
                </div>

                {/* Card 2: Connection & Destination Details */}
                <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col gap-space-sm border border-white/5 shadow-sm">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-space-xs">
                      <MaterialIcon name="public" className="text-secondary text-[18px]" />
                      <span className="font-title-sm text-title-sm text-on-surface">
                        Connection & Remote Socket
                      </span>
                    </div>
                    <span className="px-space-xs py-0.5 rounded bg-surface-container-highest text-secondary font-code-sm text-code-sm">
                      {activeModalEvent.interfaceName}
                    </span>
                  </div>
                  <div className="flex flex-col gap-1.5 pt-1">
                    <div className="flex items-center justify-between text-on-surface-variant font-label-md text-label-md">
                      <span>Remote Target:</span>
                      <span className="font-code-sm text-code-sm text-error font-semibold break-all">
                        {activeModalEvent.remoteDomain}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-on-surface-variant font-label-md text-label-md">
                      <span>Destination Endpoint:</span>
                      <span className="font-code-sm text-code-sm text-on-surface">
                        {activeModalEvent.remoteIp}:{activeModalEvent.remotePort} [
                        {activeModalEvent.protocol}]
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-on-surface-variant font-label-md text-label-md">
                      <span>Local Socket:</span>
                      <span className="font-code-sm text-code-sm text-on-surface-variant">
                        {activeModalEvent.localSocket}
                      </span>
                    </div>
                    <div className="flex flex-col gap-1 mt-1 bg-surface-container-lowest p-space-sm rounded-lg shadow-inner">
                      <span className="font-label-sm text-label-sm text-on-surface-variant uppercase tracking-wider">
                        Autonomous System (GeoIP / BGP):
                      </span>
                      <div className="flex items-center justify-between">
                        <span className="font-body-md text-body-md text-on-surface font-semibold">
                          {activeModalEvent.asn}
                        </span>
                        <span className="font-label-sm text-label-sm px-space-xs py-0.5 rounded bg-surface-container-high text-on-surface-variant">
                          {activeModalEvent.geoLocation}
                        </span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between bg-surface-container-highest/60 px-space-sm py-1.5 rounded-lg mt-0.5 font-label-md text-label-md text-on-surface-variant">
                      <span>DNS Protocol:</span>
                      <span className="text-tertiary font-code-sm text-code-sm">
                        {activeModalEvent.dnsStatus}
                      </span>
                    </div>
                    {activeModalEvent.threatFeedWarning && (
                      <span className="font-label-sm text-label-sm text-error flex items-center gap-1">
                        <MaterialIcon name="warning" className="text-[13px]" />
                        {activeModalEvent.threatFeedWarning}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Card 3: Gemini Threat & Anomaly Intelligence */}
              <div className="bg-surface-container-low rounded-xl p-space-md flex flex-col gap-space-sm border border-secondary/30 shadow-md">
                <div className="flex flex-wrap items-center justify-between gap-space-xs">
                  <div className="flex items-center gap-space-xs">
                    <MaterialIcon name="neurology" className="text-secondary text-[20px]" />
                    <span className="font-title-sm text-title-sm text-on-surface font-bold">
                      Gemini Threat & Behavioral Anomaly Intelligence
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 px-space-sm py-0.5 rounded-full bg-secondary-container text-on-secondary-container font-label-sm text-label-sm shadow-sm">
                    <span className="w-1.5 h-1.5 rounded-full bg-secondary animate-pulse" />
                    <span>
                      Gemini Heuristic Anomaly (Score: {activeModalEvent.heuristicScore.toFixed(2)})
                    </span>
                  </div>
                </div>
                <div className="bg-surface-container-lowest p-space-md rounded-lg flex flex-col gap-space-xs shadow-inner">
                  <p className="font-body-md text-body-md text-on-surface leading-relaxed">
                    {activeModalEvent.geminiNarrative}
                  </p>
                </div>
              </div>

              {/* Action Buttons Bar */}
              <div className="flex flex-wrap items-center justify-between gap-space-sm pt-1">
                <div className="flex items-center gap-2 font-code-sm text-code-sm text-on-surface-variant">
                  <span>Rule Scope: Process + Destination IP + Port</span>
                </div>
                <div className="flex flex-wrap items-center gap-space-sm">
                  <button
                    type="button"
                    onClick={() => {
                      onResolveIntercept(activeModalEvent.id, 'ALLOW_ONCE');
                      setSelectedModalId(null);
                    }}
                    className="px-4 py-2 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-title-sm text-title-sm transition-colors"
                  >
                    Allow Once
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      onResolveIntercept(activeModalEvent.id, 'ALLOW_ALWAYS');
                      setSelectedModalId(null);
                    }}
                    className="px-4 py-2 rounded-lg bg-tertiary-container text-on-tertiary-container hover:brightness-110 font-title-sm text-title-sm font-semibold transition-all"
                  >
                    Allow Always (Create Rule)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      onResolveIntercept(activeModalEvent.id, 'DENY');
                      setSelectedModalId(null);
                    }}
                    className="px-5 py-2 rounded-lg bg-error-container text-on-error-container hover:bg-error hover:text-on-error font-title-sm text-title-sm font-semibold transition-all shadow-md"
                  >
                    Block Connection & Drop Socket
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
