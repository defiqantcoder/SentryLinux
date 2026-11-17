import React, { useState, useEffect, useCallback } from 'react';
import type {
  AppArmorProfileItem,
  AskSentryResult,
  CisBenchmarkRule,
  DnsQueryRecord,
  IncidentEvent,
  InterceptSocketEvent,
  LiveSystemTelemetry,
  NetworkMode,
  PolkitActionRule,
  ProjectState,
  QuarantinedArtifact,
  StaleDaemonItem,
  SweepFinding,
  TabId,
  WireGuardTunnel,
} from './types/project';
import { MaterialIcon, Tooltip } from './components/Primitives';
import {
  OverviewDeck,
  DnsSentryDeck,
  OutboundInterceptsDeck,
} from './decks/TelemetryDecks';
import {
  UsgCisAuditDeck,
  MalwareSweepDeck,
  DaemonRestartsDeck,
  NetworkProfilesDeck,
  RulesAndQuarantineDeck,
  SettingsAndPolkitDeck,
} from './decks/ComplianceAndConfigDecks';
import {
  DEFAULT_PROJECT_STATE,
  INITIAL_APPARMOR_PROFILES,
  INITIAL_CIS_RULES,
  INITIAL_DNS_QUERIES,
  INITIAL_INCIDENTS,
  INITIAL_INTERCEPTS,
  INITIAL_POLKIT_RULES,
  INITIAL_QUARANTINE,
  INITIAL_STALE_DAEMONS,
  INITIAL_SWEEP_FINDINGS,
  INITIAL_SYSTEMD_UNITS,
  INITIAL_WIREGUARD_TUNNELS,
  INITIAL_SUBAPPS,
  compileSpecBundle,
  fetchLiveSystemTelemetry,
  fetchSubAppsStatus,
  saveSpecBundleToDisk,
  validateCanonicalPath,
} from './services/sentryBridge';
import { SubAppInstallerModal } from './components/SubAppInstallerModal';
import type { SecuritySubApp } from './types/project';
import { queryAskSentry } from './services/geminiService';

const STORAGE_KEY_STATE = 'sentrylinux_app_state_v2';

export default function App() {
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [networkMode, setNetworkMode] = useState<NetworkMode>('coexist');
  const [isLockdown, setIsLockdown] = useState(false);
  const [lockdownPermanent, setLockdownPermanent] = useState(false);
  const [lockdownRemainingSec, setLockdownRemainingSec] = useState(300);

  const [snapshotId, setSnapshotId] = useState('9fa2c4');
  const [projectState] = useState<ProjectState>(DEFAULT_PROJECT_STATE);
  const [incidents, setIncidents] = useState<IncidentEvent[]>(INITIAL_INCIDENTS);
  const [dnsQueries, setDnsQueries] = useState<DnsQueryRecord[]>(INITIAL_DNS_QUERIES);
  const [intercepts, setIntercepts] = useState<InterceptSocketEvent[]>(INITIAL_INTERCEPTS);
  const [cisRules, setCisRules] = useState<CisBenchmarkRule[]>(INITIAL_CIS_RULES);
  const [sweepFindings, setSweepFindings] = useState<SweepFinding[]>(INITIAL_SWEEP_FINDINGS);
  const [staleDaemons, setStaleDaemons] = useState<StaleDaemonItem[]>(INITIAL_STALE_DAEMONS);
  const [tunnels, setTunnels] = useState<WireGuardTunnel[]>(INITIAL_WIREGUARD_TUNNELS);
  const [quarantineItems, setQuarantineItems] =
    useState<QuarantinedArtifact[]>(INITIAL_QUARANTINE);
  const [appArmorProfiles, setAppArmorProfiles] = useState<AppArmorProfileItem[]>(
    INITIAL_APPARMOR_PROFILES,
  );
  const [polkitRules, setPolkitRules] = useState<PolkitActionRule[]>(INITIAL_POLKIT_RULES);
  const [systemTelemetry, setSystemTelemetry] = useState<LiveSystemTelemetry>({
    kernelVersion: 'Linux 6.8.0-40-generic',
    uptimeFormatted: '14d 06h 42m',
    loadAverage: '0.42, 0.38, 0.31',
    memoryUsedMb: 6420,
    memoryTotalMb: 32768,
    lockdownMode: 'integrity',
    kptrRestrict: '2 (Restricted)',
    tpmPcrStatus: 'PCR 0,2,4,7 Nominal (SHA-256 Verified)',
    luksKeyslotsActive: 2,
    secureBootEnabled: true,
  });

  // Ask Sentry Search Bar
  const [askQuery, setAskQuery] = useState('');
  const [askResult, setAskResult] = useState<AskSentryResult | null>(null);
  const [askLoading, setAskLoading] = useState(false);

  // Native Spec Bundle Export Modal (T008)
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [exportTargetDir, setExportTargetDir] = useState('~/Projects/CrateBench-BOMs');
  const [compiledFiles, setCompiledFiles] = useState<Record<string, string>>({});
  const [exportStatus, setExportStatus] = useState<{ ok: boolean; message: string } | null>(null);

  // 1-Click Security Sub-Application Installer Modal
  const [subApps, setSubApps] = useState<SecuritySubApp[]>(INITIAL_SUBAPPS);
  const [subAppInstallerOpen, setSubAppInstallerOpen] = useState(false);

  // Hydrate persisted state & live telemetry
  useEffect(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY_STATE);
      if (saved) {
        const parsed = JSON.parse(saved) as {
          activeTab?: TabId;
          networkMode?: NetworkMode;
          snapshotId?: string;
        };
        if (parsed.activeTab) setActiveTab(parsed.activeTab);
        if (parsed.networkMode) setNetworkMode(parsed.networkMode);
        if (parsed.snapshotId) setSnapshotId(parsed.snapshotId);
      }
    } catch {
      // ignore corrupted local storage
    }

    fetchLiveSystemTelemetry().then(setSystemTelemetry).catch(() => {});
    fetchSubAppsStatus().then(setSubApps).catch(() => {});
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(
        STORAGE_KEY_STATE,
        JSON.stringify({ activeTab, networkMode, snapshotId }),
      );
    } catch {
      // ignore
    }
  }, [activeTab, networkMode, snapshotId]);

  // 5-Minute Lockdown Failsafe Countdown (per spec.md Section 4)
  useEffect(() => {
    if (!isLockdown || lockdownPermanent) return;
    const timer = window.setInterval(() => {
      setLockdownRemainingSec((prev) => {
        if (prev <= 1) {
          setIsLockdown(false);
          return 300;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [isLockdown, lockdownPermanent]);

  // Keyboard shortcuts: Alt+S for Export Modal, Escape to close modals
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.altKey && e.key.toLowerCase() === 's') {
        e.preventDefault();
        handleOpenExportModal();
      } else if (e.key === 'Escape') {
        setExportModalOpen(false);
        setAskResult(null);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleToggleLockdown = () => {
    if (isLockdown) {
      setIsLockdown(false);
      setLockdownPermanent(false);
      setLockdownRemainingSec(300);
    } else {
      setIsLockdown(true);
      setLockdownPermanent(false);
      setLockdownRemainingSec(300);
    }
  };

  const handleTakeSnapshot = () => {
    const nextHash = Math.floor(0x100000 + Math.random() * 0xefffff).toString(16);
    setSnapshotId(nextHash);
  };

  const handleAskSentrySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAskLoading(true);
    const result = await queryAskSentry(askQuery);
    setAskResult(result);
    setAskLoading(false);
  };

  const handleOpenExportModal = async () => {
    const files = await compileSpecBundle(projectState);
    setCompiledFiles(files);
    setExportStatus(null);
    setExportModalOpen(true);
  };

  const handleExecuteExport = async () => {
    const res = await saveSpecBundleToDisk(exportTargetDir, compiledFiles);
    setExportStatus(res);
  };

  const handleAddSimulatedQuery = useCallback((q: DnsQueryRecord) => {
    setDnsQueries((prev) => [q, ...prev].slice(0, 35));
  }, []);

  const staleCount = staleDaemons.filter((d) => d.status === 'Stale').length;
  const pendingInterceptsCount = intercepts.filter((i) => i.verdict === 'PENDING').length;

  const formatCountdown = (sec: number) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  const pathCheck = validateCanonicalPath(exportTargetDir);

  return (
    <div className="min-h-screen bg-surface font-body-md text-on-surface antialiased select-none">
      {/* Top Fixed Libadwaita Headerbar */}
      <header className="fixed top-0 left-0 right-0 h-16 bg-surface-container/90 backdrop-blur-xl z-50 flex items-center justify-between px-space-lg border-b border-[#363243] shadow-[0_1px_8px_rgba(0,0,0,0.4)] gap-3">
        {/* Brand Emblem & Version */}
        <div className="flex items-center gap-space-md shrink-0">
          <div className="w-9 h-9 rounded-xl bg-primary-container flex items-center justify-center text-white shadow-md">
            <MaterialIcon name="shield_lock" className="text-[22px]" />
          </div>
          <div className="flex flex-col">
            <div className="flex items-center gap-space-xs">
              <span className="font-headline-md text-headline-md text-on-surface tracking-tight">
                SentryLinux
              </span>
              <span className="font-code-sm text-code-sm px-space-xs py-0.5 rounded bg-surface-container-highest text-on-surface-variant">
                v2.4.1-lts (Tauri v2)
              </span>
            </div>
            <span className="font-code-sm text-[10px] text-on-surface-variant hidden sm:inline">
              Ubuntu 24.04 LTS Endpoint Security & Telemetry Hub
            </span>
          </div>
        </div>

        {/* Plain-English Syscall & Journal Query Engine ("Ask Sentry") */}
        <form
          onSubmit={handleAskSentrySubmit}
          className="flex-1 max-w-xl hidden md:flex items-center relative"
        >
          <MaterialIcon
            name="manage_search"
            className="absolute left-3 text-secondary text-[18px]"
          />
          <input
            type="text"
            value={askQuery}
            onChange={(e) => setAskQuery(e.target.value)}
            placeholder='Ask Sentry (e.g., "Did any process touch .ssh?" or "Allow subnet to 8080")'
            className="w-full bg-surface-container-lowest/90 border border-[#363243] focus:border-primary-container rounded-full py-1.5 pl-9 pr-24 font-code-sm text-code-sm text-on-surface focus:outline-none transition-colors"
          />
          <button
            type="submit"
            disabled={askLoading}
            className="absolute right-1.5 px-2.5 py-0.5 rounded-full bg-secondary-container text-on-secondary-container font-code-sm text-[10px] font-semibold hover:brightness-110"
          >
            {askLoading ? 'Querying...' : 'Ask AI'}
          </button>
        </form>

        {/* Network Mode Pill, Spec Exporter & Emergency Lockdown Switch */}
        <div className="flex items-center gap-space-sm shrink-0">
          <Tooltip explainerKey="coexistence-mode">
            <button
              type="button"
              onClick={() => {
                const order: NetworkMode[] = ['coexist', 'nextdns', 'proton'];
                const next = order[(order.indexOf(networkMode) + 1) % order.length];
                setNetworkMode(next);
              }}
              className="hidden lg:flex items-center gap-space-xs bg-surface-container-low hover:bg-surface-container-high px-space-md py-1.5 rounded-full border border-[#363243] transition-colors"
            >
              <span className="w-2 h-2 rounded-full bg-tertiary animate-pulse" />
              <span className="font-label-md text-label-md text-on-surface">
                {networkMode === 'coexist'
                  ? 'Co-Existence: Proton + NextDNS'
                  : networkMode === 'nextdns'
                    ? 'NextDNS Only (DoH/DoT)'
                    : 'Proton VPN Only (NetShield)'}
              </span>
              <MaterialIcon name="sync_alt" className="text-[15px] text-on-surface-variant" />
            </button>
          </Tooltip>

          <button
            type="button"
            onClick={() => setSubAppInstallerOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-surface-container-high hover:bg-surface-bright text-on-surface font-label-md text-label-md border border-[#443e54] transition-all shadow-sm"
            title="1-Click Security Sub-Application Installer"
          >
            <MaterialIcon name="apps" className="text-[16px] text-tertiary" />
            <span className="hidden md:inline font-medium">1-Click Tool Installer</span>
            <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-primary/20 text-primary font-code-sm font-semibold">
              {subApps.filter((a) => a.installed).length}/{subApps.length}
            </span>
          </button>

          <button
            type="button"
            onClick={handleOpenExportModal}
            className="flex items-center gap-1 px-3 py-1.5 rounded-full bg-surface-container-high hover:bg-surface-bright text-on-surface font-label-md text-label-md border border-[#363243] transition-colors"
            title="Save Spec Bundle to Computer (Alt+S)"
          >
            <MaterialIcon name="save" className="text-[16px] text-primary" />
            <span className="hidden sm:inline">Save to Computer</span>
          </button>

          <Tooltip explainerKey="lockdown-mode">
            <button
              type="button"
              onClick={handleToggleLockdown}
              className={`flex items-center gap-space-xs px-space-md py-1.5 rounded-full transition-colors font-label-md text-label-md font-semibold shadow-sm ${
                isLockdown
                  ? 'bg-error text-on-error animate-pulse'
                  : 'bg-error-container text-on-error-container hover:bg-error hover:text-on-error'
              }`}
            >
              <MaterialIcon name="shield_with_heart" className="text-[18px]" />
              <span>{isLockdown ? `Lockdown (${formatCountdown(lockdownRemainingSec)})` : 'Emergency Lockdown'}</span>
            </button>
          </Tooltip>
        </div>
      </header>

      {/* Ask Sentry Result Popover */}
      {askResult && (
        <div className="fixed top-20 left-1/2 -translate-x-1/2 z-50 w-full max-w-2xl p-space-md rounded-xl bg-surface-container border-2 border-secondary shadow-2xl space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <MaterialIcon name="psychology" className="text-secondary text-[20px]" />
              <span className="font-title-sm text-title-sm text-on-surface font-bold">
                Ask Sentry — Syscall & Journal Query Engine ({askResult.executionEngine})
              </span>
            </div>
            <button
              type="button"
              onClick={() => setAskResult(null)}
              className="text-on-surface-variant hover:text-on-surface"
            >
              <MaterialIcon name="close" />
            </button>
          </div>
          <div className="p-2 rounded bg-surface-container-lowest font-code-sm text-code-sm text-tertiary">
            $ {askResult.translatedCommand}
          </div>
          <p className="font-body-md text-body-md text-on-surface">{askResult.timelineSummary}</p>
          <div className="space-y-1 pt-1">
            {askResult.matchedRecords.map((rec, i) => (
              <div
                key={i}
                className="p-2 rounded bg-surface-container-low font-code-sm text-code-sm flex items-center justify-between gap-2"
              >
                <span className="text-outline">{rec.timestamp}</span>
                <span className="text-primary font-semibold">
                  {rec.comm} (PID {rec.pid})
                </span>
                <span className="text-on-surface flex-1 truncate">{rec.detail}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Left Fixed Navigation Sidebar */}
      <aside className="fixed left-0 top-16 bottom-0 w-72 bg-surface-container-low border-r border-[#363243] z-40 hidden md:flex flex-col justify-between p-space-md">
        <div className="flex flex-col gap-space-md overflow-y-auto">
          {/* Group 1: Security Telemetry */}
          <div className="flex flex-col gap-space-xs">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant px-space-sm">
              Security Telemetry
            </span>
            <nav className="flex flex-col gap-space-xs">
              <button
                type="button"
                onClick={() => setActiveTab('overview')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'overview'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="shield" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">Overview</span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('dns-sentry')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'dns-sentry'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="public" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">DNS Sentry</span>
                </div>
                <span className="font-code-sm text-code-sm px-space-xs py-0.5 rounded-full bg-surface-container-highest text-tertiary">
                  428/s
                </span>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('outbound-intercepts')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'outbound-intercepts'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="track_changes" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">Outbound Intercepts</span>
                </div>
                {pendingInterceptsCount > 0 && (
                  <span className="font-code-sm text-code-sm px-space-xs py-0.5 rounded-full bg-error-container text-on-error-container">
                    {pendingInterceptsCount}
                  </span>
                )}
              </button>
            </nav>
          </div>

          {/* Group 2: Hardening & Compliance */}
          <div className="flex flex-col gap-space-xs">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant px-space-sm">
              Hardening & Compliance
            </span>
            <nav className="flex flex-col gap-space-xs">
              <button
                type="button"
                onClick={() => setActiveTab('usg-and-lynis-cis-audit')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'usg-and-lynis-cis-audit'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="checklist" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">USG & Lynis CIS Audit</span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('malware-and-sweep')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'malware-and-sweep'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="radar" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">Malware & Sweep</span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('daemon-restarts-and-needrestart')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'daemon-restarts-and-needrestart'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="restart_alt" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">
                    Daemon Restarts & needrestart
                  </span>
                </div>
                {staleCount > 0 && (
                  <span className="font-code-sm text-code-sm px-1.5 py-0.5 rounded-full bg-surface-container-lowest text-primary font-semibold">
                    {staleCount}
                  </span>
                )}
              </button>
            </nav>
          </div>

          {/* Group 3: Configuration */}
          <div className="flex flex-col gap-space-xs">
            <span className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant px-space-sm">
              Configuration
            </span>
            <nav className="flex flex-col gap-space-xs">
              <button
                type="button"
                onClick={() => setActiveTab('network-profiles-and-wireguard')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'network-profiles-and-wireguard'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="hub" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">
                    Network Profiles & WireGuard
                  </span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('rules-and-quarantine')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'rules-and-quarantine'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="folder_supervised" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">Rules & Quarantine</span>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setActiveTab('settings-and-polkit-auth')}
                className={`flex items-center justify-between px-space-md py-2 rounded-lg transition-colors text-left ${
                  activeTab === 'settings-and-polkit-auth'
                    ? 'bg-primary-container text-on-primary-container font-semibold shadow-sm'
                    : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
                }`}
              >
                <div className="flex items-center gap-space-sm">
                  <MaterialIcon name="tune" className="text-[18px]" />
                  <span className="font-title-sm text-title-sm">Settings & Polkit Auth</span>
                </div>
              </button>
            </nav>
          </div>
        </div>

        {/* Bottom Kernel & Polkit Status Card */}
        <div className="mt-auto p-space-sm rounded-lg bg-surface-container border border-[#363243] flex flex-col gap-space-xs">
          <div className="flex items-center justify-between">
            <span className="font-code-sm text-code-sm text-on-surface-variant truncate">
              {systemTelemetry.kernelVersion}
            </span>
            <span className="w-2 h-2 rounded-full bg-tertiary shrink-0" />
          </div>
          <Tooltip explainerKey="polkit-token">
            <div className="flex items-center justify-between w-full">
              <span className="font-label-sm text-label-sm text-on-surface">
                Polkit: Active Token
              </span>
              <span className="font-code-sm text-code-sm text-tertiary">Valid 14m</span>
            </div>
          </Tooltip>
          <div className="flex items-center gap-space-xs text-on-surface-variant">
            <MaterialIcon name="smart_toy" className="text-[14px] text-secondary" />
            <span className="font-label-sm text-label-sm">
              Gemini 4 + Local Fallback Ready
            </span>
          </div>
        </div>
      </aside>

      {/* Main Content Canvas */}
      <div className="md:pl-72">
        <main className="w-full min-h-screen pt-20 px-space-lg md:px-space-xl pb-space-xl bg-surface/90">
          {/* Emergency Lockdown Active Banner with 5-Minute Countdown Failsafe */}
          {isLockdown && (
            <div className="mb-space-lg p-space-md rounded-xl bg-error-container border-2 border-error text-on-error-container flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-md shadow-xl">
              <div className="flex items-center gap-3">
                <MaterialIcon name="gpp_maybe" className="text-[28px] text-error shrink-0" />
                <div>
                  <div className="font-headline-md text-headline-md font-bold">
                    EMERGENCY LOCKDOWN ENGAGED — Non-Loopback Sockets Severed
                  </div>
                  <p className="font-code-sm text-code-sm">
                    UFW set to deny all incoming/outgoing; all 68 AppArmor profiles forced to
                    Enforce.{' '}
                    {lockdownPermanent
                      ? 'Permanent lockdown confirmed by operator.'
                      : `Failsafe auto-revert in ${formatCountdown(lockdownRemainingSec)} unless confirmed.`}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {!lockdownPermanent && (
                  <button
                    type="button"
                    onClick={() => setLockdownPermanent(true)}
                    className="px-3 py-1.5 rounded-lg bg-black/30 hover:bg-black/50 text-white font-label-md"
                  >
                    Confirm Permanent
                  </button>
                )}
                <button
                  type="button"
                  onClick={handleToggleLockdown}
                  className="px-4 py-1.5 rounded-lg bg-white text-black font-label-md font-bold"
                >
                  Disengage & Restore Network
                </button>
              </div>
            </div>
          )}

          {activeTab === 'overview' && (
            <OverviewDeck
              incidents={incidents}
              onIsolateIncident={(id) =>
                setIncidents((prev) =>
                  prev.map((inc) =>
                    inc.id === id ? { ...inc, isolated: true, severity: 'MITIGATED' } : inc,
                  ),
                )
              }
              isLockdown={isLockdown}
              onToggleLockdown={handleToggleLockdown}
              snapshotId={snapshotId}
              onTakeSnapshot={handleTakeSnapshot}
              staleCount={staleCount}
              onRestartAllStale={() =>
                setStaleDaemons((prev) => prev.map((d) => ({ ...d, status: 'Remapped' })))
              }
              onNavigate={setActiveTab}
              systemTelemetry={systemTelemetry}
              systemdUnits={INITIAL_SYSTEMD_UNITS}
            />
          )}

          {activeTab === 'dns-sentry' && (
            <DnsSentryDeck
              queries={dnsQueries}
              onAllowDomain={(id) =>
                setDnsQueries((prev) =>
                  prev.map((q) => (q.id === id ? { ...q, status: 'Allowed' } : q)),
                )
              }
              onDenyDomain={(id) =>
                setDnsQueries((prev) =>
                  prev.map((q) => (q.id === id ? { ...q, status: 'Blocked' } : q)),
                )
              }
              onClearQueries={() => setDnsQueries([])}
              onAddSimulatedQuery={handleAddSimulatedQuery}
            />
          )}

          {activeTab === 'outbound-intercepts' && (
            <OutboundInterceptsDeck
              intercepts={intercepts}
              onResolveIntercept={(id, verdict) =>
                setIntercepts((prev) =>
                  prev.map((item) =>
                    item.id === id
                      ? { ...item, verdict, ruleApplied: `operator-${verdict.toLowerCase()}` }
                      : item,
                  ),
                )
              }
            />
          )}

          {activeTab === 'usg-and-lynis-cis-audit' && (
            <UsgCisAuditDeck
              rules={cisRules}
              onToggleRuleStage={(id) =>
                setCisRules((prev) =>
                  prev.map((r) =>
                    r.id === id ? { ...r, stagedForFix: !r.stagedForFix } : r,
                  ),
                )
              }
              onApplyStagedFixes={() => {
                handleTakeSnapshot();
                setCisRules((prev) =>
                  prev.map((r) =>
                    r.stagedForFix
                      ? {
                          ...r,
                          status: 'Passed',
                          stagedForFix: false,
                          currentValue: r.targetValue,
                        }
                      : r,
                  ),
                );
              }}
              snapshotId={snapshotId}
              onRevertSnapshot={handleTakeSnapshot}
              onRunFullUsgScan={() => {}}
            />
          )}

          {activeTab === 'malware-and-sweep' && (
            <MalwareSweepDeck
              findings={sweepFindings}
              onHealFinding={(id) =>
                setSweepFindings((prev) =>
                  prev.map((f) => (f.id === id ? { ...f, status: 'Healed' } : f)),
                )
              }
              onPurgeFinding={(id) =>
                setSweepFindings((prev) => prev.filter((f) => f.id !== id))
              }
              onNavigateQuarantine={() => setActiveTab('rules-and-quarantine')}
            />
          )}

          {activeTab === 'daemon-restarts-and-needrestart' && (
            <DaemonRestartsDeck
              daemons={staleDaemons}
              onRestartDaemon={(id) =>
                setStaleDaemons((prev) =>
                  prev.map((d) => (d.id === id ? { ...d, status: 'Remapped' } : d)),
                )
              }
              onRestartAllStale={() =>
                setStaleDaemons((prev) => prev.map((d) => ({ ...d, status: 'Remapped' })))
              }
            />
          )}

          {activeTab === 'network-profiles-and-wireguard' && (
            <NetworkProfilesDeck
              networkMode={networkMode}
              onChangeNetworkMode={setNetworkMode}
              tunnels={tunnels}
              onToggleTunnel={(id) =>
                setTunnels((prev) =>
                  prev.map((t) =>
                    t.id === id
                      ? {
                          ...t,
                          status:
                            t.status === 'ACTIVE DEFAULT' ? 'STANDBY' : 'ACTIVE DEFAULT',
                        }
                      : t,
                  ),
                )
              }
            />
          )}

          {activeTab === 'rules-and-quarantine' && (
            <RulesAndQuarantineDeck
              quarantineItems={quarantineItems}
              onShredArtifact={(id) =>
                setQuarantineItems((prev) => prev.filter((q) => q.id !== id))
              }
              appArmorProfiles={appArmorProfiles}
              onToggleAppArmorMode={(id) =>
                setAppArmorProfiles((prev) =>
                  prev.map((p) =>
                    p.id === id
                      ? { ...p, mode: p.mode === 'Enforce' ? 'Complain' : 'Enforce' }
                      : p,
                  ),
                )
              }
            />
          )}

          {activeTab === 'settings-and-polkit-auth' && (
            <SettingsAndPolkitDeck
              polkitRules={polkitRules}
              onTogglePolkitRule={(id) =>
                setPolkitRules((prev) =>
                  prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r)),
                )
              }
              projectState={projectState}
              onOpenExportModal={handleOpenExportModal}
              onOpenSubAppInstaller={() => setSubAppInstallerOpen(true)}
            />
          )}
        </main>
      </div>

      {/* Native Ubuntu Save / Spec Bundle Exporter Modal (T008) */}
      {exportModalOpen && (
        <div className="fixed inset-0 bg-black/75 backdrop-blur-sm z-50 flex items-center justify-center p-4 select-text">
          <div className="w-full max-w-2xl rounded-xl bg-surface-container border-2 border-primary-container p-space-lg shadow-2xl space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <MaterialIcon name="folder_zip" className="text-primary-container text-[24px]" />
                <h2 className="font-headline-md text-headline-md text-on-surface font-bold">
                  Save Specification Bundle to Computer
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setExportModalOpen(false)}
                className="text-on-surface-variant hover:text-on-surface"
              >
                <MaterialIcon name="close" />
              </button>
            </div>

            <div className="space-y-1">
              <label className="font-label-md text-label-md text-on-surface block">
                Target Ubuntu Directory Path (Canonical Path Guard Enforced):
              </label>
              <input
                type="text"
                value={exportTargetDir}
                onChange={(e) => setExportTargetDir(e.target.value)}
                className="w-full bg-surface-container-lowest border border-[#363243] rounded-lg px-3 py-2 font-code-sm text-code-sm text-on-surface"
              />
              {!pathCheck.valid ? (
                <div className="text-error font-code-sm text-code-sm flex items-center gap-1 pt-1">
                  <MaterialIcon name="error" className="text-[15px]" />
                  <span>{pathCheck.error}</span>
                </div>
              ) : (
                <div className="text-tertiary font-code-sm text-code-sm flex items-center gap-1 pt-1">
                  <MaterialIcon name="verified" className="text-[15px]" />
                  <span>Canonical path verified: {pathCheck.normalized}</span>
                </div>
              )}
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 font-code-sm text-code-sm">
              {Object.entries(compiledFiles).map(([name, body]) => (
                <div
                  key={name}
                  className="p-2.5 rounded-lg bg-surface-container-low border border-white/5 flex flex-col justify-between"
                >
                  <span className="text-primary font-semibold">{name}</span>
                  <span className="text-on-surface-variant text-[10px]">
                    {body.length} bytes • UTF-8
                  </span>
                </div>
              ))}
            </div>

            {exportStatus && (
              <div
                className={`p-3 rounded-lg font-code-sm text-code-sm ${
                  exportStatus.ok
                    ? 'bg-tertiary-container/20 border border-tertiary text-tertiary'
                    : 'bg-error-container/30 border border-error text-error'
                }`}
              >
                {exportStatus.message}
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setExportModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-surface-container-high text-on-surface font-label-md"
              >
                Close
              </button>
              <button
                type="button"
                disabled={!pathCheck.valid}
                onClick={handleExecuteExport}
                className="px-5 py-2 rounded-lg bg-primary-container text-white font-label-md font-semibold shadow-md hover:brightness-110 disabled:opacity-50"
              >
                Export All Artifacts & SHA256SUMS.txt
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 1-Click Security Sub-Application Installer Modal */}
      {subAppInstallerOpen && (
        <SubAppInstallerModal
          subApps={subApps}
          onClose={() => setSubAppInstallerOpen(false)}
          onSubAppInstalled={(id) =>
            setSubApps((prev) =>
              prev.map((a) => (a.id === id ? { ...a, installed: true } : a)),
            )
          }
        />
      )}
    </div>
  );
}
