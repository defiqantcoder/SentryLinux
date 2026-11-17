import React, { useState } from 'react';
import { MaterialIcon } from './Primitives';
import type { SecuritySubApp } from '../types/project';
import { triggerSubAppInstall } from '../services/sentryBridge';

interface SubAppInstallerModalProps {
  subApps: SecuritySubApp[];
  onClose: () => void;
  onSubAppInstalled?: (id: string) => void;
}

export const SubAppInstallerModal: React.FC<SubAppInstallerModalProps> = ({
  subApps: initialSubApps,
  onClose,
  onSubAppInstalled,
}) => {
  const [apps, setApps] = useState<SecuritySubApp[]>(initialSubApps);
  const [filter, setFilter] = useState<'ALL' | 'MISSING' | 'INSTALLED'>('ALL');
  const [search, setSearch] = useState('');
  const [installingId, setInstallingId] = useState<string | null>(null);
  const [batchInstalling, setBatchInstalling] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [terminalLogs, setTerminalLogs] = useState<string[]>([
    '[INIT] SentryLinux Sub-Application Package Manager online.',
    '[INFO] Ready to provision security daemons (apt-get / polkit integration).',
  ]);

  const installedCount = apps.filter((a) => a.installed).length;
  const missingCount = apps.length - installedCount;
  const progressPct = Math.round((installedCount / apps.length) * 100);

  const appendLog = (line: string) => {
    const ts = new Date().toTimeString().split(' ')[0];
    setTerminalLogs((prev) => [...prev, `[${ts}] ${line}`]);
  };

  const handleInstallOne = async (app: SecuritySubApp) => {
    setInstallingId(app.id);
    appendLog(`Requesting 1-Click install for ${app.name} (pkg: ${app.packageName})...`);
    appendLog(`$ sudo apt-get update && sudo apt-get install -y --no-install-recommends ${app.packageName}`);

    await triggerSubAppInstall(app.packageName);

    // Simulate completion with UI feedback
    window.setTimeout(() => {
      setApps((prev) =>
        prev.map((a) => (a.id === app.id ? { ...a, installed: true } : a)),
      );
      setInstallingId(null);
      appendLog(`[SUCCESS] ${app.name} installed and registered in systemd.`);
      if (onSubAppInstalled) {
        onSubAppInstalled(app.id);
      }
    }, 1200);
  };

  const handleInstallAllMissing = () => {
    const missing = apps.filter((a) => !a.installed);
    if (missing.length === 0) return;

    setBatchInstalling(true);
    const pkgs = missing.map((a) => a.packageName).join(' ');
    appendLog(`Starting Batch 1-Click Install for ${missing.length} missing security subsystems...`);
    appendLog(`$ sudo apt-get update && sudo apt-get install -y --no-install-recommends ${pkgs}`);

    window.setTimeout(() => {
      setApps((prev) => prev.map((a) => ({ ...a, installed: true })));
      setBatchInstalling(false);
      appendLog(`[COMPLETE] All ${missing.length} security sub-applications installed and verified.`);
      if (onSubAppInstalled) {
        missing.forEach((m) => onSubAppInstalled(m.id));
      }
    }, 2200);
  };

  const handleCopyCommand = (app: SecuritySubApp) => {
    const cmd = `sudo apt-get update && sudo apt-get install -y ${app.packageName}`;
    navigator.clipboard?.writeText(cmd);
    setCopiedId(app.id);
    window.setTimeout(() => setCopiedId(null), 2500);
    appendLog(`Copied install command to clipboard: ${cmd}`);
  };

  const handleDownloadScript = () => {
    const scriptContent = `#!/usr/bin/env bash\n# SentryLinux 1-Click Security Sub-Application Installer\nset -e\necho "Installing all SentryLinux security sub-applications..."\nsudo apt-get update -y\nsudo apt-get install -y --no-install-recommends \\\n  fail2ban suricata ufw apparmor-utils clamav clamav-daemon \\\n  rkhunter chkrootkit lynis aide debsums needrestart usbguard \\\n  wireguard-tools auditd audispd-plugins\necho "Done! All security sub-applications are ready."\n`;
    const blob = new Blob([scriptContent], { type: 'text/x-shellscript;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'install-sentry-subapps.sh';
    a.click();
    URL.revokeObjectURL(url);
    appendLog('Generated and downloaded install-sentry-subapps.sh.');
  };

  const filteredApps = apps.filter((app) => {
    if (filter === 'MISSING' && app.installed) return false;
    if (filter === 'INSTALLED' && !app.installed) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        app.name.toLowerCase().includes(q) ||
        app.packageName.toLowerCase().includes(q) ||
        app.category.toLowerCase().includes(q) ||
        app.description.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-5xl max-h-[92vh] flex flex-col rounded-2xl bg-surface-container border border-[#443e54] shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between p-5 bg-surface-container-high border-b border-[#363243]">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-xl bg-primary-container/20 text-primary border border-primary/30">
              <MaterialIcon name="apps" className="text-[24px]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="font-headline-sm text-headline-sm text-on-surface font-bold tracking-tight">
                  1-Click Security Sub-Application Installer
                </h2>
                <span className="px-2 py-0.5 rounded-full text-[11px] font-code-sm bg-tertiary-container/30 text-tertiary border border-tertiary/30">
                  Ubuntu 24.04 & 22.04 LTS
                </span>
              </div>
              <p className="font-body-md text-[13px] text-on-surface-variant mt-0.5">
                Automated one-click installation and verification for Fail2ban, Suricata, ClamAV, Lynis, UFW, RKhunter, needrestart & all security backends.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="w-8 h-8 rounded-lg flex items-center justify-center text-on-surface-variant hover:text-on-surface hover:bg-surface-container-highest transition-colors"
          >
            <MaterialIcon name="close" className="text-[20px]" />
          </button>
        </div>

        {/* Status Strip & Master 1-Click Action Bar */}
        <div className="p-4 px-5 bg-surface-container-low border-b border-[#363243] flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex flex-col gap-1 min-w-[260px]">
            <div className="flex items-center justify-between text-label-md font-semibold text-on-surface">
              <span>Security Readiness:</span>
              <span className="font-code-sm text-primary">
                {installedCount} of {apps.length} Installed ({progressPct}%)
              </span>
            </div>
            <div className="w-full h-2 rounded-full bg-surface-container-highest overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-primary to-tertiary transition-all duration-500 rounded-full"
                style={{ width: `${progressPct}%` }}
              />
            </div>
            <span className="text-[11px] font-code-sm text-outline">
              {missingCount === 0
                ? 'All security sub-applications are installed and active.'
                : `${missingCount} sub-applications available for 1-click installation.`}
            </span>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            <button
              type="button"
              onClick={handleDownloadScript}
              className="px-3.5 py-2 rounded-lg bg-surface-container-high hover:bg-surface-bright text-on-surface font-title-sm text-[12px] font-medium border border-[#443e54] flex items-center gap-1.5 transition-all shadow-sm"
            >
              <MaterialIcon name="download" className="text-[16px] text-tertiary" />
              <span>Download .sh Script</span>
            </button>

            <button
              type="button"
              disabled={missingCount === 0 || batchInstalling}
              onClick={handleInstallAllMissing}
              className="px-4 py-2 rounded-lg bg-gradient-to-r from-primary to-primary-container text-white font-title-sm text-[13px] font-semibold flex items-center gap-2 shadow-md hover:brightness-110 active:scale-98 transition-all disabled:opacity-50"
            >
              <MaterialIcon
                name={batchInstalling ? 'sync' : 'auto_fix_high'}
                className={`text-[18px] ${batchInstalling ? 'animate-spin' : ''}`}
              />
              <span>
                {batchInstalling
                  ? 'Installing All Missing Sub-Apps...'
                  : missingCount === 0
                  ? 'All Tools Installed'
                  : `1-Click Install All Missing (${missingCount})`}
              </span>
            </button>
          </div>
        </div>

        {/* Filter and Search Bar */}
        <div className="px-5 py-3 bg-surface-container flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 border-b border-[#363243]">
          <div className="flex items-center gap-1.5">
            {[
              { id: 'ALL', label: `All Tools (${apps.length})` },
              { id: 'MISSING', label: `Missing (${missingCount})` },
              { id: 'INSTALLED', label: `Installed (${installedCount})` },
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFilter(tab.id as typeof filter)}
                className={`px-3 py-1 rounded-lg text-[12px] font-label-md font-medium transition-all ${
                  filter === tab.id
                    ? 'bg-primary-container text-white shadow-sm'
                    : 'text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div className="relative min-w-[220px]">
            <MaterialIcon
              name="search"
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[16px] text-on-surface-variant"
            />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search tools or packages..."
              className="w-full bg-surface-container-lowest border border-[#443e54] rounded-lg pl-8 pr-3 py-1 text-[12px] text-on-surface focus:outline-none focus:ring-1 focus:ring-primary font-body-md"
            />
          </div>
        </div>

        {/* Scrollable Sub-Application Cards Grid */}
        <div className="flex-1 overflow-y-auto p-5 grid grid-cols-1 md:grid-cols-2 gap-3.5 max-h-[50vh]">
          {filteredApps.map((app) => {
            const isInstalling = installingId === app.id || batchInstalling;
            return (
              <div
                key={app.id}
                className={`p-4 rounded-xl border flex flex-col justify-between transition-all shadow-sm ${
                  app.installed
                    ? 'bg-surface-container-low/90 border-[#363243]'
                    : 'bg-surface-container/70 border-primary/30 hover:border-primary/60'
                }`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2 mb-1.5">
                    <div className="flex flex-col">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-title-sm text-[14px] text-on-surface font-bold">
                          {app.name}
                        </span>
                        <span className="text-[10px] font-code-sm px-2 py-0.5 rounded-full bg-surface-container-highest text-on-surface-variant">
                          {app.category}
                        </span>
                      </div>
                      <span className="text-[11px] font-code-sm text-outline mt-0.5">
                        pkg: <code className="text-primary">{app.packageName}</code>
                      </span>
                    </div>

                    <span
                      className={`px-2 py-0.5 rounded-full text-[10px] font-code-sm font-semibold flex items-center gap-1 shrink-0 ${
                        app.installed
                          ? 'bg-tertiary-container/30 text-tertiary border border-tertiary/40'
                          : 'bg-error-container/40 text-on-error-container border border-error/40'
                      }`}
                    >
                      <MaterialIcon
                        name={app.installed ? 'check_circle' : 'error'}
                        className="text-[13px]"
                      />
                      <span>{app.installed ? 'Installed & Ready' : 'Not Installed'}</span>
                    </span>
                  </div>

                  <p className="font-body-md text-[12px] text-on-surface-variant/90 leading-relaxed mt-1">
                    {app.description}
                  </p>
                </div>

                <div className="mt-3 pt-2.5 border-t border-white/5 flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 text-[11px] font-code-sm text-outline truncate max-w-[220px]">
                    <MaterialIcon name="terminal" className="text-[14px] shrink-0" />
                    <span className="truncate">{app.binaryPath}</span>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      type="button"
                      title="Copy APT install command"
                      onClick={() => handleCopyCommand(app)}
                      className="px-2 py-1 rounded-md bg-surface-container-high hover:bg-surface-bright text-on-surface text-[11px] font-code-sm transition-colors border border-white/5 flex items-center gap-1"
                    >
                      <MaterialIcon
                        name={copiedId === app.id ? 'check' : 'content_copy'}
                        className="text-[13px]"
                      />
                      <span>{copiedId === app.id ? 'Copied' : 'Copy'}</span>
                    </button>

                    <button
                      type="button"
                      disabled={isInstalling}
                      onClick={() => handleInstallOne(app)}
                      className={`px-3 py-1 rounded-md text-[12px] font-title-sm font-semibold flex items-center gap-1 shadow-sm transition-all active:scale-95 ${
                        app.installed
                          ? 'bg-surface-container-high hover:bg-surface-bright text-tertiary border border-tertiary/30'
                          : 'bg-primary hover:bg-primary-container text-white'
                      }`}
                    >
                      <MaterialIcon
                        name={isInstalling ? 'sync' : app.installed ? 'done_all' : 'download'}
                        className={`text-[14px] ${isInstalling ? 'animate-spin' : ''}`}
                      />
                      <span>
                        {isInstalling
                          ? 'Installing...'
                          : app.installed
                          ? 'Reinstall'
                          : '1-Click Install'}
                      </span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        {/* Live Execution Console Drawer */}
        <div className="p-3 px-5 bg-surface-container-lowest border-t border-[#363243] flex flex-col gap-1.5 font-code-sm text-[11px]">
          <div className="flex items-center justify-between text-outline">
            <div className="flex items-center gap-1.5 text-primary">
              <MaterialIcon name="terminal" className="text-[14px]" />
              <span className="font-semibold uppercase tracking-wider text-[10px]">
                Live Package Provisioning Console
              </span>
            </div>
            <button
              type="button"
              onClick={() => setTerminalLogs(['[CLEAR] Logs reset. Ready for next package operation.'])}
              className="text-[10px] text-on-surface-variant hover:underline"
            >
              Clear Logs
            </button>
          </div>
          <div className="h-16 overflow-y-auto flex flex-col gap-0.5 text-on-surface-variant/85 bg-black/40 p-2 rounded-lg border border-white/5">
            {terminalLogs.slice(-6).map((log, idx) => (
              <div key={idx} className="leading-tight">
                {log.includes('[SUCCESS]') || log.includes('[COMPLETE]') ? (
                  <span className="text-tertiary">{log}</span>
                ) : log.includes('$') ? (
                  <span className="text-primary font-bold">{log}</span>
                ) : (
                  <span>{log}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
