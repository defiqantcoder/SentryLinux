import React, { useState, useEffect } from 'react';
import { 
  Shield, Activity, Globe, Lock, Cpu, Settings, Network, 
  Search, Power, AlertTriangle, XCircle, 
  RefreshCw, Play, ShieldAlert, ShieldCheck, Server, Key
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

// --- Simulated Data Generators ---
const generateIP = () => `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
const domains = ['api.tracker.com', 'telemetry.ubuntu.com', 'cdn.jsdelivr.net', 'github.com', 'malicious-c2.net', 'metrics.app.io', 'update.server.org'];
const processes = ['/usr/bin/curl', '/usr/lib/firefox/firefox', '/usr/bin/apt-get', '/sbin/auditd', '/usr/bin/python3', 'unknown_binary'];

// --- Types ---
type ButtonVariant = 'default' | 'primary' | 'destructive' | 'flat';

interface GtkButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  variant?: ButtonVariant;
  className?: string;
}

interface GtkSwitchProps {
  checked: boolean;
  onChange: (checked: boolean) => void;
  label?: string;
}

interface GtkCardProps {
  children: React.ReactNode;
  className?: string;
  title?: string;
}

interface DnsQuery {
  id: number;
  domain: string;
  ip: string;
  status: 'Blocked' | 'Allowed';
  time: string;
}

interface InterceptEvent {
  process: string;
  pid: number;
  ip: string;
  port: number;
}

// --- GTK4 UI Components ---
const GtkButton = ({ children, onClick, variant = 'default', className = '', ...props }: GtkButtonProps) => {
  const baseStyle = "px-4 py-2 rounded-lg font-medium transition-colors text-sm flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed";
  const variants: Record<ButtonVariant, string> = {
    default: "bg-[#383838] hover:bg-[#4a4a4a] text-white border border-white/10",
    primary: "bg-[#3584e4] hover:bg-[#4a90d9] text-white",
    destructive: "bg-[#e01b24] hover:bg-[#f66151] text-white",
    flat: "bg-transparent hover:bg-white/10 text-white"
  };
  return (
    <button onClick={onClick} className={`${baseStyle} ${variants[variant]} ${className}`} {...props}>
      {children}
    </button>
  );
};

const GtkSwitch = ({ checked, onChange, label }: GtkSwitchProps) => (
  <label className="flex items-center cursor-pointer gap-3">
    {label && <span className="text-sm font-medium text-gray-200">{label}</span>}
    <div className="relative">
      <input type="checkbox" className="sr-only" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <div className={`block w-12 h-7 rounded-full transition-colors ${checked ? 'bg-[#3584e4]' : 'bg-[#4a4a4a]'}`}></div>
      <div className={`absolute left-1 top-1 bg-white w-5 h-5 rounded-full transition-transform ${checked ? 'transform translate-x-5' : ''}`}></div>
    </div>
  </label>
);

const GtkCard = ({ children, className = '', title }: GtkCardProps) => (
  <div className={`bg-[#2d2d2d] rounded-xl border border-white/5 shadow-md overflow-hidden ${className}`}>
    {title && <div className="px-4 py-3 border-b border-white/5 bg-[#242424]/50 font-semibold text-gray-100">{title}</div>}
    <div className="p-4">{children}</div>
  </div>
);

// --- Core Modules ---

const OverviewTelemetry = ({ isLockdown }: { isLockdown: boolean }) => {
  const [flashLogs, setFlashLogs] = useState<string[]>([]);
  const [proLogs, setProLogs] = useState<string[]>([]);
  const [exposureScore, setExposureScore] = useState<number>(4.2);

  useEffect(() => {
    if (isLockdown) return;
    const flashInterval = setInterval(() => {
      setFlashLogs(prev => [`[${new Date().toLocaleTimeString()}] Triage: ${processes[Math.floor(Math.random()*processes.length)]} syscall execve verified. Risk: Low`, ...prev].slice(0, 15));
    }, 1500);

    const proInterval = setInterval(() => {
      const risks = ['Anomaly detected: Repeated outbound probes dropped by UFW.', 'Dependency scan complete. No new CVEs found in APT cache.', 'Analyzing eBPF hook: Behavior matches known Ubuntu backport. Safe.'];
      setProLogs(prev => [`[${new Date().toLocaleTimeString()}] Deep Analysis: ${risks[Math.floor(Math.random()*risks.length)]}`, ...prev].slice(0, 10));
      setExposureScore(prev => Math.max(1.0, Math.min(10.0, prev + (Math.random() - 0.5) * 0.5)));
    }, 4000);

    return () => { clearInterval(flashInterval); clearInterval(proInterval); };
  }, [isLockdown]);

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <GtkCard className="col-span-1 flex flex-col items-center justify-center p-6">
          <div className="text-sm text-gray-400 mb-2">Systemd Exposure Score</div>
          <div className={`text-5xl font-bold ${exposureScore < 4 ? 'text-green-400' : exposureScore < 7 ? 'text-yellow-400' : 'text-red-400'}`}>
            {exposureScore.toFixed(1)}
          </div>
          <div className="text-xs text-gray-500 mt-2">0.0 (Hardened) - 10.0 (Exposed)</div>
        </GtkCard>
        <GtkCard title="Gemini 3.8 Flash (Live Triage)" className="col-span-2 h-64 flex flex-col">
          <div className="font-mono text-xs text-green-400 overflow-y-auto flex-1 space-y-1">
            {flashLogs.map((log, i) => <div key={i} className="opacity-80">{log}</div>)}
            {flashLogs.length === 0 && <div className="text-gray-500">Waiting for telemetry...</div>}
          </div>
        </GtkCard>
      </div>
      <GtkCard title="Gemini 3.1 Pro (Forensic Reasoning)" className="h-64 flex flex-col">
        <div className="font-mono text-sm text-blue-300 overflow-y-auto flex-1 space-y-2">
          {proLogs.map((log, i) => <div key={i} className="border-l-2 border-blue-500/30 pl-2 opacity-90">{log}</div>)}
          {proLogs.length === 0 && <div className="text-gray-500">Awaiting complex anomalies...</div>}
        </div>
      </GtkCard>
    </div>
  );
};

const DNSSentry = () => {
  const [queries, setQueries] = useState<DnsQuery[]>([]);

  useEffect(() => {
    const interval = setInterval(() => {
      const domain = domains[Math.floor(Math.random() * domains.length)];
      const isBlocked = domain.includes('malicious') || domain.includes('tracker');
      const newQuery: DnsQuery = {
        id: Date.now(),
        domain,
        ip: generateIP(),
        status: isBlocked ? 'Blocked' : 'Allowed',
        time: new Date().toLocaleTimeString()
      };
      setQueries(prev => [newQuery, ...prev].slice(0, 10));
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="flex justify-between items-center">
        <GtkCard className="flex items-center gap-4 bg-green-900/20 border-green-500/30">
          <ShieldCheck className="text-green-400" size={24} />
          <div>
            <div className="font-semibold text-green-100">DoH/DoT Encryption Active</div>
            <div className="text-xs text-green-400/70">Connected to NextDNS (Anycast)</div>
          </div>
        </GtkCard>
        <GtkButton variant="default"><RefreshCw size={16} /> Flush Cache</GtkButton>
      </div>
      <GtkCard title="Live NextDNS Telemetry (SSE Stream)" className="overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left">
            <thead className="text-xs text-gray-400 uppercase bg-[#242424]">
              <tr>
                <th className="px-4 py-3">Time</th>
                <th className="px-4 py-3">Domain</th>
                <th className="px-4 py-3">Resolved IP</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {queries.map(q => (
                <tr key={q.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                  <td className="px-4 py-3 font-mono text-gray-400">{q.time}</td>
                  <td className="px-4 py-3 font-medium">{q.domain}</td>
                  <td className="px-4 py-3 font-mono text-gray-400">{q.ip}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 rounded-full text-xs ${q.status === 'Blocked' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
                      {q.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right space-x-2">
                    <GtkButton variant="flat" className="!px-2 !py-1 text-green-400 hover:bg-green-500/20">Allow</GtkButton>
                    <GtkButton variant="flat" className="!px-2 !py-1 text-red-400 hover:bg-red-500/20">Deny</GtkButton>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </GtkCard>
    </div>
  );
};

const NetworkIntercept = () => {
  const [intercept, setIntercept] = useState<InterceptEvent | null>(null);

  useEffect(() => {
    const triggerIntercept = () => {
      setIntercept({
        process: processes[Math.floor(Math.random() * processes.length)],
        pid: Math.floor(Math.random() * 9000) + 1000,
        ip: generateIP(),
        port: [80, 443, 8080, 22, 53][Math.floor(Math.random() * 5)]
      });
    };
    const timer = setTimeout(triggerIntercept, 3000);
    return () => clearTimeout(timer);
  }, []);

  const handleAction = () => {
    setIntercept(null);
    setTimeout(() => {
      setIntercept({
        process: processes[Math.floor(Math.random() * processes.length)],
        pid: Math.floor(Math.random() * 9000) + 1000,
        ip: generateIP(),
        port: [80, 443, 8080, 22, 53][Math.floor(Math.random() * 5)]
      });
    }, 8000); // Trigger next intercept after a delay
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {intercept ? (
        <div className="bg-[#2d2d2d] border-2 border-[#3584e4] rounded-xl p-6 shadow-2xl shadow-blue-900/20 relative overflow-hidden">
           <div className="absolute top-0 left-0 w-full h-1 bg-blue-500 animate-pulse"></div>
           <div className="flex items-start gap-4">
             <div className="p-3 bg-blue-500/20 rounded-full text-blue-400">
               <ShieldAlert size={32} />
             </div>
             <div className="flex-1">
               <h3 className="text-xl font-bold text-white mb-2">Outbound Connection Intercepted</h3>
               <p className="text-gray-300 mb-4">
                 Process <span className="font-mono bg-black/30 px-1 rounded text-orange-300">{intercept.process}</span> (PID {intercept.pid}) 
                 wants to reach <span className="font-mono text-blue-300">{intercept.ip}:{intercept.port}</span>.
               </p>
               <div className="flex gap-3">
                 <GtkButton variant="primary" onClick={handleAction}>Allow Once</GtkButton>
                 <GtkButton variant="default" onClick={handleAction}>Allow Always</GtkButton>
                 <GtkButton variant="destructive" onClick={handleAction}>Deny</GtkButton>
               </div>
             </div>
           </div>
        </div>
      ) : (
        <GtkCard className="text-center py-8 text-gray-400">
          <ShieldCheck size={48} className="mx-auto mb-4 opacity-50" />
          <p>No active connection intercepts.</p>
        </GtkCard>
      )}

      <GtkCard title="UFW Active Rules" className="mt-6">
         <table className="w-full text-sm text-left">
            <thead className="text-xs text-gray-400 uppercase border-b border-white/10">
              <tr><th>To</th><th>Action</th><th>From</th></tr>
            </thead>
            <tbody className="divide-y divide-white/5 font-mono text-gray-300">
              <tr><td className="py-2">22/tcp</td><td className="text-green-400">ALLOW IN</td><td>192.168.1.0/24</td></tr>
              <tr><td className="py-2">80,443/tcp</td><td className="text-green-400">ALLOW IN</td><td>Anywhere</td></tr>
              <tr><td className="py-2">Any</td><td className="text-red-400">DENY IN</td><td>185.15.0.0/16</td></tr>
            </tbody>
          </table>
      </GtkCard>
    </div>
  );
};

const MalwareSweep = () => {
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);

  const startScan = () => {
    setScanning(true);
    setProgress(0);
    const interval = setInterval(() => {
      setProgress(p => {
        if (p >= 100) {
          clearInterval(interval);
          setScanning(false);
          return 100;
        }
        return p + Math.floor(Math.random() * 15);
      });
    }, 500);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <GtkCard title="Manual Scanners">
          <div className="space-y-3">
            <GtkButton className="w-full justify-start" variant="primary" onClick={startScan} disabled={scanning}>
              <Play size={18} /> {scanning ? 'Scanning...' : 'Quick Scan (ClamAV)'}
            </GtkButton>
            <GtkButton className="w-full justify-start" onClick={startScan} disabled={scanning}>
              <Search size={18} /> Full System Audit (RKhunter + ClamAV)
            </GtkButton>
            <GtkButton className="w-full justify-start" variant="destructive">
              <AlertTriangle size={18} /> Deep Clean (Interruptive)
            </GtkButton>
          </div>
          {scanning && (
            <div className="mt-4 space-y-2">
              <div className="flex justify-between text-xs text-gray-400">
                <span>Scanning /usr/bin...</span>
                <span>{Math.min(progress, 100)}%</span>
              </div>
              <div className="w-full bg-[#1e1e1e] rounded-full h-2">
                <div className="bg-[#3584e4] h-2 rounded-full transition-all duration-300" style={{ width: `${Math.min(progress, 100)}%` }}></div>
              </div>
            </div>
          )}
        </GtkCard>

        <GtkCard title="Quarantine Vault">
          <div className="space-y-3">
             <div className="flex items-center justify-between p-3 bg-red-900/10 border border-red-500/20 rounded-lg">
                <div>
                  <div className="font-mono text-sm text-red-300">Suspicious_Hook.so</div>
                  <div className="text-xs text-gray-500">Detected by RKhunter • 2h ago</div>
                </div>
                <GtkButton variant="destructive" className="!px-2 !py-1 text-xs">Purge</GtkButton>
             </div>
             <div className="flex items-center justify-between p-3 bg-[#242424] rounded-lg">
                <div>
                  <div className="font-mono text-sm text-gray-300">installer_v2.sh</div>
                  <div className="text-xs text-gray-500">Heuristic Match • 1d ago</div>
                </div>
                <div className="flex gap-2">
                  <GtkButton variant="default" className="!px-2 !py-1 text-xs">Restore</GtkButton>
                  <GtkButton variant="destructive" className="!px-2 !py-1 text-xs">Purge</GtkButton>
                </div>
             </div>
          </div>
        </GtkCard>
      </div>
    </div>
  );
};

const DaemonInspector = () => {
  const staleServices = [
    { name: 'systemd-networkd.service', memory: '14.2 MB', uptime: '14d' },
    { name: 'pulseaudio.service', memory: '45.1 MB', uptime: '14d' },
    { name: 'dbus.service', memory: '8.4 MB', uptime: '14d' }
  ];

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
       <div className="bg-yellow-900/20 border border-yellow-500/30 rounded-xl p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <AlertTriangle className="text-yellow-500" />
            <div>
              <h4 className="font-semibold text-yellow-100">Obsolete Libraries Detected</h4>
              <p className="text-sm text-yellow-500/80">3 services are using deleted/updated shared libraries (needrestart).</p>
            </div>
          </div>
          <GtkButton variant="primary"><RefreshCw size={16} /> Restart Obsolete Services</GtkButton>
       </div>

       <GtkCard title="Stale Daemons">
         <table className="w-full text-sm text-left">
            <thead className="text-xs text-gray-400 uppercase border-b border-white/10">
              <tr><th>Service Name</th><th>Stale Memory</th><th>Uptime</th><th>Action</th></tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {staleServices.map((srv, i) => (
                <tr key={i} className="hover:bg-white/5 transition-colors">
                  <td className="py-3 font-mono">{srv.name}</td>
                  <td className="py-3 text-orange-300">{srv.memory}</td>
                  <td className="py-3 text-gray-400">{srv.uptime}</td>
                  <td className="py-3"><GtkButton variant="flat" className="!py-1 text-sm">Restart</GtkButton></td>
                </tr>
              ))}
            </tbody>
          </table>
       </GtkCard>
    </div>
  );
};

const SettingsAuth = () => {
  const [useFido, setUseFido] = useState(true);
  const [requirePin, setRequirePin] = useState(false);

  return (
    <div className="space-y-6 animate-in fade-in duration-300 max-w-2xl">
      <GtkCard title="Polkit & Sudo Administration">
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-white">Require Hardware Token (pam-u2f)</div>
              <div className="text-sm text-gray-400">Enforce FIDO2/YubiKey physical presence for sudo commands.</div>
            </div>
            <GtkSwitch checked={useFido} onChange={setUseFido} />
          </div>
          <div className="h-px bg-white/10"></div>
          <div className="flex items-center justify-between">
            <div>
              <div className="font-medium text-white">Require PIN for Token</div>
              <div className="text-sm text-gray-400">Prompt for FIDO2 PIN in addition to physical touch.</div>
            </div>
            <GtkSwitch checked={requirePin} onChange={setRequirePin} />
          </div>
        </div>
        <div className="mt-6 p-4 bg-[#242424] rounded-lg flex items-center gap-4 border border-white/5">
          <Key className="text-gray-400" />
          <div className="flex-1">
            <div className="text-sm font-medium">YubiKey 5 NFC (Registered)</div>
            <div className="text-xs text-gray-500 font-mono">ID: 04:A1:B2:C3...</div>
          </div>
          <GtkButton variant="destructive" className="!px-3 !py-1 text-xs">Revoke</GtkButton>
        </div>
      </GtkCard>
    </div>
  );
};

const NetworkProfiles = () => {
  const [profile, setProfile] = useState('coexist');

  const Option = ({ id, title, desc, icon: Icon }: { id: string; title: string; desc: string; icon: LucideIcon }) => (
    <label className={`flex items-start gap-4 p-4 rounded-xl cursor-pointer border-2 transition-all ${profile === id ? 'border-[#3584e4] bg-[#3584e4]/10' : 'border-white/5 bg-[#2d2d2d] hover:bg-[#323232]'}`}>
      <input type="radio" name="net_profile" value={id} checked={profile === id} onChange={(e) => setProfile(e.target.value)} className="sr-only" />
      <div className={`p-2 rounded-full ${profile === id ? 'bg-[#3584e4] text-white' : 'bg-[#1e1e1e] text-gray-400'}`}>
        <Icon size={24} />
      </div>
      <div>
        <div className="font-bold text-lg text-white mb-1">{title}</div>
        <div className="text-sm text-gray-400 leading-relaxed">{desc}</div>
      </div>
    </label>
  );

  return (
    <div className="space-y-4 animate-in fade-in duration-300 max-w-3xl">
      <h2 className="text-xl font-semibold mb-6 text-gray-100">WireGuard & DNS Co-Existence</h2>
      <Option 
        id="nextdns" 
        title="NextDNS Only" 
        desc="Binds local network interfaces directly to your NextDNS profile via DoT/DoH. VPN tunnels are disabled." 
        icon={Server} 
      />
      <Option 
        id="proton" 
        title="Proton VPN Only" 
        desc="Routes all system traffic through Proton VPN using native Proton NetShield DNS resolvers (10.2.0.1). Strict VPN enforcement." 
        icon={Shield} 
      />
      <Option 
        id="coexist" 
        title="Co-Existence Mode (Proton + NextDNS)" 
        desc="Tunnels outbound traffic through Proton VPN while routing DNS exclusively to your authenticated NextDNS profile. Manages systemd-resolved dynamically to prevent leaks." 
        icon={Network} 
      />
      
      {profile === 'coexist' && (
        <div className="mt-6 p-4 bg-blue-900/20 border border-blue-500/30 rounded-lg animate-in slide-in-from-top-2 text-sm text-blue-200">
          <strong>Status:</strong> Linked IP synchronized successfully with NextDNS via API hook on wg0 interface.
        </div>
      )}
    </div>
  );
};


// --- Main Application ---
export default function App() {
  const [activeTab, setActiveTab] = useState('overview');
  const [isLockdown, setIsLockdown] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const tabs = [
    { id: 'overview', label: 'Overview Telemetry', icon: Activity },
    { id: 'dns', label: 'DNS Sentry', icon: Globe },
    { id: 'network', label: 'Network Intercept', icon: Network },
    { id: 'malware', label: 'Malware Sweep', icon: ShieldAlert },
    { id: 'daemons', label: 'Daemon Inspector', icon: Cpu },
    { id: 'auth', label: 'Settings & Auth', icon: Lock },
    { id: 'profiles', label: 'Network Profiles', icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-[#1e1e1e] text-gray-200 font-sans flex flex-col overflow-hidden selection:bg-[#3584e4] selection:text-white">
      
      {/* Header Bar (GTK HeaderBar style) */}
      <header className="bg-[#2d2d2d] h-14 border-b border-black/50 flex items-center justify-between px-4 shadow-sm z-20 shrink-0">
        <div className="flex items-center gap-3">
          <Shield className="text-[#3584e4]" size={24} />
          <span className="font-bold text-gray-100 tracking-wide">SentryLinux</span>
        </div>
        
        {/* Ask Sentry Search */}
        <div className="flex-1 max-w-xl mx-8">
          <div className="relative group">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400 group-focus-within:text-[#3584e4]" size={16} />
            <input 
              type="text" 
              placeholder="Ask Sentry (e.g., 'Did any process touch .ssh today?')"
              className="w-full bg-[#1e1e1e] border border-white/10 rounded-lg py-1.5 pl-10 pr-4 text-sm text-white focus:outline-none focus:border-[#3584e4] focus:ring-1 focus:ring-[#3584e4] transition-all"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        {/* Lockdown Switch */}
        <div className="flex items-center gap-4">
          <div className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider ${isLockdown ? 'bg-red-500 text-white animate-pulse' : 'bg-green-500/20 text-green-400'}`}>
            {isLockdown ? 'Lockdown Active' : 'System Secure'}
          </div>
          <button 
            onClick={() => setIsLockdown(!isLockdown)}
            className={`w-10 h-10 rounded-full flex items-center justify-center transition-colors ${isLockdown ? 'bg-red-500 hover:bg-red-600' : 'bg-[#383838] hover:bg-[#4a4a4a] border border-white/10'}`}
            title="Master Kill-Switch"
          >
            <Power size={18} className={isLockdown ? 'text-white' : 'text-gray-300'} />
          </button>
        </div>
      </header>

      {/* Main Layout */}
      <div className="flex flex-1 overflow-hidden">
        
        {/* Sidebar */}
        <nav className="w-64 bg-[#242424] border-r border-black/30 flex flex-col py-4 shrink-0">
          <div className="px-3 space-y-1">
            {tabs.map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors ${
                    isActive 
                      ? 'bg-[#3584e4]/10 text-[#3584e4] font-medium' 
                      : 'text-gray-400 hover:bg-white/5 hover:text-gray-200'
                  }`}
                >
                  <Icon size={18} />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </nav>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-8 relative">
          {/* Lockdown Overlay */}
          {isLockdown && (
            <div className="absolute inset-0 bg-red-950/20 border-[4px] border-red-500 pointer-events-none z-10 flex items-start justify-center pt-4">
              <div className="bg-red-500 text-white px-6 py-2 rounded-full font-bold shadow-lg shadow-red-500/50 flex items-center gap-2">
                <XCircle size={20} /> ALL CONNECTIONS DROPPED
              </div>
            </div>
          )}

          <div className="max-w-5xl mx-auto">
            <h1 className="text-2xl font-bold text-white mb-6">
              {tabs.find(t => t.id === activeTab)?.label}
            </h1>
            
            {activeTab === 'overview' && <OverviewTelemetry isLockdown={isLockdown} />}
            {activeTab === 'dns' && <DNSSentry />}
            {activeTab === 'network' && <NetworkIntercept />}
            {activeTab === 'malware' && <MalwareSweep />}
            {activeTab === 'daemons' && <DaemonInspector />}
            {activeTab === 'auth' && <SettingsAuth />}
            {activeTab === 'profiles' && <NetworkProfiles />}
          </div>
        </main>
      </div>
    </div>
  );
}