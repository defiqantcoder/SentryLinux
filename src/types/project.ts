export type TargetPlatform = 'desktop';
export type CodingLanguageId = 'rust-tauri';

export type TabId =
  | 'overview'
  | 'dns-sentry'
  | 'outbound-intercepts'
  | 'usg-and-lynis-cis-audit'
  | 'malware-and-sweep'
  | 'daemon-restarts-and-needrestart'
  | 'network-profiles-and-wireguard'
  | 'rules-and-quarantine'
  | 'settings-and-polkit-auth';

export type NetworkMode = 'nextdns' | 'proton' | 'coexist';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'WARN' | 'MEDIUM' | 'LOW' | 'INFO' | 'MITIGATED';

export interface ProjectState {
  id: string;
  appName: string;
  tagline: string;
  coreIdea: string;
  targetPlatform: TargetPlatform;
  codingLanguage?: CodingLanguageId;
  features: string[];
  groundRules: {
    offlineFirst: true;
    highPerformance: true;
    localPrivacy: true;
    darkModeDefault: true;
  };
  clarifications: Array<{
    id: string;
    category: string;
    question: string;
    selectedAnswer?: string;
  }>;
}

export interface IncidentEvent {
  id: string;
  timestamp: string;
  severity: SeverityLevel;
  title: string;
  binary: string;
  pid: number;
  parentProcess: string;
  targetSocket: string;
  summary: string;
  heuristicScore: number;
  geminiInsight: string;
  mitreTag: string;
  isolated?: boolean;
}

export interface DnsQueryRecord {
  id: string;
  timestamp: string;
  process: string;
  pid: number;
  domain: string;
  recordType: 'A' | 'AAAA' | 'HTTPS' | 'TXT' | 'CNAME';
  cnameChain?: string;
  resolvedIp: string;
  category: string;
  threatFeed?: string;
  protocol: 'DoH (NextDNS)' | 'DoT (Strict)' | 'mDNS (Local)' | 'UDP 53 (Fallback)';
  dnssec: boolean;
  status: 'Blocked' | 'Allowed' | 'C2 Flagged';
  latencyMs: number;
  cnameDependencyWarning?: string;
}

export interface InterceptSocketEvent {
  id: string;
  timestamp: string;
  binary: string;
  pid: number;
  uid: string;
  parentTree: string;
  cmdLine: string;
  sha256: string;
  packageVerified: string;
  remoteDomain: string;
  remoteIp: string;
  remotePort: number;
  protocol: 'HTTPS' | 'SSH' | 'TCP' | 'UDP';
  localSocket: string;
  interfaceName: string;
  asn: string;
  geoLocation: string;
  dnsStatus: string;
  threatFeedWarning?: string;
  heuristicScore: number;
  geminiNarrative: string;
  verdict: 'PENDING' | 'ALLOW_ONCE' | 'ALLOW_ALWAYS' | 'DENY';
  ruleApplied: string;
}

export interface CisBenchmarkRule {
  id: string;
  code: string;
  sectionId: number;
  title: string;
  risk: 'Critical' | 'High Risk' | 'Medium Risk' | 'Low Risk';
  serviceTag: string;
  status: 'Failed' | 'Queued' | 'Passed' | 'Manual';
  stagedForFix: boolean;
  currentValue: string;
  targetValue: string;
  targetFile: string;
  diffRemoved: string[];
  diffAdded: string[];
  aiVulnerabilityExplanation: string;
}

export interface SweepFinding {
  id: string;
  name: string;
  path: string;
  engine: 'ClamAV 1.3.1' | 'RKhunter 1.4.6' | 'Debsums 3.0.2' | 'LMD v1.6.5' | 'Trivy Container';
  category: 'Quarantined' | 'Checksum Anomaly' | 'Rootkit Hook' | 'Supply Chain';
  severity: 'Critical' | 'High' | 'Medium';
  sha256: string;
  packageOwner: string;
  detectedAt: string;
  stage1DebsumsResult: string;
  stage2GeminiForensics: string;
  status: 'Active' | 'Quarantined' | 'Healed' | 'Verified Backport';
}

export interface StaleDaemonItem {
  id: string;
  unitName: string;
  pid: number;
  severity: 'Critical' | 'High' | 'Nominal';
  badgeLabel: string;
  description: string;
  rssMemory: string;
  uptime: string;
  supersededObject: string;
  cveId?: string;
  cvssScore?: string;
  impactAssessment: string;
  scope: 'System' | 'Session';
  memoryMaps: string[];
  status: 'Stale' | 'Restarting' | 'Remapped' | 'Postponed';
}

export interface WireGuardTunnel {
  id: string;
  interfaceName: string;
  location: string;
  provider: 'Proton VPN' | 'Mullvad' | 'Internal VPC';
  status: 'ACTIVE DEFAULT' | 'STANDBY' | 'SPLIT-ONLY';
  tunnelIp: string;
  endpoint: string;
  allowedIps: string;
  publicKey: string;
  rxGiB: number;
  txGiB: number;
  latencyMs: number;
}

export interface QuarantinedArtifact {
  id: string;
  binaryName: string;
  inode: number;
  classification: string;
  fileType: string;
  severity: 'High Alert' | 'Medium' | 'Staged Deletion' | 'False Positive';
  originPath: string;
  vaultPath: string;
  sha256: string;
  permissions: string;
  capturedAt: string;
}

export interface AppArmorProfileItem {
  id: string;
  profileName: string;
  binaryPath: string;
  mode: 'Enforce' | 'Complain';
  confinedProcesses: number;
  recentDenials: number;
  cgroupSlice: string;
  ramLimitMb: number;
}

export interface PolkitActionRule {
  id: string;
  actionId: string;
  policyLevel: 'auth_admin_keep' | 'auth_self_keep' | 'auth_admin';
  ttlLabel: string;
  description: string;
  category: 'Quarantine' | 'Network' | 'CIS Audit' | 'System';
  promptMode: string;
  enabled: boolean;
  icon: string;
}

export interface SystemdExposureUnit {
  unit: string;
  exposureScore: number;
  level: 'SAFE' | 'OK' | 'MEDIUM' | 'EXPOSED' | 'UNSAFE';
  protectSystem: string;
  protectHome: string;
  privateTmp: boolean;
  noNewPrivileges: boolean;
  dropInDraft: string;
}

export interface BlastRadiusReport {
  pid: number;
  binary: string;
  riskSummary: string;
  dependentProcesses: string[];
  sharedLibraries: string[];
  openSockets: string[];
  recommendedAction: 'SIGSTOP (Freeze cgroup)' | 'Graceful SIGHUP' | 'Safe to SIGKILL';
  desktopSessionSafe: boolean;
}

export interface SafetyCriticVerdict {
  approved: boolean;
  auditorModel: string;
  confidence: number;
  rubricChecks: {
    noCredentialWipes: boolean;
    noUserLockout: boolean;
    noBootTargetDisruption: boolean;
    reversibleSnapshotReady: boolean;
  };
  summary: string;
}

export interface AskSentryResult {
  query: string;
  translatedCommand: string;
  executionEngine: 'ausearch' | 'journalctl' | 'ufw + fail2ban' | 'resolvectl';
  timelineSummary: string;
  matchedRecords: Array<{
    timestamp: string;
    pid: number;
    comm: string;
    detail: string;
    severity: 'INFO' | 'WARN' | 'CRITICAL';
  }>;
}

export interface LiveSystemTelemetry {
  kernelVersion: string;
  uptimeFormatted: string;
  loadAverage: string;
  memoryUsedMb: number;
  memoryTotalMb: number;
  lockdownMode: string;
  kptrRestrict: string;
  tpmPcrStatus: string;
  luksKeyslotsActive: number;
  secureBootEnabled: boolean;
}
