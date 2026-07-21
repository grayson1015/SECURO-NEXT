export type PinStatus = "queued" | "scanning" | "completed" | "failed" | "timeout";
export type ScanProfile = "quick" | "standard" | "deep";
export type RiskLevel = "High" | "Medium" | "Low" | "Confirmed" | "Suspicious" | "Weak" | "Clean-but-limited" | "Insufficient data";

export type TimelineEvent = {
  time?: string;
  source?: string;
  text?: string;
  confidence?: "Possible" | "Likely" | "Confirmed" | string;
};

export type SecuroSession = {
  gameId?: string;
  placeId?: string;
  jobId?: string;
  userId?: string;
  username?: string;
  displayName?: string;
  version?: string;
  launchTime?: string;
  exitTime?: string;
  duration?: string;
  status?: string;
  linkedDetections?: SecuroFinding[];
  logFile?: string;
  loadClientSettings?: string[];
  events?: RobloxLogEvent[];
  fastFlags?: RobloxFastFlag[];
  robloxLogs?: RobloxLogArtifact[];
};

export type RobloxLogEvent = {
  timestamp?: string;
  type?: string;
  sourceLog?: string;
  message?: string;
};

export type RobloxFastFlag = {
  name?: string;
  value?: string;
  sourceLog?: string;
  timestamp?: string;
  line?: string;
  placeId?: string;
  jobId?: string;
  userId?: string;
};

export type RobloxLogArtifact = {
  logFile?: string;
  modifiedTime?: string;
  startTime?: string;
  endTime?: string;
  duration?: string;
  placeId?: string;
  jobId?: string;
  userId?: string;
  username?: string;
  displayName?: string;
  version?: string;
  events?: RobloxLogEvent[];
  fastFlags?: RobloxFastFlag[];
  loadClientSettings?: string[];
  errors?: string[];
  crashes?: string[];
  rawLog?: string;
};

export type AccountIdentifier = {
  platform?: "Roblox" | string;
  userId?: string;
  username?: string;
  displayName?: string;
  firstSeen?: string;
  lastSeen?: string;
  places?: string[];
  jobs?: string[];
  sources?: string[];
  confidenceLevel?: string;
  evidenceNote?: string;
};

export type AccountIdentifierContext = {
  privacyNote?: string;
  roblox?: AccountIdentifier[];
  discord?: AccountIdentifier[];
  discordStatus?: Record<string, unknown>;
};

export type UsnJournalStatus = {
  available?: boolean;
  readable?: boolean;
  recordsCollected?: number;
  volume?: string;
  firstUsn?: number;
  nextUsn?: number;
  error?: string;
  readCommand?: string;
};

export type SystemResetEvidence = {
  type?: string;
  timestamp?: string;
  source?: string;
  details?: string;
  eventId?: number;
};

export type WindowsInstallRecord = {
  productName?: string;
  releaseId?: string;
  currentBuild?: string;
  installDate?: string;
  source?: string;
};

export type SysMainServiceInfo = {
  serviceName?: string;
  currentState?: string;
  startupType?: string;
  lastChanged?: string;
  changeDetail?: string;
  manualReviewRequired?: boolean;
};

export type DefenderExclusion = {
  type?: "Path" | "Process" | "Extension" | "IP Address" | string;
  value?: string;
  source?: string;
  severity?: "Info" | "Review" | string;
  manualReviewRequired?: boolean;
  reasons?: string[];
};

export type UsnJournalEvent = {
  timestamp?: string;
  eventType?: "Created" | "Deleted" | "Renamed" | "Modified" | "Changed" | string;
  fileName?: string;
  path?: string;
  reason?: string;
  usn?: string;
  fileId?: string;
  parentFileId?: string;
  volume?: string;
  source?: string;
};

export type SecuroFinding = {
  name?: string;
  path?: string;
  sha256?: string;
  score?: number;
  category?: string;
  classification?: string;
  confidenceLevel?: "Possible" | "Likely" | "Confirmed" | string;
  firstSeen?: string;
  evidenceTypes?: string[];
  detectionCategories?: string[];
  detections?: {
    category?: string;
    reason?: string;
    risk?: string;
  }[];
  supportingEvidence?: string[];
};

export type SecuroReportJson = {
  scanTime: string;
  hostname: string;
  highestResult: string;
  confidence: string;
  evidenceSources: Record<string, boolean | string | number | null>;
  timeline: TimelineEvent[];
  sessions: SecuroSession[];
  robloxLogs?: RobloxLogArtifact[];
  detectedFastFlags?: RobloxFastFlag[];
  usnJournalEvents?: UsnJournalEvent[];
  usnJournalStatus?: UsnJournalStatus;
  shellBagArtifacts?: {
    path?: string;
    classification?: string;
    shellType?: string;
    timestamp?: string;
    firstInteracted?: string;
    lastInteracted?: string;
    slot?: string;
    mruPosition?: string;
    sourceHive?: string;
    sourceExport?: string;
    manualReviewRequired?: boolean;
  }[];
  accountIdentifiers?: AccountIdentifierContext;
  systemResetEvidence?: SystemResetEvidence[];
  windowsInstallHistory?: WindowsInstallRecord[];
  sysMainService?: SysMainServiceInfo;
  defenderExclusions?: DefenderExclusion[];
  findings: SecuroFinding[];
  limitations: string[];
  [key: string]: unknown;
};

export type PinRow = {
  id: string;
  pin_code: string;
  owner_user_id: string | null;
  owner_email?: string | null;
  status: PinStatus;
  scan_profile?: ScanProfile | string | null;
  created_at: string;
  expires_at: string;
  scan_stage?: string | null;
  scan_progress?: number | null;
  files_scanned?: number | null;
  last_successful_operation?: string | null;
  status_updated_at?: string | null;
};

export type ReportRow = {
  id: string;
  pin_id: string;
  owner_user_id: string | null;
  owner_email?: string | null;
  uploaded_at: string;
  hostname: string;
  scan_time: string;
  risk_level: string;
  evidence_score: number;
  report_json: SecuroReportJson;
};

export type AllowedUserRow = {
  id: string;
  email: string;
  role: "owner" | "admin" | "moderator";
  created_at: string;
};

export type AccessKeyRow = {
  id: string;
  key_code: string;
  assigned_email: string | null;
  assigned_user_id: string | null;
  used_at: string | null;
  created_at: string;
  license_type?: "standard" | "business";
  max_emails?: number;
  expires_at?: string | null;
};

export type BusinessLicenseRow = {
  key_code: string;
  license_type: "business";
  max_emails: number;
  emails_used: number;
  created_at: string;
  expires_at: string | null;
};

export type BusinessLicenseUserRow = {
  license_key: string;
  email: string;
  activated_at: string;
  last_seen_at: string;
};
