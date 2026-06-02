export type PinStatus = "pending" | "connected" | "completed";
export type RiskLevel = "High" | "Medium" | "Low" | "Confirmed" | "Suspicious" | "Weak" | "Clean-but-limited" | "Insufficient data";

export type TimelineEvent = {
  time?: string;
  source?: string;
  text?: string;
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
};

export type SecuroFinding = {
  name?: string;
  path?: string;
  sha256?: string;
  score?: number;
  category?: string;
  classification?: string;
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
  created_at: string;
  expires_at: string;
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
};
