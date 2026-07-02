import type { ReportRow, RobloxLogArtifact, SecuroFinding, SecuroReportJson, SecuroSession, TimelineEvent } from "@/lib/types";

const DAY_MS = 24 * 60 * 60 * 1000;

export function compactReportRow(report: ReportRow, days = 7, includeRawLogs = false): ReportRow {
  return {
    ...report,
    report_json: compactReportJson(report.report_json, days, includeRawLogs)
  };
}

export function compactReportJson(report: SecuroReportJson, days = 7, includeRawLogs = false): SecuroReportJson {
  const scanTime = new Date(report.scanTime || "").getTime();
  const referenceTime = Number.isFinite(scanTime) ? scanTime : Date.now();
  const cutoff = Number.isFinite(days) ? referenceTime - Math.max(1, days) * DAY_MS : 0;
  const inRange = (value?: string) => {
    if (!cutoff) return true;
    const time = new Date(value || "").getTime();
    return !Number.isFinite(time) || time >= cutoff;
  };

  const sessions = (report.sessions || [])
    .filter((session) => inRange(session.launchTime || session.exitTime))
    .slice(0, 80)
    .map(compactSession);
  const timeline = (report.timeline || [])
    .filter((event) => inRange(event.time))
    .slice(-500)
    .map(compactTimelineEvent);
  const robloxLogs = (report.robloxLogs || [])
    .filter((log) => inRange(log.startTime || log.modifiedTime))
    .slice(0, includeRawLogs ? 80 : 20)
    .map((log) => compactRobloxLog(log, includeRawLogs));
  const fastFlags = (report.detectedFastFlags || [])
    .filter((flag) => inRange(flag.timestamp))
    .slice(0, includeRawLogs ? 1000 : 250);
  const findings = (report.findings || []).slice(0, 500).map(compactFinding);

  return {
    ...report,
    timeline,
    sessions,
    findings,
    robloxLogs,
    detectedFastFlags: fastFlags,
    _summary: {
      findingCount: report.findings?.length || 0,
      sessionCount: report.sessions?.length || 0,
      robloxLogCount: report.robloxLogs?.length || 0,
      compactedForDashboard: !includeRawLogs
    }
  };
}

function compactTimelineEvent(event: TimelineEvent): TimelineEvent {
  return {
    time: event.time,
    source: event.source,
    text: event.text,
    confidence: event.confidence
  };
}

function compactSession(session: SecuroSession): SecuroSession {
  return {
    gameId: session.gameId,
    placeId: session.placeId,
    jobId: session.jobId,
    userId: session.userId,
    username: session.username,
    displayName: session.displayName,
    version: session.version,
    launchTime: session.launchTime,
    exitTime: session.exitTime,
    duration: session.duration,
    status: session.status,
    linkedDetections: session.linkedDetections?.slice(0, 20),
    loadClientSettings: session.loadClientSettings?.slice(0, 20),
    events: session.events?.slice(0, 40),
    fastFlags: session.fastFlags?.slice(0, 80)
  };
}

function compactRobloxLog(log: RobloxLogArtifact, includeRawLogs: boolean): RobloxLogArtifact {
  return {
    logFile: log.logFile,
    modifiedTime: log.modifiedTime,
    startTime: log.startTime,
    endTime: log.endTime,
    duration: log.duration,
    placeId: log.placeId,
    jobId: log.jobId,
    userId: log.userId,
    username: log.username,
    displayName: log.displayName,
    version: log.version,
    events: log.events?.slice(0, includeRawLogs ? 1000 : 80),
    fastFlags: log.fastFlags?.slice(0, includeRawLogs ? 1000 : 120),
    loadClientSettings: log.loadClientSettings?.slice(0, 40),
    errors: log.errors?.slice(0, 25),
    crashes: log.crashes?.slice(0, 25),
    rawLog: includeRawLogs ? log.rawLog : ""
  };
}

function compactFinding(finding: SecuroFinding): SecuroFinding {
  return {
    name: finding.name,
    path: finding.path,
    sha256: finding.sha256,
    score: finding.score,
    category: finding.category,
    classification: finding.classification,
    confidenceLevel: finding.confidenceLevel,
    firstSeen: finding.firstSeen,
    evidenceTypes: finding.evidenceTypes,
    detectionCategories: finding.detectionCategories,
    detections: finding.detections,
    supportingEvidence: finding.supportingEvidence?.slice(0, 20)
  };
}
