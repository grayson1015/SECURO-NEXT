import Foundation

actor ScannerEngine {
    private let collectors: [EvidenceCollector]

    init(collectors: [EvidenceCollector] = [
        SystemCollector(),
        RobloxLogCollector(),
        RunningProcessCollector(),
        RobloxIntegrityCollector(),
        QuarantineCollector(),
        FileArtifactCollector(),
        PersistenceCollector()
    ]) {
        self.collectors = collectors
    }

    func scan(
        profile: ScanProfile,
        progress: @MainActor @escaping (ScanProgress) -> Void
    ) async -> SecuroReport {
        let started = Date()
        let context = ScanContext(
            profile: profile,
            deadline: started.addingTimeInterval(profile.timeLimit),
            fileManager: .default
        )
        var timeline = [TimelineEvent(time: started, source: "Scan diagnostics", text: "macOS scan started")]
        var sessions: [RobloxSession] = []
        var findings: [SecuroFinding] = []
        var limitations: [String] = []
        var evidence: [String: EvidenceValue] = [:]

        for (index, collector) in collectors.enumerated() {
            if context.expired {
                limitations.append("The \(profile.rawValue) scan reached its time limit. A partial report was generated.")
                break
            }
            let percent = Int((Double(index) / Double(max(collectors.count, 1))) * 90.0)
            await progress(ScanProgress(stage: "Checking \(collector.name)...", percent: percent))
            let result = collector.collect(context: context)
            evidence[result.sourceName] = .bool(result.available)
            evidence["\(result.sourceName) records"] = .integer(result.recordsCollected)
            timeline.append(contentsOf: result.timeline)
            sessions.append(contentsOf: result.sessions)
            findings.append(contentsOf: result.findings)
            limitations.append(contentsOf: result.limitations)
        }

        findings = TriageEngine().classify(findings)
        timeline.sort { $0.time < $1.time }
        sessions = dedupeSessions(sessions)
        let highest = highestResult(findings)
        await progress(ScanProgress(stage: "Building report...", percent: 95))
        return SecuroReport(
            scanTime: ISO8601DateFormatter().string(from: started),
            hostname: Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
            highestResult: highest,
            confidence: highest,
            evidenceSources: evidence,
            timeline: timeline,
            sessions: sessions,
            findings: findings,
            limitations: limitations,
            platform: "macos",
            platformVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            scannerVersion: "0.1.0-alpha",
            scanProfile: profile.rawValue,
            systemContext: SystemCollector.context()
        )
    }

    private func dedupeSessions(_ sessions: [RobloxSession]) -> [RobloxSession] {
        var seen = Set<String>()
        return sessions.filter {
            let key = [$0.userId, $0.placeId, $0.jobId, $0.sourceLog].compactMap { $0 }.joined(separator: "|")
            return seen.insert(key).inserted
        }
    }

    private func highestResult(_ findings: [SecuroFinding]) -> String {
        if findings.contains(where: { $0.confidenceLevel == FindingConfidence.confirmed.rawValue }) { return "Confirmed" }
        if findings.contains(where: { $0.confidenceLevel == FindingConfidence.likely.rawValue }) { return "Likely" }
        if !findings.isEmpty { return "Possible" }
        return "No confirmed evidence"
    }
}

struct TriageEngine {
    func classify(_ input: [SecuroFinding]) -> [SecuroFinding] {
        input.map { original in
            var finding = original
            finding.score = min(max(finding.score, 0), 100)

            let knownBadHash = finding.supportingEvidence.contains { $0.lowercased().contains("known-bad hash") }
            let runtimeEvidence = finding.supportingEvidence.contains {
                let value = $0.lowercased()
                return value.contains("loaded into roblox")
                    || value.contains("roblox process interaction")
                    || value.contains("roblox bundle modified")
            }
            let namedExecutor = ["macsploit", "opiumware"].contains {
                URL(fileURLWithPath: finding.path ?? "").deletingPathExtension().lastPathComponent
                    .lowercased().replacingOccurrences(of: " ", with: "").contains($0)
            }

            if knownBadHash || (namedExecutor && runtimeEvidence) {
                finding.classification = FindingConfidence.confirmed.rawValue
                finding.confidenceLevel = FindingConfidence.confirmed.rawValue
                finding.score = max(finding.score, 80)
            } else if finding.score >= 40 {
                finding.classification = FindingConfidence.likely.rawValue
                finding.confidenceLevel = FindingConfidence.likely.rawValue
            } else {
                finding.classification = FindingConfidence.possible.rawValue
                finding.confidenceLevel = FindingConfidence.possible.rawValue
            }
            return finding
        }
    }
}
