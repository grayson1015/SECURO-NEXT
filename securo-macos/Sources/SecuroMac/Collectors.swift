import CryptoKit
import Foundation

protocol EvidenceCollector {
    var name: String { get }
    func collect(context: ScanContext) -> CollectorResult
}

struct ScanContext {
    let profile: ScanProfile
    let deadline: Date
    let fileManager: FileManager

    var expired: Bool { Date() >= deadline }
}

struct SystemCollector: EvidenceCollector {
    let name = "macOS system context"

    func collect(context: ScanContext) -> CollectorResult {
        CollectorResult(sourceName: name, available: true, recordsCollected: 1)
    }

    static func context() -> MacSystemContext {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return MacSystemContext(
            productName: "macOS",
            productVersion: "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)",
            buildVersion: command("/usr/bin/sw_vers", ["-buildVersion"]) ?? "Unknown",
            architecture: command("/usr/bin/uname", ["-m"]) ?? "Unknown"
        )
    }
}

struct RobloxLogCollector: EvidenceCollector {
    let name = "Roblox Player logs"

    func collect(context: ScanContext) -> CollectorResult {
        let home = context.fileManager.homeDirectoryForCurrentUser
        let roots = [
            home.appendingPathComponent("Library/Logs/Roblox"),
            home.appendingPathComponent("Library/Application Support/Roblox/logs")
        ]
        var result = CollectorResult(sourceName: name, available: false)
        let parser = RobloxLogParser()
        let cutoff = Calendar.current.date(byAdding: .day, value: -days(for: context.profile), to: Date()) ?? .distantPast

        for root in roots where !context.expired {
            guard let files = try? context.fileManager.contentsOfDirectory(
                at: root,
                includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey],
                options: [.skipsHiddenFiles]
            ) else { continue }
            result.available = true
            for file in files.sorted(by: { $0.lastPathComponent < $1.lastPathComponent }) where !context.expired {
                guard file.pathExtension.lowercased() == "log",
                      !file.lastPathComponent.lowercased().contains("studio"),
                      let values = try? file.resourceValues(forKeys: [.contentModificationDateKey]),
                      (values.contentModificationDate ?? .distantPast) >= cutoff,
                      let data = try? Data(contentsOf: file, options: [.mappedIfSafe]),
                      data.count <= 25_000_000,
                      let text = String(data: data, encoding: .utf8) else { continue }
                result.recordsCollected += 1
                let parsed = parser.parse(text: text, source: file.path, fallbackDate: values.contentModificationDate ?? Date())
                result.sessions.append(contentsOf: parsed.sessions)
                result.timeline.append(contentsOf: parsed.timeline)
                result.findings.append(contentsOf: parsed.findings)
            }
        }
        if !result.available {
            result.limitations.append("Roblox Player log folders were unavailable or contained no readable logs.")
        }
        return result
    }

    private func days(for profile: ScanProfile) -> Int {
        switch profile {
        case .quick: return 3
        case .standard: return 14
        case .deep: return 30
        }
    }
}

struct RobloxLogParser {
    private let userPatterns = [
        #"(?i)\buser(?:id)?["' :=]+(\d{4,20})"#,
        #"(?i)\buserid=(\d{4,20})"#
    ]
    private let placePatterns = [#"(?i)\bplace(?:id)?["' :=]+(\d{4,20})"#]
    private let jobPatterns = [#"(?i)\bjob(?:id)?["' :=]+([0-9a-f-]{16,})"#]
    private let fastFlagPattern = #"(?i)\b((?:D|F)?Flag[A-Za-z0-9_]+)\s*[:=]\s*([^,\r\n}]+)"#

    func parse(text: String, source: String, fallbackDate: Date) -> CollectorResult {
        var result = CollectorResult(sourceName: "Roblox Player logs", available: true)
        let userId = firstMatch(patterns: userPatterns, text: text)
        let placeId = firstMatch(patterns: placePatterns, text: text)
        let jobId = firstMatch(patterns: jobPatterns, text: text)

        if userId != nil || placeId != nil || jobId != nil {
            result.sessions.append(RobloxSession(
                id: UUID(),
                username: nil,
                displayName: nil,
                userId: userId,
                placeId: placeId,
                jobId: jobId,
                startTime: ISO8601DateFormatter().string(from: fallbackDate),
                endTime: nil,
                durationSeconds: nil,
                sourceLog: source
            ))
        }

        for match in matches(pattern: fastFlagPattern, text: text).prefix(200) {
            guard match.count >= 3 else { continue }
            let flag = match[1]
            let value = match[2].trimmingCharacters(in: .whitespacesAndNewlines)
            result.timeline.append(TimelineEvent(
                time: fallbackDate,
                source: "Roblox FastFlag",
                text: "\(flag)=\(value) in \(URL(fileURLWithPath: source).lastPathComponent)"
            ))
            result.findings.append(SecuroFinding(
                id: UUID(),
                name: "Roblox FastFlag observed",
                category: "Roblox configuration",
                classification: FindingConfidence.possible.rawValue,
                confidenceLevel: FindingConfidence.possible.rawValue,
                score: 5,
                path: source,
                sha256: nil,
                signer: nil,
                firstSeen: ISO8601DateFormatter().string(from: fallbackDate),
                reason: "A FastFlag assignment was present in a Roblox Player log.",
                supportingEvidence: ["\(flag)=\(value)"]
            ))
        }
        return result
    }

    private func firstMatch(patterns: [String], text: String) -> String? {
        for pattern in patterns {
            if let value = matches(pattern: pattern, text: text).first, value.count > 1 {
                return value[1]
            }
        }
        return nil
    }

    private func matches(pattern: String, text: String) -> [[String]] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        return regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { match in
            (0..<match.numberOfRanges).map {
                let range = match.range(at: $0)
                return range.location == NSNotFound ? "" : ns.substring(with: range)
            }
        }
    }
}

struct FileArtifactCollector: EvidenceCollector {
    let name = "Mac application and file artifacts"
    private let extensions = Set(["app", "dylib", "command", "sh", "zip", "rar", "7z"])
    private let knownNames = ["macsploit", "opiumware"]

    func collect(context: ScanContext) -> CollectorResult {
        let home = context.fileManager.homeDirectoryForCurrentUser
        let roots = [
            home.appendingPathComponent("Downloads"),
            home.appendingPathComponent("Desktop"),
            home.appendingPathComponent("Applications"),
            home.appendingPathComponent("Library/Application Support/Roblox")
        ]
        let fileCap = context.profile == .quick ? 1_500 : context.profile == .standard ? 5_000 : 12_000
        var visited = 0
        var result = CollectorResult(sourceName: name, available: false)

        for root in roots where !context.expired && visited < fileCap {
            guard let enumerator = context.fileManager.enumerator(
                at: root,
                includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .creationDateKey, .contentModificationDateKey],
                options: [.skipsHiddenFiles, .skipsPackageDescendants]
            ) else { continue }
            result.available = true
            for case let url as URL in enumerator {
                if context.expired || visited >= fileCap { break }
                visited += 1
                result.recordsCollected = visited
                let normalizedName = url.deletingPathExtension().lastPathComponent
                    .lowercased()
                    .replacingOccurrences(of: " ", with: "")
                    .replacingOccurrences(of: "-", with: "")
                    .replacingOccurrences(of: "_", with: "")
                let ext = url.pathExtension.lowercased()
                guard extensions.contains(ext) || knownNames.contains(where: normalizedName.contains) else { continue }

                let values = try? url.resourceValues(forKeys: [.isRegularFileKey, .creationDateKey, .contentModificationDateKey])
                let nameMatch = knownNames.first(where: normalizedName.contains)
                let signature = signatureStatus(url)
                let lowerPath = url.path.lowercased()
                let riskyLocation = lowerPath.contains("/downloads/")
                    || lowerPath.contains("/desktop/")
                    || lowerPath.contains("/private/tmp/")
                    || lowerPath.contains("/var/folders/")
                let executableLike = ["app", "dylib", "command", "sh"].contains(ext)
                guard nameMatch != nil || (riskyLocation && executableLike && signature == "unsigned") else {
                    continue
                }
                var evidence = ["File discovered in a user-accessible scan location."]
                var score = 8
                if let nameMatch {
                    evidence.append("Flagged item name matched the Mac executor IOC \(nameMatch).")
                    score += 35
                }
                if signature == "unsigned" {
                    evidence.append("Code signature was missing or invalid.")
                    score += 15
                }
                let hash = values?.isRegularFile == true ? sha256(url) : nil
                let confidence: FindingConfidence = nameMatch != nil && signature == "unsigned" ? .likely : .possible
                result.findings.append(SecuroFinding(
                    id: UUID(),
                    name: nameMatch != nil ? "Known Mac executor indicator" : "Reviewable Mac file artifact",
                    category: "Mac file artifact",
                    classification: confidence.rawValue,
                    confidenceLevel: confidence.rawValue,
                    score: min(score, 79),
                    path: url.path,
                    sha256: hash,
                    signer: signature,
                    firstSeen: ISO8601DateFormatter().string(from: values?.creationDate ?? values?.contentModificationDate ?? Date()),
                    reason: evidence.joined(separator: " "),
                    supportingEvidence: evidence
                ))
            }
        }
        if context.expired || visited >= fileCap {
            result.limitations.append("File artifact collection reached the \(context.profile.rawValue) scan limit after \(visited) entries.")
        }
        return result
    }

    private func signatureStatus(_ url: URL) -> String {
        guard ["app", "dylib"].contains(url.pathExtension.lowercased()) else { return "not_applicable" }
        return command("/usr/bin/codesign", ["--verify", "--deep", "--strict", url.path]) == nil ? "unsigned" : "valid"
    }

    private func sha256(_ url: URL) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while autoreleasepool(invoking: {
            let data = try? handle.read(upToCount: 1_048_576)
            guard let data, !data.isEmpty else { return false }
            hasher.update(data: data)
            return true
        }) {}
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

struct PersistenceCollector: EvidenceCollector {
    let name = "macOS persistence"

    func collect(context: ScanContext) -> CollectorResult {
        let home = context.fileManager.homeDirectoryForCurrentUser
        let roots = [
            home.appendingPathComponent("Library/LaunchAgents"),
            URL(fileURLWithPath: "/Library/LaunchAgents"),
            URL(fileURLWithPath: "/Library/LaunchDaemons")
        ]
        var result = CollectorResult(sourceName: name, available: false)
        for root in roots where !context.expired {
            guard let files = try? context.fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey]) else { continue }
            result.available = true
            for file in files where file.pathExtension.lowercased() == "plist" {
                result.recordsCollected += 1
                guard let data = try? Data(contentsOf: file),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
                      let dictionary = plist as? [String: Any] else { continue }
                let program = (dictionary["Program"] as? String)
                    ?? (dictionary["ProgramArguments"] as? [String])?.first
                    ?? ""
                let lower = program.lowercased()
                let review = lower.contains("/downloads/") || lower.contains("/tmp/") || lower.contains("macsploit") || lower.contains("opiumware")
                guard review else { continue }
                let modified = (try? file.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? Date()
                result.findings.append(SecuroFinding(
                    id: UUID(),
                    name: "Suspicious LaunchAgent or LaunchDaemon",
                    category: "Persistence",
                    classification: FindingConfidence.likely.rawValue,
                    confidenceLevel: FindingConfidence.likely.rawValue,
                    score: 45,
                    path: file.path,
                    sha256: nil,
                    signer: nil,
                    firstSeen: ISO8601DateFormatter().string(from: modified),
                    reason: "A startup item points to a user-writable or executor-related location.",
                    supportingEvidence: [program]
                ))
                result.timeline.append(TimelineEvent(time: modified, source: "macOS persistence", text: "\(file.lastPathComponent) launches \(program)"))
            }
        }
        return result
    }
}

struct RunningProcessCollector: EvidenceCollector {
    let name = "macOS running processes"

    func collect(context: ScanContext) -> CollectorResult {
        guard let output = command("/bin/ps", ["-axo", "pid=,ppid=,comm=,args="]) else {
            return CollectorResult(
                sourceName: name,
                available: false,
                limitations: ["The macOS process list could not be read."]
            )
        }
        let lines = output.split(separator: "\n").map(String.init)
        var result = CollectorResult(sourceName: name, available: true, recordsCollected: lines.count)
        let robloxRunning = lines.contains { $0.lowercased().contains("robloxplayer") || $0.lowercased().contains("/roblox.app/") }

        for line in lines {
            let lower = line.lowercased()
            if lower.contains("robloxplayer") || lower.contains("/roblox.app/") {
                result.timeline.append(TimelineEvent(time: Date(), source: "macOS process list", text: "Roblox Player was active when Securo scanned running processes."))
            }
            guard lower.contains("macsploit") || lower.contains("opiumware") else { continue }
            let executor = lower.contains("macsploit") ? "MacSploit" : "Opiumware"
            var evidence = ["A process matching \(executor) was active at scan time."]
            if robloxRunning {
                evidence.append("Roblox process interaction: the executor indicator and Roblox were active at the same scan time.")
            }
            result.findings.append(SecuroFinding(
                id: UUID(),
                name: "\(executor) process indicator",
                category: "Running process",
                classification: robloxRunning ? FindingConfidence.confirmed.rawValue : FindingConfidence.likely.rawValue,
                confidenceLevel: robloxRunning ? FindingConfidence.confirmed.rawValue : FindingConfidence.likely.rawValue,
                score: robloxRunning ? 85 : 65,
                path: processExecutablePath(line),
                sha256: nil,
                signer: nil,
                firstSeen: ISO8601DateFormatter().string(from: Date()),
                reason: evidence.joined(separator: " "),
                supportingEvidence: evidence
            ))
            result.timeline.append(TimelineEvent(time: Date(), source: "macOS process list", text: "\(executor) process indicator was active."))
        }
        return result
    }

    private func processExecutablePath(_ line: String) -> String? {
        line.split(whereSeparator: { $0.isWhitespace }).first(where: { $0.hasPrefix("/") }).map(String.init)
    }
}

struct RobloxIntegrityCollector: EvidenceCollector {
    let name = "Roblox application integrity"

    func collect(context: ScanContext) -> CollectorResult {
        let home = context.fileManager.homeDirectoryForCurrentUser
        let candidates = [
            URL(fileURLWithPath: "/Applications/Roblox.app"),
            home.appendingPathComponent("Applications/Roblox.app")
        ]
        guard let app = candidates.first(where: { context.fileManager.fileExists(atPath: $0.path) }) else {
            return CollectorResult(
                sourceName: name,
                available: false,
                limitations: ["Roblox.app was not found in the standard system or user Applications folders."]
            )
        }
        let valid = command("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path]) != nil
        var result = CollectorResult(sourceName: name, available: true, recordsCollected: 1)
        if !valid {
            result.findings.append(SecuroFinding(
                id: UUID(),
                name: "Roblox application integrity issue",
                category: "Roblox integrity",
                classification: FindingConfidence.likely.rawValue,
                confidenceLevel: FindingConfidence.likely.rawValue,
                score: 55,
                path: app.path,
                sha256: nil,
                signer: "invalid_or_unverifiable",
                firstSeen: ISO8601DateFormatter().string(from: Date()),
                reason: "The installed Roblox application bundle failed strict code-signature verification.",
                supportingEvidence: ["Roblox bundle modified or its code signature could not be verified."]
            ))
            result.timeline.append(TimelineEvent(time: Date(), source: "Roblox integrity", text: "Roblox.app failed strict code-signature verification."))
        }
        return result
    }
}

struct QuarantineCollector: EvidenceCollector {
    let name = "macOS quarantine download records"

    func collect(context: ScanContext) -> CollectorResult {
        let database = context.fileManager.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
        guard context.fileManager.fileExists(atPath: database.path) else {
            return CollectorResult(
                sourceName: name,
                available: false,
                limitations: ["The macOS quarantine database was unavailable."]
            )
        }
        let query = """
        select coalesce(LSQuarantineTimeStamp,0), coalesce(LSQuarantineAgentName,''), coalesce(LSQuarantineDataURLString,''), coalesce(LSQuarantineOriginURLString,'')
        from LSQuarantineEvent
        where lower(coalesce(LSQuarantineDataURLString,'')) like '%macsploit%'
           or lower(coalesce(LSQuarantineDataURLString,'')) like '%opiumware%'
           or lower(coalesce(LSQuarantineOriginURLString,'')) like '%macsploit%'
           or lower(coalesce(LSQuarantineOriginURLString,'')) like '%opiumware%'
        order by LSQuarantineTimeStamp desc limit 100;
        """
        guard let output = command("/usr/bin/sqlite3", ["-separator", "\t", database.path, query]) else {
            return CollectorResult(
                sourceName: name,
                available: false,
                limitations: ["The macOS quarantine database existed but could not be queried. Full Disk Access may be required."]
            )
        }
        let rows = output.split(separator: "\n").map(String.init)
        var result = CollectorResult(sourceName: name, available: true, recordsCollected: rows.count)
        for row in rows {
            let fields = row.components(separatedBy: "\t")
            guard fields.count >= 4 else { continue }
            let combined = fields.joined(separator: " ").lowercased()
            let executor = combined.contains("macsploit") ? "MacSploit" : "Opiumware"
            let macSeconds = TimeInterval(fields[0]) ?? 0
            let timestamp = Date(timeIntervalSince1970: macSeconds + 978_307_200)
            let sourceHost = URL(string: fields[3])?.host ?? URL(string: fields[2])?.host ?? "Source host unavailable"
            result.findings.append(SecuroFinding(
                id: UUID(),
                name: "\(executor) download trace",
                category: "Quarantine metadata",
                classification: FindingConfidence.likely.rawValue,
                confidenceLevel: FindingConfidence.likely.rawValue,
                score: 50,
                path: URL(string: fields[2])?.lastPathComponent,
                sha256: nil,
                signer: nil,
                firstSeen: ISO8601DateFormatter().string(from: timestamp),
                reason: "macOS quarantine metadata contains a download trace matching \(executor).",
                supportingEvidence: ["Download agent: \(fields[1])", "Source host: \(sourceHost)"]
            ))
            result.timeline.append(TimelineEvent(time: timestamp, source: "macOS quarantine", text: "\(executor) download trace recorded by \(fields[1])."))
        }
        return result
    }
}

func command(_ executable: String, _ arguments: [String]) -> String? {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = Pipe()
    do {
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines)
    } catch {
        return nil
    }
}
