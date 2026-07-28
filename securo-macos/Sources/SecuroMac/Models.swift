import Foundation

enum ScanProfile: String, Codable, CaseIterable {
    case quick
    case standard
    case deep

    var timeLimit: TimeInterval {
        switch self {
        case .quick: return 120
        case .standard: return 360
        case .deep: return 600
        }
    }
}

enum FindingConfidence: String, Codable {
    case possible = "Possible"
    case likely = "Likely"
    case confirmed = "Confirmed"
}

struct TimelineEvent: Codable, Identifiable {
    let id: UUID
    let time: String
    let source: String
    let text: String

    init(time: Date, source: String, text: String) {
        id = UUID()
        self.time = ISO8601DateFormatter().string(from: time)
        self.source = source
        self.text = text
    }
}

struct RobloxSession: Codable, Identifiable {
    let id: UUID
    var username: String?
    var displayName: String?
    var userId: String?
    var placeId: String?
    var jobId: String?
    var startTime: String?
    var endTime: String?
    var durationSeconds: Int?
    var sourceLog: String
}

struct SecuroFinding: Codable, Identifiable {
    let id: UUID
    var name: String
    var category: String
    var classification: String
    var confidenceLevel: String
    var score: Int
    var path: String?
    var sha256: String?
    var signer: String?
    var firstSeen: String?
    var reason: String
    var supportingEvidence: [String]
}

struct MacSystemContext: Codable {
    var productName: String
    var productVersion: String
    var buildVersion: String
    var architecture: String
}

struct SecuroReport: Codable {
    var scanTime: String
    var hostname: String
    var highestResult: String
    var confidence: String
    var evidenceSources: [String: EvidenceValue]
    var timeline: [TimelineEvent]
    var sessions: [RobloxSession]
    var findings: [SecuroFinding]
    var limitations: [String]
    var platform: String
    var platformVersion: String
    var scannerVersion: String
    var scanProfile: String
    var systemContext: MacSystemContext
}

enum EvidenceValue: Codable, Equatable {
    case bool(Bool)
    case string(String)
    case integer(Int)

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int.self) {
            self = .integer(value)
        } else {
            self = .string(try container.decode(String.self))
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .bool(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        }
    }
}

struct ConnectPinResponse: Decodable {
    var ok: Bool
    var pinId: String?
    var scanProfile: String?
    var error: String?
}

struct UploadResponse: Decodable {
    var ok: Bool
    var error: String?
}

struct ScanProgress {
    var stage: String
    var percent: Int
}

struct CollectorResult {
    var sourceName: String
    var available: Bool
    var recordsCollected: Int = 0
    var timeline: [TimelineEvent] = []
    var sessions: [RobloxSession] = []
    var findings: [SecuroFinding] = []
    var limitations: [String] = []
}
