import Foundation

enum APIError: LocalizedError {
    case invalidURL
    case server(String)
    case invalidResponse

    var errorDescription: String? {
        switch self {
        case .invalidURL: return "The Securo API URL is invalid."
        case .server(let message): return message
        case .invalidResponse: return "Securo returned an unreadable response."
        }
    }
}

struct APIClient {
    let baseURL: URL
    var session: URLSession = .shared

    init(baseURLString: String) throws {
        guard let url = URL(string: baseURLString.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw APIError.invalidURL
        }
        baseURL = url
    }

    func connect(pin: String) async throws -> ConnectPinResponse {
        try await post(path: "api/connect-pin", body: ["pin": pin], response: ConnectPinResponse.self)
    }

    func upload(pin: String, report: SecuroReport) async throws -> UploadResponse {
        let reportData = try JSONEncoder.securo.encode(report)
        let reportObject = try JSONSerialization.jsonObject(with: reportData)
        let score = report.findings.map(\.score).max() ?? 0
        let body: [String: Any] = [
            "pin": pin,
            "hostname": report.hostname,
            "riskLevel": riskLevel(score: score),
            "evidenceScore": min(max(score, 0), 100),
            "reportData": reportObject
        ]
        return try await post(path: "api/upload-report", body: body, response: UploadResponse.self)
    }

    private func post<T: Decodable>(path: String, body: Any, response: T.Type) async throws -> T {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, urlResponse) = try await session.data(for: request)
        guard let http = urlResponse as? HTTPURLResponse else { throw APIError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let decoded = try? JSONDecoder().decode(UploadResponse.self, from: data)
            throw APIError.server(decoded?.error ?? "Securo API request failed (\(http.statusCode)).")
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func riskLevel(score: Int) -> String {
        if score >= 80 { return "High" }
        if score >= 40 { return "Medium" }
        return "Low"
    }
}

extension JSONEncoder {
    static var securo: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }
}
