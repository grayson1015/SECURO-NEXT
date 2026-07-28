import XCTest
@testable import SecuroMac

final class SecuroMacTests: XCTestCase {
    func testRobloxLogParserExtractsIdentifiersAndFastFlags() {
        let text = """
        2026-07-28 Joining placeId: 987654321 userId: 123456789 jobId: abcdef12-3456-7890-abcd-ef1234567890
        FFlagExampleFeature=true
        """
        let result = RobloxLogParser().parse(
            text: text,
            source: "/tmp/Player.log",
            fallbackDate: Date(timeIntervalSince1970: 100)
        )
        XCTAssertEqual(result.sessions.first?.userId, "123456789")
        XCTAssertEqual(result.sessions.first?.placeId, "987654321")
        XCTAssertEqual(result.sessions.first?.jobId, "abcdef12-3456-7890-abcd-ef1234567890")
        XCTAssertEqual(result.findings.first?.classification, "Possible")
    }

    func testNameMatchWithoutRuntimeEvidenceIsNotConfirmed() {
        let finding = SecuroFinding(
            id: UUID(),
            name: "Known Mac executor indicator",
            category: "Mac file artifact",
            classification: "Likely",
            confidenceLevel: "Likely",
            score: 60,
            path: "/Users/test/Downloads/MacSploit.app",
            sha256: nil,
            signer: "unsigned",
            firstSeen: nil,
            reason: "Name and signature indicators",
            supportingEvidence: ["Flagged item name matched the Mac executor IOC macsploit."]
        )
        let classified = TriageEngine().classify([finding])
        XCTAssertEqual(classified.first?.confidenceLevel, "Likely")
    }

    func testExecutorAndRuntimeEvidenceCanConfirm() {
        let finding = SecuroFinding(
            id: UUID(),
            name: "Known Mac executor indicator",
            category: "Mac file artifact",
            classification: "Likely",
            confidenceLevel: "Likely",
            score: 60,
            path: "/Users/test/Downloads/Opiumware.app",
            sha256: nil,
            signer: "unsigned",
            firstSeen: nil,
            reason: "Correlated evidence",
            supportingEvidence: ["Unexpected library loaded into Roblox during the active session."]
        )
        let classified = TriageEngine().classify([finding])
        XCTAssertEqual(classified.first?.confidenceLevel, "Confirmed")
        XCTAssertGreaterThanOrEqual(classified.first?.score ?? 0, 80)
    }

    func testEvidenceValueEncodesAsPrimitive() throws {
        let data = try JSONEncoder().encode(["available": EvidenceValue.bool(true)])
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["available"] as? Bool, true)
    }
}
