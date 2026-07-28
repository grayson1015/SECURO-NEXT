import AppKit
import Foundation

@MainActor
final class AppModel: ObservableObject {
    enum Screen {
        case pin
        case consent
        case scanning
        case review
        case complete
    }

    @Published var screen: Screen = .pin
    @Published var pin = ""
    @Published var profile: ScanProfile = .standard
    @Published var status = "Enter the six-digit PIN provided by Securo staff."
    @Published var progress = 0
    @Published var report: SecuroReport?
    @Published var isBusy = false
    @Published var consentAccepted = false
    @Published var uploadConsentAccepted = false

    let apiURL = "https://securo-next.vercel.app"
    private let scanner = ScannerEngine()

    func verifyPin() {
        guard pin.range(of: #"^\d{6}$"#, options: .regularExpression) != nil else {
            status = "Enter a valid six-digit PIN."
            return
        }
        isBusy = true
        status = "Verifying PIN..."
        Task {
            do {
                let response = try await APIClient(baseURLString: apiURL).connect(pin: pin)
                guard response.ok else { throw APIError.server(response.error ?? "Invalid or expired PIN.") }
                profile = ScanProfile(rawValue: response.scanProfile ?? "standard") ?? .standard
                status = "PIN verified. Review the scan disclosure."
                screen = .consent
            } catch {
                status = error.localizedDescription
            }
            isBusy = false
        }
    }

    func startScan() {
        guard consentAccepted else {
            status = "Consent is required before scanning."
            return
        }
        screen = .scanning
        isBusy = true
        Task {
            let generated = await scanner.scan(profile: profile) { update in
                self.status = update.stage
                self.progress = update.percent
            }
            report = generated
            do {
                let location = try saveLocally(generated)
                status = "Scan complete. Local report saved to \(location.path). Review before uploading."
            } catch {
                status = "Scan complete, but the local report could not be saved: \(error.localizedDescription)"
            }
            progress = 100
            isBusy = false
            screen = .review
        }
    }

    func upload() {
        guard uploadConsentAccepted, let report else {
            status = "Upload consent is required."
            return
        }
        isBusy = true
        status = "Uploading structured report..."
        Task {
            do {
                let response = try await APIClient(baseURLString: apiURL).upload(pin: pin, report: report)
                guard response.ok else { throw APIError.server(response.error ?? "Upload failed.") }
                status = "Report uploaded successfully."
                screen = .complete
            } catch {
                status = "Upload failed: \(error.localizedDescription). The local report was kept."
            }
            isBusy = false
        }
    }

    func openReportsFolder() {
        guard let directory = try? reportsDirectory() else { return }
        NSWorkspace.shared.open(directory)
    }

    private func reportsDirectory() throws -> URL {
        let documents = try FileManager.default.url(
            for: .documentDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        )
        let directory = documents.appendingPathComponent("Securo/Reports", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func saveLocally(_ report: SecuroReport) throws -> URL {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        let url = try reportsDirectory().appendingPathComponent("securo-macos-\(formatter.string(from: Date())).json")
        try JSONEncoder.securo.encode(report).write(to: url, options: .atomic)
        return url
    }
}
