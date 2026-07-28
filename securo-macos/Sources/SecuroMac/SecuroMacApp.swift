import AppKit
import SwiftUI

final class SecuroAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        DispatchQueue.main.async {
            NSApp.activate(ignoringOtherApps: true)
            NSApp.windows.first?.makeKeyAndOrderFront(nil)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }
}

@main
struct SecuroMacApp: App {
    @NSApplicationDelegateAdaptor(SecuroAppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("Securo") {
            ContentView()
                .environmentObject(model)
                .frame(minWidth: 640, minHeight: 480)
        }
        .windowResizability(.contentMinSize)
    }
}

struct ContentView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            Color(red: 0.025, green: 0.03, blue: 0.035).ignoresSafeArea()
            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 12) {
                    Image(systemName: "hexagon.fill")
                        .font(.system(size: 34))
                        .foregroundStyle(Color.green)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Securo").font(.system(size: 28, weight: .bold))
                        Text("Roblox evidence checker for macOS").foregroundStyle(.secondary)
                    }
                }
                Divider()
                screen
                Spacer()
                Text(model.status)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            .padding(30)
        }
        .preferredColorScheme(.dark)
    }

    @ViewBuilder
    private var screen: some View {
        switch model.screen {
        case .pin:
            Text("Enter your check PIN").font(.title2.bold())
            TextField("6-digit PIN", text: $model.pin)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 24, design: .monospaced))
                .frame(maxWidth: 280)
                .onChange(of: model.pin) { value in
                    model.pin = String(value.filter(\.isNumber).prefix(6))
                }
            Button("Continue", action: model.verifyPin)
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .disabled(model.isBusy)

        case .consent:
            Text("Review and consent").font(.title2.bold())
            GroupBox {
                Text("""
                Securo performs a read-only local audit of available macOS and Roblox evidence. It does not collect passwords, cookies, authentication tokens, browser sessions, private messages, clipboard contents, photos, contacts, or unrelated private documents. It does not delete, quarantine, inject, bypass security tools, or modify Roblox.

                Findings are indicators and can include false positives. Missing macOS permissions will be reported as limitations.
                """)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
            }
            Toggle("I consent to this local \(model.profile.rawValue) scan.", isOn: $model.consentAccepted)
            Button("Start Scan", action: model.startScan)
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .disabled(!model.consentAccepted)

        case .scanning:
            Text("Scanning this Mac").font(.title2.bold())
            ProgressView(value: Double(model.progress), total: 100)
                .tint(.green)
            Text("\(model.progress)%")
                .font(.system(.headline, design: .monospaced))

        case .review:
            Text("Scan complete").font(.title2.bold())
            if let report = model.report {
                HStack(spacing: 28) {
                    metric("Result", report.highestResult)
                    metric("Findings", "\(report.findings.count)")
                    metric("Sessions", "\(report.sessions.count)")
                }
            }
            Toggle("I consent to upload the structured report to the PIN owner.", isOn: $model.uploadConsentAccepted)
            HStack {
                Button("Upload Report", action: model.upload)
                    .buttonStyle(.borderedProminent)
                    .tint(.green)
                    .disabled(!model.uploadConsentAccepted || model.isBusy)
                Button("Open Reports Folder", action: model.openReportsFolder)
            }

        case .complete:
            Label("Report uploaded successfully", systemImage: "checkmark.seal.fill")
                .font(.title2.bold())
                .foregroundStyle(.green)
            Button("Open Reports Folder", action: model.openReportsFolder)
        }
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title3.bold())
        }
    }
}
