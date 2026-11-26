import Foundation
import Network

/// Pairing and Airlift are fallback/diagnostic services. FairPlayed's native
/// FairPlay path in fpcore.c remains the primary IPA processing mechanism.
@objcMembers
final class FPAirliftManager: NSObject {
    private static let singleton = FPAirliftManager()

    /// Stable Objective-C entry point used by the UIKit controller.
    @objc(shared)
    static func sharedManager() -> FPAirliftManager { singleton }

    private let cacheLock = NSLock()
    private let operationLock = NSLock()
    private var installedBundlePaths: [String: String] = [:]
    private var operationRunning = false

    private func beginOperation() -> Bool {
        operationLock.lock()
        defer { operationLock.unlock() }
        guard !operationRunning else { return false }
        operationRunning = true
        return true
    }

    private func finishOperation() {
        operationLock.lock()
        operationRunning = false
        operationLock.unlock()
    }

    private override init() {
        super.init()
        _ = al_log_init(nil, nil)
    }

    var pairingStatusText: String {
        let status = PairingController.shared.pairingStatus
        if status == "idle" {
            return isPairingFileAvailable ? "Pairing file imported" : "No pairing file"
        }
        return status
    }

    var pairingPINText: String {
        PairingController.shared.pairingPIN ?? ""
    }

    var isPairingFileAvailable: Bool {
        let path = PairingController.pairingFilePath()
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)), !data.isEmpty,
              let value = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = value as? [String: Any],
              let publicKey = dict["public_key"] as? Data, publicKey.count == 32,
              let privateKey = dict["private_key"] as? Data, privateKey.count == 32,
              let identifier = dict["identifier"] as? String,
              !identifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return false
        }
        return true
    }

    var isLocalDevVPNActive: Bool {
        NetworkStatus.loopbackVPNUp()
    }

    var isPairingRunning: Bool {
        PairingController.shared.running
    }

    func startPairing() {
        guard !PairingController.shared.running else { return }
        Task {
            do {
                let path = try await PairingController.shared.startAndWait()
                NSLog("[FairPlayed pairing] saved pairing file: %@", path)
            } catch {
                NSLog("[FairPlayed pairing] failed: %@", error.localizedDescription)
            }
        }
    }

    func cancelPairing() {
        PairingController.shared.softCancel()
    }

    /// Returns nil on success, otherwise a user-readable error string.
    @objc(importPairingFileAtURL:)
    func importPairingFile(at sourceURL: URL) -> String? {
        do {
            let path = try PairingController.importPairingFile(from: sourceURL)
            cacheLock.lock()
            installedBundlePaths.removeAll()
            cacheLock.unlock()
            NSLog("[FairPlayed pairing] imported pairing file: %@", path)
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    /// InstallationProxy returns app metadata and bundle paths; it does not
    /// itself grant filesystem access to those paths.
    @objc(installedAppBundlePathForBundleID:)
    func installedAppBundlePath(forBundleID bundleID: String) -> String? {
        cacheLock.lock()
        defer { cacheLock.unlock() }
        return installedBundlePaths[bundleID]
    }

    @objc(scanInstalledAppsWithCompletion:)
    func scanInstalledApps(completion: @escaping (String?, String?) -> Void) {
        guard isPairingFileAvailable else {
            completion(nil, "Import or create a valid FairPlayed pairing file first.")
            return
        }
        guard NetworkStatus.loopbackVPNUp() else {
            completion(nil, "Pairing file is present, but LocalDevVPN is not active. Enable the existing 10.7.x loopback tunnel and retry.")
            return
        }
        guard beginOperation() else {
            completion(nil, "An Airlift operation is already running.")
            return
        }

        let pairingPath = PairingController.pairingFilePath()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var outJSON: UnsafeMutablePointer<CChar>?
            var outError: UnsafeMutablePointer<CChar>?
            let rc = pairingPath.withCString { path in
                al_list_app_containers(path, nil, nil, &outJSON, &outError)
            }
            let json = Self.takeCString(&outJSON)
            let error = Self.takeCString(&outError)

            var resultText: String?
            var failure: String?
            if rc == 0, let json,
               let data = json.data(using: .utf8),
               let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let bundleEntries = payload["bundles"] as? [[String: Any]] ?? []
                var paths: [String: String] = [:]
                for entry in bundleEntries {
                    guard let bundleID = entry["bundleID"] as? String, !bundleID.isEmpty,
                          let rawPath = entry["path"] as? String else { continue }
                    let path = rawPath.hasPrefix("/private/var/")
                        ? String(rawPath.dropFirst("/private".count)) : rawPath
                    guard Self.isValidInstalledBundlePath(path) else { continue }
                    paths[bundleID] = path
                }

                self.cacheLock.lock()
                self.installedBundlePaths = paths
                self.cacheLock.unlock()

                let destination = Self.documentsDirectory
                    .appendingPathComponent("AirliftDiagnostics", isDirectory: true)
                do {
                    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
                    try Data(json.utf8).write(to: destination.appendingPathComponent("installationproxy.json"), options: .atomic)
                } catch {
                    NSLog("[FairPlayed Airlift] unable to save scan JSON: %@", error.localizedDescription)
                }
                let appContainerCount = (payload["applications"] as? [[String: Any]])?.count ?? 0
                let bundleIDs = paths.keys.sorted()
                let previewIDs = bundleIDs.prefix(12).joined(separator: "\n• ")
                let previewText = previewIDs.isEmpty ? "No installed .app paths were returned." : "First Bundle IDs (enter one in the probe/read action):\n• \(previewIDs)"
                let remaining = max(0, bundleIDs.count - 12)
                let suffix = remaining > 0 ? "\n… and \(remaining) more; see installationproxy.json." : ""
                resultText = "InstallationProxy scan succeeded: \(appContainerCount) data-container metadata entries, \(bundleEntries.count) bundle metadata entries, \(paths.count) validated installed .app paths.\n\(previewText)\(suffix)\nFull diagnostic JSON: Documents/AirliftDiagnostics/installationproxy.json"
            } else {
                failure = error ?? "InstallationProxy failed (rc=\(rc))."
            }

            DispatchQueue.main.async {
                self.finishOperation()
                completion(resultText, failure)
            }
        }
    }

    /// Reads one exact .app path obtained from the InstallationProxy response.
    /// The underlying Airlift folder reader performs its own temporary remote
    /// staging/restore transaction; the returned ZIP is diagnostic and is not
    /// automatically a valid input for fairplayd from the app Data Container.
    @objc(readInstalledAppBundleWithBundleID:allowRestoreTransaction:completion:)
    func readInstalledAppBundle(
        withBundleID bundleID: String,
        allowRestoreTransaction: Bool,
        completion: @escaping (String?, String?) -> Void
    ) {
        guard isPairingFileAvailable else {
            completion(nil, "A valid pairing file is required.")
            return
        }
        guard NetworkStatus.loopbackVPNUp() else {
            completion(nil, "LocalDevVPN is not active. Enable the existing 10.7.x loopback tunnel and retry.")
            return
        }

        cacheLock.lock()
        let remotePath = installedBundlePaths[bundleID]
        cacheLock.unlock()
        guard let remotePath, Self.isValidInstalledBundlePath(remotePath) else {
            completion(nil, "No validated installed .app path for \(bundleID). Run InstallationProxy scan first and check the exact Bundle ID.")
            return
        }
        guard beginOperation() else {
            completion(nil, "An Airlift operation is already running.")
            return
        }

        let pairingPath = PairingController.pairingFilePath()
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            var outJSON: UnsafeMutablePointer<CChar>?
            var outError: UnsafeMutablePointer<CChar>?
            let rc = pairingPath.withCString { pair in
                remotePath.withCString { target in
                    if allowRestoreTransaction {
                        return al_exploit_read_folder(pair, target, nil, nil, &outJSON, &outError)
                    }
                    return al_exploit_read_afc_only_folder(pair, target, nil, nil, &outJSON, &outError)
                }
            }
            let json = Self.takeCString(&outJSON)
            let error = Self.takeCString(&outError)

            var resultText: String?
            var failure: String?
            if rc == 0, let json,
               let data = json.data(using: .utf8),
               let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                let localPath = payload["localPath"] as? String
                let method = payload["method"] as? String ?? "unknown"
                let isAFCOnly = method == "afc-only"
                let restoreWarning = payload["restoreWarning"] as? String
                let restoreError = payload["restoreError"] as? String
                let restoreConfirmed = payload["restoreConfirmed"] as? Bool ?? isAFCOnly
                let restoreHandoffCompleted = payload["restoreHandoffCompleted"] as? Bool ?? isAFCOnly
                let recoveryPath = payload["recoveryPath"] as? String
                if let localPath, FileManager.default.fileExists(atPath: localPath) {
                    let exportDir = Self.documentsDirectory.appendingPathComponent("AirliftExports", isDirectory: true)
                    do {
                        try FileManager.default.createDirectory(at: exportDir, withIntermediateDirectories: true)
                        let safeName = bundleID.replacingOccurrences(of: "[^A-Za-z0-9._-]", with: "_", options: .regularExpression)
                        let destination = exportDir.appendingPathComponent("\(safeName)-installed-bundle.zip")
                        try? FileManager.default.removeItem(at: destination)
                        try FileManager.default.copyItem(at: URL(fileURLWithPath: localPath), to: destination)
                        let methodText = isAFCOnly
                            ? "AFC-only read (no AirTraffic staging or device writes)"
                            : "Airlift restore-transaction read"
                        resultText = "\(methodText) export saved: \(destination.lastPathComponent). This is an inspection copy; it is not automatically passed to FairPlayed's primary FairPlay path."
                        if !restoreConfirmed || !restoreHandoffCompleted {
                            let detail = restoreWarning ?? restoreError ?? "Airlift could not confirm that the original folder was restored."
                            let recovery = recoveryPath.map { " Recovery path: \($0)." } ?? ""
                            failure = "SAFETY WARNING: \(detail)\(recovery) Keep the target app closed until its original bundle is verified."
                        } else if let restoreWarning, !restoreWarning.isEmpty {
                            failure = "Airlift reported a restore warning: \(restoreWarning)"
                        }
                    } catch {
                        failure = "Airlift returned a local archive but it could not be copied into Documents: \(error.localizedDescription)"
                    }
                } else {
                    let warning = restoreWarning.map { " Restore warning: \($0)" } ?? ""
                    failure = "Airlift returned no complete local ZIP. Result: \(json)\(warning)"
                }
            } else {
                failure = error ?? "Airlift folder read failed (rc=\(rc))."
            }

            DispatchQueue.main.async {
                self.finishOperation()
                completion(resultText, failure)
            }
        }
    }

    private static var documentsDirectory: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    private static func isValidInstalledBundlePath(_ path: String) -> Bool {
        let root = "/var/containers/Bundle/Application/"
        guard path.hasPrefix(root), !path.contains("..") else { return false }
        let parts = path.dropFirst(root.count).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              UUID(uuidString: String(parts[0])) != nil,
              String(parts[1]).lowercased().hasSuffix(".app") else { return false }
        return true
    }

    private static func takeCString(_ pointer: inout UnsafeMutablePointer<CChar>?) -> String? {
        guard let value = pointer else { return nil }
        let string = String(cString: value)
        al_string_free(value)
        pointer = nil
        return string
    }
}
