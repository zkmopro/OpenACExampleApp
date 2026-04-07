//
//  ProofViewModel.swift
//  OpenACExampleApp
//

import Foundation
import Observation
import OpenACSwift
import ZIPFoundation

private let circuitZipURL = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/rs256.r1cs.zip")!

@Observable
@MainActor
final class ProofViewModel {

    enum StepStatus: Equatable {
        case idle
        case running
        case success(String)
        case failure(String)

        var isSuccess: Bool {
            if case .success = self { return true }
            return false
        }
    }

    // Pipeline step states
    var setupStatus: StepStatus = .idle
    var proveStatus: StepStatus = .idle
    var verifyStatus: StepStatus = .idle
    var isRunning = false

    // Circuit download state
    var circuitReady = false
    var isDownloading = false
    var downloadProgress: Double = 0        // 0.0 – 1.0
    var downloadError: String?
    var downloadSeconds: Double?
    var unzipSeconds: Double?

    // MARK: - Paths

    private var workDir: URL {
        FileManager.default
            .urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("ZKVectors", isDirectory: true)
    }

    var documentsPath: String { workDir.path }
    var inputPath: String { workDir.appendingPathComponent("input.json").path }

    // MARK: - Resource Setup

    func prepareResources() throws {
        let fm = FileManager.default
        try fm.createDirectory(at: workDir, withIntermediateDirectories: true)

        // Copy bundled input.json on first launch.
        if let src = Bundle.main.path(forResource: "input", ofType: "json") {
            let dst = workDir.appendingPathComponent("input.json")
            if !fm.fileExists(atPath: dst.path) {
                try fm.copyItem(atPath: src, toPath: dst.path)
            }
        }

        circuitReady = fm.fileExists(atPath: workDir.appendingPathComponent("rs256.r1cs").path)
    }

    // MARK: - Download Circuit

    func downloadCircuit() async {
        guard !isDownloading else { return }
        isDownloading = true
        downloadProgress = 0
        downloadError = nil
        downloadSeconds = nil
        unzipSeconds = nil

        let tmpZip = FileManager.default.temporaryDirectory
            .appendingPathComponent("rs256.r1cs.zip")
        let destDir = workDir

        do {
            // Run download + unzip off the main actor so the UI stays live.
            let (dl, unzip) = try await Task.detached(priority: .userInitiated) {
                let t0 = Date()
                try await Self.downloadFile(from: circuitZipURL, to: tmpZip) { progress in
                    Task { @MainActor [weak self] in
                        self?.downloadProgress = progress
                    }
                }
                let downloadTime = Date().timeIntervalSince(t0)

                let t1 = Date()
                let archive = try Archive(url: tmpZip, accessMode: .read)
                for entry in archive where entry.type == .file {
                    let dest = destDir.appendingPathComponent(entry.path)
                    if FileManager.default.fileExists(atPath: dest.path) {
                        try FileManager.default.removeItem(at: dest)
                    }
                    _ = try archive.extract(entry, to: dest)
                }
                try? FileManager.default.removeItem(at: tmpZip)
                let unzipTime = Date().timeIntervalSince(t1)

                return (downloadTime, unzipTime)
            }.value

            downloadSeconds = dl
            unzipSeconds = unzip

            circuitReady = FileManager.default.fileExists(
                atPath: workDir.appendingPathComponent("rs256.r1cs").path
            )
        } catch {
            downloadError = error.localizedDescription
        }

        isDownloading = false
    }

    private static func downloadFile(
        from url: URL,
        to destination: URL,
        progress: @escaping (Double) -> Void
    ) async throws {
        let delegate = DownloadProgressDelegate(onProgress: progress)
        let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        let (tmpURL, _) = try await session.download(from: url, delegate: delegate)
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: tmpURL, to: destination)
    }

    // MARK: - Pipeline Actions


    func reset() {
        setupStatus = .idle
        proveStatus = .idle
        verifyStatus = .idle
    }

    func runAll() async {
        guard !isRunning else { return }
        isRunning = true
        reset()

        await runSetupKeys()
        guard setupStatus.isSuccess else { isRunning = false; return }

        await runProve()
        guard proveStatus.isSuccess else { isRunning = false; return }

        await runVerify()
        isRunning = false
    }

    func runSetupKeys() async {
        setupStatus = .running
        let dp = documentsPath, ip = inputPath
        do {
            let msg = try await Task.detached(priority: .userInitiated) {
                try setupKeys(documentsPath: dp, inputPath: ip)
            }.value
            setupStatus = .success(msg)
        } catch {
            setupStatus = .failure(error.localizedDescription)
        }
    }

    func runProve() async {
        proveStatus = .running
        let dp = documentsPath, ip = inputPath
        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try prove(documentsPath: dp, inputPath: ip)
            }.value
            proveStatus = .success("\(result.proveMs) ms · \(result.proofSizeBytes) B")
        } catch {
            proveStatus = .failure(error.localizedDescription)
        }
    }

    func runVerify() async {
        verifyStatus = .running
        let dp = documentsPath
        do {
            let valid = try await Task.detached(priority: .userInitiated) {
                try verify(documentsPath: dp)
            }.value
            verifyStatus = valid ? .success("Proof is valid") : .failure("Proof is invalid")
        } catch {
            verifyStatus = .failure(error.localizedDescription)
        }
    }
}

// MARK: - Download Delegate

private final class DownloadProgressDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    let onProgress: (Double) -> Void

    init(onProgress: @escaping (Double) -> Void) {
        self.onProgress = onProgress
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData _: Int64, totalBytesWritten: Int64,
                    totalBytesExpectedToWrite total: Int64) {
        guard total > 0 else { return }
        onProgress(Double(totalBytesWritten) / Double(total))
    }

    // Required by the protocol but handled by the async/await continuation.
    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {}
}
