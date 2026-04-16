//
//  ProofViewModel.swift
//  OpenACExampleApp
//

import Foundation
import Observation
import UIKit
import OpenACSwift
import ZIPFoundation

private let circuitZipURL = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/sha256rsa4096.r1cs.zip")!
private let provingKeyURL = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/rs256_4096_proving.key.zip")!
private let verifyingKeyURL = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/rs256_4096_verifying.key.zip")!
private let serverURL = URL(string: "https://aff7-211-75-7-191.ngrok-free.app/challenge")!

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
    var circuitName = "sha256rsa4096.r1cs"
    var provingKeyName = "rs256_4096_proving.key"
    var verifyingKeyName = "rs256_4096_verifying.key"
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

        // For simulator testing
        // Copy bundled input.json on first launch.
        if let src = Bundle.main.path(forResource: "input", ofType: "json") {
            let dst = workDir.appendingPathComponent("input.json")
            print("copying input.json from \(src) to \(dst.path)")
            try fm.copyItem(atPath: src, toPath: dst.path)
        }
        circuitReady = fm.fileExists(atPath: workDir.appendingPathComponent(circuitName).path)
            && fm.fileExists(atPath: workDir.appendingPathComponent("keys").appendingPathComponent(provingKeyName).path)

        // Copy bundled MOICA-G3.cer into workDir if not already present
        let certDest = workDir.appendingPathComponent("MOICA-G3.cer")
        if !fm.fileExists(atPath: certDest.path),
           let certSrc = Bundle.main.url(forResource: "MOICA-G3", withExtension: "cer") {
            try fm.copyItem(at: certSrc, to: certDest)
        }
    }

    // MARK: - Download Circuit

    func downloadCircuit() async {
        guard !isDownloading else { return }
        isDownloading = true
        downloadProgress = 0
        downloadError = nil
        downloadSeconds = nil
        unzipSeconds = nil

        let tmpR1cs = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(circuitName).zip")
        let tmpKey = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(provingKeyName).zip")
        let r1csDestDir = workDir
        let keysDestDir = workDir.appendingPathComponent("keys", isDirectory: true)

        // Capture progress updater on the main actor before entering the detached task.
        // Inside Task.detached, self is @MainActor-isolated and unreachable, so
        // [weak self] inside a nested Task would always be nil without this capture.
        let setProgress: @Sendable (Double) -> Void = { [weak self] p in
            Task { @MainActor [weak self] in self?.downloadProgress = p }
        }

        let r1csExists = FileManager.default.fileExists(atPath: workDir.appendingPathComponent(circuitName).path)
        let keyExists  = FileManager.default.fileExists(atPath: workDir.appendingPathComponent("keys").appendingPathComponent(provingKeyName).path)

        if r1csExists && keyExists {
            circuitReady = true
            isDownloading = false
            return
        }

        do {
            try FileManager.default.createDirectory(at: keysDestDir, withIntermediateDirectories: true)
            // Run download + unzip off the main actor so the UI stays live.
            let (dl, unzip) = try await Task.detached(priority: .userInitiated) {
                let t0 = Date()

                // Download r1cs (progress 0.0–0.5) only if missing
                if !r1csExists {
                    try await Self.downloadFile(from: circuitZipURL, to: tmpR1cs) { p in
                        setProgress(p * 0.5)
                    }
                } else {
                    setProgress(0.5)
                }

                // Download proving key (progress 0.5–1.0) only if missing
                if !keyExists {
                    try await Self.downloadFile(from: provingKeyURL, to: tmpKey) { p in
                        setProgress(0.5 + p * 0.5)
                    }
                } else {
                    setProgress(1.0)
                }
                let downloadTime = Date().timeIntervalSince(t0)

                let t1 = Date()
                for (tmpZip, destDir, exists) in [(tmpR1cs, r1csDestDir, r1csExists), (tmpKey, keysDestDir, keyExists)] {
                    guard !exists else { continue }
                    let archive = try Archive(url: tmpZip, accessMode: .read)
                    for entry in archive where entry.type == .file {
                        let dest = destDir.appendingPathComponent(entry.path)
                        if FileManager.default.fileExists(atPath: dest.path) {
                            try FileManager.default.removeItem(at: dest)
                        }
                        _ = try archive.extract(entry, to: dest)
                    }
                    try? FileManager.default.removeItem(at: tmpZip)
                }
                let unzipTime = Date().timeIntervalSince(t1)

                return (downloadTime, unzipTime)
            }.value

            downloadSeconds = dl
            unzipSeconds = unzip

            circuitReady = FileManager.default.fileExists(atPath: workDir.appendingPathComponent(circuitName).path)
                && FileManager.default.fileExists(atPath: workDir.appendingPathComponent("keys").appendingPathComponent(provingKeyName).path)
        } catch {
            downloadError = error.localizedDescription
        }

        isDownloading = false
    }

    private static func downloadFile(
        from url: URL,
        to destination: URL,
        progress: @escaping @Sendable (Double) -> Void
    ) async throws {
        try await withCheckedThrowingContinuation { continuation in
            let delegate = DownloadTaskDelegate(
                destination: destination,
                onProgress: progress,
                onCompletion: { continuation.resume(with: $0) }
            )
            let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
            delegate.session = session
            session.downloadTask(with: url).resume()
        }
    }

    // MARK: - SP Ticket / MOICA

    static let returnScheme = "openac"
    static let returnURL    = "\(returnScheme)://callback"

    var idNum: String = "A123456789"
    var spTicketStatus: StepStatus = .idle
    var spTicket: String?
    var tbs: String = ""
    var challengeId: String = ""
    var rtnVal: String?

    var tbsStatus: StepStatus = .idle

    func regenerateTBS() async {
        tbsStatus = .running
        do {
            var request = URLRequest(url: serverURL)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue("true", forHTTPHeaderField: "ngrok-skip-browser-warning")
            request.httpBody = Data("{}".utf8)
            let (data, _) = try await URLSession.shared.data(for: request)
            let raw = String(data: data, encoding: .utf8) ?? ""
            print("regenerateTBS raw response: \(raw)")
            let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
            guard let challengeBytes = json["challenge_bytes"] as? String else {
                throw URLError(.cannotParseResponse)
            }
            tbs = challengeBytes
            challengeId = json["challenge_id"] as? String ?? ""
            tbsStatus = .success("challenge received")
        } catch {
            tbsStatus = .failure(error.localizedDescription)
            print("regenerateTBS error: \(error)")
        }
    }

    // Stored ath-result fields used to generate circuit input
    var athResponseString: String?
    var athIssuerCert: String?
    var athIssuerId: String = "g2"
    var generateInputStatus: StepStatus = .idle
    var generatedInputPath: String?


    func computeSPTicket() async {
        spTicketStatus = .running
        spTicket = nil
        rtnVal = nil
        do {
            print("tbs: \(tbs)")
            let raw = try await getSpTicket(params: SpTicketParams(
                transactionID: UUID().uuidString,
                idNum:         idNum,
                opCode:        "SIGN",
                opMode:        "APP2APP",
                hint:          "待簽署資料",
                timeLimit:     "600",
                signData:      Data(tbs.utf8).base64EncodedString(),
                signType:      "PKCS#1",
                hashAlgorithm: "SHA256",
                tbsEncoding:   "base64"
            ))

            let json = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as! [String: Any]
            spTicket = ((json["result"] as? [String: Any])?["sp_ticket"] as? String) ?? ""
            print("spTicket: \(spTicket)")

            spTicketStatus = spTicket?.isEmpty == false
                ? .success("ticket received")
                : .failure("sp_ticket not found in response: \(raw)")
        } catch {
            spTicketStatus = .failure(error.localizedDescription)
            print("spTicketStatus: \(spTicketStatus), error: \(error)")
        }
    }

    var athResultStatus: StepStatus = .idle

    func openMOICA() {
        guard let ticket = spTicket else { return }
        var comps = URLComponents()
        comps.scheme = "mobilemoica"
        comps.host   = "moica.moi.gov.tw"
        comps.path   = "/a2a/verifySign"
        let rtnUrlBase64 = Data(Self.returnURL.utf8).base64EncodedString()
        comps.queryItems = [
            URLQueryItem(name: "sp_ticket", value: ticket),
            URLQueryItem(name: "rtn_url",   value: rtnUrlBase64),
            URLQueryItem(name: "rtn_val",   value: ""),
        ]
        guard let deepLink = comps.url else { return }
        print("deepLink: \(deepLink)")
        UIApplication.shared.open(deepLink)
    }


    func pollAthResult() async {
        athResultStatus = .running
        guard let ticket = spTicket else {
            athResultStatus = .failure("No sp_ticket available")
            return
        }
        do {
            let result = try await pollSignResult(spTicket: ticket)
            athResponseString = result.result?.signedResponse
            athIssuerCert     = result.result?.cert
            athResultStatus   = .success("result: \(result)")
            print("pollAthResult: \(athResultStatus)")
        } catch {
            athResultStatus = .failure(error.localizedDescription)
            print("pollAthResult error: \(athResultStatus)")
        }
    }


    func handleCallback(url: URL) {
        guard url.scheme == Self.returnScheme,
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let item  = comps.queryItems?.first(where: { $0.name == "rtn_val" })
        else { return }
        rtnVal = item.value
    }

    // MARK: - Pipeline Actions


    func reset() {
        generateInputStatus = .idle
        generatedInputPath = nil
        setupStatus = .idle
        proveStatus = .idle
        verifyStatus = .idle
    }

    func runAll() async {
        guard !isRunning else { return }
        isRunning = true
        reset()

        await _runProve()
        guard proveStatus.isSuccess else { isRunning = false; return }

        await _runVerify()
        isRunning = false
    }

    func runGenerateInput() async {
        let outPath = workDir.appendingPathComponent("input.json").path
        guard let certb64 = athIssuerCert else { return }
        guard let signedResponse = athResponseString else { return  }
        let issuerCertPath = workDir.appendingPathComponent("MOICA-G3.cer").path
        print("certb64: \(certb64)")
        print("signedResponse: \(signedResponse)")
        print("tbs: \(tbs)")
        print("issuerCertPath: \(issuerCertPath)")
        print("outPath: \(outPath)")
        do {
            let resultPath = try await Task.detached(priority: .userInitiated) {
                try await generateInputFido(
                    certb64: certb64,
                    signedResponse: signedResponse,
                    tbs: self.tbs,
                    issuerCertPath: issuerCertPath,
                    smtServer: nil,
                    issuerId: "g2",
                    outputPath: outPath
                )
            }.value
            generatedInputPath = resultPath
            generateInputStatus = .success(resultPath)
            let resultJson = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: resultPath))) as? [String: Any]
            print("resultJson: \(resultJson)")
        } catch {
            generateInputStatus = .failure(error.localizedDescription)
        }
    }

    func runSetupKeys() async {
        setupStatus = .running
        let dp = documentsPath, ip = inputPath
        do {
            let msg = try await Task.detached(priority: .userInitiated) {
                try setupKeysFido(documentsPath: dp, inputPath: ip)
            }.value
            setupStatus = .success(msg)
        } catch {
            setupStatus = .failure(error.localizedDescription)
        }
    }

    func runProve() async {
        guard !isRunning else { return }
        isRunning = true
        proveStatus = .idle
        await _runProve()
        isRunning = false
    }

    func runVerify() async {
        guard !isRunning else { return }
        isRunning = true
        verifyStatus = .idle
        await _runVerify()
        isRunning = false
    }

    private func _runProve() async {
        proveStatus = .running
        let dp = documentsPath
        let ip = generatedInputPath ?? inputPath
        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try proveFido(documentsPath: dp, inputPath: ip)
            }.value
            proveStatus = .success("\(result.proveMs) ms · \(result.proofSizeBytes) B")
        } catch {
            proveStatus = .failure(error.localizedDescription)
        }
    }

    private func _runVerify() async {
        verifyStatus = .running

        // Download verifying key on demand if not already present
        let keysDir = workDir.appendingPathComponent("keys", isDirectory: true)
        let verifyingKeyDest = keysDir.appendingPathComponent(verifyingKeyName)
        if !FileManager.default.fileExists(atPath: verifyingKeyDest.path) {
            let tmpVerifyingKey = FileManager.default.temporaryDirectory
                .appendingPathComponent("\(verifyingKeyName).zip")
            do {
                try FileManager.default.createDirectory(at: keysDir, withIntermediateDirectories: true)
                try await Task.detached(priority: .userInitiated) {
                    try await Self.downloadFile(from: verifyingKeyURL, to: tmpVerifyingKey) { _ in }
                    let archive = try Archive(url: tmpVerifyingKey, accessMode: .read)
                    for entry in archive where entry.type == .file {
                        let dest = keysDir.appendingPathComponent(entry.path)
                        if FileManager.default.fileExists(atPath: dest.path) {
                            try FileManager.default.removeItem(at: dest)
                        }
                        _ = try archive.extract(entry, to: dest)
                    }
                    try? FileManager.default.removeItem(at: tmpVerifyingKey)
                }.value
            } catch {
                verifyStatus = .failure("Failed to download verifying key: \(error.localizedDescription)")
                return
            }
        }

        let dp = documentsPath
        do {
            let valid = try await Task.detached(priority: .userInitiated) {
                try verifyFido(documentsPath: dp)
            }.value
            verifyStatus = valid ? .success("Proof is valid") : .failure("Proof is invalid")
        } catch {
            verifyStatus = .failure(error.localizedDescription)
        }
    }
}

// MARK: - Download Delegate

private final class DownloadTaskDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let destination: URL
    private let onProgress: @Sendable (Double) -> Void
    private let onCompletion: (Result<Void, Error>) -> Void
    private var finished = false
    var session: URLSession?

    init(destination: URL,
         onProgress: @escaping @Sendable (Double) -> Void,
         onCompletion: @escaping (Result<Void, Error>) -> Void) {
        self.destination = destination
        self.onProgress = onProgress
        self.onCompletion = onCompletion
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didWriteData _: Int64, totalBytesWritten: Int64,
                    totalBytesExpectedToWrite total: Int64) {
        guard total > 0 else { return }
        onProgress(Double(totalBytesWritten) / Double(total))
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask,
                    didFinishDownloadingTo location: URL) {
        guard !finished else { return }
        finished = true
        do {
            try? FileManager.default.removeItem(at: destination)
            try FileManager.default.moveItem(at: location, to: destination)
            onCompletion(.success(()))
        } catch {
            onCompletion(.failure(error))
        }
        self.session?.finishTasksAndInvalidate()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let error, !finished else { return }
        finished = true
        onCompletion(.failure(error))
        self.session?.finishTasksAndInvalidate()
    }
}
