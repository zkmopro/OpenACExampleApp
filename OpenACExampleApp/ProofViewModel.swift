//
//  ProofViewModel.swift
//  OpenACExampleApp
//

import Foundation
import Observation
import UIKit
import zlib
import OpenACSwift

private let certChainR1csURL         = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096.r1cs.gz")!
private let certChainProvingKeyURL   = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_proving.key.gz")!
private let certChainVerifyingKeyURL = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_verifying.key.gz")!
private let deviceSigR1csURL         = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/device_sig_rs2048.r1cs.gz")!
private let deviceSigProvingKeyURL   = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/device_sig_rs2048_proving.key.gz")!
private let deviceSigVerifyingKeyURL = URL(string: "https://github.com/zkmopro/zkID/releases/download/latest/device_sig_rs2048_verifying.key.gz")!
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

    // Circuit file names
    let certChainR1csName         = "cert_chain_rs4096.r1cs"
    let certChainProvingKeyName   = "cert_chain_rs4096_proving.key"
    let certChainVerifyingKeyName = "cert_chain_rs4096_verifying.key"
    let deviceSigR1csName         = "device_sig_rs2048.r1cs"
    let deviceSigProvingKeyName   = "device_sig_rs2048_proving.key"
    let deviceSigVerifyingKeyName = "device_sig_rs2048_verifying.key"
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
        let keysDir = workDir.appendingPathComponent("keys")
        circuitReady = fm.fileExists(atPath: workDir.appendingPathComponent(certChainR1csName).path)
            && fm.fileExists(atPath: keysDir.appendingPathComponent(certChainProvingKeyName).path)
            && fm.fileExists(atPath: workDir.appendingPathComponent(deviceSigR1csName).path)
            && fm.fileExists(atPath: keysDir.appendingPathComponent(deviceSigProvingKeyName).path)

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

        let fm = FileManager.default
        let keysDestDir = workDir.appendingPathComponent("keys", isDirectory: true)

        let certR1csExists  = fm.fileExists(atPath: workDir.appendingPathComponent(certChainR1csName).path)
        let certKeyExists   = fm.fileExists(atPath: keysDestDir.appendingPathComponent(certChainProvingKeyName).path)
        let devR1csExists   = fm.fileExists(atPath: workDir.appendingPathComponent(deviceSigR1csName).path)
        let devKeyExists    = fm.fileExists(atPath: keysDestDir.appendingPathComponent(deviceSigProvingKeyName).path)

        if certR1csExists && certKeyExists && devR1csExists && devKeyExists {
            circuitReady = true
            isDownloading = false
            return
        }

        let setProgress: @Sendable (Double) -> Void = { [weak self] p in
            Task { @MainActor [weak self] in self?.downloadProgress = p }
        }

        // Capture URL and name constants for use in detached task
        let certR1csURL    = certChainR1csURL
        let certKeyURL     = certChainProvingKeyURL
        let devR1csURL     = deviceSigR1csURL
        let devKeyURL      = deviceSigProvingKeyURL
        let certR1csName   = certChainR1csName
        let certKeyName    = certChainProvingKeyName
        let devR1csName    = deviceSigR1csName
        let devKeyName     = deviceSigProvingKeyName
        let r1csDir        = workDir
        let tmpDir         = fm.temporaryDirectory

        do {
            try fm.createDirectory(at: workDir, withIntermediateDirectories: true)
            try fm.createDirectory(at: keysDestDir, withIntermediateDirectories: true)

            let (dl, unzip) = try await Task.detached(priority: .userInitiated) {
                let t0 = Date()

                // 4 files, 25% progress each: certR1cs, certKey, devR1cs, devKey
                let jobs: [(URL, URL, Bool, String)] = [
                    (certR1csURL,  r1csDir,      certR1csExists, certR1csName),
                    (certKeyURL,   keysDestDir,  certKeyExists,  certKeyName),
                    (devR1csURL,   r1csDir,      devR1csExists,  devR1csName),
                    (devKeyURL,    keysDestDir,  devKeyExists,   devKeyName),
                ]

                for (i, (remoteURL, destDir, alreadyExists, fileName)) in jobs.enumerated() {
                    let base = Double(i) * 0.25
                    if alreadyExists {
                        setProgress(base + 0.25)
                        continue
                    }
                    let tmp = tmpDir.appendingPathComponent("\(fileName).gz")
                    try await Self.downloadFile(from: remoteURL, to: tmp) { p in
                        setProgress(base + p * 0.25)
                    }
                    let dest = destDir.appendingPathComponent(fileName)
                    try await Self.decompressGz(from: tmp, to: dest)
                }

                let downloadTime = Date().timeIntervalSince(t0)
                return (downloadTime, 0.0)
            }.value

            downloadSeconds = dl
            unzipSeconds = unzip > 0 ? unzip : nil

            circuitReady = fm.fileExists(atPath: workDir.appendingPathComponent(certChainR1csName).path)
                && fm.fileExists(atPath: keysDestDir.appendingPathComponent(certChainProvingKeyName).path)
                && fm.fileExists(atPath: workDir.appendingPathComponent(deviceSigR1csName).path)
                && fm.fileExists(atPath: keysDestDir.appendingPathComponent(deviceSigProvingKeyName).path)
        } catch {
            downloadError = error.localizedDescription
        }

        isDownloading = false
    }

    private static func decompressGz(from gzURL: URL, to destination: URL) throws {
        guard let gz = gzopen(gzURL.path, "rb") else {
            throw NSError(domain: "GzipDecompressError", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Cannot open: \(gzURL.lastPathComponent)"])
        }
        defer { gzclose(gz) }

        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        guard let outHandle = FileHandle(forWritingAtPath: destination.path) else {
            throw NSError(domain: "GzipDecompressError", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Cannot write: \(destination.lastPathComponent)"])
        }
        defer { try? outHandle.close() }

        let bufSize: Int32 = 65536
        var buf = [UInt8](repeating: 0, count: Int(bufSize))
        while true {
            let n = gzread(gz, &buf, UInt32(bufSize))
            if n <= 0 { break }
            outHandle.write(Data(buf[..<Int(n)]))
        }
        try? FileManager.default.removeItem(at: gzURL)
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
        guard let certb64 = athIssuerCert else { return }
        guard let signedResponse = athResponseString else { return }
        let outDir = workDir.path
        let issuerCertPath = workDir.appendingPathComponent("MOICA-G3.cer").path
        let tbsCapture = tbs
        generateInputStatus = .running
        do {
            let resultPath = try await Task.detached(priority: .userInitiated) {
                try generateCertChainRs4096Input(
                    certb64: certb64,
                    signedResponse: signedResponse,
                    tbs: tbsCapture,
                    issuerCertPath: issuerCertPath,
                    smtServer: nil,
                    issuerId: "g2",
                    outputDir: outDir
                )
            }.value
            generatedInputPath = resultPath
            // Log all files written to outDir to verify both input JSONs are present
            let created = (try? FileManager.default.contentsOfDirectory(atPath: outDir)) ?? []
            print("generateCertChainRs4096Input returned: \(resultPath)")
            print("workDir contents after generate: \(created.sorted())")
            generateInputStatus = .success(resultPath)
        } catch {
            generateInputStatus = .failure(error.localizedDescription)
        }
    }

    func runSetupKeys() async {
        setupStatus = .running
        let dp = documentsPath
        do {
            let msg = try await Task.detached(priority: .userInitiated) {
                try setupKeys(documentsPath: dp)
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
        do {
            let ms = try await Task.detached(priority: .userInitiated) {
                let t0 = Date()
                _ = try proveCertChainRs4096(documentsPath: dp)
                _ = try proveDeviceSigRs2048(documentsPath: dp)
                return Int(Date().timeIntervalSince(t0) * 1000)
            }.value
            proveStatus = .success("\(ms) ms")
        } catch {
            proveStatus = .failure(error.localizedDescription)
        }
    }

    private func _runVerify() async {
        verifyStatus = .running

        let fm = FileManager.default
        let keysDir = workDir.appendingPathComponent("keys", isDirectory: true)

        // Download verifying keys on demand
        let verifyingKeys: [(String, URL)] = [
            (certChainVerifyingKeyName,  certChainVerifyingKeyURL),
            (deviceSigVerifyingKeyName,  deviceSigVerifyingKeyURL),
        ]
        for (keyName, remoteURL) in verifyingKeys {
            let dest = keysDir.appendingPathComponent(keyName)
            guard !fm.fileExists(atPath: dest.path) else { continue }
            let tmp = fm.temporaryDirectory.appendingPathComponent("\(keyName).gz")
            do {
                try fm.createDirectory(at: keysDir, withIntermediateDirectories: true)
                try await Task.detached(priority: .userInitiated) {
                    try await Self.downloadFile(from: remoteURL, to: tmp) { _ in }
                    try await Self.decompressGz(from: tmp, to: dest)
                }.value
            } catch {
                verifyStatus = .failure("Failed to download \(keyName): \(error.localizedDescription)")
                return
            }
        }

        let dp = documentsPath
        do {
            let (validChain, validDevice) = try await Task.detached(priority: .userInitiated) {
                let c = try verifyCertChainRs4096(documentsPath: dp)
                let d = try verifyDeviceSigRs2048(documentsPath: dp)
                return (c, d)
            }.value
            switch (validChain, validDevice) {
            case (true, true):   verifyStatus = .success("Both proofs valid")
            case (false, _):     verifyStatus = .failure("CertChain proof invalid")
            case (_, false):     verifyStatus = .failure("DeviceSig proof invalid")
            }
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
