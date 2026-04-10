//
//  ProofViewModel.swift
//  OpenACExampleApp
//

import Foundation
import Observation
import UIKit
import OpenACSwift
import ZIPFoundation

private let circuitZipURL = URL(string: "https://pub-ef10768896384fdf9617f26d43e11a65.r2.dev/sha256rsa4096.r1cs.zip")!

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

        // For simulator testing
        // Copy bundled input.json on first launch.
        if let src = Bundle.main.path(forResource: "input", ofType: "json") {
            let dst = workDir.appendingPathComponent("input.json")
            print("copying input.json from \(src) to \(dst.path)")
            try fm.copyItem(atPath: src, toPath: dst.path)
        }
        circuitReady = fm.fileExists(atPath: workDir.appendingPathComponent("sha256rsa4096.r1cs").path)

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

        let tmpZip = FileManager.default.temporaryDirectory
            .appendingPathComponent("sha256rsa4096.r1cs.zip")
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
                atPath: workDir.appendingPathComponent("sha256rsa4096.r1cs").path
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

    // MARK: - SP Ticket / MOICA

    static let returnScheme = "openac"
    static let returnURL    = "\(returnScheme)://callback"

    var idNum: String = "A123456789"
    var spTicketStatus: StepStatus = .idle
    var spTicket: String?
    var tbs: String?
    var rtnVal: String?

    // Stored ath-result fields used to generate circuit input
    var athResponseString: String?
    var athIssuerCert: String?
    var athIssuerId: String = "g2"
    var generateInputStatus: StepStatus = .idle


    func computeSPTicket() async {
        spTicketStatus = .running
        spTicket = nil
        rtnVal = nil
        do {
            let raw = try await getSpTicket(params: SpTicketParams(
                transactionID: UUID().uuidString,
                idNum:         idNum,
                opCode:        "SIGN",
                opMode:        "APP2APP",
                hint:          "待簽署資料",
                timeLimit:     "600",
                signData:      "ZTc3NWYyODA1ZmI5OTNlMDVhMjA4ZGJmZjE1ZDFjMQ==",
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

    func runGenerateInput() async {
        let tbs = "e775f2805fb993e05a208dbff15d1c1"
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
                try generateInputFido(
                    certb64: certb64,
                    signedResponse: signedResponse,
                    tbs: tbs,
                    issuerCertPath: issuerCertPath,
                    smtServer: nil,
                    issuerId: "g2",
                    outputPath: outPath
                )
            }.value
            generateInputStatus = .success(outPath)
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
        proveStatus = .running
        let dp = documentsPath, ip = inputPath
        do {
            let result = try await Task.detached(priority: .userInitiated) {
                try proveFido(documentsPath: dp, inputPath: ip)
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
                try verifyFido(documentsPath: dp)
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
