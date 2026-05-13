//
//  ProofViewModel.swift
//  OpenACExampleApp
//

import Foundation
import Observation
import OpenACSwift
import UIKit
import zlib

private let certChainProvingKeyURL = URL(
  string:
    "https://github.com/zkmopro/zkID/releases/download/latest/cert_chain_rs4096_proving.key.gz")!
private let userSigProvingKeyURL = URL(
  string:
    "https://github.com/zkmopro/zkID/releases/download/latest/user_sig_rs2048_proving.key.gz")!
private let smtSnapshotURL = URL(
  string:
    "https://github.com/moven0831/moica-revocation-smt/releases/download/snapshot-latest/g3-tree-snapshot.json.gz"
)!
private let serverURL = URL(string: "https://a5b6-3-85-109-129.ngrok-free.app/challenge")!
private let linkVerifyURL = URL(string: "https://a5b6-3-85-109-129.ngrok-free.app/link-verify")!

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

    var errorMessage: String? {
      if case .failure(let msg) = self { return msg }
      return nil
    }
  }

  // Pipeline step states
  var setupStatus: StepStatus = .idle
  var proveStatus: StepStatus = .idle
  var verifyStatus: StepStatus = .idle
  var isRunning = false

  // Circuit file names
  let certChainProvingKeyName = "cert_chain_rs4096_proving.key"
  let userSigProvingKeyName = "user_sig_rs2048_proving.key"
  let smtSnapshotName = "g3-tree-snapshot.json.gz"
  var circuitReady = false
  var isDownloading = false
  var downloadProgress: Double = 0  // 0.0 – 1.0
  var downloadError: String?
  var downloadSeconds: Double?
  var unzipSeconds: Double?

  // MARK: - Flow Navigation

  enum FlowStep: Equatable {
    case intro
    case readiness
    case returned
    case verifying
    case submitting
    case success
    case failure(String)
  }

  var flowStep: FlowStep = .intro
  var verificationStartTime: Date?
  var totalVerificationSeconds: Double?
  var verifyMilliseconds: Int?

  var moicaAppInstalled: Bool {
    guard let url = URL(string: "mobilemoica://") else { return false }
    return UIApplication.shared.canOpenURL(url)
  }

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
    circuitReady =
      fm.fileExists(atPath: keysDir.appendingPathComponent(certChainProvingKeyName).path)
      && fm.fileExists(atPath: keysDir.appendingPathComponent(userSigProvingKeyName).path)
      && fm.fileExists(atPath: workDir.appendingPathComponent(smtSnapshotName).path)

    // Copy bundled MOICA-G3.cer into workDir if not already present
    let certDest = workDir.appendingPathComponent("MOICA-G3.cer")
    if !fm.fileExists(atPath: certDest.path),
      let certSrc = Bundle.main.url(forResource: "MOICA-G3", withExtension: "cer")
    {
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

    let workDirCapture = workDir
    let certKeyExists = fm.fileExists(
      atPath: keysDestDir.appendingPathComponent(certChainProvingKeyName).path)
    let userKeyExists = fm.fileExists(
      atPath: keysDestDir.appendingPathComponent(userSigProvingKeyName).path)
    let snapshotExists = fm.fileExists(
      atPath: workDirCapture.appendingPathComponent(smtSnapshotName).path)

    if certKeyExists && userKeyExists && snapshotExists {
      circuitReady = true
      isDownloading = false
      return
    }

    let setProgress: @Sendable (Double) -> Void = { [weak self] p in
      Task { @MainActor [weak self] in self?.downloadProgress = p }
    }

    // Capture URL and name constants for use in detached task
    let certKeyURL = certChainProvingKeyURL
    let userKeyURL = userSigProvingKeyURL
    let snapURL = smtSnapshotURL
    let certKeyName = certChainProvingKeyName
    let userKeyName = userSigProvingKeyName
    let snapName = smtSnapshotName
    let tmpDir = fm.temporaryDirectory

    do {
      try fm.createDirectory(at: keysDestDir, withIntermediateDirectories: true)

      let dl = try await Task.detached(priority: .userInitiated) {
        let t0 = Date()

        // (remoteURL, alreadyExists, destination, decompress)
        let jobs: [(URL, Bool, URL, Bool)] = [
          (certKeyURL, certKeyExists, keysDestDir.appendingPathComponent(certKeyName), true),
          (userKeyURL, userKeyExists, keysDestDir.appendingPathComponent(userKeyName), true),
          (snapURL, snapshotExists, workDirCapture.appendingPathComponent(snapName), false),
        ]
        let slice = 1.0 / Double(jobs.count)
        for (i, (remoteURL, alreadyExists, dest, decompress)) in jobs.enumerated() {
          let base = Double(i) * slice
          if alreadyExists {
            setProgress(base + slice)
            continue
          }
          if decompress {
            let tmp = tmpDir.appendingPathComponent(dest.lastPathComponent + ".gz")
            try await Self.downloadFile(from: remoteURL, to: tmp) { p in
              setProgress(base + p * slice)
            }
            try Self.decompressGz(from: tmp, to: dest)
          } else {
            try await Self.downloadFile(from: remoteURL, to: dest) { p in
              setProgress(base + p * slice)
            }
          }
        }
        return Date().timeIntervalSince(t0)
      }.value

      downloadSeconds = dl
      unzipSeconds = nil

      circuitReady =
        fm.fileExists(atPath: keysDestDir.appendingPathComponent(certChainProvingKeyName).path)
        && fm.fileExists(atPath: keysDestDir.appendingPathComponent(userSigProvingKeyName).path)
        && fm.fileExists(atPath: workDirCapture.appendingPathComponent(smtSnapshotName).path)
    } catch {
      downloadError = error.localizedDescription
    }

    isDownloading = false
  }

  private nonisolated static func decompressGz(from gzURL: URL, to destination: URL) throws {
    guard let gz = gzopen(gzURL.path, "rb") else {
      throw NSError(
        domain: "GzipDecompressError", code: 1,
        userInfo: [NSLocalizedDescriptionKey: "Cannot open: \(gzURL.lastPathComponent)"])
    }
    defer { gzclose(gz) }

    if FileManager.default.fileExists(atPath: destination.path) {
      try FileManager.default.removeItem(at: destination)
    }
    FileManager.default.createFile(atPath: destination.path, contents: nil)
    guard let outHandle = FileHandle(forWritingAtPath: destination.path) else {
      throw NSError(
        domain: "GzipDecompressError", code: 2,
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
  static let returnURL = "\(returnScheme)://callback"

  var idNum: String = ""
  /// Bumped when `idNum` is edited so in-flight `computeSPTicket` results are ignored.
  private var identityCheckEpoch: UInt = 0
  var spTicketStatus: StepStatus = .idle
  var spTicket: String?
  var tbs: String = ""
  var challenge: String = ""
  /// Server deadline for the current challenge (from `regenerateTBS` → `expires_at`).
  var challengeExpiresAt: Date?
  var rtnVal: String?

  var tbsStatus: StepStatus = .idle

  /// When `challengeExpiresAt` is set and in the past, the user must refresh the challenge.
  var isChallengeExpired: Bool {
    guard let end = challengeExpiresAt else { return false }
    return Date() >= end
  }

  /// Call when the user edits the national ID field so prior ticket / success / failure no longer applies.
  func resetIdentityCheckOnIdNumberEdit() {
    identityCheckEpoch += 1
    spTicketStatus = .idle
    spTicket = nil
    rtnVal = nil
    challengeExpiresAt = nil
  }

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
      guard let appIdBytes = json["app_id"] as? String,
            let challengeString = json["challenge"] as? String else {
        challengeExpiresAt = nil
        tbsStatus = .failure("Server error")
        return
      }
      tbs = appIdBytes
      challenge = challengeString
      if let expiresString = json["expires_at"] as? String {
        challengeExpiresAt = Self.parseChallengeExpiry(expiresString)
      } else {
        challengeExpiresAt = nil
      }

      tbsStatus = .success("challenge received")
    } catch {
      challengeExpiresAt = nil
      tbsStatus = .failure("Server error")
      print("regenerateTBS error: \(error)")
    }
  }

  // Stored ath-result fields used to generate circuit input
  var athResponseString: String?
  var athIssuerCert: String?
  var generateInputStatus: StepStatus = .idle
  var generatedInputPath: String?

  func computeSPTicket() async {
    let epochAtStart = identityCheckEpoch
    spTicketStatus = .running
    spTicket = nil
    rtnVal = nil
    do {
      print("tbs: \(tbs)")
      let raw = try await getSpTicket(
        params: SpTicketParams(
          transactionID: UUID().uuidString,
          idNum: idNum,
          opCode: "SIGN",
          opMode: "APP2APP",
          hint: "待簽署資料",
          timeLimit: "600",
          signData: Data(tbs.utf8).base64EncodedString(),
          signType: "PKCS#1",
          hashAlgorithm: "SHA256",
          tbsEncoding: "base64"
        ))

      guard epochAtStart == identityCheckEpoch else { return }

      let json = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as! [String: Any]
      let ticketCandidate = ((json["result"] as? [String: Any])?["sp_ticket"] as? String) ?? ""
      print("spTicket: \(ticketCandidate)")

      guard epochAtStart == identityCheckEpoch else { return }

      spTicket = ticketCandidate

      if !ticketCandidate.isEmpty {
        spTicketStatus = .success("ticket received")
      } else if let errMsg = json["error_message"] as? String, !errMsg.isEmpty {
        if errMsg.contains("input id number not found in database") {
          spTicketStatus = .failure("ID not found in database")
        } else {
          spTicketStatus = .failure(errMsg)
        }
      } else if let errCode = json["error_code"] as? String, !errCode.isEmpty {
        spTicketStatus = .failure(errCode)
      } else {
        spTicketStatus = .failure("sp_ticket not found in response: \(raw)")
      }
    } catch {
      guard epochAtStart == identityCheckEpoch else { return }
      spTicketStatus = .failure(error.localizedDescription)
      print("spTicketStatus: \(spTicketStatus), error: \(error)")
    }
  }

  var athResultStatus: StepStatus = .idle

  func openMOICA() {
    guard !isChallengeExpired else { return }
    guard let ticket = spTicket else { return }
    var comps = URLComponents()
    comps.scheme = "mobilemoica"
    comps.host = "moica.moi.gov.tw"
    comps.path = "/a2a/verifySign"
    let rtnUrlBase64 = Data(Self.returnURL.utf8).base64EncodedString()
    comps.queryItems = [
      URLQueryItem(name: "sp_ticket", value: ticket),
      URLQueryItem(name: "rtn_url", value: rtnUrlBase64),
      URLQueryItem(name: "rtn_val", value: ""),
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
      athIssuerCert = result.result?.cert
      athResultStatus = .success("result: \(result)")
      print("pollAthResult: \(athResultStatus)")
    } catch {
      athResultStatus = .failure(error.localizedDescription)
      print("pollAthResult error: \(athResultStatus)")
    }
  }

  func handleCallback(url: URL) {
    guard url.scheme == Self.returnScheme,
      let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
      let item = comps.queryItems?.first(where: { $0.name == "rtn_val" })
    else { return }
    rtnVal = item.value
    flowStep = .returned
    Task { await pollAthResult() }
  }

  // MARK: - Pipeline Actions

  func reset() {
    identityCheckEpoch += 1
    isRunning = false
    generateInputStatus = .idle
    generatedInputPath = nil
    setupStatus = .idle
    proveStatus = .idle
    verifyStatus = .idle
    athResultStatus = .idle
    athResponseString = nil
    athIssuerCert = nil
    spTicket = nil
    spTicketStatus = .idle
    tbs = ""
    challenge = ""
    tbsStatus = .idle
    rtnVal = nil
    challengeExpiresAt = nil
    verificationStartTime = nil
    totalVerificationSeconds = nil
    verifyMilliseconds = nil
    idNum = ""
    flowStep = .intro
  }

  private static let iso8601Fractional: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
  }()

  private static let iso8601Plain: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f
  }()

  /// Parses server timestamps such as `2026-05-02T14:38:30.798088+08:00`.
  private static func parseChallengeExpiry(_ string: String) -> Date? {
    Self.iso8601Fractional.date(from: string) ?? Self.iso8601Plain.date(from: string)
  }

  func runLocalVerification() async {
    verificationStartTime = Date()
    flowStep = .verifying
    isRunning = true

    if isChallengeExpired {
      let msg = "Challenge expired, please refresh"
      verifyStatus = .failure(msg)
      flowStep = .failure(msg)
      isRunning = false
      return
    }

    await runGenerateInput()
    guard generateInputStatus.isSuccess else {
      flowStep = .failure(generateInputStatus.errorMessage ?? "Failed to prepare input")
      isRunning = false
      return
    }

    await _runProve()
    guard proveStatus.isSuccess else {
      flowStep = .failure(proveStatus.errorMessage ?? "Prove failed")
      isRunning = false
      return
    }

    if isChallengeExpired {
      let msg = "Challenge expired, please refresh"
      verifyStatus = .failure(msg)
      flowStep = .failure(msg)
      isRunning = false
      return
    }

    flowStep = .submitting
    await _runVerify()

    if verifyStatus.isSuccess {
      totalVerificationSeconds = verificationStartTime.map { Date().timeIntervalSince($0) }
      flowStep = .success
    } else {
      flowStep = .failure(verifyStatus.errorMessage ?? "Verify failed")
    }
    isRunning = false
  }

  func runAll() async {
    guard !isRunning else { return }
    isRunning = true
    reset()

    await _runProve()
    guard proveStatus.isSuccess else {
      isRunning = false
      return
    }

    guard !isChallengeExpired else {
      verifyStatus = .failure("Challenge expired, please refresh")
      isRunning = false
      return
    }

    await _runVerify()
    isRunning = false
  }

  func runGenerateInput() async {
    guard let certb64 = athIssuerCert else { return }
    guard let signedResponse = athResponseString else { return }
    let outDir = workDir.path
    let issuerCertPath = workDir.appendingPathComponent("MOICA-G3.cer").path
    let smtSnapshotPath = workDir.appendingPathComponent("g3-tree-snapshot.json.gz").path
    let tbsCapture = tbs
    let challenge: String = challenge
    generateInputStatus = .running
    do {
      let resultPath = try await Task.detached(priority: .userInitiated) {
        try generateCertChainRs4096Input(
          certb64: certb64,
          signedResponse: signedResponse,
          tbs: tbsCapture,
          issuerCertPath: issuerCertPath,
          smtSnapshotPath: smtSnapshotPath,
          outputDir: outDir,
          challenge: challenge

        )
      }.value
      generatedInputPath = resultPath
      // Log all files written to outDir to verify both input JSONs are present
            let created = (try? FileManager.default.contentsOfDirectory(atPath: outDir)) ?? []
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
        _ = try proveUserSigRs2048(documentsPath: dp)
        return Int(Date().timeIntervalSince(t0) * 1000)
      }.value
      proveStatus = .success("\(ms) ms")
    } catch {
      proveStatus = .failure(error.localizedDescription)
    }
  }

  private func cleanupCircuitFiles() {
    let fm = FileManager.default
    try? fm.removeItem(at: workDir.appendingPathComponent("keys"))
    try? fm.removeItem(at: workDir.appendingPathComponent(smtSnapshotName))
    circuitReady = false
  }

  private func _runVerify() async {
    if isChallengeExpired {
      verifyStatus = .failure("Challenge expired, please refresh")
      return
    }

    verifyStatus = .running
    let verifyStart = Date()

    let dp = documentsPath
    let workDirCapture = workDir
    do {
      let ( ccProof, usProof) = try await Task.detached(
        priority: .userInitiated
      ) {
        let ccProof = try Data(
          contentsOf: workDirCapture.appendingPathComponent("keys").appendingPathComponent("cert_chain_rs4096_proof.bin"))
        let usProof = try Data(
          contentsOf: workDirCapture.appendingPathComponent("keys").appendingPathComponent("user_sig_rs2048_proof.bin"))
        return (ccProof, usProof)
      }.value


      struct LinkVerifyRequest: Encodable {
        let certChainType: String
        let certChainProof: Data
        let userSigProof: Data
        enum CodingKeys: String, CodingKey {
          case certChainType = "cert_chain_type"
          case certChainProof = "cert_chain_proof"
          case userSigProof = "user_sig_proof"
        }
      }

      var request = URLRequest(url: linkVerifyURL)
      request.httpMethod = "POST"
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.setValue("true", forHTTPHeaderField: "ngrok-skip-browser-warning")
      request.httpBody = try JSONEncoder().encode(
        LinkVerifyRequest(
          certChainType: "rs4096",
          certChainProof: ccProof,
          userSigProof: usProof,
        ))

      let (data, response) = try await URLSession.shared.data(for: request)
      let raw = String(data: data, encoding: .utf8) ?? ""
      print("link-verify response: \(raw)")

      guard (response as? HTTPURLResponse)?.statusCode == 200 else {
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        verifyStatus = .failure("link-verify failed (\(code)): \(raw)")
        return
      }

      verifyMilliseconds = Int(Date().timeIntervalSince(verifyStart) * 1000)
      verifyStatus = .success("All proofs valid")
      cleanupCircuitFiles()
    } catch {
      print("_runVerify error: \(error)")
      verifyStatus = .failure(error.localizedDescription)
    }
  }
}

// MARK: - Download Delegate

private final class DownloadTaskDelegate: NSObject, URLSessionDownloadDelegate, @unchecked Sendable
{
  private let destination: URL
  private let onProgress: @Sendable (Double) -> Void
  private let onCompletion: (Result<Void, Error>) -> Void
  private var finished = false
  var session: URLSession?

  init(
    destination: URL,
    onProgress: @escaping @Sendable (Double) -> Void,
    onCompletion: @escaping (Result<Void, Error>) -> Void
  ) {
    self.destination = destination
    self.onProgress = onProgress
    self.onCompletion = onCompletion
  }

  func urlSession(
    _ session: URLSession, downloadTask: URLSessionDownloadTask,
    didWriteData _: Int64, totalBytesWritten: Int64,
    totalBytesExpectedToWrite total: Int64
  ) {
    guard total > 0 else { return }
    onProgress(Double(totalBytesWritten) / Double(total))
  }

  func urlSession(
    _ session: URLSession, downloadTask: URLSessionDownloadTask,
    didFinishDownloadingTo location: URL
  ) {
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
