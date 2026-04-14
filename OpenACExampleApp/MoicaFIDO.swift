import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Configuration

private func getSpServiceID() -> String {
    ProcessInfo.processInfo.environment["FIDO_SP_SERVICE_ID"] ?? Secrets.fidoSpServiceID
}

private func getAESKeyBase64() -> String {
    ProcessInfo.processInfo.environment["FIDO_AES_KEY"] ?? Secrets.fidoAESKey
}

private let baseURL = "https://fidoapi.moi.gov.tw"

// MARK: - Models

struct SpTicketParams {
    var transactionID: String
    var idNum: String
    var opCode: String      // "SIGN" | "ATH" | "NFCSIGN"
    var opMode: String      // "APP2APP" | "I-SCAN" | …
    var hint: String
    var timeLimit: String   // e.g. "600"
    var signData: String    // base64 string
    var signType: String    // "PKCS#7" | "CMS" | "RAW"
    var hashAlgorithm: String
    var tbsEncoding: String // "base64" | "utf8"
}

struct SpTicketPayload: Decodable {
    let transactionID: String
    let spTicketID: String
    let opCode: String

    enum CodingKeys: String, CodingKey {
        case transactionID   = "transaction_id"
        case spTicketID      = "sp_ticket_id"
        case opCode          = "op_code"
    }
}

struct SignResult: Decodable {
    let hashedIDNum: String?
    let signedResponse: String?
    let idpChecksum: String?
    let cert: String?

    enum CodingKeys: String, CodingKey {
        case hashedIDNum    = "hashed_id_num"
        case signedResponse = "signed_response"
        case idpChecksum    = "idp_checksum"
        case cert
    }
}

struct AthOrSignResultResponse: Decodable {
    let errorCode: String
    let errorMessage: String
    let result: SignResult?

    enum CodingKeys: String, CodingKey {
        case errorCode    = "error_code"
        case errorMessage = "error_message"
        case result
    }
}

// MARK: - Checksum

enum FIDOError: Error {
    case invalidAESKey
    case encryptionFailed
    case invalidSpTicket(String)
    case httpError(Int)
    case decodingError(String)
}

/// Implements the 5-step sp_checksum algorithm from the spec.
func computeSpChecksum(payload: String) throws -> String {
    // [2] SHA-256 → hex string
    let payloadData = Data(payload.utf8)
    let sha256Bytes = SHA256.hash(data: payloadData)
    let sha256Hex = sha256Bytes.map { String(format: "%02x", $0) }.joined()

    // [1] decode AES key
    guard let keyData = Data(base64Encoded: getAESKeyBase64()),
          keyData.count == 32 else {
        throw FIDOError.invalidAESKey
    }

    // [3] zero IV (12 bytes)
    let iv = Data(repeating: 0, count: 12)

    // [4] AES-256-GCM encrypt
    let symmetricKey = SymmetricKey(data: keyData)
    let nonce = try AES.GCM.Nonce(data: iv)
    let sealed = try AES.GCM.seal(Data(sha256Hex.utf8), using: symmetricKey, nonce: nonce)

    // ciphertext + tag (CryptoKit separates them)
    let ciphertextWithTag = sealed.ciphertext + sealed.tag

    // [5] hex(iv) + hex(ciphertext+tag)
    let ivHex = iv.map { String(format: "%02x", $0) }.joined()
    let ctHex = ciphertextWithTag.map { String(format: "%02x", $0) }.joined()
    return ivHex + ctHex
}

// MARK: - sp_ticket decode

/// Splits "Payload.Digest" on the last '.' and base64url-decodes the Payload segment.
func decodeSpTicket(_ spTicket: String) throws -> SpTicketPayload {
    guard let dotIndex = spTicket.lastIndex(of: ".") else {
        throw FIDOError.invalidSpTicket("missing '.' separator")
    }
    let payloadB64 = String(spTicket[spTicket.startIndex..<dotIndex])

    // base64url → base64 (add padding)
    var base64 = payloadB64
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }

    guard let raw = Data(base64Encoded: base64) else {
        throw FIDOError.invalidSpTicket("base64 decode failed")
    }

    return try JSONDecoder().decode(SpTicketPayload.self, from: raw)
}

// MARK: - API: getSpTicket

func getSpTicket(params: SpTicketParams) async throws -> String {
    let payload = params.transactionID + getSpServiceID() + params.idNum +
                  params.opCode + params.opMode + params.hint + params.signData
    let checksum = try computeSpChecksum(payload: payload)
    print("checksum: \(checksum)")
    print("payload: \(payload)")

    let body: [String: Any] = [
        "transaction_id": params.transactionID,
        "sp_service_id":  getSpServiceID(),
        "sp_checksum":    checksum,
        "id_num":         params.idNum,
        "op_code":        params.opCode,
        "op_mode":        params.opMode,
        "hint":           params.hint,
        "time_limit":     params.timeLimit,
        "sign_info": [
            "tbs_encoding":   params.tbsEncoding,
            "sign_data":      params.signData,
            "hash_algorithm": params.hashAlgorithm,
            "sign_type":      params.signType,
        ]
    ]

    var req = URLRequest(url: URL(string: "\(baseURL)/moise/sp/getSpTicket")!)
    req.httpMethod = "POST"
    req.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
    req.httpBody = try JSONSerialization.data(withJSONObject: body)

    let (data, response) = try await URLSession.shared.data(for: req)
    if let http = response as? HTTPURLResponse, http.statusCode != 200 {
        throw FIDOError.httpError(http.statusCode)
    }
    return String(data: data, encoding: .utf8) ?? ""
}

// MARK: - API: getAthOrSignResult

/// Per spec, callers should wait at least 4 seconds between poll attempts.
func getAthOrSignResult(spTicket: String) async throws -> AthOrSignResultResponse {
    let ticket = try decodeSpTicket(spTicket)

    let payload = ticket.transactionID + getSpServiceID() + ticket.spTicketID
    let checksum = try computeSpChecksum(payload: payload)

    let body: [String: Any] = [
        "transaction_id": ticket.transactionID,
        "sp_service_id":  getSpServiceID(),
        "sp_checksum":    checksum,
        "sp_ticket_id":   ticket.spTicketID,
    ]

    var req = URLRequest(url: URL(string: "\(baseURL)/moise/sp/getAthOrSignResult")!)
    req.httpMethod = "POST"
    req.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
    req.httpBody = try JSONSerialization.data(withJSONObject: body)

    let (data, response) = try await URLSession.shared.data(for: req)
    if let http = response as? HTTPURLResponse, http.statusCode != 200 {
        throw FIDOError.httpError(http.statusCode)
    }
    return try JSONDecoder().decode(AthOrSignResultResponse.self, from: data)
}

// MARK: - Poll Sign Result

func pollSignResult(spTicket: String) async throws -> AthOrSignResultResponse {
    while true {
        let result = try await getAthOrSignResult(spTicket: spTicket)
        switch result.errorCode {
        case "0":
            return result
        case "20002", "20003":
            print("Waiting for user action...")
            try await Task.sleep(nanoseconds: 4_000_000_000) // 4 秒
        default:
            throw FIDOError.decodingError("error \(result.errorCode): \(result.errorMessage)")
        }
    }
}