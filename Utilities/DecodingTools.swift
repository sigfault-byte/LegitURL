//
//  DecodingTools.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//

import Foundation
import SwiftUI

enum DecodingError: Error {
    case failedDecoding
    case unknownEncoding
}

/// The result of a successful decoding operation.
struct DecodingResult {
    let decodedString: String
    let encodingUsed: DecodingTools.EncodingType
}

struct DecodingTools {
    
    // MARK: - Encoding Type
    
    /// The supported encoding types.
    enum EncodingType: String, CustomStringConvertible {
        case base64, hex, unicode, html, mime, url, unknown
        
        public var description: String {
            return self.rawValue.capitalized
        }
    }
    
    // MARK: - Entry Function
    
    /// Attempts to decode the input string using the detected encoding.
    /// - Parameter input: The input string to decode.
    /// - Returns: A `Result` containing a `DecodingResult` on success, or a `DecodingError` on failure.
    static func attemptToDecode(_ input: String) -> Result<DecodingResult, DecodingError> {
        let trimmedInput = input.trimmingCharacters(in: .whitespacesAndNewlines)
        //        debugLog("Attempting to decode: \(trimmedInput)")
//        Need to return what encoding was decoded
        let encodingType = detectEncodingType(trimmedInput)
        var decodedString: String? = nil
        var methodUsed = ""
        
        switch encodingType {
        case .hex:
            decodedString = decodeHex(trimmedInput)
            methodUsed = "Hex"
        case .unicode:
            decodedString = decodeUnicodeEscape(trimmedInput)
            methodUsed = "Unicode"
        case .html:
            decodedString = decodeHTMLEntities(trimmedInput)
            methodUsed = "HTML"
        case .mime:
            decodedString = decodeMIME(trimmedInput)
            methodUsed = "MIME"
        case .url:
            decodedString = decodeURLEncoding(trimmedInput)
            methodUsed = "URL"
        case .base64:
            decodedString = decodeBase64(trimmedInput)
            methodUsed = "Base64"
        case .unknown:
            //            debugLog("Unknown encoding type for input: \(trimmedInput)")
            return .failure(.unknownEncoding)
        }
        
        if let decoded = decodedString {
            //            debugLog("Successfully decoded using \(methodUsed) method.")
            let result = DecodingResult(decodedString: decoded, encodingUsed: encodingType)
            return .success(result)
        } else {
            //            debugLog("Decoding failed using \(methodUsed) method.")
            return .failure(.failedDecoding)
        }
    }
    
    // MARK: - Encoding Detection
    
    /// Detects the encoding type of the given input.
    /// - Parameter input: The input string.
    /// - Returns: The detected `EncodingType`.
    static func detectEncodingType(_ input: String) -> EncodingType {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        //        debugLog("Checking encoding pattern for: \(trimmed)")
        
        // Check for Hex encoding.
        if trimmed.hasPrefix("0x") || trimmed.range(of: #"^(0x)?[0-9A-Fa-f]+$"#, options: .regularExpression) != nil {
            return .hex
        }
        
        // Check for Base64 encoding.
        if looksLikeBase64(trimmed) { return .base64 }
        
        // Check for Unicode escape sequences.
        if trimmed.contains("\\u") { return .unicode }
        
        // Check for HTML entities (named or numerical).
        if trimmed.contains("&") && trimmed.contains(";") { return .html }
        
        // Check for MIME encoding patterns.
        if trimmed.contains("=?UTF-8?B?") || trimmed.contains("=?ISO-8859-1?Q?") { return .mime }
        
        // Check for URL percent encoding.
        if trimmed.contains("%") { return .url }
        
        //        debugLog("No known encoding detected for: \(trimmed)")
        return .unknown
    }
    
    // MARK: - Debug Logging
    
    //    /// Logs a debug message.
    //    private static func debugLog(_ message: String) {
    ////        print("DEBUG: \(message)")
    //    }
    //
    // MARK: - Decoding Functions
    
    /// Checks if a string looks like valid Base64.
    static func looksLikeBase64(_ input: String) -> Bool {
        let base64Regex = #"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"#
        // Base64 strings are usually longer than 8 characters and must have a length that is a multiple of 4.
        //        print("checking: \(input)")
        guard input.count >= 8, input.count % 4 == 0 else {
            return false
        }
        return input.range(of: base64Regex, options: .regularExpression) != nil
    }
    
    /// Decodes a Base64 encoded string.
    static func decodeBase64(_ input: String) -> String? {
        guard let data = Data(base64Encoded: input) else {
            //            debugLog("Base64 decoding failed for input: \(input)")
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
    
    /// Decodes a URL percent-encoded string.
    static func decodeURLEncoding(_ input: String) -> String? {
        return input.removingPercentEncoding
    }
    
    /// Decodes a hexadecimal encoded string.
    static func decodeHex(_ input: String) -> String? {
        var hexString = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if hexString.hasPrefix("0x") || hexString.hasPrefix("0X") {
            hexString = String(hexString.dropFirst(2))
        }
        
        // Ensure an even number of characters.
        guard hexString.count % 2 == 0 else {
            //            debugLog("Hex decoding failed: uneven number of characters in \(hexString)")
            return nil
        }
        
        var decoded = ""
        var index = hexString.startIndex
        
        while index < hexString.endIndex {
            let nextIndex = hexString.index(index, offsetBy: 2)
            let hexPair = String(hexString[index..<nextIndex])
            
            guard let intValue = UInt8(hexPair, radix: 16) else {
                //                debugLog("Hex decoding failed: invalid hex pair \(hexPair)")
                return nil
            }
            
            decoded.append(Character(UnicodeScalar(intValue)))
            index = nextIndex
        }
        
        return decoded.isEmpty ? nil : decoded
    }
    
    /// Decodes Unicode escape sequences (e.g. "\u0041") into their character representations.
    static func decodeUnicodeEscape(_ input: String) -> String? {
        var decoded = input
        let pattern = #"\\u([0-9A-Fa-f]{4})"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
            //            debugLog("Unicode decoding failed: regex creation failed.")
            return nil
        }
        let matches = regex.matches(in: input, options: [], range: NSRange(location: 0, length: input.utf16.count))
        // Process matches in reverse order to avoid index issues.
        for match in matches.reversed() {
            if let range = Range(match.range(at: 1), in: input),
               let codePoint = UInt32(input[range], radix: 16),
               let unicodeScalar = UnicodeScalar(codePoint) {
                let fullMatchRange = Range(match.range(at: 0), in: input)!
                decoded.replaceSubrange(fullMatchRange, with: String(Character(unicodeScalar)))
            } else {
                //                debugLog("Unicode decoding failed: invalid escape sequence in \(input)")
                return nil
            }
        }
        return decoded
    }
    
    /// Decodes HTML entities (both named and numerical) in a string.
    static func decodeHTMLEntities(_ input: String) -> String? {
        guard let data = input.data(using: .utf8) else {
            //            debugLog("HTML decoding failed: cannot convert input to data.")
            return nil
        }
        
        // Use the appropriate options based on environment availability.
#if canImport(UIKit)
        let options: [NSAttributedString.DocumentReadingOptionKey: Any] = [
            .documentType: NSAttributedString.DocumentType.html,
            .characterEncoding: String.Encoding.utf8.rawValue
        ]
#else
        let options: [String: Any] = [
            NSDocumentTypeDocumentAttribute: NSHTMLTextDocumentType,
            NSCharacterEncodingDocumentAttribute: String.Encoding.utf8.rawValue
        ]
#endif
        
        if let attributedString = try? NSAttributedString(data: data, options: options, documentAttributes: nil) {
            return attributedString.string
        }
        
        //        debugLog("HTML decoding failed: could not create attributed string.")
        return nil
    }
    
    /// Decodes MIME-encoded words in a string.
    static func decodeMIME(_ input: String) -> String? {
        // Check for UTF-8 Base64 encoded pattern.
        if input.contains("=?UTF-8?B?") {
            guard let base64Part = input.components(separatedBy: "?B?").dropFirst().first?.components(separatedBy: "?=").first else {
                //                debugLog("MIME decoding failed: could not extract Base64 segment from \(input)")
                return nil
            }
            return decodeBase64(base64Part)
        }
        // Check for ISO-8859-1 Q-encoded pattern.
        else if input.contains("=?ISO-8859-1?Q?") {
            // Perform a simple replacement for Q-encoding.
            return input.replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: "=", with: "")
        }
        return nil
    }
    
    // MARK: - UUID Analysis
    
    struct UUIDAnalysisResult {
        let original: String
        let formatted: String?
        let version: Int?
        let variant: String?
        let classification: String
    }
    
    static func analyzeUUID(_ input: String) -> UUIDAnalysisResult {
        let normalized = input.lowercased()
        var formattedUUID: String? = nil
        
        // Ensure it's hexadecimal
        guard normalized.range(of: #"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$|^[0-9a-f]{32}$"#, options: .regularExpression) != nil else {
            return UUIDAnalysisResult(original: input, formatted: nil, version: nil, variant: nil, classification: "Not a UUID")
        }
        
        // If 32 characters, add hyphens
        if normalized.count == 32 {
            formattedUUID = [
                normalized.prefix(8),
                normalized.dropFirst(8).prefix(4),
                normalized.dropFirst(12).prefix(4),
                normalized.dropFirst(16).prefix(4),
                normalized.dropFirst(20)
            ].joined(separator: "-")
        } else {
            formattedUUID = normalized
        }
        
        // Extract Version and Variant
        guard let formatted = formattedUUID else {
            return UUIDAnalysisResult(original: input, formatted: nil, version: nil, variant: nil, classification: "Malformed UUID")
        }
        
        let versionChar = formatted[formatted.index(formatted.startIndex, offsetBy: 14)]
        let variantChar = formatted[formatted.index(formatted.startIndex, offsetBy: 19)]
        
        let version = Int(String(versionChar), radix: 16)
        let variantBinary = Int(String(variantChar), radix: 16)
        
        let variant = {
            switch variantBinary {
            case 8, 9, 10, 11:
                return "RFC 4122"
            default:
                return "Non-standard"
            }
        }()
        
        // Determine classification
        let classification: String
        if variant == "Non-standard" {
            classification = "Malformed UUID (Possible Marketing ID)"
        } else if let version = version {
            switch version {
            case 1:
                classification = "Persistent UUID (MAC-based)"
            case 4:
                classification = "Tracking UUID (Random-based)"
            case 5:
                classification = "Marketing UUID (Deterministic)"
            default:
                classification = "Valid UUID (Other Version)"
            }
        } else {
            classification = "Malformed UUID"
        }
        
        return UUIDAnalysisResult(original: input, formatted: formatted, version: version, variant: variant, classification: classification)
    }
}
