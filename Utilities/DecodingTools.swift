//
//  DecodingTools.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
//

import Foundation

struct DecodingTools {

    // MARK: - UUID Analysis
    
    struct UUIDAnalysisResult: Hashable {
        let original: String
        let formatted: String?
        let version: Int?
        let variant: String?
        let classification: String
    }
    
    static func analyzeUUID(_ input: String) -> UUIDAnalysisResult {
        let normalized = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        var formattedUUID: String? = nil
        print("🧪 UUID Regex test: '\(normalized)' (length: \(normalized.count))")
        
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
