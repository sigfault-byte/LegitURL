//
//  CSPGenerator.swift
//  LegitURL
//
//  Created by Chief Babylon Slayer
//
//TODO: Need sha check... Maybe sri too. before trying recommendedCSP
import Foundation
import CryptoKit

class RecommendedCSPGenerator {
    
    // MARK: - Inputs
    var detectedScriptHosts: Set<String> = []
    var hasInlineScripts: Bool = false
    var detectedInlineScriptContents: [String] = []
    var detectedScriptNonces: Set<String> = []
    
    // Other assets: images, frames, etc... !
    
    // MARK: - Public Interface
    func generateRecommendedCSP() -> CSPRecommendation {
        var directives: [String: [String]] = [:]
        var findings: [CSPRecommendation.Finding] = []

        // Default to 'self'
        directives["default-src"] = ["'self'"]

        // Script-src
        var scriptSources = ["'self'"]
        scriptSources.append(contentsOf: detectedScriptHosts)

        if !detectedScriptNonces.isEmpty {
            scriptSources.append("'nonce-<your_nonce_here>'")
        } else if hasInlineScripts {
            if detectedInlineScriptContents.count <= 5 {
                for inlineContent in detectedInlineScriptContents {
                    let hash = RecommendedCSPGenerator.hashInlineScript(inlineContent)
                    scriptSources.append("'sha256-\(hash)'")
                }
            } else {
                scriptSources.append("'unsafe-inline'")
                findings.append(.unsafeInlineDetected)
            }
        }

        directives["script-src"] = Array(Set(scriptSources)) // Deduplicate

        // Block objects
        directives["object-src"] = ["'none'"]

        // Future: Add img-src, frame-src, etc. based on findings

        // Convert into header string
        let header = directives.map { key, values in
            "\(key) \(values.joined(separator: " "));"
        }.joined(separator: " ")

        return CSPRecommendation(cspHeader: "Content-Security-Policy: \(header)", findings: findings)
    }
    
    private static func hashInlineScript(_ script: String) -> String {
        guard let data = script.data(using: .utf8) else { return "" }
        let hashed = SHA256.hash(data: data)
        return Data(hashed).base64EncodedString()
    }
}

struct CSPRecommendation {
    let cspHeader: String
    let findings: [Finding]

    enum Finding {
        case unsafeInlineDetected
        case dataUriDetected
        // More later
    }
}

// MARK: - Example Usage

/*
let generator = RecommendedCSPGenerator()
generator.detectedScriptHosts = ["https://github.io"]
generator.hasInlineScripts = true
let csp = generator.generateRecommendedCSP()
print(csp)
*/

// Output:
// Content-Security-Policy: default-src 'self'; script-src 'self' https://github.io 'unsafe-inline'; object-src 'none';
