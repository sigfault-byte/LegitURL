//
//  GenerateCSP.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//
import Foundation

struct GenerateCSP {
    
    static func generate(from result: ScriptExtractionResult, rawBody: Data) -> CSPRecommendation {
        var externalHosts = Set<String>()
        var hasInlineScript = false
        var inlineScriptContents = [String]()
        var scriptNonces = Set<String>()
        
        for script in result.scripts {
            if script.origin == .httpsExternal, let src = script.extractedSrc, let url = URL(string: src) {
                if let host = url.host {
                    externalHosts.insert("https://" + host)
                }
            } else if script.origin == .inline {
                hasInlineScript = true
                
                if let start = script.end, let end = script.endTagPos, start < end, end <= rawBody.count {
                    let dataSlice = rawBody[start + 1..<end] // +1 for the > because swift "end" is ON the >
                    if let content = String(data: dataSlice, encoding: .utf8) {
                        let cleaned = content.trimmingCharacters(in: .whitespacesAndNewlines) // clean leading char for SHA
                        inlineScriptContents.append(cleaned)
                    }
                }
                
                if let nonce = script.nonceValue {
                    scriptNonces.insert(nonce)
                }
            }
        }

        let generator = RecommendedCSPGenerator()
        generator.detectedScriptHosts = externalHosts
        generator.hasInlineScripts = hasInlineScript
        generator.detectedInlineScriptContents = inlineScriptContents
        generator.detectedScriptNonces = scriptNonces
        
        return generator.generateRecommendedCSP()
    }
}

//Minimal headers should be:
//Strict-Transport-Security: max-age=31536000; includeSubDomains
//Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'
//Content-Type: text/html; charset=UTF-8
//X-Content-Type-Options: nosniff
//Referrer-Policy: strict-origin-when-cross-origin

//Anything other should be assessed as unsecured / miss configured
//Especially the htst + CSP + XCTO
//Alternatively COOP and COEP should be mandatory. 
