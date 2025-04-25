//
//  GenerateCSP.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//
import Foundation

struct GenerateCSP {
    
    static func generate(from result: ScriptExtractionResult) -> CSPRecommendation {
        var externalHosts = Set<String>()
        var hasInlineScript = false

        for script in result.scripts {
            if script.origin == .httpsExternal, let src = script.extractedSrc, let url = URL(string: src) {
                if let host = url.host {
                    externalHosts.insert("https://" + host)
                }
            } else if script.origin == .inline {
                hasInlineScript = true
            }
        }

        let generator = RecommendedCSPGenerator()
        generator.detectedScriptHosts = externalHosts
        generator.hasInlineScripts = hasInlineScript
        
        return generator.generateRecommendedCSP()
    }
}
