//  TLDAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
//TODO: correctly normalize https://www.surbl.org/static/tld-abuse-complete-rankings.txt, and more tests instead of random penalty for the suss tld

struct TLDAnalyzer {
    static func analyze(_ tld: String, urlInfo: inout URLInfo) -> Void {
        let suspiciousTLD = "." + tld.lowercased()
        
        
        if let penalty = PenaltySystem.suspiciousTLDs[suspiciousTLD] {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ The TLD '\(suspiciousTLD)' is commonly associated with suspicious domains.",
                severity: .suspicious,
                penalty: penalty,
                url: urlInfo.components.coreURL ?? "",
                source: .host
            ))
        }
    }
}
