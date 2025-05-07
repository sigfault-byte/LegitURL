//
//  DomainAndTLDExtract.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
struct DomainAndTLDExtractor {
    // Extracts domain & TLD from exploded host parts
    static func extract(hostidnaEncoded: String) -> (host: String?, tld: String?)? {

        let explodedParts = CommonTools.explodeURL(host: hostidnaEncoded)

        guard !explodedParts.isEmpty else { return nil }
        
        var longestValidTLD: String?
        var domainCandidate: String?

        for i in stride(from: explodedParts.count - 1, to: 0, by: -1) {
            let possibleTLD = explodedParts.suffix(i).joined(separator: ".")

            
            if isValidTLD(possibleTLD) {
                longestValidTLD = possibleTLD
                domainCandidate = explodedParts[explodedParts.count - i - 1]
                break
            }
        }
        
        if let domain = domainCandidate, let tld = longestValidTLD {
            return (domain, tld)
        }
        #if DEBUG
        print("❌ ERROR: No valid TLD found")
        #endif
        return nil
    }
}
