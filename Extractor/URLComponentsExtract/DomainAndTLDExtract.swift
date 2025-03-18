//
//  DomainAndTLDExtract.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//

struct DomainAndTLDExtract {
    // Extracts domain & TLD from exploded host parts
    static func extract(hostidnaEncoded: String) -> (host: String?, tld: String?)? {
        print("extract domain & tld: ", hostidnaEncoded)
        let explodedParts = LegitURLTools.explodeURL(host: hostidnaEncoded)
        print("exploded: ", explodedParts, "\n")
        guard !explodedParts.isEmpty else { return nil }
        
        var longestValidTLD: String?
        var domainCandidate: String?
        
        for i in stride(from: explodedParts.count - 1, to: 0, by: -1) {
            let possibleTLD = explodedParts.suffix(i).joined(separator: ".")
            
            if isValidTLD(possibleTLD) { // Now calls the dedicated function
                longestValidTLD = possibleTLD
                domainCandidate = explodedParts[explodedParts.count - i - 1]
                break
            }
        }
        
        if let domain = domainCandidate, let tld = longestValidTLD {
            return (domain, tld)
        }
        
        print("❌ ERROR: No valid TLD found")
        return nil
    }
}
