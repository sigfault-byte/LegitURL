//
//  TLSHeuristics.swift
//  URLChecker
//
//  Created by Chief Hakka on 05/04/2025.
//
import Foundation

struct TLSHeuristics {
    static func domainIsCoveredBySANs(domain: String, host: String, sans: [String]) -> Bool {

        // First try wildcard matches against the domain
        for san in sans {
            if san.hasPrefix("*.") {
                let base = san.dropFirst(2)
                if domain.hasSuffix(base) {
                    return true
                }
            }
        }
        // Fallback: try exact SAN match against the host
        for san in sans {
            if host == san {
                return true
            }
        }
        return false
    }
    
    static func formattedDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: date)
    }
    
    static func classifyCertificatePolicyOIDs(_ oids: [String]) -> [(String, SecurityWarning.SeverityLevel)] {
        return oids.map { oid in
            switch oid {
            case "2.23.140.1.1":
                return ("Extended Validation (EV)", .info)
            case "2.23.140.1.2.2":
                return ("Organization Validation (OV)", .info)
            case "2.23.140.1.2.1":
                return ("Domain Validation (DV)", .suspicious)
            default:
                return ("Unknown Certificate Policy OID: \(oid)", .suspicious)
            }
        }
    }
}
