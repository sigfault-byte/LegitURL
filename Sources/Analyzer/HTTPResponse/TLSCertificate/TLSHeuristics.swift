//
//  TLSHeuristics.swift
//  LegitURL
//
//  Created by Chief Hakka on 05/04/2025.
//
import Foundation

struct TLSHeuristics {
    static func domainIsCoveredBySANs(domain: String, host: String, sans: [String]) -> Bool {

//         First try wildcard matches against the domain
//        print("NUMBER OF SANs: ", sans.count)
//        var i = 1
//        for san in sans {
//            print(i, "SAN: ", san)
//            i+=1
//        }
        
        for san in sans {
            if san.hasPrefix("*.") {
                let base = String(san.dropFirst(2))
                if host.hasSuffix("." + base) || host == base {
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


// TODO: Passive TLS SAN Analysis Infrastructure
// ------------------------------------------------
// Reminder:
// steampowered.com -> DV -> too many SANs
// redirect to store.steampowered.com -> EV -> 2 SANs

//
// TLS certificates with a high number of SANs (e.g. > 30) and no wildcards are highly suspicious.
// Especially when:
//  Each SAN is an unrelated FQDN (no shared base domain)
//  Only one SAN matches the target domain
//  Issuer is Let's Encrypt (or other free CA)
// This pattern strongly suggests automated scam infra (phishing kits or redirect networks).
//
// We can leverage this as a passive fingerprinting signal:
//   Use the SAN list as a graph node connecting domains across different scans
//   If a domain scores as DANGEROUS and its cert includes unrelated SANs,
//   store the cert fingerprint and SANs in a local database (SQLite).
//
// Future use cases:
//   If another domain appears in that cert's SANs, elevate its risk (greylist logic)
//   If a known scam domain is linked via SANs → critical penalty for all siblings
//
// Note: Avoid static blacklists — instead, grow a passive cert-based graph over time.
// This allows LegitURL to infer trust relationships (or abuse clusters) using TLS alone.
//CREATE TABLE tls_certs (
//    fingerprint TEXT PRIMARY KEY,
//    issuer TEXT,
//    not_before TEXT,
//    not_after TEXT
//);
//
//-- Domains linked by SANs (many-to-many relationship)
//CREATE TABLE tls_san_domains (
//    fingerprint TEXT,
//    domain TEXT,
//    PRIMARY KEY (fingerprint, domain)
//);
//
//-- Optional: Relationships derived from shared certs
//CREATE TABLE tls_domain_links (
//    domain_a TEXT,
//    domain_b TEXT,
//    shared_cert TEXT
//);
