//
//  URLCertificate.swift
//  LegitURL
//
//  Created by Chief Hakka on 08/04/2025.
//
import Foundation

struct ParsedEKU {
    let oid: String
    let shortDescription: String
    let description: String
    let severity: SecurityWarning.SeverityLevel
}

struct ParsedCertificate {
    var commonName: String?
    var organization: String?
    var issuerCommonName: String?
    var issuerOrganization: String?
    var notBefore: Date?
    var notAfter: Date?
    var publicKeyAlgorithm: String?
    var keyUsage: String?
    var publicKeyBits: Int?
    var fingerprintSHA256: String?
    var extendedKeyUsageOID: String?
    var extendedKeyUsageString: [ParsedEKU]?
    var certificatePolicyOIDs: String?
    var isSelfSigned: Bool = false
    var subjectAlternativeNames: [String]?
    
    var inferredValidationLevel: CertificateValidationLevel {
        guard let oids = certificatePolicyOIDs?.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) else {
            return .unknown
        }
        
        if oids.contains("2.23.140.1.1") {
            return .ev
        } else if oids.contains("2.23.140.1.2.2") {
            return .ov
        } else if oids.contains("2.23.140.1.2.1") {
            return .dv
        } else {
            return .unknown
        }
    }
    
    var mainCertificatePolicy: String? {
        let knownPolicies: [String: String] = [
            "2.23.140.1.1": "Extended Validation",
            "2.23.140.1.2.2": "Organization Validation",
            "2.23.140.1.2.1": "Domain Validation"
        ]

        guard let oids = certificatePolicyOIDs?.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) else {
            return nil
        }

        for oid in oids {
            if let known = knownPolicies[oid] {
                return "\(known) [\(oid)]"
            }
        }

        return oids.first
    }
}

enum CertificateValidationLevel: String {
    case ev = "Extended Validation"
    case ov = "Organization Validation"
    case dv = "Domain Validation"
    case unknown = "Unknown"
}

extension ParsedCertificate {
    var formattedEKU: String? {
        guard let ekuList = extendedKeyUsageString else { return nil }
        return ekuList.map { "\($0.shortDescription) [\($0.oid)]" }.joined(separator: "\n")
    }
}
