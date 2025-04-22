import Foundation

enum ExtendedKeyUsageOID: String {
    case serverAuth = "1.3.6.1.5.5.7.3.1"
    case clientAuth = "1.3.6.1.5.5.7.3.2"
    case codeSigning = "1.3.6.1.5.5.7.3.3"
    case emailProtection = "1.3.6.1.5.5.7.3.4"
    case timeStamping = "1.3.6.1.5.5.7.3.8"
    case ocspSigning = "1.3.6.1.5.5.7.3.9"
    case anyExtendedUsage = "2.5.29.37.0"

    var description: String {
        switch self {
        case .serverAuth: return "TLS Web Server Authentication (expected)"
        case .clientAuth: return "TLS Web Client Authentication (optional)"
        case .codeSigning: return "Code Signing (unusual for websites)"
        case .emailProtection: return "Email Protection (S/MIME)"
        case .timeStamping: return "Time Stamping (usually unnecessary)"
        case .ocspSigning: return "OCSP Signing (for CAs only)"
        case .anyExtendedUsage: return "Any Extended Key Usage (very permissive, suspicious)"
        }
    }

    var shortLabel: String {
        switch self {
        case .serverAuth: return "TLS Web Server Auth"
        case .clientAuth: return "TLS Web Client Auth"
        case .codeSigning: return "Code Signing"
        case .emailProtection: return "Email Protection"
        case .timeStamping: return "Time Stamping"
        case .ocspSigning: return "OCSP Signing"
        case .anyExtendedUsage: return "Any Extended Usage"
        }
    }

    var severity: SecurityWarning.SeverityLevel {
        switch self {
        case .serverAuth, .clientAuth, .emailProtection:
            return .info
        case .codeSigning, .timeStamping, .ocspSigning, .anyExtendedUsage:
            return .suspicious
        }
    }

    static func from(_ raw: String) -> ExtendedKeyUsageOID? {
        return Self(rawValue: raw)
    }
}

func parseEKUs(from rawString: String) -> [ParsedEKU] {
    let oids = rawString
        .split(separator: ",")
        .map { $0.trimmingCharacters(in: .whitespaces) }

    return oids.map {
        if let known = ExtendedKeyUsageOID.from($0) {
            return ParsedEKU(
                oid: $0,
                shortDescription: known.shortLabel,
                description: known.description,
                severity: known.severity
            )
        } else {
            return ParsedEKU(
                oid: $0,
                shortDescription: "Unknown Usage",
                description: "❓ Unknown EKU OID: \($0)",
                severity: .suspicious
            )
        }
    }
}
