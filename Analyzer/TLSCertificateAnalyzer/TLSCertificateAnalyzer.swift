import Foundation


//🔍 Certificate Chain:
//→ All certificates in the chain are issued and signed by the same organization.
//→ This is common in large corporations (e.g. Google, Apple).
////→ While technically valid, it reduces third-party trust diversity. => not needed for now
//•    Chain depth / issuer-to-CN overlap (you’ve debated this — keep it optional/advanced)
//•    Custom certificate policies (you log them, and they’ll be useful down the line)
//•    Certificate transparency / OCSP (not offline-friendly but future ideas)

struct TLSCertificateAnalyzer {
    static func analyze(certificate: ParsedCertificate,
                        host: String,
                        domain: String,
                        warnings: inout [SecurityWarning],
                        responseCode: Int) {
        
        func addWarning(_ message: String, _ severity: SecurityWarning.SeverityLevel, penalty: Int) {
            warnings.append(SecurityWarning(
                message: message,
                severity: severity,
                penalty: penalty,
                url: host,
                source: .tls
            ))
        }

        // 1. Domain Coverage via SANs
        guard let sans = certificate.subjectAlternativeNames, !sans.isEmpty else {
            addWarning("TLS certificate has no Subject Alternative Names", .critical, penalty: PenaltySystem.Penalty.critical)
            return
        }

        guard TLSHeuristics.domainIsCoveredBySANs(domain: domain.lowercased(), host: host.lowercased(), sans: sans) else {
            addWarning("TLS Certificate does not cover domain \(domain) or host \(host)", .critical, penalty: PenaltySystem.Penalty.critical)
            return
        }

        // 2. Trust Anchor (Self-signed)
        if certificate.isSelfSigned {
            addWarning("TLS Certificate is self-signed (not issued by a trusted Certificate Authority)", .critical, penalty: PenaltySystem.Penalty.critical)
        }

        // 3. Expiry Window
        let now = Date()

        if let notAfter = certificate.notAfter {
            if notAfter < now {
                addWarning("TLS Certificate expired on \(TLSHeuristics.formattedDate(notAfter))", .critical, penalty: PenaltySystem.Penalty.critical)
            } else if Calendar.current.dateComponents([.day], from: now, to: notAfter).day ?? 0 <= 7 {
            } else if Calendar.current.dateComponents([.year], from: now, to: notAfter).year ?? 0 > 3 {
                addWarning("TLS Certificate expiry is more than 3 years away — unusual for DV certs", .suspicious, penalty: PenaltySystem.Penalty.suspiciousStatusCode)
            }
        }

        if let notBefore = certificate.notBefore {
            if let daysOld = Calendar.current.dateComponents([.day], from: notBefore, to: now).day, daysOld <= 1 {
                addWarning("TLS Certificate was issued recently on \(TLSHeuristics.formattedDate(notBefore))", .suspicious, penalty: PenaltySystem.Penalty.tlsIsNew)
            }

            if let notAfter = certificate.notAfter {
                if let lifespan = Calendar.current.dateComponents([.day], from: notBefore, to: notAfter).day, lifespan <= 30 {
                    addWarning("TLS Certificate has an unusually short lifespan of \(lifespan) days", .suspicious, penalty: PenaltySystem.Penalty.tlsShortLifespan )
                }
            }
        }

        // 4. Key Strength
        if let keyBits = certificate.publicKeyBits,
           let algorithm = certificate.publicKeyAlgorithm?.lowercased() {

            if algorithm.contains("rsa") {
                if keyBits < 2048 {
                    addWarning("TLS Certificate uses a weak RSA key size of \(keyBits) bits", .dangerous, penalty: PenaltySystem.Penalty.tksWeakKey)
                } else if keyBits >= 4096 {
                    addWarning("TLS Certificate uses a strong RSA key size of \(keyBits) bits", .info, penalty: 0)
                }
            } else if algorithm.contains("ec") || algorithm.contains("ecdsa") {
                if keyBits < 256 {
                    addWarning("TLS Certificate uses a weak EC key (less than 256 bits)", .info, penalty: 0)
                } else if keyBits < 384 {
                    addWarning("TLS Certificate uses an EC key of \(keyBits) bits", .info, penalty: 0)
                } else {
                    addWarning("TLS Certificate uses a strong EC key of \(keyBits) bits", .info, penalty: 0)
                }
            }
        }

        // 5. Extended Key Usage
        if let ekuRaw = certificate.extendedKeyUsageOID {
            let ekuList = parseEKUs(from: ekuRaw)
            for eku in ekuList {
                let penalty: Int = eku.severity == .info ? 0 : PenaltySystem.Penalty.suspiciousPattern
                addWarning("Extended Key Usage: \(eku.description)", eku.severity, penalty: penalty)
            }

            // Positive signal: EV or strong OV indication

            switch certificate.inferredValidationLevel {
            case .ev:
                addWarning("✅ Certificate is Extended Validation (EV)", .info, penalty: 10)
            case .ov:
                addWarning("✅ Certificate is Organization Validated (OV)", .info, penalty: 10)
            case .dv:
                addWarning("✅ Certificate is Domain Validated (DV)", .info, penalty: 0)
                if certificate.issuerCommonName == "WE1"{
                    // TODO: Replace with real label before release
                    addWarning("✅ DV Cert issued by a Hotdogwater CN (WE1)", .info, penalty: PenaltySystem.Penalty.hotDogwaterCN)
//                    swift autocompletion proposed: Certificate is Domain Validated (DV) by a bullshit CA.
                }
                    
                break // DV is the default, nothing to reward
            case .unknown:
                addWarning("✅ Certificate is not EV, OV or DV", .suspicious, penalty: 0)
                break
            }
        }

        // 6. SAN Quality Checks
        if let sans = certificate.subjectAlternativeNames {
            for entry in sans {
                if entry.contains(".local") || entry.contains("127.") || entry.contains("192.168.") || entry.contains("10.") {
                    addWarning("SAN includes private/internal address: \(entry)", .suspicious, penalty: PenaltySystem.Penalty.suspiciousStatusCode)
                }
            }
        }
    }
}
