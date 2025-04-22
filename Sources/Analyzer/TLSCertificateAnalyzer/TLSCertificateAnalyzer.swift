import Foundation

//🔍 Certificate Chain:
//→ All certificates in the chain are issued and signed by the same organization.
//→ This is common in large corporations (e.g. Google, Apple).
////→ While technically valid, it reduces third-party trust diversity. => not needed for now
//•    Chain depth / issuer-to-CN overlap (you’ve debated this — keep it optional/advanced)
//•    Custom certificate policies (you log them, and they’ll be useful down the line)
//•    Certificate transparency / OCSP (not offline-friendly but future ideas)

//Because TLS Certificate is both highly important and not important, its easy for folks to get a "good" certificate, with with strong keys.
//The only signal i see here, is the fresh certificate, the CN that is distributing certificate without seconds thoughts and
//the wildcard san where user can create content sharing the certificate

struct TLSCertificateAnalyzer {
//    tract tls accross the redirect chain to confirm heuristics or correct them
    
    static var tlsSANReusedMemory: [String: (domain: String, fingerprint: String)] = [:]
    static func resetMemory() {
        tlsSANReusedMemory.removeAll()
    }
    
    
    static func analyze(certificate: ParsedCertificate,
                        host: String,
                        domain: String,
                        warnings: inout [SecurityWarning],
                        responseCode: Int, origin: String) {
        
        if let existing = tlsSANReusedMemory[host],
           existing.fingerprint == certificate.fingerprintSHA256 {
            addWarning("TLS certificate for this host has already been analyzed (same fingerprint reused). Skipping redundant checks.", .info, penalty: 0)
            return // Already analyzed this certificate for this host
        }

        // Store the certificate fingerprint for potential comparison
        if let fingerprint = certificate.fingerprintSHA256 {
            tlsSANReusedMemory[host] = (domain: domain, fingerprint: fingerprint)
        }
        
        
        func addWarning(_ message: String, _ severity: SecurityWarning.SeverityLevel, penalty: Int, bitFlags: WarningFlags? = nil) {
            warnings.append(SecurityWarning(
                message: message,
                severity: severity,
                penalty: penalty,
                url: origin,
                source: .tls,
                bitFlags: bitFlags
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
            if let daysOld = Calendar.current.dateComponents([.day], from: notBefore, to: now).day {
                if daysOld <= 7 {
                    addWarning("TLS Certificate was issued very recently (\(daysOld) days ago) on \(TLSHeuristics.formattedDate(notBefore))", .suspicious, penalty: PenaltySystem.Penalty.tlsIsNew7days, bitFlags: WarningFlags.TLS_IS_FRESH)
                } else if daysOld <= 30 {
                    addWarning("TLS Certificate was issued recently (\(daysOld) days ago) on \(TLSHeuristics.formattedDate(notBefore))", .info, penalty: PenaltySystem.Penalty.tlsIsNew30days, bitFlags: WarningFlags.TLS_IS_FRESH)
                }
            }
            
            if let notAfter = certificate.notAfter {
                if let lifespan = Calendar.current.dateComponents([.day], from: notBefore, to: notAfter).day, lifespan <= 30 {
                    addWarning("TLS Certificate has an unusually short lifespan of \(lifespan) days", .suspicious, penalty: PenaltySystem.Penalty.tlsShortLifespan)
                }
            }
        }
        
        // 4. Key Strength
        if let keyBits = certificate.publicKeyBits,
           let algorithm = certificate.publicKeyAlgorithm?.lowercased() {
            
            if algorithm.contains("rsa") {
                if keyBits < 2048 {
                    addWarning("TLS Certificate uses a weak RSA key size of \(keyBits) bits", .dangerous, penalty: PenaltySystem.Penalty.tksWeakKey)
                } /*else if keyBits >= 4096 {*/
                //                    addWarning("TLS Certificate uses a strong RSA key size of \(keyBits) bits", .info, penalty: 0)
                //                }
                //            } else if algorithm.contains("ec") || algorithm.contains("ecdsa") {
                //                if keyBits < 256 {
                //                    addWarning("TLS Certificate uses a weak EC key (less than 256 bits)", .info, penalty: 0)
                //                } else if keyBits < 384 {
                //                    addWarning("TLS Certificate uses an EC key of \(keyBits) bits", .info, penalty: 0)
                //                } else {
                //                    addWarning("TLS Certificate uses a strong EC key of \(keyBits) bits", .info, penalty: 0)
                //                }
            }
        }
        
        // 5. Extended Key Usage
        if let ekuRaw = certificate.extendedKeyUsageOID {
            let ekuList = parseEKUs(from: ekuRaw)
            for eku in ekuList {
                let penalty: Int = eku.severity == .info ? 0 : PenaltySystem.Penalty.suspiciousPattern
                if penalty > 0 {
                    addWarning("Extended Key Usage: \(eku.description)", eku.severity, penalty: penalty)
                }
            }
            // Positive signal: EV or strong OV indication
            
            switch certificate.inferredValidationLevel {
            case .ev:
                addWarning("✅ Certificate is Extended Validation (EV)", .info, penalty: 10)
            case .ov:
                addWarning("✅ Certificate is Organization Validated (OV)", .info, penalty: 10)
            case .dv:
                addWarning("✅ Certificate is Domain Validated (DV)", .info, penalty: 0)
                //                This either need more digging into the shaddy world of CN, or womething was missed on the TLS logic
                //                if certificate.issuerCommonName == "WE1"{
                //                    // TODO: Replace with real labels and maybe a list of weird CN bulk giving tls
                //                    addWarning("✅ DV Cert issued by a Hotdogwater CN (WE1)", .info, penalty: PenaltySystem.Penalty.hotDogwaterCN)
                ////                    swift autocompletion proposed: Certificate is Domain Validated (DV) by a bullshit CA.
                //                }
                
                break // DV is the default, nothing to reward, on the contrary
            case .unknown:
                addWarning("✅ Certificate is not EV, OV or DV", .suspicious, penalty: -10)
                break
            }
        }
        
        // 6. SAN Quality Checks
        if let sans = certificate.subjectAlternativeNames {
            for entry in sans {
                let lower = entry.lowercased()
                if lower.hasSuffix(".local") ||
                    lower.hasPrefix("127.") ||
                    lower.hasPrefix("192.168.") ||
                    lower.hasPrefix("10.") ||
                    lower.hasPrefix("::1") ||
                    lower == "localhost" {
                    addWarning("SAN includes private/internal address: \(entry)", .suspicious, penalty: PenaltySystem.Penalty.suspiciousStatusCode)
                }
            }
        }
        
        // 7. SAN Overload Heuristic
//        Could parsed SANs for typosquatting in LegitURL 42.1
        let hasWildcard = sans.contains { $0.hasPrefix("*.")}
        if !hasWildcard {
            let normalizedHost = host.lowercased()
            let normalizedDomain = domain.lowercased()
            
            let matchedSANs = sans.filter { san in
                let normalizedSAN = san.lowercased()
                return normalizedSAN == normalizedHost || normalizedSAN == normalizedDomain
            }
            
            if matchedSANs.count == 1 && sans.count > 20 && !hasWildcard{
                switch certificate.inferredValidationLevel {
                case .dv:
                    addWarning("TLS Certificate includes \(sans.count) SANs, but only 1 matches the current domain — likely reused across unrelated infrastructure", .suspicious, penalty: PenaltySystem.Penalty.reusedTLS1FDQN)
                    // Save it for retroactive downgrade later
                    // tlsSANReusedMemory[host] = (domain: domain, fingerprint: certificate.fingerprintSHA256 ?? "unknown")
                    //            case .ov, .ev:
                    //                addWarning("TLS Certificate includes \(sans.count) SANs, only 1 matches the domain — allowed for OV/EV, but may indicate reuse", .info, penalty: 0)
                default:
                    break
                }
            }
        }

        // 8. Retroactive SAN Heuristic Reversal
        if let previous = tlsSANReusedMemory.first(where: { $0.value.domain == domain }),
           previous.value.fingerprint != certificate.fingerprintSHA256,
           certificate.inferredValidationLevel == .ev || sans.count <= 5 {
            addWarning("Previously flagged TLS certificate on this domain appeared suspicious, but was followed by a clean certificate (EV or low SAN count). Penalty waived.", .info, penalty: 20)
            tlsSANReusedMemory.removeValue(forKey: previous.key)
        }
    }
}
