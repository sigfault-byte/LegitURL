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
                        warnings: inout [SecurityWarning]) {
        
        // Apple URLSession in strict mode enforces it, but turning it off helps ID the various ssl problem that might occur
        guard let sans = certificate.subjectAlternativeNames, !sans.isEmpty else {
            warnings.append(SecurityWarning(
                message: "TLS certificate has no Subject Alternative Names",
                severity: .critical,
                url: host,
                source: .onlineAnalysis
            ))
            return
        }
        
        // Apple URLSession in strict mode enforces it, but turning it off helps ID the various ssl problem that might occur
        guard TLSHeuristics.domainIsCoveredBySANs(domain: domain, host: host, sans: sans) else {
            warnings.append(SecurityWarning(
                message: "TLS Certificate does not cover domain \(domain) or host \(host)",
                severity: .critical,
                url: host,
                source: .onlineAnalysis
            ))
            return
        }
        
        // Apple URLSession in strict mode enforces it, but turning it off helps ID the various ssl problem that might occur
        // Self-signed certificate check
        if certificate.isSelfSigned {
            warnings.append(SecurityWarning(
                message: "TLS Certificate is self-signed (not issued by a trusted Certificate Authority)",
                severity: .critical,
                url: host,
                source: .onlineAnalysis
            ))
        }
        // Apple URLSession in strict mode enforces the validty, but turning it off helps ID the various ssl problem that might occur
        // Certificate Expiration Analysis
        let now = Date()

        if let notAfter = certificate.notAfter {
            if notAfter < now {
                warnings.append(SecurityWarning(
                    message: "TLS Certificate expired on \(TLSHeuristics.formattedDate(notAfter))",
                    severity: .critical,
                    url: host,
                    source: .onlineAnalysis
                ))
            } else if Calendar.current.dateComponents([.day], from: now, to: notAfter).day ?? 0 <= 7 {
                warnings.append(SecurityWarning(
                    message: "TLS Certificate will expire soon on \(TLSHeuristics.formattedDate(notAfter))",
                    severity: .suspicious,
                    url: host,
                    source: .onlineAnalysis
                ))
            }
        }

        if let notBefore = certificate.notBefore {
            if let daysOld = Calendar.current.dateComponents([.day], from: notBefore, to: now).day, daysOld <= 1 {
                warnings.append(SecurityWarning(
                    message: "TLS Certificate was issued recently on \(TLSHeuristics.formattedDate(notBefore))",
                    severity: .info,
                    url: host,
                    source: .onlineAnalysis
                ))
            }

            if let notAfter = certificate.notAfter {
                if let lifespan = Calendar.current.dateComponents([.day], from: notBefore, to: notAfter).day, lifespan <= 30 {
                    warnings.append(SecurityWarning(
                        message: "TLS Certificate has an unusually short lifespan of \(lifespan) days",
                        severity: .suspicious,
                        url: host,
                        source: .onlineAnalysis
                    ))
                }
            }
        }

        // Public Key Strength Analysis
        if let keyBits = certificate.publicKeyBits,
           let algorithm = certificate.publicKeyAlgorithm?.lowercased() {

            if algorithm.contains("rsa") {
                if keyBits < 2048 {
                    warnings.append(SecurityWarning(
                        message: "TLS Certificate uses a weak RSA key size of \(keyBits) bits",
                        severity: .dangerous,
                        url: host,
                        source: .onlineAnalysis
                    ))
                } else if keyBits >= 4096 {
                    warnings.append(SecurityWarning(
                        message: "TLS Certificate uses a strong RSA key size of \(keyBits) bits",
                        severity: .info,
                        url: host,
                        source: .onlineAnalysis
                    ))
                }
            } else if algorithm.contains("ec") || algorithm.contains("ecdsa") {
                if keyBits < 256 {
                    warnings.append(SecurityWarning(
                        message: "TLS Certificate uses a weak EC key (less than 256 bits)",
                        severity: .info,
                        url: host,
                        source: .onlineAnalysis
                    ))
                } else if keyBits < 384 {
                        warnings.append(SecurityWarning(
                            message: "TLS Certificate uses an EC key of \(keyBits) bits",
                            severity: .info,
                            url: host,
                            source: .onlineAnalysis
                        ))
                    } else if keyBits >= 384 {
                    warnings.append(SecurityWarning(
                        message: "TLS Certificate uses a strong EC key of \(keyBits) bits",
                        severity: .info,
                        url: host,
                        source: .onlineAnalysis
                    ))
                }
            }
        }

        // Extended Key Usage Analysis
        if let ekuRaw = certificate.extendedKeyUsageOID {
            let ekuList = parseEKUs(from: ekuRaw)
            for eku in ekuList {
                warnings.append(SecurityWarning(
                    message: "Extended Key Usage: \(eku.description)",
                    severity: eku.severity,
                    url: host,
                    source: .onlineAnalysis
                ))
            }
        }

        if let policyOIDRaw = certificate.certificatePolicyOIDs {
            let rawOIDs = policyOIDRaw
                .split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }

            let policyResults = TLSHeuristics.classifyCertificatePolicyOIDs(rawOIDs)

            for (description, severity) in policyResults {
                warnings.append(SecurityWarning(
                    message: "Certificate Policy: \(description)",
                    severity: severity,
                    url: host,
                    source: .onlineAnalysis
                ))
            }
        }
    }
}
