import Foundation

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
        guard domainIsCoveredBySANs(domain: domain, host: host, sans: sans) else {
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
                    message: "TLS Certificate expired on \(formattedDate(notAfter))",
                    severity: .critical,
                    url: host,
                    source: .onlineAnalysis
                ))
            } else if Calendar.current.dateComponents([.day], from: now, to: notAfter).day ?? 0 <= 7 {
                warnings.append(SecurityWarning(
                    message: "TLS Certificate will expire soon on \(formattedDate(notAfter))",
                    severity: .suspicious,
                    url: host,
                    source: .onlineAnalysis
                ))
            }
        }

        if let notBefore = certificate.notBefore {
            if let daysOld = Calendar.current.dateComponents([.day], from: notBefore, to: now).day, daysOld <= 1 {
                warnings.append(SecurityWarning(
                    message: "TLS Certificate was issued recently on \(formattedDate(notBefore))",
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
                        severity: .suspicious,
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
                        severity: .suspicious,
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

        // Date formatter utility
        func formattedDate(_ date: Date) -> String {
            let formatter = DateFormatter()
            formatter.dateStyle = .medium
            formatter.timeStyle = .none
            return formatter.string(from: date)
        }
    }

    private static func domainIsCoveredBySANs(domain: String, host: String, sans: [String]) -> Bool {
        print("✅ Checking cert against domain: \(domain) and host: \(host)")

        // First try wildcard matches against the domain
        for san in sans {
            if san.hasPrefix("*.") {
                let base = san.dropFirst(2)
                if domain.hasSuffix(base) {
                    print("✅ Domain '\(domain)' matched wildcard SAN '\(san)'")
                    return true
                }
            }
        }
        // Fallback: try exact SAN match against the host
        for san in sans {
            if host == san {
                print("✅ Host '\(host)' matched exact SAN '\(san)'")
                return true
            }
        }

        print("❌ Neither domain '\(domain)' nor host '\(host)' matched any SAN")
        return false
    }
}
