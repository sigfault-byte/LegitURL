//  TLSExtract.swift
//  URLChecker
//
//  Created by Chief Hakka on 07/04/2025.
//
import Foundation
import ASN1Decoder
import ObjectiveC

struct TLSExtract {
    
    // URLSessionDelegate method for handling SSL challenges.
    // When an SSL challenge is received, this method simply accepts the server's certificate.
    // It logs the host for which the SSL challenge is being processed.
    func extract(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            print("❌ No valid server trust found.")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        var sslCertificateDetails: [String: Any] = [:]
        
        // ✅ Extract certificate details using ASN1Decoder
        if let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
           let firstCertificate = certificateChain.first {
            
            let certificateData = SecCertificateCopyData(firstCertificate) as Data
            
            if let decodedCertificate = try? X509Certificate(data: certificateData){
                
                sslCertificateDetails["Issuer"] = decodedCertificate.issuerDistinguishedName
                sslCertificateDetails["Issuer Organization"] = decodedCertificate.issuer(oid: .organizationName)
                sslCertificateDetails["Validity"] = [
                    "Not Before": decodedCertificate.notBefore,
                    "Not After": decodedCertificate.notAfter
                ]
                
                let parsedCert = ParsedCertificate(
                    commonName: decodedCertificate.subject(oid: .commonName)?.first,
                    organization: decodedCertificate.subject(oid: .organizationName)?.first,
                    issuerCommonName: decodedCertificate.issuer(oid: .commonName),
                    issuerOrganization: decodedCertificate.issuer(oid: .organizationName),
                    notBefore: decodedCertificate.notBefore,
                    notAfter: decodedCertificate.notAfter,
                    publicKeyAlgorithm: {
                        if let oid = decodedCertificate.publicKey?.algOid,
                           let named = OID(rawValue: oid) {
                            return "\(named)"
                        }
                        return decodedCertificate.publicKey?.algOid
                    }(),
                    keyUsage: decodedCertificate.keyUsage.enumerated().compactMap { index, isSet in
                        isSet ? ["Digital Signature", "Non-Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Cert Sign", "CRL Sign", "Encipher Only", "Decipher Only"][index] : nil
                    }.joined(separator: ", "),  // Convert Key Usage Bits
                    publicKeyBits: inferredPublicKeyBits(from: decodedCertificate),
                    extendedKeyUsageOID: decodedCertificate.extendedKeyUsage.joined(separator: ", "),
                    extendedKeyUsageString: parseEKUs(from: decodedCertificate.extendedKeyUsage.joined(separator: ", ")),
                    certificatePolicyOIDs: extractCertificatePolicyOIDs(from: decodedCertificate),
                    isSelfSigned: decodedCertificate.subjectDistinguishedName == decodedCertificate.issuerDistinguishedName,
                    subjectAlternativeNames: decodedCertificate.subjectAlternativeNames
                )
                sslCertificateDetails["ParsedCertificate"] = parsedCert
            } else {
                print("❌ Failed to decode certificate using ASN1Decoder")
            }
        }
        
        // ✅ Store extracted details globally
        HTTPResponseExtract.sharedInstance.sslCertificateDetails = sslCertificateDetails
        
        // Accept the SSL certificate, this is terrible but necessary
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
    
}

func inferredPublicKeyBits(from cert: X509Certificate) -> Int? {
    guard let algOID = cert.publicKey?.algOid,
          let keyOID = OID(rawValue: algOID) else { return nil }
    
    switch keyOID {
    case .rsaEncryption:
        if let keyByteCount = cert.publicKey?.key?.count {
            return keyByteCount * 8
        }
    case .ecPublicKey:
        guard let curveOID = cert.publicKey?.algParams else { return nil }
        switch curveOID {
        case OID.prime256v1.rawValue: return 256
            // coudnt find ECC alg in the library
        case "1.3.132.0.34": return 384  // secp384r1
        case "1.3.132.0.35": return 521  // secp521r1
        default: return nil
        }
    default:
        return nil
    }
    
    return nil
}

// Helper function to extract certificate policy OIDs from a decoded certificate
func extractCertificatePolicyOIDs(from decodedCertificate: X509Certificate) -> String {
    guard let certPoliciesExt = decodedCertificate.extensionObject(oid: OID.certificatePolicies)
            as? X509Certificate.CertificatePoliciesExtension else {
        return ""
    }
    
//    debug
//    for policy in certPoliciesExt.policies ?? [] {
//        print("Policy OID: \(policy.oid)")
//        for qualifier in policy.qualifiers ?? [] {
//            print("  ↪ Qualifier OID: \(qualifier.oid)")
//            print("  ↪ Qualifier Value: \(qualifier.value ?? "No value")")
//        }
//    }
    
    return certPoliciesExt.policies?.map { $0.oid }.joined(separator: ", ") ?? ""
}
