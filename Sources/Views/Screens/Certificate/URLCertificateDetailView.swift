//
//  URLCertificateDetailView.swift
//  LegitURL
//
//  Created by Chief Hakka on 05/04/2025.
//
import SwiftUI

struct URLCertificateDetailView: View {
    var cert: ParsedCertificate
    
    var body: some View {
        List {
            Section(header: Text("Certificate Info")) {
                ForEach([
                    ("Main Certificate Policy", cert.mainCertificatePolicy),
//                    ("Validation Level", cert.inferredValidationLevel.rawValue),
                    ("Common Name", cert.commonName),
                    ("Organization", cert.organization),
                    ("Issuer CN", cert.issuerCommonName),
                    ("Issuer Org", cert.issuerOrganization),
                    ("Public Key", cert.publicKeyAlgorithm != nil && cert.publicKeyBits != nil ? "\(cert.publicKeyAlgorithm!) (\(cert.publicKeyBits!) bits)" : nil),
                    ("Key Usage", cert.keyUsage),
                    ("Extended Key Usage", cert.formattedEKU),
                    ("Valid From", cert.notBefore?.formatted()),
                    ("Valid Until", cert.notAfter?.formatted()),
                    ("Self-Signed", cert.isSelfSigned ? "Yes" : nil),
                    ("SANs (\(cert.subjectAlternativeNames?.count ?? 0))", cert.subjectAlternativeNames?.joined(separator: "\n"))
                ].compactMap { label, value in
                    value.map { (label, $0) }
                }, id: \.0) { label, value in
                    LabeledContent(label, value: value)
                }
                .navigationTitle("Certificate")
            }
        }
    }
}
