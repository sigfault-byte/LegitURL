//
//  CSPRecommendationView.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//


import SwiftUI

struct CSPRecommendationView: View {
    let recommendation: CSPRecommendation

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Recommended script-src directive")
                        .font(.headline)
                    
                    Text(recommendation.cspHeader)
                        .font(.system(.body, design: .monospaced))
                        .padding()
                        .background(Color(.secondarySystemBackground))
                        .cornerRadius(8)
                        .contextMenu {
                            Button("Copy CSP to Clipboard") {
                                UIPasteboard.general.string = recommendation.cspHeader
                            }
                        }
                }
                .padding()
                .background(Color(.tertiarySystemBackground))
                .cornerRadius(12)

                if !recommendation.findings.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Warnings")
                            .font(.headline)
                        
                        ForEach(recommendation.findings, id: \.self) { finding in
                            switch finding {
                            case .unsafeInlineDetected:
                                Text("⚠️ Inline scripts detected — consider using a CSP nonce instead of 'unsafe-inline'.")
                                    .font(.caption)
                                    .foregroundColor(.yellow)
                            case .dataUriDetected:
                                Text("⚠️ data: URI script detected — dangerous in secure environments.")
                                    .font(.caption)
                                    .foregroundColor(.red)
                            }
                        }
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(12)
                } else {
                    Text("No critical findings.")
                        .font(.caption)
                        .foregroundColor(.green)
                        .padding(.vertical)
                }

                Text("Script-src CSP recommendation generated successfully.")
                    .font(.footnote)
                    .foregroundColor(.green)
                    .padding(.top, 8)
                
                Text("ℹ️ Note: CSP nonces must be dynamically generated for each HTTP response. Do not use a static or hardcoded nonce value. Use secure random generation.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.top, 4)
            }
            .padding()
        }
    }
}
