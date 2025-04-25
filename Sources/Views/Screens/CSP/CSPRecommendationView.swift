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
                    Text("Recommended CSP Header")
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
                    Text("✅ No critical findings. Good job!")
                        .font(.caption)
                        .foregroundColor(.green)
                        .padding(.vertical)
                }

                Text("Full CSP generation (img-src, frame-src, style-src) coming soon!")
                    .font(.footnote)
                    .foregroundColor(.gray)
                    .padding(.top, 8)
            }
            .padding()
        }
    }
}
