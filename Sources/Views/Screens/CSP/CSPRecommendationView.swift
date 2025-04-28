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

                VStack(alignment: .leading, spacing: 6) {
                    Text("ℹ️ Important: Each page load must generate a unique nonce. Script hashes are static but must exactly match the script content to ensure integrity.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Divider()
                    Text("⚠️ Disclaimer: This script-src directive example is minimal. Your site may require custom allowances based on how your scripts behave. Always review and adapt CSPs for your real-world needs.")
                        .font(.caption)
                        .foregroundColor(.orange)
                    }
                    .padding(.top, 8)
            }
            .padding()
        }
    }
}
