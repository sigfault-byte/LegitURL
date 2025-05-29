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
                                Text("`unsafe-inline` was added because more than 5 Inline scripts are in the page, using CSP nonce instead of 'unsafe-inline', paired with strict-dynamic if needed is recommended.")
                                    .font(.caption)
                                    .foregroundColor(.yellow)
                            case .dataUriDetected:
                                Text("data: URI script — should be avoided in secure environments.")
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
                    Text("Important: Each page load must generate a unique nonce. Script hashes are static but must exactly match the script content to ensure integrity.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Divider()
                    Text("Disclaimer: This script-src directive is a simplified example generated automatically. It may not suit complex websites or production environments yet.\nAlways review and tailor your CSP based on your site's actual script behavior.")
                        .font(.caption)
                        .foregroundColor(.orange)
                    Link("Consult Mozilla guide about CSP", destination: URL(string:"https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP")!)
                        .font(.footnote)
                        .foregroundColor(.blue)
                    }
                    .padding(.top, 8)
            }
            .padding()
        }
    }
}
