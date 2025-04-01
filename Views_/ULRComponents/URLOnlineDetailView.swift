//
//  URLOnlineDetailView.swift
//  URLChecker
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

struct URLOnlineDetailView: View {
    var onlineInfo: OnlineURLInfo
    
    var body: some View {
        Group {
            if let responseCode = onlineInfo.serverResponseCode {
                URLDetailRow(label: "Server Response Code", value: "\(responseCode)")
            }
            if let statusText = onlineInfo.statusText {
                URLDetailRow(label: "Status Text", value: statusText)
            }
            if let finalRedirectURL = onlineInfo.finalRedirectURL {
                URLDetailRow(label: "Server redirects to:", value: finalRedirectURL)
            }
            URLDetailRow(label: "SSL Validity", value: onlineInfo.sslValidity ? "✅ Valid" : "❌ Invalid")
            if let cert = onlineInfo.parsedCertificate {
                NavigationLink(destination: URLCertificateDetailView(cert: cert)) {
                Text("View Certificate Details")
                }
            }
            if let parsedHeaders = onlineInfo.parsedHeaders {
                NavigationLink(destination: RawToFormated(title: "Response Headers", content: formatParsedHeaders(parsedHeaders))) {
                    Text("View Response Headers")
                }
            }
            if !onlineInfo.formattedBody.isEmpty {
                NavigationLink(destination: RawToFormated(title: "Response Body", content: onlineInfo.formattedBody)) {
                    Text("View Response Body")
                }
            }
        }
    }
}

private struct RawToFormated: View {
    var title: String
    var content: String
    
    var body: some View {
        List {
            Section {
                Text(content)
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(.primary)
                    .padding(.vertical, 8)
            }
        }
        .listStyle(InsetGroupedListStyle())
        .navigationTitle(title)
    }
}

private func formatParsedHeaders(_ headers: ParsedHeaders) -> String {
    var output = ""
    
    if !headers.securityHeaders.isEmpty {
        output += "🔒 **Security Headers**\n"
        for (key, value) in headers.securityHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    if !headers.trackingHeaders.isEmpty {
        output += "👁️ **Tracking Indicators**\n"
        for (key, value) in headers.trackingHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    if !headers.serverHeaders.isEmpty {
        output += "🖥 **Server Information**\n"
        for (key, value) in headers.serverHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    if !headers.otherHeaders.isEmpty {
        output += "📦 **Other Headers**\n"
        for (key, value) in headers.otherHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    return output.isEmpty ? "No Headers Available" : output
}
