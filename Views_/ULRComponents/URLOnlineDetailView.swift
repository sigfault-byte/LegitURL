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
            bodyNavigationLink(for: onlineInfo)
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

private struct RawToFormatedForHeavyBody: View {
    var title: String
    var content: String
    
    var body: some View {
        ScrollView {
            Text(content)
                .font(.system(size: 10, weight: .regular, design: .monospaced))
                .foregroundColor(.primary)
                .padding()
        }
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

private func bodyNavigationLink(for info: OnlineURLInfo) -> some View {
    Group {
        if let humanReadableBody = info.humanReadableBody, !humanReadableBody.isEmpty {
            let bodyView: some View = {
                let bodySize = info.humanBodySize ?? 0
                if bodySize > 150_000 {
                    return AnyView(RawToFormatedForHeavyBody(title: "Response Body", content: humanReadableBody))
                } else {
                    return AnyView(RawToFormated(title: "Response Body", content: humanReadableBody))
                }
            }()

            let bodySize = info.humanBodySize ?? 0
            let label: String = {
                if bodySize > 150_000 {
                    return "⚠️ Heavy Response Body (~\(bodySize / 1024) KB)"
                } else {
                    return "View Response Body"
                }
            }()

            NavigationLink(destination: bodyView) {
                Text(label)
            }
        }
    }
}
