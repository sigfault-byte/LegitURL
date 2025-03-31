//
//  Untitled.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import SwiftUI
import Foundation

struct URLDetailView: View {
    var urlInfo: URLInfo
    var onlineInfo: OnlineURLInfo?
    @State private var isExpanded = false
    @State private var isPathExpanded = false
    @State private var isQueryExpanded = false
    @State private var isFragmentExpanded = false
    
    var body: some View {
        List {
            Section(header: Text("FULL URL")) {
                URLDetailHeaderView(isExpanded: $isExpanded, fullURL: urlInfo.components.fullURL)
            }
            Section(header: Text("OFFLINE INFORMATION")) {
                URLComponentSection(urlInfo: urlInfo, isPathExpanded: $isPathExpanded, isQueryExpanded: $isQueryExpanded, isFragmentExpanded: $isFragmentExpanded)
            }
            if let onlineInfo = onlineInfo {
                Section(header: Text("ONLINE INFORMATION")) {
                    URLSSLSection(onlineInfo: onlineInfo)
                }
            }
        }
        .listStyle(InsetGroupedListStyle())
        .navigationTitle("URL Details")
        .navigationBarTitleDisplayMode(.inline)
    }
}

private struct URLDetailHeaderView: View {
    @Binding var isExpanded: Bool
    var fullURL: String?
    
    var body: some View {
        Text(isExpanded ? (fullURL ?? "Unknown URL") : truncatedURL)
            .font(.callout)
            .foregroundColor(.secondary)
            .lineLimit(isExpanded ? nil : 1)
            .truncationMode(.tail)
            .contentShape(Rectangle())
            .onTapGesture {
                withAnimation {
                    isExpanded.toggle()
                }
            }
    }
    
    private var truncatedURL: String {
        guard let fullURL = fullURL else { return "Unknown URL" }
        if fullURL.count > 60 {
            return fullURL.prefix(60) + "…"
        }
        return fullURL
    }
}

private struct URLComponentSection: View {
    var urlInfo: URLInfo
    @Binding var isPathExpanded: Bool
    @Binding var isQueryExpanded: Bool
    @Binding var isFragmentExpanded: Bool
    
    var body: some View {
        Group {
            ForEach(componentRows.indices, id: \.self) { index in
                componentRows[index]
            }
            if !urlInfo.components.lamaiTrees.isEmpty,
               urlInfo.components.lamaiTrees.flatMap(\.value).contains(where: { !$0.children.isEmpty }) {
                NavigationLink(destination: LamaiTreeViewComponent(lamaiTrees: urlInfo.components.lamaiTrees)) {
                    Text("View Lamai Decoded Tree")
                }
            }
        }
    }
    
    private var componentRows: [AnyView] {
        [
            urlInfo.components.scheme.map { AnyView(URLDetailRow(label: "Scheme", value: $0)) },
            urlInfo.components.userinfo.map { AnyView(URLDetailRow(label: "User Info", value: $0)) },
            urlInfo.components.userPassword.map { AnyView(URLDetailRow(label: "Password", value: $0)) },
            urlInfo.components.host.map { AnyView(URLDetailRow(label: "Host", value: $0)) },
            urlInfo.components.punycodeHostEncoded.map { AnyView(URLDetailRow(label: "Punycode Host", value: $0)) },
            urlInfo.components.extractedTLD.map { AnyView(URLDetailRow(label: "TLD", value: $0)) },
            urlInfo.components.port.map { AnyView(URLDetailRow(label: "Port", value: $0)) },
            (urlInfo.components.path != "/" ? urlInfo.components.path.map {
                AnyView(
                    URLDetailRow(label: "Path", value: isPathExpanded ? $0 : ($0.count > 40 ? "\($0.prefix(40))…" : $0))
                        .onTapGesture { withAnimation { isPathExpanded.toggle() } }
                )
            } : nil),
            urlInfo.components.query.map {
                AnyView(
                    URLDetailRow(label: "Query", value: isQueryExpanded ? $0 : ($0.count > 40 ? "\($0.prefix(40))…" : $0))
                        .onTapGesture { withAnimation { isQueryExpanded.toggle() } }
                )
            },
            urlInfo.components.fragment.map {
                AnyView(
                    URLDetailRow(label: "Fragment", value: isFragmentExpanded ? $0 : ($0.count > 40 ? "\($0.prefix(40))…" : $0))
                        .onTapGesture { withAnimation { isFragmentExpanded.toggle() } }
                )
            }
        ].compactMap { $0 }
    }
}

private struct URLSSLSection: View {
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
                NavigationLink(destination: URLFormattedView(title: "Response Headers", content: formatParsedHeaders(parsedHeaders))) {
                    Text("View Response Headers")
                }
            }
            if !onlineInfo.formattedBody.isEmpty {
                NavigationLink(destination: URLFormattedView(title: "Response Body", content: onlineInfo.formattedBody)) {
                    Text("View Response Body")
                }
            }
        }
    }
}

struct URLFormattedView: View {
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

/// **Reusable Row for URL Components**
struct URLDetailRow: View {
    var label: String
    var value: String
    
    var body: some View {
        if value.count > 50 {
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.body)
                    .foregroundColor(.primary)
                
                Text(value)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.leading)
                    .lineLimit(nil)
            }
            .padding(.vertical, 4)
        } else {
            HStack {
                Text(label)
                    .font(.body)
                    .foregroundColor(.primary)
                
                Spacer()
                
                Text(value)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.trailing)
                    .lineLimit(3)
            }
            .padding(.vertical, 4)
        }
    }
}

struct URLCertificateDetailView: View {
    var cert: ParsedCertificate
    
    var body: some View {
        List {
            Section(header: Text("Certificate Info")) {
                LabeledContent("Common Name", value: cert.commonName ?? "N/A")
                LabeledContent("Organization", value: cert.organization ?? "N/A")
                LabeledContent("Issuer CN", value: cert.issuerCommonName ?? "N/A")
                LabeledContent("Issuer Org", value: cert.issuerOrganization ?? "N/A")
                LabeledContent("Public Key", value: "\(cert.publicKeyAlgorithm ?? "N/A") (\(cert.publicKeyBits ?? 0) bits)")
                LabeledContent("Key Usage", value: cert.keyUsage ?? "N/A")
                LabeledContent("Extended Key Usage", value: cert.extendedKeyUsage ?? "N/A")
                LabeledContent("Valid From", value: cert.notBefore?.formatted() ?? "N/A")
                LabeledContent("Valid Until", value: cert.notAfter?.formatted() ?? "N/A")
                LabeledContent("Self-Signed", value: cert.isSelfSigned ? "Yes" : "No")
            }
        }
        .navigationTitle("Certificate")
    }
}
