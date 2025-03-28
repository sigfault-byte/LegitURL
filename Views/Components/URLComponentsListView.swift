//
//  Untitled.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import SwiftUI
import Foundation

struct URLListView: View {
    @ObservedObject var urlQueue: URLQueue
    
    var body: some View {
        List {
            ForEach(urlQueue.offlineQueue) { urlInfo in
                NavigationLink(destination: URLDetailView(urlInfo: urlInfo, onlineInfo: urlQueue.onlineQueue.first(where: { $0.id == urlInfo.id }))) {
                    Text(urlInfo.components.fullURL ?? "Unknown URL")
                        .font(.footnote)
                        .foregroundColor(.blue)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }
        }
        .navigationTitle("URL List")
    }
}

struct URLDetailView: View {
    var urlInfo: URLInfo
    var onlineInfo: OnlineURLInfo?
    @State private var isExpanded = false
    @State private var isPathExpanded = false
    @State private var isQueryExpanded = false
    @State private var isFragmentExpanded = false
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                URLDetailHeaderView(isExpanded: $isExpanded, fullURL: urlInfo.components.fullURL)
                URLComponentSection(urlInfo: urlInfo, isPathExpanded: $isPathExpanded, isQueryExpanded: $isQueryExpanded, isFragmentExpanded: $isFragmentExpanded)
                
                if let onlineInfo = onlineInfo {
                    URLSSLSection(onlineInfo: onlineInfo)
                        .padding(.top, 12)
                }
            }
            .padding(.horizontal)
        }
        .background(Color(.systemGroupedBackground).ignoresSafeArea())
        .navigationTitle("URL Details")
    }
}

private struct URLDetailHeaderView: View {
    @Binding var isExpanded: Bool
    var fullURL: String?
    
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(isExpanded ? (fullURL ?? "Unknown URL") : (fullURL?.prefix(60) ?? "Unknown URL") + "…")
                .font(.callout)
                .foregroundColor(.secondary)
                .lineLimit(isExpanded ? nil : 1)
                .truncationMode(.tail)
                .onTapGesture {
                    withAnimation {
                        isExpanded.toggle()
                    }
                }
        }
    }
}

private struct URLComponentSection: View {
    var urlInfo: URLInfo
    @Binding var isPathExpanded: Bool
    @Binding var isQueryExpanded: Bool
    @Binding var isFragmentExpanded: Bool
    
    var body: some View {
        let rows: [AnyView] = [
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
        
        return VStack(alignment: .leading, spacing: 8) {
            ForEach(0..<rows.count, id: \.self) { index in
                rows[index]
                if index < rows.count - 1 {
                    iOSStyleDivider()
                }
            }
            
            if !urlInfo.components.lamaiTrees.isEmpty,
               urlInfo.components.lamaiTrees.flatMap(\.value).contains(where: { !$0.children.isEmpty }) {
                iOSStyleDivider()
                NavigationLink(destination: LamaiTreeViewComponent(lamaiTrees: urlInfo.components.lamaiTrees)) {
                    HStack {
                        Text("View Lamai Decoded Tree")
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundColor(.gray)
                    }
                    .foregroundColor(.primary)
                    .padding(.vertical, 8)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color(.separator), lineWidth: 0.5)
        )
        .padding(.vertical, 8)
    }
}

private struct URLSSLSection: View {
    var onlineInfo: OnlineURLInfo
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let responseCode = onlineInfo.serverResponseCode {
                URLDetailRow(label: "Server Response Code", value: "\(responseCode)")
                iOSStyleDivider()
            }
            
            if let statusText = onlineInfo.statusText {
                URLDetailRow(label: "Status Text", value: statusText)
                iOSStyleDivider()
            }
            
            if let finalRedirectURL = onlineInfo.finalRedirectURL {
                URLDetailRow(label: "Server redirects to:", value: finalRedirectURL)
                iOSStyleDivider()
            }
            
            URLDetailRow(label: "SSL Validity", value: onlineInfo.sslValidity ? "✅ Valid" : "❌ Invalid")
            iOSStyleDivider()
            
            if let cert = onlineInfo.parsedCertificate {
                NavigationLink(destination: URLCertificateDetailView(cert: cert)) {
                    HStack {
                        Text("View Certificate Details")
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundColor(.gray)
                    }
                    .foregroundColor(.primary)
                    .padding(.vertical, 8)
                }
                iOSStyleDivider()
            }
            
            if let parsedHeaders = onlineInfo.parsedHeaders {
                NavigationLink(destination: URLFormattedView(title: "Response Headers", content: formatParsedHeaders(parsedHeaders))) {
                    HStack {
                        Text("View Response Headers")
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundColor(.gray)
                    }
                    .foregroundColor(.primary)
                    .padding(.vertical, 8)
                }
                iOSStyleDivider()
            }
            
            if !onlineInfo.formattedBody.isEmpty {
                NavigationLink(destination: URLFormattedView(title: "Response Body", content: onlineInfo.formattedBody)) {
                    HStack {
                        Text("View Response Body")
                        Spacer()
                        Image(systemName: "chevron.right")
                            .foregroundColor(.gray)
                    }
                    .foregroundColor(.primary)
                    .padding(.vertical, 8)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(Color(.separator), lineWidth: 0.5)
        )
        .padding(.vertical, 8)
    }
}

struct URLFormattedView: View {
    var title: String
    var content: String
    
    var body: some View {
        ScrollView {
            Text(content)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(Color(.systemGray5))
                .cornerRadius(6)
        }
        .navigationTitle(title)
        .padding()
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

/// Thin iOS-style divider with leading inset
struct iOSStyleDivider: View {
    var body: some View {
        Divider()
            .padding(.leading, 16)
            .padding(.trailing, 0)
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
