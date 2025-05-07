//  URLOnlineDetailView.swift
//  LegitURL
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

struct URLOnlineDetailComponent: View {
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
            if let cert = onlineInfo.parsedCertificate {
                NavigationLink(destination: URLCertificateDetailView(cert: cert)) {
                Text("Certificate")
                }
            }
            bodyNavigationLink(for: onlineInfo)
            if let parsedHeaders = onlineInfo.parsedHeaders {
                NavigationLink(destination: RawToFormated(title: "Response Headers", content: formatParsedHeaders(parsedHeaders))) {
                    Text("Response Headers")
                }
            }
            if let cspOfHeader = onlineInfo.cspOfHeader {
                NavigationLink(destination: CSPInspectorView(csp: cspOfHeader)){
                    Text(cspOfHeader.source == "CSP" ? "Content-Security-Policy" : "Content-Security-Policy-Report-Only")
                }
            }
            
            let cookies = onlineInfo.cookiesForUI.compactMap { $0 }
            if !cookies.isEmpty {
                NavigationLink(destination: CookieListView(cookies: cookies)) {
                    Text("Cookies (\(cookies.count))")
                }
            }
            
            let script4UI = onlineInfo.script4daUI
            if !script4UI.isEmpty {
                NavigationLink(destination: HotDogWaterView(previews: script4UI)){
                    Text("Scripts (\(script4UI.count))")
                }
            }
        }
    }
}


/// Need to find how to safely protects this against massive body content
private func bodyNavigationLink(for info: OnlineURLInfo) -> some View {
    Group {
        if let humanReadableBody = info.humanReadableBody, !humanReadableBody.isEmpty {
            let bodySizeKB = (info.humanBodySize ?? 0) / 1024
            let isHeavyBody = info.isBodyTooLarge
            
            NavigationLink(
                destination: {
                    if isHeavyBody {
                        RawToFormatedForHeavyBody(title: "Response Body", content: humanReadableBody)
                    } else {
                        RawToFormated(title: "Response Body", content: humanReadableBody)
                    }
                },
                label: {
                    Text(isHeavyBody ? "Heavy Response Body (⚠️~\(bodySizeKB) KB)" : "Response Body")
                }
            )
        }
    }
}

private struct RawToFormated: View {
    var title: String
    var content: String
    @State private var copied = false

    var body: some View {
        List {
            Section {
                Text(content)
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(.primary)
                    .padding(.vertical, 8)

                Button(action: {
                    UIPasteboard.general.string = content
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                        copied = false
                    }
                }) {
                    Label(copied ? "Copied!" : "Copy", systemImage: copied ? "checkmark.circle.fill" : "doc.on.doc")
                }
                .buttonStyle(.bordered)
                .foregroundColor(copied ? .green : .blue)
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
            TextEditor(text: .constant(content))
                .font(.system(size: 10, weight: .regular, design: .monospaced))
                .foregroundColor(.primary)
                .padding()
                .frame(minHeight: 400)
                .background(Color(.systemBackground))
                .navigationTitle(title)
    }
}

private func formatParsedHeaders(_ headers: ParsedHeaders) -> String {
    var output = ""
    
    if !headers.securityHeaders.isEmpty {
        output += "**Security Headers**\n"
        for (key, value) in headers.securityHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    if !headers.trackingHeaders.isEmpty {
        output += "**Tracking**\n"
        for (key, value) in headers.trackingHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    if !headers.serverHeaders.isEmpty {
        output += "**Server Information**\n"
        for (key, value) in headers.serverHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    if !headers.otherHeaders.isEmpty {
        output += "**Other Headers**\n"
        for (key, value) in headers.otherHeaders {
            output += "- \(key): \(value)\n"
        }
        output += "\n"
    }
    
    return output.isEmpty ? "No Headers Available" : output
}
