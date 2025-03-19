//
//  Untitled.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
import SwiftUI

struct URLComponentsListView: View {
    @ObservedObject var urlQueue: URLQueue
    
    var body: some View {
        NavigationLink(destination: URLListView(urlQueue: urlQueue)) {
            HStack {
                Text("🔍 URL Decomposition")
                    .font(.headline)
                    .bold()
                
                Spacer()
                
                Text("\(urlQueue.offlineQueue.count)")
                    .font(.subheadline)
                    .padding(6)
                    .background(Circle().fill(Color.blue.opacity(0.2)))
            }
            .padding()
            .background(Color.gray.opacity(0.1))
            .cornerRadius(8)
        }
        .buttonStyle(PlainButtonStyle())
    }
    
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
        
        var body: some View {
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    Text(urlInfo.components.fullURL ?? "Unknown URL")
                        .font(.title3)
                        .bold()
                    
                    Divider()
                    
                    if let scheme = urlInfo.components.scheme {
                        URLDetailRow(label: "Scheme", value: scheme, color: .green)
                    }
                    
                    if let userinfo = urlInfo.components.userinfo {
                        URLDetailRow(label: "User Info", value: userinfo, color: .red)
                    }
                    
                    if let password = urlInfo.components.userPassword {
                        URLDetailRow(label: "Password", value: password, color: .red)
                    }
                    
                    if let host = urlInfo.components.host {
                        URLDetailRow(label: "Host", value: host, color: .primary)
                    }
                    
                    if let punycodeHost = urlInfo.components.punycodeHostEncoded {
                        URLDetailRow(label: "Punycode Host", value: punycodeHost, color: .primary)
                    }
                    
                    if let tld = urlInfo.components.extractedTLD {
                        URLDetailRow(label: "TLD", value: tld, color: .blue)
                    }
                    
                    if let port = urlInfo.components.port {
                        URLDetailRow(label: "Port", value: port, color: .brown)
                    }
                    
                    if let path = urlInfo.components.path {
                        URLDetailRow(label: "Path", value: path, color: .orange)
                    }
                    
                    if let query = urlInfo.components.query {
                        URLDetailRow(label: "Query", value: query, color: .red)
                    }
                    
                    if let fragment = urlInfo.components.fragment {
                        URLDetailRow(label: "Fragment", value: fragment, color: .purple)
                    }
                    
                    if let onlineInfo = onlineInfo {
                        Divider()
                        
                        if let responseCode = onlineInfo.serverResponseCode {
                            URLDetailRow(label: "Server Response Code", value: "\(responseCode)")
                        }
                        
                        if let statusText = onlineInfo.statusText {
                            URLDetailRow(label: "Status Text", value: statusText)
                        }
                        
                        if let certAuth = onlineInfo.certificateAuthority {
                            URLDetailRow(label: "Certificate Authority", value: certAuth)
                        }
                        
                        URLDetailRow(label: "SSL Validity", value: onlineInfo.sslValidity ? "✅ Valid" : "❌ Invalid", color: onlineInfo.sslValidity ? .green : .red)
                        
                        if !onlineInfo.formattedHeaders.isEmpty {
                            NavigationLink(destination: URLFormattedView(title: "Response Headers", content: onlineInfo.formattedHeaders)) {
                                Text("🔍 View Response Headers")
                                    .foregroundColor(.blue)
                                    .padding(6)
                                    .background(Color(.systemGray5))
                                    .cornerRadius(6)
                            }
                            .padding(.vertical)
                        }
                        
                        if !onlineInfo.formattedBody.isEmpty {
                            NavigationLink(destination: URLFormattedView(title: "Response Body", content: onlineInfo.formattedBody)) {
                                Text("📄 View Response Body")
                                    .foregroundColor(.blue)
                                    .padding(6)
                                    .background(Color(.systemGray5))
                                    .cornerRadius(6)
                            }
                            .padding(.vertical)
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("URL Details")
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
    
    struct URLHeaderView: View {
        var headers: String
        
        var body: some View {
            ScrollView {
                Text(headers)
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(.systemGray5))
                    .cornerRadius(6)
            }
            .navigationTitle("Response Headers")
            .padding()
        }
    }
}

/// **Reusable Row for URL Components**
struct URLDetailRow: View {
    var label: String
    var value: String
    var color: Color = .primary
    
    var body: some View {
        HStack {
            Text("\(label):")
                .font(.subheadline)
                .foregroundColor(.gray)
            
            Text(value)
                .font(.footnote)
                .foregroundColor(color)
                .lineLimit(2)
                .truncationMode(.tail)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
