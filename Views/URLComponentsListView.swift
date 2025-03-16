
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
                    URLDetailRow(label: "Scheme", value: scheme)
                }

                if let host = urlInfo.components.host {
                    URLDetailRow(label: "Host", value: host)
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

                    if let certAuth = onlineInfo.certificateAuthority {
                        URLDetailRow(label: "Certificate Authority", value: certAuth)
                    }

                    URLDetailRow(label: "SSL Validity", value: onlineInfo.sslValidity ? "✅ Valid" : "❌ Invalid", color: onlineInfo.sslValidity ? .green : .red)

                    if !onlineInfo.formattedHeaders.isEmpty {
                        NavigationLink(destination: URLHeaderView(headers: onlineInfo.formattedHeaders)) {
                            Text("🔍 View Response Headers")
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

struct URLComponentView: View {
    var urlInfo: URLInfo
    var onlineInfo: OnlineURLInfo?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {

            Text(urlInfo.components.fullURL ?? "Unknown URL")
                .font(.system(size: 12, weight: .bold)) // Slightly larger than components
                .foregroundColor(.primary)
                .textSelection(.disabled) // Prevents it from being detected as a link
                .multilineTextAlignment(.leading)

            VStack(alignment: .leading, spacing: 6) {
                if let scheme = urlInfo.components.scheme {
                    URLDetailRow(label: "Scheme", value: scheme)
                }

                if let userinfo = urlInfo.components.userinfo {
                    URLDetailRow(label: "User Info", value: userinfo)
                }

                if let password = urlInfo.components.userPassword {
                    URLDetailRow(label: "Password", value: password, color: .red)
                }

                if let host = urlInfo.components.host {
                    URLDetailRow(label: "Host", value: host)
                }

                if let punycodeHost = urlInfo.components.punycodeHostEncoded {
                    URLDetailRow(label: "Punycode Host", value: punycodeHost, color: .secondary)
                }

                if let port = urlInfo.components.port {
                    URLDetailRow(label: "Port", value: port)
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

                // ✅ Online Info
                if let onlineInfo = onlineInfo {
                    if let responseCode = onlineInfo.serverResponseCode {
                        URLDetailRow(label: "Server Response Code", value: "\(responseCode)")
                    }

                    if let certAuth = onlineInfo.certificateAuthority {
                        URLDetailRow(label: "Certificate Authority", value: certAuth)
                    }

                    URLDetailRow(label: "SSL Validity", value: onlineInfo.sslValidity ? "✅ Valid" : "❌ Invalid", color: onlineInfo.sslValidity ? .green : .red)
                    if !onlineInfo.formattedHeaders.isEmpty {
                        DisclosureGroup("🔍 Response Headers") {
                            ScrollView(.vertical, showsIndicators: true) {
                                Text(onlineInfo.formattedHeaders)
                                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                                    .padding()
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .background(Color(.systemGray5))
                                    .cornerRadius(6)
                            }
                            .frame(height: 100) // Adjust if needed
                        }
                        .font(.system(size: 12, weight: .bold))
                        .padding(.vertical, 4)
                    }
                }
            }
            .padding(.vertical, 6)
            .background(Color(.systemGray6))
            .cornerRadius(8)

            Spacer()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(10)
        .shadow(radius: 3)
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



//struct URLComponentsListView: View {
//    @ObservedObject var urlQueue: URLQueue
//    @State private var isExpanded = false // ✅ Controls list visibility
//    @State private var selectedURLId: UUID? = nil // ✅ Tracks selected URL
//
//    var body: some View {
//        VStack(alignment: .leading, spacing: 10) {
//            // ✅ Clickable header with count
//            Button(action: { isExpanded.toggle() }) {
//                HStack {
//                    Text("🔍 URL Decomposition")
//                        .font(.headline)
//                        .bold()
//
//                    Spacer()
//
//                    Text("\(urlQueue.offlineQueue.count)")
//                        .font(.subheadline)
//                        .padding(6)
//                        .background(Circle().fill(Color.blue.opacity(0.2)))
//                }
//                .padding()
//                .background(Color.gray.opacity(0.1))
//                .cornerRadius(8)
//            }
//            .buttonStyle(PlainButtonStyle())
//
//            // ✅ Expandable URL List
//            if isExpanded {
//                VStack {
//                    ForEach(urlQueue.offlineQueue) { urlInfo in
//                        let matchingOnlineInfo = urlQueue.onlineQueue.first(where: { $0.id == urlInfo.id })
//
//                        // ✅ Clickable URL row
//                        Button(action: {
//                            selectedURLId = (selectedURLId == urlInfo.id) ? nil : urlInfo.id
//                        }) {
//                            HStack {
//                                Text(urlInfo.components.fullURL ?? "Unknown URL")
//                                    .font(.footnote)
//                                    .foregroundColor(.blue)
//                                    .lineLimit(1)
//                                    .truncationMode(.tail)
//
//                                Spacer()
//
//                                Image(systemName: selectedURLId == urlInfo.id ? "chevron.up" : "chevron.down")
//                                    .foregroundColor(.gray)
//                            }
//                            .padding(.vertical, 4)
//                            .padding(.horizontal)
//                            .background(Color(.systemGray6))
//                            .cornerRadius(6)
//                        }
//                        .buttonStyle(PlainButtonStyle())
//
//                        // ✅ Expand URL details when selected
//                        if selectedURLId == urlInfo.id {
//                            URLComponentView(urlInfo: urlInfo, onlineInfo: matchingOnlineInfo)
//                                .padding(.horizontal)
//                                .frame(maxWidth: .infinity, alignment: .leading)
//                        }
//                    }
//                }
//                .padding(.top, 4)
//            }
//        }
//        .frame(maxWidth: .infinity, alignment: .leading)
//        .padding()
//    }
//}
//
//struct URLComponentView: View {
//    var urlInfo: URLInfo
//    var onlineInfo: OnlineURLInfo?
//
//    var body: some View {
//        VStack(alignment: .leading, spacing: 8) {
//
//            Text(urlInfo.components.fullURL ?? "Unknown URL")
//                .font(.system(size: 12, weight: .bold)) // Slightly larger than components
//                .foregroundColor(.primary)
//                .textSelection(.disabled) // Prevents it from being detected as a link
//                .multilineTextAlignment(.leading)
//
//            VStack(alignment: .leading, spacing: 6) {
//                if let scheme = urlInfo.components.scheme {
//                    URLDetailRow(label: "Scheme", value: scheme)
//                }
//
//                if let userinfo = urlInfo.components.userinfo {
//                    URLDetailRow(label: "User Info", value: userinfo)
//                }
//
//                if let password = urlInfo.components.userPassword {
//                    URLDetailRow(label: "Password", value: password, color: .red)
//                }
//
//                if let host = urlInfo.components.host {
//                    URLDetailRow(label: "Host", value: host)
//                }
//
//                if let punycodeHost = urlInfo.components.punycodeHostEncoded {
//                    URLDetailRow(label: "Punycode Host", value: punycodeHost, color: .secondary)
//                }
//
//                if let port = urlInfo.components.port {
//                    URLDetailRow(label: "Port", value: port)
//                }
//
//                if let path = urlInfo.components.path {
//                    URLDetailRow(label: "Path", value: path, color: .orange)
//                }
//
//                if let query = urlInfo.components.query {
//                    URLDetailRow(label: "Query", value: query, color: .red)
//                }
//
//                if let fragment = urlInfo.components.fragment {
//                    URLDetailRow(label: "Fragment", value: fragment, color: .purple)
//                }
//
//                // ✅ Online Info
//                if let onlineInfo = onlineInfo {
//                    if let responseCode = onlineInfo.serverResponseCode {
//                        URLDetailRow(label: "Server Response Code", value: "\(responseCode)")
//                    }
//
//                    if let certAuth = onlineInfo.certificateAuthority {
//                        URLDetailRow(label: "Certificate Authority", value: certAuth)
//                    }
//
//                    URLDetailRow(label: "SSL Validity", value: onlineInfo.sslValidity ? "✅ Valid" : "❌ Invalid", color: onlineInfo.sslValidity ? .green : .red)
//                    if !onlineInfo.formattedHeaders.isEmpty {
//                        DisclosureGroup("🔍 Response Headers") {
//                            ScrollView(.vertical, showsIndicators: true) {
//                                Text(onlineInfo.formattedHeaders)
//                                    .font(.system(size: 10, weight: .medium, design: .monospaced))
//                                    .padding()
//                                    .frame(maxWidth: .infinity, alignment: .leading)
//                                    .background(Color(.systemGray5))
//                                    .cornerRadius(6)
//                            }
//                            .frame(height: 100) // Adjust if needed
//                        }
//                        .font(.system(size: 12, weight: .bold))
//                        .padding(.vertical, 4)
//                    }
//                }
//            }
//            .padding(.vertical, 6)
//            .background(Color(.systemGray6))
//            .cornerRadius(8)
//
//            Spacer()
//        }
//        .frame(maxWidth: .infinity, alignment: .leading)
//        .padding()
//        .background(Color(.systemGray6))
//        .cornerRadius(10)
//        .shadow(radius: 3)
//    }
//}
//
///// **Reusable Row for URL Components**
//struct URLDetailRow: View {
//    var label: String
//    var value: String
//    var color: Color = .primary
//
//    var body: some View {
//        HStack {
//            Text("\(label):")
//                .font(.subheadline)
//                .foregroundColor(.gray)
//
//            Text(value)
//                .font(.footnote)
//                .foregroundColor(color)
//                .lineLimit(2)
//                .truncationMode(.tail)
//                .frame(maxWidth: .infinity, alignment: .leading)
//        }
//    }
//}
