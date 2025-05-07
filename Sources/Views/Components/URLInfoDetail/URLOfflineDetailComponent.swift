//
//  URLOfflineDetailView.swift
//  LegitURL
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

struct URLOfflineDetailComponent: View {
    var urlInfo: URLInfo
    
    @State var isPathExpanded: Bool = false
    @State var isQueryExpanded: Bool = false
    @State var isFragmentExpanded: Bool = false
    
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
            schemeRow,
            userInfoRow,
            userPasswordRow,
            hostRow,
            punycodeHostRow,
            tldRow,
            portRow,
            pathRow,
            queryRow,
            fragmentRow
        ].compactMap { $0 }
    }
    
    private var schemeRow: AnyView? {
        urlInfo.components.scheme.map { AnyView(URLDetailRow(label: "Scheme", value: $0)) }
    }
    
    private var userInfoRow: AnyView? {
        urlInfo.components.userinfo.map { AnyView(URLDetailRow(label: "User Info", value: $0)) }
    }
    
    private var userPasswordRow: AnyView? {
        urlInfo.components.userPassword.map { AnyView(URLDetailRow(label: "Password", value: $0)) }
    }
    
    private var hostRow: AnyView? {
        urlInfo.components.host.map { AnyView(URLDetailRow(label: "Host", value: $0)) }
    }
    
    private var punycodeHostRow: AnyView? {
        if urlInfo.components.host != urlInfo.components.punycodeHostEncoded {
            return urlInfo.components.punycodeHostEncoded.map { AnyView(URLDetailRow(label: "Punycode Host", value: $0)) }
        }
        return nil
    }
    
    private var tldRow: AnyView? {
        urlInfo.components.extractedTLD.map { AnyView(URLDetailRow(label: "TLD", value: $0)) }
    }
    
    private var portRow: AnyView? {
        urlInfo.components.port.map { AnyView(URLDetailRow(label: "Port", value: $0)) }
    }
    
    private var pathRow: AnyView? {
        urlInfo.components.path != "/" ? urlInfo.components.path.map {
            AnyView(
                URLDetailRow(label: "Path", value: isPathExpanded ? $0 : ($0.count > 40 ? "\($0.prefix(40))…" : $0))
                    .onTapGesture { withAnimation { isPathExpanded.toggle() } }
            )
        } : nil
    }
    
    private var queryRow: AnyView? {
        urlInfo.components.query.map {
            AnyView(
                URLDetailRow(label: "Query", value: isQueryExpanded ? $0 : ($0.count > 40 ? "\($0.prefix(40))…" : $0))
                    .onTapGesture { withAnimation { isQueryExpanded.toggle() } }
            )
        }
    }
    
    private var fragmentRow: AnyView? {
        urlInfo.components.fragment.map {
            AnyView(
                URLDetailRow(label: "Fragment", value: isFragmentExpanded ? $0 : ($0.count > 40 ? "\($0.prefix(40))…" : $0))
                    .onTapGesture { withAnimation { isFragmentExpanded.toggle() } }
            )
        }
    }
}
