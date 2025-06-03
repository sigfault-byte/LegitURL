//
//  URLInfoExtensions.swift
//  LegitURL
//
//  Created by Chief Hakka on 03/06/2025.
//
extension URLInfo {
    var domain: String? { components.extractedDomain }
    var tld: String? { components.extractedTLD }
    var host: String? { components.host }

    static var placeholder: URLInfo {
        URLInfo(
            components: URLComponentsInfo(fullURL: "https://placeholder.url"),
            warnings: []
        )
    }
}
