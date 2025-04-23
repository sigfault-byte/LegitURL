//
//  GetAnalyzerUtils.swift
//  URLChecker
//
//  Created by Chief Hakka on 07/04/2025.
//

import Foundation

enum HeaderExtractionType: String {
    case setCookie = "set-cookie"
    case contentSecurityPolicy = "content-security-policy"
    case location = "location"
    // Add more if needed
}

struct HTTPRespUtils {
    static func extract(_ what: HeaderExtractionType, from headers: [String: String]) -> [String] {
        return headers.compactMap { key, value in
            return key.lowercased() == what.rawValue ? value : nil
        }
    }
    
    //resolving relative redirect. This sucks a little bit
    public static func resolveRelativeRedirectIfNeeded(headers: [String: String], originalURL: String) -> String? {
        guard let locationHeader = headers["location"],
              !locationHeader.contains("://"),
              let baseURL = URL(string: originalURL),
              let resolved = URL(string: locationHeader, relativeTo: baseURL)?.absoluteString else {
            return nil
        }
        return resolved
    }
}
