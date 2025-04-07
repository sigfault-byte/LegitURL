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

struct GetAnalyzerUtils {
    static func extract(_ what: HeaderExtractionType, from headers: [String: String]) -> [String] {
        return headers.compactMap { key, value in
            return key.lowercased() == what.rawValue ? value : nil
        }
    }
}
