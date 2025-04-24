//
//  RedirectAnalyzer.swift
//  URLChecker
//
//  Created by Chief Hakka on 25/03/2025.
//

import Foundation

struct RedirectAnalyzer {
    
    static func analyzeRedirect(toInfo: URLInfo, fromInfo: inout URLInfo, responseCode: Int? = nil) {
        let urlOrigin = fromInfo.components.coreURL ?? ""
        guard let originalDomain = fromInfo.domain?.lowercased(),
              let targetDomain = toInfo.domain?.lowercased(),
              let originalTLD = fromInfo.tld?.lowercased(),
              let targetTLD = toInfo.tld?.lowercased(),
              let originalHost = fromInfo.host?.lowercased(),
              let targetHost = toInfo.host?.lowercased(),
              let source: SecurityWarning.SourceType = {
                  if let responseCode = responseCode, (300...399).contains(responseCode) {
                      return .redirect
                  }
                  return .query
              }()
        else {
            fromInfo.warnings.append(SecurityWarning(
                message: "Missing or malformed domain, TLD, or host information for redirect: \(toInfo.components.fullURL ?? "Error no fullURL to display").",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: responseCode != nil ? .redirect : .query
            ))
            return
        }

        if originalDomain.lowercased() != targetDomain.lowercased() {
            fromInfo.warnings.append(SecurityWarning(
                message: "🚨 Redirect goes to a different domain: was \(originalDomain) now is \(targetDomain)",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.redirectToDifferentDomain,
                url: urlOrigin,
                source: source
            ))
            
        } else if originalTLD != targetTLD && originalDomain == targetDomain {
            fromInfo.warnings.append(SecurityWarning(
                message: "🚨 Redirect to a different TLD, was \(originalTLD) now is:\(targetTLD)",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.redirectToDifferentTLD,
                url: urlOrigin,
                source: source
            ))
            
        } else if originalHost != targetHost && originalDomain == targetDomain {
            fromInfo.warnings.append(SecurityWarning(
                message: "🔄 Internal redirect to different subdomain: \(targetHost)",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: source
            ))
        }
        else {
            fromInfo.warnings.append(SecurityWarning(
                message: "🔄 Internal redirect to same domain: \(targetHost)",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: source
            ))
        }
    }
}
