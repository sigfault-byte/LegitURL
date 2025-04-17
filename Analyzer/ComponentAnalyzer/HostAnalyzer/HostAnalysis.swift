//
//  HostAnalysis.swift
//  URLChecker
//
//  Created by Chief Hakka on 22/03/2025.
//
import Foundation

struct HostAnalysis {
    
    static func analyze(urlObject: inout URLInfo) {
        let host = urlObject.components.host ?? ""
        let domainRoot = urlObject.components.extractedDomain ?? ""
        let tld = urlObject.components.extractedTLD ?? ""
        let subdomains: [String] = extractSubdomains(from: host, domain: domainRoot, tld: tld)
        
        if LegitURLTools.isIPv4(host) || LegitURLTools.isIPv6(host) {
            urlObject.warnings.append(SecurityWarning(
                message: "🚨 The host \(host) is an IP address.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlObject.components.coreURL!,
                source: .host
            ))
            return
        }
        
        // skip domain and tld analysis if it was already encoutered
        let shouldSkipDomainAnalysis: Bool = {
            guard let currentIndex = URLQueue.shared.offlineQueue.firstIndex(where: { $0.id == urlObject.id }),
                  currentIndex > 0 else { return false }

            let previous = URLQueue.shared.offlineQueue[currentIndex - 1]
            return previous.domain == domainRoot && previous.tld == tld
        }()

        if shouldSkipDomainAnalysis {
            urlObject.warnings.append(SecurityWarning(
                message: "Same domain and TLD as previous request, skipping domain and tld analysis",
                severity: .info,
                penalty: PenaltySystem.Penalty.informational,
                url: urlObject.components.coreURL!,
                source: .host
            ))
        } else {
            AnalyzeDomain.analyze(in: &urlObject, domain: domainRoot, tld: tld)
            AnalyzeTLD.analyze(tld, urlInfo: &urlObject)
        }
        
        AnalyzeSubdomains.analyze(urlInfo: &urlObject, subdomains: subdomains)
        
        // MARK: - Check for suspicious user info
        if let userInfo = urlObject.components.userinfo, !userInfo.isEmpty {
            urlObject.warnings.append(SecurityWarning(
                message: "🚨 URL contains user info '\(userInfo)'.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.userInfoInHost,
                url: urlObject.components.coreURL!,
                source: .host,
                bitFlags: WarningFlags.ABNORMAL_URL_STRUCTURE
            ))
        }
        
        if let password = urlObject.components.userPassword, !password.isEmpty {
            urlObject.warnings.append(SecurityWarning(
                message: "🚨 URL contains a password component.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlObject.components.coreURL!,
                source: .host
            ))
        }
        
        // MARK: - Check for non-standard ports
        if let port = urlObject.components.port {
            if port != "443" {
                urlObject.warnings.append(SecurityWarning(
                    message: "🚨 URL uses port :\(port), non-standard https.",
                    severity: .critical,
                    penalty: PenaltySystem.Penalty.critical,
                    url: urlObject.components.coreURL!,
                    source: .host
                ))
            }
        }
    }
}

private func extractSubdomains(from host: String, domain: String, tld: String) -> [String] {
    let domainWithTld = domain + "." + tld
    var subdomainPart = host
    guard host.count > domainWithTld.count + 1 else {
        return []
    }
    
    if host.hasSuffix(domainWithTld) {
        let endIndex = host.index(host.endIndex, offsetBy: -domainWithTld.count - 1) // -1 for the `.`
        subdomainPart = String(host[..<endIndex])
    }
    
    let subdomainsArray = subdomainPart.split(separator: ".").map(String.init)
    return subdomainsArray
}
