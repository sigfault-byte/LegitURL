//
//  URLExctractComponents.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
//TODO: VERIFY PUNY CODE OF THE PASTED URL ASAP, AND DISCARD WITH WARNING ANYTHING THAT IS NOT REAL
//THERE IS NO SPOON
import Foundation
import Punycode

struct URLExtractComponents {
    /// Extracts components from a raw URL string and updates the global queue.
    static func extract(url: String) -> URLInfo {
        var warnings = [SecurityWarning]()
        
        // Validate URL is not empty
        guard !url.isEmpty else {
            warnings.append(SecurityWarning(
                message: "⚠️ Error parsing the URL",
                severity: .dangerous,
                url: nil
            ))
            return URLInfo(components: URLComponentsInfo(fullURL: url), warnings: warnings)
        }
        
        // Create URLComponents
        guard let components = URLComponents(string: url) else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to parse URL components",
                severity: .dangerous
            ))
            return URLInfo(components: URLComponentsInfo(fullURL: url), warnings: warnings)
        }
        
        // Extract and decode the host manually to handle punycode URLs
        let (preExtractedHost, decodedHost, encodedHost) = extractAndDecodeHost(from: url)
        
        // Build the initial URLComponentsInfo, prioritizing the manually decoded host
        var compInfo = URLComponentsInfo(
            fullURL: components.url?.absoluteString,
            scheme: components.scheme,
            userinfo: components.user,
            userPassword: components.password,
            host: decodedHost,
            punycodeHostDecoded: decodedHost,
            punycodeHostEncoded: encodedHost ?? preExtractedHost,
            port: components.port.map { "\($0)" },
            path: components.path.isEmpty ? "/" : components.path,
            pathEncoded: components.path.isEmpty ? nil : components.percentEncodedPath,
            query: components.query,
            rawQuery: components.percentEncodedQuery,
            fragment: components.fragment,
            rawFragment: components.percentEncodedFragment
        )
        
        // Validate host extraction and punycode encoding
        guard let host = compInfo.host else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to extract host from URL components",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
            return URLInfo(components: compInfo, warnings: warnings)
        }
        
        guard compInfo.punycodeHostEncoded != nil else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to encode host to punycode",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
            return URLInfo(components: compInfo, warnings: warnings)
        }
        
        // Validate host with a regex (per RFC 1035 & RFC 1123) using the ASCII punycode representation.
        let hostnameRegex = #"^(?:\[(?:[0-9A-Fa-f:]+)\]|(?:[0-9A-Fa-f:]+)|(?:\d{1,3}\.){3}\d{1,3}|(?:(?!-)[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*))$"#
        let hostToValidate = compInfo.punycodeHostEncoded ?? host
        if hostToValidate.range(of: hostnameRegex, options: .regularExpression) == nil {
            warnings.append(SecurityWarning(
                message: "⚠️ Host is malformed: \(host). No reason to analyze.",
                severity: .critical
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.critical
            return URLInfo(components: compInfo, warnings: warnings)
        }
        
        // Attempt extraction of domain and TLD into temporary optionals.
        var extractedDomain: String? = nil
        var extractedTLD: String? = nil

        if let result = DomainAndTLDExtract.extract(hostidnaEncoded: decodedHost) {
            extractedDomain = result.0
            extractedTLD = result.1
        } else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to identify Domain and TLD from the PSL",
                severity: .dangerous
            ))
            URLQueue.shared.LegitScore += PenaltySystem.Penalty.unrecognizedTLD
            return URLInfo(components: compInfo, warnings: warnings)
        }

        // Update compInfo with the extracted values (they remain optional as defined in compInfo)
        compInfo.extractedDomain = extractedDomain
        compInfo.idnaEncodedExtractedDomain = extractedDomain?.idnaEncoded
        compInfo.idnaDecodedExtractedDomain = extractedDomain?.idnaDecoded
        compInfo.extractedTLD = extractedTLD
        compInfo.punycodeEncodedExtractedTLD = extractedTLD?.idnaEncoded

        // if both domain and TLD are non-nil, compute the expected suffix for the subdomain extraction.
        if let domain = extractedDomain, let tld = extractedTLD {
            let expectedSuffix = "\(domain).\(tld)"
            
            if host.hasSuffix(expectedSuffix) {
                let subdomainPart = host.replacingOccurrences(of: expectedSuffix, with: "").trimmingCharacters(in: ["."])
                compInfo.subdomain = subdomainPart.isEmpty ? nil : subdomainPart
            }
        }
        return URLInfo(components: compInfo, warnings: warnings)
    }
    
    /// Extracts and decodes the host, ensuring we retain both the encoded and decoded forms.
    private static func extractAndDecodeHost(from url: String) -> (preExtractedHost: String?, decodedHost: String, encodedHost: String?) {
        guard let rawHost = URL(string: url)?.host else {
            return (nil, "", nil)
        }
        let decoded = rawHost.idnaDecoded ?? rawHost
        let encoded = decoded.idnaEncoded ?? decoded  // Ensure we always have an encoded form
        return (rawHost, decoded, encoded)
    }
}
