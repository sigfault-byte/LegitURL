//
//  URLExctractComponents.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
//<<<<<------- THERE IS NO SPOON ----->>>>
import Foundation
import Punycode

struct URLComponentExtractor {
    /// Extracts components from a raw URL string and updates the global queue.
    static func extract(url: String) -> URLInfo {
        var warnings = [SecurityWarning]()
        
        // Validate URL is not empty
        guard !url.isEmpty else {
            warnings.append(SecurityWarning(
                message: "⚠️ Error parsing the URL",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: url,
                source: .host
            ))
            return URLInfo(components: URLComponentsInfo(fullURL: url), warnings: warnings)
        }
        
        // Create URLComponents
        guard let components = URLComponents(string: url) else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to parse URL components",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: url,
                source: .host
            ))
            return URLInfo(components: URLComponentsInfo(fullURL: url), warnings: warnings)
        }
        
        // Extract and decode the host manually to handle punycode URLs
        let (preExtractedHost, decodedHost, encodedHost) = extractAndDecodeHost(from: url)
        
        // Build the initial URLComponentsInfo, prioritizing the manually decoded host
        var compInfo = URLComponentsInfo(
            fullURL: components.url?.absoluteString,
            coreURL: decodedHost + (components.path.isEmpty ? "/" : components.path),
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
        
        // Detect double "?" or "#" which can break URLComponents. This is not RFC (3986??) compliant anyway
        let numQuestionMarks = url.filter { $0 == "?" }.count
        let numHashes = url.filter { $0 == "#" }.count
        
        if (compInfo.query == nil && numQuestionMarks > 1) || (compInfo.fragment == nil && numHashes > 1) {
            warnings.append(SecurityWarning(
                message: "Malformed URL with multiple '?' or '#' delimiters. May indicate obfuscated redirect or broken structure.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: url,
                source: .host
            ))
            return URLInfo(components: compInfo, warnings: warnings)
        }
        
        // Validate host extraction and punycode encoding
        guard let host = compInfo.host else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to extract host from URL components",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: components.url?.absoluteString ?? url,
                source: .host
            ))
            return URLInfo(components: compInfo, warnings: warnings)
        }
        
        guard compInfo.punycodeHostEncoded != nil else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to encode host to punycode",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: components.url?.absoluteString ?? "",
                source: .host
            ))
            return URLInfo(components: compInfo, warnings: warnings)
        }
        
        // Validate host with a regex (per RFC 1035 & RFC 1123) using the ASCII punycode representation.
        let hostnameRegex = #"^(?:\[(?:[0-9A-Fa-f:]+)\]|(?:[0-9A-Fa-f:]+)|(?:\d{1,3}\.){3}\d{1,3}|(?:(?!-)[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*))$"#
        let hostToValidate = compInfo.punycodeHostEncoded ?? host
        if hostToValidate.range(of: hostnameRegex, options: .regularExpression) == nil {
            warnings.append(SecurityWarning(
                message: "⚠️ Host is malformed: \(host).",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: components.url?.absoluteString ?? url,
                source: .host
            ))
            return URLInfo(components: compInfo, warnings: warnings)
        }
        
        // Attempt extraction of domain and TLD into temporary optionals.
        var extractedDomain: String? = nil
        var extractedTLD: String? = nil

        guard let extractionResult = DomainAndTLDExtractor.extract(hostidnaEncoded: encodedHost ?? preExtractedHost ?? "") else {
            warnings.append(SecurityWarning(
                message: "⚠️ Failed to identify Domain and TLD from the PSL",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: components.url?.absoluteString ?? "",
                source: .host
            ))
            return URLInfo(components: compInfo, warnings: warnings)
        }

        extractedDomain = extractionResult.0
        extractedTLD = extractionResult.1

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
        
        // Https check, before return so the offline extraction is done
        guard compInfo.scheme?.lowercased() == "https" else {
            warnings.append(SecurityWarning(
                message: "URL: \(url) is not using TLS encryption. \nAnalysis aborded",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: components.url?.absoluteString ?? "",
                source: .tls
            ))
            return URLInfo(components: compInfo, warnings: warnings)
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
