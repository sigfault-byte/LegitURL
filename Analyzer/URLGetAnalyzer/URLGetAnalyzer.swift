//
//  URLGetAnalyzer.swift
//  URLChecker
//
//  Created by Chief Hakka on 18/03/2025.
//

import Foundation

struct URLGetAnalyzer {
    static func analyze(urlInfo: inout URLInfo) {
        let originalURL = urlInfo.components.fullURL ?? ""
        
        // ✅ Retrieve OnlineURLInfo using the ID
        guard let onlineInfo = URLQueue.shared.onlineQueue.first(where: { $0.id == urlInfo.id }) else {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ No online analysis found for this URL. Skipping further checks.",
                severity: .info
            ))
            return
        }
        
        let finalURL = onlineInfo.finalRedirectURL ?? originalURL
        let headers = onlineInfo.responseHeaders ?? [:]

        // ✅ Call HTTP response handler using stored response code
        if let statusCode = onlineInfo.serverResponseCode {
            HandleHTTPResponse.cases(responseCode: statusCode, urlInfo: &urlInfo)
        }

        // ✅ Analyze headers for security
        analyzeHeaders(responseHeaders: headers, urlInfo: &urlInfo)

        // ✅ Detect silent redirect (200 OK but URL changed)
        let normalizedOriginalURL = originalURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let normalizedFinalURL = finalURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        if onlineInfo.serverResponseCode == 200, normalizedFinalURL != normalizedOriginalURL {
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 Hidden / Silent redirect detected.\nOriginal URL: \(originalURL)\nFinal URL: \(finalURL)\nThis is either bad practice or a scam attempt.",
                severity: .suspicious
            ))
        }
    }
    
    private static func analyzeHeaders(responseHeaders: [String: String], urlInfo: inout URLInfo) {
        checkMissingSecurityHeaders(responseHeaders: responseHeaders, urlInfo: &urlInfo)
        checkCookieSecurityFlags(responseHeaders: responseHeaders, urlInfo: &urlInfo)
        detectServerMisconfigurations(responseHeaders: responseHeaders, urlInfo: &urlInfo)
    }

    // ✅ **Function to check missing security headers**
    private static func checkMissingSecurityHeaders(responseHeaders: [String: String], urlInfo: inout URLInfo) {
        let securityHeaders: [String: String] = [
            "Strict-Transport-Security": "required",
            "Content-Security-Policy": "required",
            "X-Frame-Options": "required",
            "X-Content-Type-Options": "required",
            "Referrer-Policy": "recommended",
            "Set-Cookie": "check_flags"
        ]

        for (header, requirement) in securityHeaders {
            if responseHeaders[header] == nil {
                if requirement == "required" {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "🚨 Missing security header: \(header). This is a serious security issue.",
                        severity: .dangerous
                    ))
                } else if requirement == "recommended" {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ Recommended security header is missing: \(header).",
                        severity: .suspicious
                    ))
                }
            } else {
                let value = responseHeaders[header] ?? ""
                if header == "X-Frame-Options", value != "DENY" && value != "SAMEORIGIN" {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ X-Frame-Options has an unusual value: \(value). This could allow clickjacking.",
                        severity: .suspicious
                    ))
                }
                if header == "Strict-Transport-Security", !value.contains("max-age") {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "⚠️ HSTS header is present but missing `max-age` directive. This weakens its protection.",
                        severity: .suspicious
                    ))
                }
            }
        }
    }

    // ✅ **Function to check cookie security flags**
    private static func checkCookieSecurityFlags(responseHeaders: [String: String], urlInfo: inout URLInfo) {
        if let cookies = responseHeaders["Set-Cookie"] {
            let cookieValues = cookies.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
            if !cookieValues.contains("Secure") || !cookieValues.contains("HttpOnly") {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Cookie is missing Secure or HttpOnly flag: \(cookies). This could allow session hijacking.",
                    severity: .suspicious
                ))
            }

            // ✅ Check entropy of cookie value to detect randomness
            let (isHighEntropy, entropyValue) = LegitURLTools.isHighEntropy(cookies)
            if isHighEntropy {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ High entropy detected in Set-Cookie value (Entropy: \(String(format: "%.2f", entropyValue ?? 0))). This could indicate a session token or tracking ID.",
                    severity: .suspicious
                ))
            }
        }
    }

    // ✅ **Function to detect server misconfigurations**
    private static func detectServerMisconfigurations(responseHeaders: [String: String], urlInfo: inout URLInfo) {
        if let serverHeader = responseHeaders["Server"] {
            let outdatedIndicators = ["Apache/2.2", "PHP/5.3", "IIS/6.0"] // Example outdated versions
            for indicator in outdatedIndicators {
                if serverHeader.contains(indicator) {
                    urlInfo.warnings.append(SecurityWarning(
                        message: "🚨 Outdated server detected: \(serverHeader). This could be vulnerable to known exploits.",
                        severity: .dangerous
                    ))
                }
            }
        }

        // ✅ Check for verbose headers leaking too much info
        let verboseHeaders = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for verboseHeader in verboseHeaders {
            if let value = responseHeaders[verboseHeader] {
                urlInfo.warnings.append(SecurityWarning(
                    message: "⚠️ Verbose server information exposed in \(verboseHeader): \(value).",
                    severity: .suspicious
                ))
            }
        }

        // ✅ Check for potential Content-Type mismatches
        if let contentType = responseHeaders["Content-Type"] {
            let disallowedTypes = ["text/html", "application/javascript"]
            if disallowedTypes.contains(contentType), responseHeaders["Content-Disposition"]?.contains("attachment") == true {
                urlInfo.warnings.append(SecurityWarning(
                    message: "🚨 Content-Disposition set to 'attachment' for \(contentType). This could be an attempt to force a malicious download.",
                    severity: .critical
                ))
            }
        }
    }
}
