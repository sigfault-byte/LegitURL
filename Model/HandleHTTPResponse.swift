//
//  HandleHTTPResponse.swift
//  URLChecker
//
//  Created by Chief Hakka on 18/03/2025.
//
import Foundation

struct HandleHTTPResponse {
    public static func cases(responseCode: Int, urlInfo: inout URLInfo) {
        let statusCode = responseCode
        let urlOrigin = urlInfo.components.coreURL ?? ""
        
        switch statusCode {
        case 200:
            urlInfo.warnings.append(SecurityWarning(
                message: "✅ 200 OK: The request was successful.",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: .responseCode
            ))

        case 201:
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 Received 201 Created on a GET request. This should NOT happen!",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .responseCode
            ))

        case 204:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 204 No Content: The server responded but returned no data.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.suspiciousStatusCode,
                url: urlOrigin,
                source: .responseCode
            ))

        case 301, 302, 307:
            let finalURL = URLQueue.shared.onlineQueue.first(where: { $0.id == urlInfo.id })?.finalRedirectURL
            urlInfo.warnings.append(SecurityWarning(
                message: "🔄 Redirect detected (\(statusCode)): Moved to \(finalURL ?? "unknown").",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: .responseCode
            ))

        case 400:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 400 Bad Request: Likely caused by stripped query parameters or incorrect format.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.suspiciousStatusCode,
                url: urlOrigin,
                source: .responseCode
            ))

        case 401:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 401 Unauthorized: Missing token or login redirect expected.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.suspiciousStatusCode,
                url: urlOrigin,
                source: .responseCode
            ))

        case 403:
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 403 Forbidden: Server actively blocked the request. Strong cloaking or access control signal.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.blockedByFirewall,
                url: urlOrigin,
                source: .responseCode
            ))

        case 404:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 404 Not Found: The requested core path doesn't exist. Possibly a disposable page.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.missConfiguredOrScam,
                url: urlOrigin,
                source: .responseCode
            ))

        case 418:
            urlInfo.warnings.append(SecurityWarning(
                message: "🫖 418 I'm a Teapot: Just vibes. No action needed. Please share the URL!",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: .responseCode
            ))

        case 429:
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 429 Too Many Requests: Rate limiting triggered from a single GET. Possibly aggressive filtering.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .responseCode
            ))

        case 500...599:
            urlInfo.warnings.append(SecurityWarning(
                message: "❌ Server error (\(statusCode)): Site may be broken or misconfigured.",
                severity: .critical,
                penalty: PenaltySystem.Penalty.serverError,
                url: urlOrigin,
                source: .responseCode
            ))

        default:
            urlInfo.warnings.append(SecurityWarning(
                message: "ℹ️ Unhandled HTTP response (\(statusCode)).",
                severity: .critical,
                penalty: PenaltySystem.Penalty.critical,
                url: urlOrigin,
                source: .responseCode
            ))
        }
    }
    
}
