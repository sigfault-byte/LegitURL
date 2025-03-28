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
        let urlOrigin = urlInfo.components.host ?? ""
        
        switch statusCode {
        case 200:
            urlInfo.warnings.append(SecurityWarning(
                message: "✅ 200 OK: The request was successful.",
                severity: .info,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 201:
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 Received 201 Created on a GET request. This should NOT happen!",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 204:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 204 No Content: The server responded, but no data was returned.",
                severity: .suspicious,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 301, 302, 307:
            let finalURL = URLQueue.shared.onlineQueue.first(where: { $0.id == urlInfo.id })?.finalRedirectURL
            urlInfo.warnings.append(SecurityWarning(
                message: "🔄 Redirect detected (\(statusCode)): Moved to \(finalURL ?? "unknown").",
                severity: .suspicious,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 400:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 400 Bad Request: The server rejected the request. Possible request blocking or bad parameters.",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 401:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 401 Unauthorized: Authentication is required but was not provided.",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 403:
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 403 Forbidden: The server actively blocked the request. Possible firewall or access restriction.",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 404:
            urlInfo.warnings.append(SecurityWarning(
                message: "ℹ️ 404 Not Found: The requested page does not exist.",
                severity: .info,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 418:
            urlInfo.warnings.append(SecurityWarning(
                message: "🫖 418 I'm a Teapot: (Easter Egg in HTTP spec). No action needed.",
                severity: .info,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 429:
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ 429 Too Many Requests: Rate limiting detected.",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        case 500...599:
            urlInfo.warnings.append(SecurityWarning(
                message: "❌ Server error (\(statusCode)): The website may be misconfigured or down.",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))

        default:
            urlInfo.warnings.append(SecurityWarning(
                message: "ℹ️ Unhandled HTTP response (\(statusCode)).",
                severity: .info,
                url: urlOrigin,
                source: .onlineAnalysis
            ))
        }
    }
    
}
