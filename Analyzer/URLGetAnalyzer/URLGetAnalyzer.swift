import Foundation

struct URLGetAnalyzer {
    static func analyze(urlInfo: inout URLInfo) {
        let originalURL = urlInfo.components.fullURL ?? ""
        let urlOrigin = urlInfo.components.host ?? ""
        
        // ✅ Retrieve OnlineURLInfo using the ID and guard for sanity check and sync mystery
        guard let onlineInfo = URLQueue.shared.onlineQueue.first(where: { $0.id == urlInfo.id }) else {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ No online analysis found for this URL. Skipping further checks.",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))
            return
        }
        
        let finalURL = onlineInfo.finalRedirectURL ?? originalURL
        let headers = onlineInfo.normalizedHeaders ?? [:]

        // Analyze body response
        if let rawbody = onlineInfo.responseBody,
           let contentType = headers["content-type"]?.lowercased(),
           let responseCode = onlineInfo.serverResponseCode {
            
            let bodyWarnings = BodyAnalyzer.analyze(bodyData: rawbody, contentType: contentType, responseCode: responseCode, urlOrigin: urlOrigin)
            urlInfo.warnings.append(contentsOf: bodyWarnings)
        }

        //  Analyze headers for security
        let headerWarnings = HeadersAnalyzer.analyze(responseHeaders: headers, urlOrigin: urlOrigin)
        urlInfo.warnings.append(contentsOf: headerWarnings)

        //  Detect silent redirect (200 OK but URL changed)
        let normalizedOriginalURL = originalURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let normalizedFinalURL = finalURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        // This shouldnt happen anymore, but in case it happens it's VERY BAD???
        if onlineInfo.serverResponseCode == 200, normalizedFinalURL != normalizedOriginalURL {
            urlInfo.warnings.append(SecurityWarning(
                message: "🚨 Hidden / Silent redirect detected.\nOriginal URL: \(originalURL)\nFinal URL: \(finalURL)\nThis is either bad practice or a scam attempt.",
                severity: .suspicious,
                url: urlOrigin,
                source: .onlineAnalysis
            ))
        }
    }
}
