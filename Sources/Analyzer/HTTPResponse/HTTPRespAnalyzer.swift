import Foundation

struct HTTPRespAnalyzer {
    static func analyze(urlInfo: URLInfo) async -> URLInfo {
        
        var urlInfo = urlInfo
        
        let originalURL = urlInfo.components.fullURL ?? ""
        let urlOrigin = urlInfo.components.coreURL ?? ""
//        let domain = urlInfo.domain
//        let tld = urlInfo.tld
        
        // Retrieve OnlineURLInfo using the ID and guard for sanity check and sync mystery
        guard let onlineInfo = URLQueue.shared.onlineQueue.first(where: { $0.id == urlInfo.id }) else {
            var modified = urlInfo
            modified.warnings.append(SecurityWarning(
                message: "⚠️ No online analysis found for this URL. Analysis is halted.",
                severity: .critical,
                penalty: -100,
                url: urlInfo.components.coreURL ?? "",
                source: .getError
            ))
            return modified
        }
        
        //Should be Done in urlgGetExtract, in the meantime ill rawdog it here
        let finalURL = onlineInfo.finalRedirectURL ?? originalURL
        
        //TODO: Change normalized header to a more friendly logic so its acutally readable!
        
        let headers = onlineInfo.normalizedHeaders ?? [:]
        
        let cookies = GetAnalyzerUtils.extract(HeaderExtractionType.setCookie, from: headers)
        
        let responseCode = onlineInfo.serverResponseCode ?? 0
        
        // Precheck for scammy relative redirect
        if let locationHeader = headers["location"], !locationHeader.contains("://") {
            urlInfo.warnings.append(SecurityWarning(
            message: "🚨 The server redirected to a relative path starting with '\(locationHeader.prefix(16))...'. This is commonly used in scam kits or misconfigured servers. Analysis halted.",
                severity: .critical,
                penalty: -100,
                url: urlOrigin,
                source: .redirect
            ))
            return urlInfo
        }
        
        //Http response handler
        
        HandleHTTPResponse.cases(responseCode: responseCode, urlInfo: &urlInfo)
        if (300...399).contains(responseCode) {
            let redirectURL = URLComponentExtractor.extract(url: finalURL)
            RedirectAnalyzer.analyzeRedirect(toInfo: redirectURL, fromInfo: &urlInfo, responseCode: responseCode)
        }
        
        
        
        // Analyze body response Body first, returns "script" found in the html, if it's perfect
        // TODO : multi check the final url, there can be only one! -> we do not extract final url from the body for now... But we should!
        var findings: ScriptExtractionResult?
        if let rawbody = onlineInfo.responseBody,
           let contentType = headers["content-type"]?.lowercased(),
           let responseCode = onlineInfo.serverResponseCode {
            
            findings = HTMLAnalyzerFast.analyze(body: rawbody,
                                                contentType: contentType,
                                                responseCode: responseCode,
                                                origin: urlOrigin,
                                                domainAndTLD: urlInfo.domain! + "." + urlInfo.tld!,
                                                into: &urlInfo.warnings
            )
        }
        
        var scriptValueToCheck: ScriptSourceToMatchCSP? = nil
        if let result = findings, !result.scripts.isEmpty {
            if let rawbody = onlineInfo.responseBody {
                scriptValueToCheck = ScriptSecurityAnalyzer.analyze(scripts: result.scripts,
                                                                    body: rawbody,
                                                                    origin: urlOrigin,
                                                                    htmlRange: result.htmlRange,
                                                                    into: &urlInfo.warnings)
            }
        }
        
        
        //Then TLS
        
        
        if let tlsCertificate = onlineInfo.parsedCertificate {
            let domainAndTLD = [urlInfo.domain, urlInfo.tld].compactMap { $0 }.joined(separator: ".")
            let host = urlInfo.host ?? ""
            TLSCertificateAnalyzer.analyze(
                certificate: tlsCertificate,
                host: host,
                domain: domainAndTLD,
                warnings: &urlInfo.warnings,
                responseCode: responseCode,
                origin: urlOrigin
            )
        }
        
        //        Headers
        //        Cookie first
        CookiesAnalyzer.analyzeAll(from: cookies,
                                   httpResponseCode: responseCode,
                                   url: urlOrigin,
                                   urlInfo: &urlInfo)
        
        
        //  Analyze headers for content security policy
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
                penalty: PenaltySystem.Penalty.silentRedirect,
                url: urlOrigin,
                source: .header
            ))
        }
        return urlInfo
    }
}
