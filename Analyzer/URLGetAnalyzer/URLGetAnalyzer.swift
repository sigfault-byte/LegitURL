import Foundation

struct URLGetAnalyzer {
    static func analyze(urlInfo: inout URLInfo) {
        let originalURL = urlInfo.components.fullURL ?? ""
        let urlOrigin = urlInfo.components.host ?? ""
        
        // ✅ Retrieve OnlineURLInfo using the ID and guard for sanity check and sync mystery
        guard let onlineInfo = urlInfo.onlineInfo else {
            urlInfo.warnings.append(SecurityWarning(
                message: "⚠️ No online analysis found for this URL. Skipping further checks.",
                severity: .critical,
                url: urlOrigin,
                source: .onlineAnalysis
            ))
            return
        }

        //Should be Done in urlgGetExtract, in the meantime ill rawdog it here
        let finalURL = onlineInfo.finalRedirectURL ?? originalURL
        let headers = onlineInfo.normalizedHeaders ?? [:]
        let cookies = GetAnalyzerUtils.extract(HeaderExtractionType.setCookie, from: headers)
        let responseCode = onlineInfo.serverResponseCode ?? 0
        
        //Http response handler
        HandleHTTPResponse.cases(responseCode: responseCode, urlInfo: &urlInfo)
        

        // Analyze body response Body first
        // TODO : multi check the final url, there can be only one! -> we do not extract final url from the body for now
        if let rawbody = onlineInfo.responseBody,
           let contentType = headers["content-type"]?.lowercased(),
           let responseCode = onlineInfo.serverResponseCode {
            
            BodyAnalyzer.analyze(bodyData: rawbody,
                                 contentType: contentType,
                                 responseCode: responseCode,
                                 urlOrigin: urlOrigin,
                                 warnings: &urlInfo.warnings)
        }

//        Then TLS

        if let tlsCertificate = onlineInfo.parsedCertificate {
            let domainAndTLD = [urlInfo.domain, urlInfo.tld].compactMap { $0 }.joined(separator: ".")
            let host = urlInfo.host ?? ""
            TLSCertificateAnalyzer.analyze(certificate: tlsCertificate,
                                           host: host,
                                           domain: domainAndTLD,
                                           warnings: &urlInfo.warnings )
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
                url: urlOrigin,
                source: .onlineAnalysis
            ))
        }
    }
}
