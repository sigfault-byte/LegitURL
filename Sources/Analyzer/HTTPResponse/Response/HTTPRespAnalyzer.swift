//
//  HTTPRespAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 16/03/2025.

import Foundation

struct HTTPRespAnalyzer {

    static func analyze(urlInfo: URLInfo) async -> (URLInfo, String?) {
        #if DEBUG
//        let start = Date()
        #endif
        var urlInfo = urlInfo
        var metaRefreshURL: String?
        let originalURL = urlInfo.components.fullURL ?? ""
        let urlOrigin = urlInfo.components.coreURL ?? ""
//        let domain = urlInfo.domain
//        let tld = urlInfo.tld
        
        // Retrieve OnlineURLInfo using the ID and guard for sanity check and sync mystery
        guard var onlineInfo = URLQueue.shared.onlineQueue.first(where: { $0.id == urlInfo.id }) else {
            var modified = urlInfo
            modified.warnings.append(SecurityWarning(
                message: "No online analysis found for this URL. Analysis is halted.",
                severity: .critical,
                penalty: -100,
                url: urlInfo.components.coreURL ?? "",
                source: .getError
            ))
            return (modified, nil)
        }
        
        
        
        //TODO: Change normalized header to a more friendly logic so its acutally readable!
        
        let headers = onlineInfo.normalizedHeaders ?? [:]
        
        let cookies = onlineInfo.extractedCookies ?? []
        
        let responseCode = onlineInfo.serverResponseCode ?? 0
        
        //Should be Done in urlgGetExtract, in the meantime ill rawdog it here
//        or maybe not. -> extract extracts, but cannot carry the logic ?? arrg
        var finalURL = originalURL
        if (300...399).contains(onlineInfo.serverResponseCode ?? 0),
           let redirectTarget = onlineInfo.finalRedirectURL {
            finalURL = redirectTarget
            
            // Detect query-only redirect attempts (e.g., ?m=1 added to the same path)
            let originalURLStripped = urlInfo.components.coreURL?.lowercased() ?? ""
            let redirectURLStripped = redirectTarget
            if originalURLStripped == redirectURLStripped && originalURL != redirectTarget {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Suspicious redirect with query-only difference.\nThe server may be withholding content unless specific query parameters are used.",
                    severity: .critical,
                    penalty: -100,
                    url: urlOrigin,
                    source: .redirect
                ))
            }
        }
        
        // Handle relative redirects: follow them, but flag as suspicious
        if let resolvedRelative = HTTPRespUtils.resolveRelativeRedirectIfNeeded(headers: headers, originalURL: originalURL) {
            finalURL = resolvedRelative
            let redirectURL = URLComponentExtractor.extract(url: resolvedRelative)
            RedirectAnalyzer.analyzeRedirect(toInfo: redirectURL, fromInfo: &urlInfo, responseCode: responseCode)
            urlInfo.warnings.append(SecurityWarning(
                message: "The server used a relative path redirect to '\(resolvedRelative)'. While technically valid, it's uncommon and sometimes used by phishing kits.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.redirectRelative,
                url: urlOrigin,
                source: .redirect
            ))
            onlineInfo.finalRedirectURL = resolvedRelative
        }
        
        // Double check for query-only redirection tricks (e.g., same domain, only ?m=1 added)
        let final = onlineInfo.finalRedirectURL
        let original = urlInfo.components.fullURL
        if final == original {
            urlInfo.warnings.append(SecurityWarning(
                message: "Repeated redirect with only query-string changes.\nThis looks like a cloaking pattern used by scam kits to withhold payload unless specific query parameters are present.",
                severity: .critical,
                penalty: -100,
                url: urlOrigin,
                source: .redirect
            ))
        }
        //Http response handler
        
        HandleHTTPResponse.cases(responseCode: responseCode, urlInfo: &urlInfo)
        if (300...399).contains(responseCode) {
            let redirectURL = URLComponentExtractor.extract(url: finalURL)
            RedirectAnalyzer.analyzeRedirect(toInfo: redirectURL, fromInfo: &urlInfo, responseCode: responseCode)
        }
        
        
        
        // Analyze body response Body first, returns "script" found in the html, if it's perfect
        // TODO: multi check the final url, there can be only one! -> we do not extract final url from the body for now... But we should!
        var findings: ScriptExtractionResult?
        var csp: Data?
        if let rawbody = onlineInfo.rawBody,
           let contentType = headers["content-type"]?.lowercased(),
           let responseCode = onlineInfo.serverResponseCode {
            
            (findings, csp, metaRefreshURL) = HTMLAnalyzerFast.analyze(body: rawbody,
                                                contentType: contentType,
                                                responseCode: responseCode,
                                                origin: urlOrigin,
                                                domainAndTLD: urlInfo.domain! + "." + urlInfo.tld!,
                                                into: &urlInfo.warnings
            )
            
            if metaRefreshURL != nil {
                urlInfo.warnings.append(SecurityWarning(
                    message: "HTML meta refresh, redirecting to: \(metaRefreshURL!)",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.metaRefreshInBody,
                    url: urlOrigin,
                    source: .redirect,
                    bitFlags: [.SLOPPY_DEVELOPMENT],
                ))
            }
        }
        
        print("==============")
        print(metaRefreshURL ?? "none")
        
        //TODO: Add the found CSP to the CSP analyszer
        if csp?.count ?? 0 > 0 {
            urlInfo.warnings.append(SecurityWarning(
                message: "CSP directives found in meta http-equiv, this is is not analyzed ( yet ) and ignored. Browsers might not honor them, or merge them with other CSP rules.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.metaCSP,
                url: urlOrigin,
                source: .body
            ))
        }
        //MARK: CSP META EQUIV
//        print("CSP META EQUIV: ", String(data: csp ?? Data(), encoding: .utf8))
        
        //TODO: Move the logic back to the extractor, it has nothing to do here.... How to mutate the warning within async extractor...?
        let maxBodyForUI: Int = 1_200_000
        let bodysize: Int = onlineInfo.rawBody?.count ?? 0
        onlineInfo.humanBodySize = bodysize
        bodysize > 120_000 ? onlineInfo.isBodyTooLarge = true : ()


        if let body = onlineInfo.rawBody {
            let slice = body.prefix(maxBodyForUI)

            //TODO: might need to use the encoding "detected" here for the <scrip> encoding in the script analysis, some script are not decoded properly. eg: societe.com
            let decodedText =
                String(data: slice, encoding: .utf8) ??
                String(data: slice, encoding: .isoLatin1) ??
                String(data: slice, encoding: .utf16)

            if let readable = decodedText {
                onlineInfo.humanReadableBody = readable
            } else {
                onlineInfo.humanReadableBody = "Response body could not be decoded (unknown encoding or corrupted data)."
            }

            if body.count > maxBodyForUI {
                onlineInfo.isBodyTooLarge = true
                urlInfo.warnings.append(SecurityWarning(
                    message: "Response body larger than 1.2MB. Display is truncated for safety.",
                    severity: .info,
                    penalty: 0,
                    url: urlOrigin,
                    source: .body
                ))
            }
        } else {
            onlineInfo.humanReadableBody = "No response body available."
        }
        
        
        var scriptValueToCheck: ScriptSourceToMatchCSP? = nil
        if var result = findings, !result.scripts.isEmpty {
            if let rawbody = onlineInfo.rawBody {
                scriptValueToCheck = ScriptSecurityAnalyzer.analyze(scripts: &result,
                                                                    body: rawbody,
                                                                    origin: urlOrigin,
                                                                    htmlRange: result.htmlRange,
                                                                    into: &urlInfo.warnings)
                findings = result // Sync mutated result back into findings LOCALE COPY ! ///LAST EDIT
//                let preview = ScriptToPreview.prepareScriptPreviews(for: result.scripts, body: rawbody)
//                onlineInfo.script4daUI = preview
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
                                   urlInfo: &urlInfo,
                                   onlineInfo: &onlineInfo)
        
        
//        print("REAL HEADERS: ")
//        for keyValue in headers {
//            print("\(keyValue.key): \(keyValue.value)")
//        }
        //  Analyze headers for content security policy
        var cspResult: ClassifiedCSPResult? = nil
        if responseCode == 200, metaRefreshURL == nil {
            let (warningsCSP, result) = CSPAnalyzer.analyze(headers,
                                                            httpEquivCSP: csp,
                                                            urlOrigin: urlOrigin,
                                                            scriptValueToCheck: scriptValueToCheck,
                                                            script: &findings)
            urlInfo.warnings.append(contentsOf: warningsCSP)
            cspResult = result
        }
        
        if let scritpsUIPreP = findings?.scripts, let rawBody = onlineInfo.rawBody {
            let preview = ScriptToPreview.prepareScriptPreviews(for: scritpsUIPreP, body: rawBody)
            onlineInfo.script4daUI = preview
        }
        
        
        // save if result was actually analyzed
        var structureCSP: [String: [Data: CSPValueType]] = [:]
        if let result = cspResult, !result.structuredCSP.isEmpty {
            onlineInfo.cspOfHeader = result
            structureCSP = result.structuredCSP
        }
        
        let headerWarnings = HeadersAnalyzer.analyze(responseHeaders: headers, urlOrigin: urlOrigin, responseCode: responseCode)
        urlInfo.warnings.append(contentsOf: headerWarnings)
        
        
        
        //TODO: This could work for the script-src, leeave disclaimer see if some people like it?
        if metaRefreshURL == nil, let findings = findings, let rawBody = onlineInfo.rawBody {
            onlineInfo.cspRecommendation = GenerateCSP.generate(from: findings, rawBody: rawBody)
        }
        
        //Rebuild headers for the view:
        HeaderRebuild.build(from: headers, cookies: cookies, StructuredCSP: structureCSP, onlineInfo: &onlineInfo)
        
        
        //  Detect silent redirect (200 OK but URL changed)
        let normalizedOriginalURL = originalURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let normalizedFinalURL = finalURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        
        // This shouldnt happen anymore, but in case it happens it's VERY BAD???
        if onlineInfo.serverResponseCode == 200, normalizedFinalURL != normalizedOriginalURL {
            urlInfo.warnings.append(SecurityWarning(
                message: "Hidden / Silent redirect detected.\nOriginal URL: \(originalURL)\nFinal URL: \(finalURL)\nThis is either very bad practice or a scam attempt.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.silentRedirect,
                url: urlOrigin,
                source: .header
            ))
        }
        
        // Syncronize the onlineInfo back into the singleotn
        if let index = URLQueue.shared.onlineQueue.firstIndex(where: { $0.id == onlineInfo.id }) {
            URLQueue.shared.onlineQueue[index] = onlineInfo
        }

        #if DEBUG
//        let end = Date()
//        let durationMS = end.timeIntervalSince(start) * 1000
//        print("Time taken: \(durationMS) ms, for a \(onlineInfo.rawBody?.count ?? 0) byte response body")
//        print("Number of script extracted and classified :", findings?.scripts.count ?? 0)
//        print("header analysis done, csp parsed")
        #endif
        return (urlInfo, metaRefreshURL)
    }
}
