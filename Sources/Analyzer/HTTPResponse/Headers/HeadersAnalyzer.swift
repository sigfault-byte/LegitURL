//
//  HeadersAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 20/03/2025.
//
struct HeadersAnalyzer {
    static func analyze(responseHeaders: [String: String], urlOrigin: String, responseCode: Int) -> [SecurityWarning] {
        //        Only evaluate 200 code response, other repsponse need a different logic.
        //        particulary the 302 found common in scam and compromised CRM used as proxies
        guard responseCode == 200 else {
            return []
        }
        
        var warnings: [SecurityWarning] = []
        
        //hsts
        warnings.append(contentsOf: HeadersUtils.checkStrictTransportSecurity(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        // content type & content type otptions
        warnings.append(contentsOf: HeadersUtils.checkContentTypeOption(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        // content len, missing real content value to cross check
        warnings.append(contentsOf: HeadersUtils.checkContentLength(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        // cache control -> tricky part that d benefit from an exhaustive list of the cache control keys of known CDNs
//        TODO: cache Control
        //referer-policy
        warnings.append(contentsOf: HeadersUtils.checkReferrerPolicy(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        
        warnings.append(contentsOf: HeadersUtils.checkServerLeak(responseHeaders: responseHeaders, urlOrigin: urlOrigin))
        
        return warnings
    }
    
   
    
    
}
