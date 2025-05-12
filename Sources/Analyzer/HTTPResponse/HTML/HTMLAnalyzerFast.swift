//  HTMLAnalyzerFast.swift
//  LegitURL
//
//  Created by Chief Hakka on ??/04/2025.
//
//TODO: Parse broken html to see wtf is going, this is not a priority, and just for fun byte parsing

import Foundation

struct HTMLAnalyzerFast {
    static func analyze(body: Data, contentType: String, responseCode: Int, origin: String, domainAndTLD: String, into warnings: inout [SecurityWarning]) -> (ScriptExtractionResult?, Data?) {
        guard responseCode == 200, contentType.contains("text/html") else { return (nil, nil) }
        let bodySize: Int = body.count
        let result = DataSignatures.extractHtmlTagRange(in: body)
        
        guard bodySize < 4_000_000 else {
            warnings.append(SecurityWarning(message: "Body too large for fast scan.", severity: .suspicious, penalty: -30 , url: origin, source: .body))
            
            return (nil, nil)
        }
        
        guard let (htmlRange, htmlClosed) = result else {
            print("IL EST PASE PAR ICI")
//            warnings.append(SecurityWarning(message: "No HTML found in response. Either the server is misconfigured, the dev are hotdogwater or it's a bad scam.",
            warnings.append(SecurityWarning(message: "No HTML structure detected in the response body. This is unexpected for a web page and may indicate a server issue or a malicious response.",
                                            severity: .critical,
                                            penalty: PenaltySystem.Penalty.critical,
                                            url: origin,
                                            source: .body,
                                            bitFlags: [.BODY_HTML_MALFORMED]
                                           ))
            return (nil, nil)
        }
        if htmlClosed == false {
//            warnings.append(SecurityWarning(message: "HTML appears malformed (missing </html> closing tag). This is common in scam kits or broken pages from hotdogwater devs.",
            warnings.append(SecurityWarning(message: "Missing closing </html> tag. This indicates a malformed HTML structure, which can be a sign of development errors or potentially malicious intent.",
                                            severity: .suspicious,
                                            penalty: PenaltySystem.Penalty.unclosedHTMLTag,
                                            url: origin,
                                            source: .body,
                                            bitFlags: [.BODY_HTML_MALFORMED]
                                           ))
        }
        
        let (scripts, metaSCP) = ScriptAndMetaExtractor.extract(body: body,
                                              origin: origin,
                                              domainAndTLD: domainAndTLD,
                                              htmlRange: htmlRange,
                                              warnings: &warnings)
        return (scripts, metaSCP)
    }
}

