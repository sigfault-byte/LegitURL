import Foundation

struct BodyAnalyzerFast {
    static func analyze(body: Data, contentType: String, responseCode: Int, origin: String, domainAndTLD: String, into warnings: inout [SecurityWarning]) -> ScriptExtractionResult? {
        guard responseCode == 200, contentType.contains("text/html") else { return nil }
        let bodySize: Int = body.count
        let htmlRange = DataSignatures.extractHtmlTagRange(in: body)
        guard let htmlRange else {
            warnings.append(SecurityWarning(message: "No HTML found in response. Either the server is misconfigured, the dev are hotdogwater or it's a bad scam.",
                                            severity: .critical,
                                            penalty: PenaltySystem.Penalty.critical,
                                            url: origin,
                                            source: .body))
            return nil
        }
        if bodySize > 900_000 {
            warnings.append(SecurityWarning(message: "Body too large for fast scan.", severity: .info, penalty: 0, url: origin, source: .body))
            return nil
        }
        else {
            
            let scripts = ScriptExtractor.extract(body: body,
                                    origin: origin,
                                    domainAndTLD: domainAndTLD,
                                    htmlRange: htmlRange,
                                    warnings: &warnings)
            return scripts
        }
    }
}
