//
//  GenerateJSON.swift
//  LegitURL
//
//  Created by Chief Hakka on 27/05/2025.
//
//  Created to generate a compact, high-signal structured JSON object from URLQueue analysis results

import Foundation

func generateLLMJson(from queue: URLQueue) throws -> [Data] {
    
    //Date formatter
    let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime] // outputs full `T` + `Z` format <3 chef kiff
        return formatter
    }()
    
    //Early guard for undefined weird quirk
    guard let first = queue.offlineQueue.first,
          let last = queue.offlineQueue.last else {
        throw NSError(domain: "Invalid queue", code: -1)
    }
    
    //Main jason object
    var finalOutput: [[String: Any]] = []
    
    //priming the model
    let prime: [String: Any] = ["Instructions": LLMPriming.instructions]
    finalOutput.append(prime)
    
    //summary of the following JSON
    let inputURL = first.components.fullURL ?? "-"
    let finalURL = last.components.fullURL ?? "-"
    let score = String(queue.legitScore.score)
    let hopCount = String(queue.offlineQueue.count - 1)
    let criticalWarnings = URLQueue.shared.offlineQueue
        .flatMap { $0.warnings }
        .filter { $0.severity == .critical || $0.severity == .fetchError }
    
    let summary: [String : Any] = ["Summary" : [
        "01_input url" : inputURL,
        "02_final url" : finalURL,
        "03_score" : score,
        "04_number_of_redirect" : hopCount, //This needs to be prime that its the number of urls report
        "05_critical_warnings" : criticalWarnings.isEmpty ? criticalWarnings : "none"
    ]]
    finalOutput.append(summary)
    
    // Loop URLs
    var scriptAppendices: [[String: Any]] = []
    for (index, urlReport) in queue.offlineQueue.enumerated() {
        
        //Offline element
        //shorthand
        let components = urlReport.components
        
        //Offline Var
        let domain = components.extractedDomain ?? "-"
        let tld = components.extractedTLD ?? "-"
        let subdomain = components.subdomain ?? "-"
        let path = components.path ?? "-"
        let query = components.query ?? "-"
        let fragment = components.fragment ?? "-"
        let punycode = components.punycodeHostEncoded ?? "_"
        //Offline findings
        let relevantOffline: [SecurityWarning.SourceType] = [.host, .path, .fragment, .query]
        let sectionWarningsOffline = urlReport.warnings.filter { relevantOffline.contains($0.source) }
        var findings : [Any] = []
        if !sectionWarningsOffline.isEmpty {
            
            for (index, warning) in sectionWarningsOffline.enumerated() {
                findings.append(["finding-\(index) in \(warning.source)" : ["\(warning.severity), \(warning.message)", "penalty: \(warning.penalty)"]])
            }
        }
        
        var reportContent: [String: Any] = [
            "01_FullURL" : urlReport.components.fullURL ?? "",
            "02_domain" : domain,
            "03_tld" : tld,
            "04_subdomain" : subdomain,
            "05_path" : path,
            "06_query" : query,
            "07_fragment" : fragment,
            "08_punycoded_host" : punycode,
            "09_findings" : findings.isEmpty ? "none" : findings
        ]
        
        // Online Var
        //HTTP response code
        let onlineMap = Dictionary(uniqueKeysWithValues: queue.onlineQueue.map { ($0.id, $0) })
        if let online = onlineMap[urlReport.id] {
            reportContent["10_requested_URL"] = components.coreURL ?? ""
            if let code = online.serverResponseCode {
                reportContent["11_response_code"] = code
            }
            if let status = online.statusText {
                reportContent["12_status_text"] = status
            }
            if let finalRedirect = online.finalRedirectURL {
                reportContent["13_final_redirect"] = finalRedirect
            }
            //TLS
            if let cert = online.parsedCertificate {
                if let issuerCommonName = cert.issuerCommonName {
                    reportContent["14_issuer_common_name"] = issuerCommonName
                }
                if let certificatePolicyOIDs = cert.certificatePolicyOIDs {
                    reportContent["15_certificate_policy_oids"] = certificatePolicyOIDs
                }
                if let notBefore = cert.notBefore {
                    reportContent["16_not_before"] = formatter.string(from: notBefore)
                }
                if let notAfter = cert.notAfter {
                    reportContent["17_not_after"] = formatter.string(from: notAfter)
                }
                if let subjectAlternativeNames = cert.subjectAlternativeNames {
                    reportContent["18_number_of_san"] = subjectAlternativeNames.count
                }
                //findings for response code and tls
                let relevantResponseTLS: [SecurityWarning.SourceType] = [.tls, .redirect, .responseCode]
                let sectionWarningsResponseTLS = urlReport.warnings.filter { relevantResponseTLS.contains($0.source) }
                var findings : [Any] = []
                if !sectionWarningsResponseTLS.isEmpty {
                    for (index, warning) in sectionWarningsResponseTLS.enumerated() {
                        findings.append(["finding-\(index) in \(warning.source)" : ["\(warning.severity), \(warning.message)", "penalty: \(warning.penalty)"]])
                    }
                }
                reportContent["19_tls_responsecode_findings"] = findings.isEmpty ? "none" : findings
            } // end TLS
            
            //Cookies
            let cookies = online.cookiesForUI
            reportContent["20_number_of_cookies"] = cookies.count
            if !cookies.isEmpty {
                var cookieDetail: [Any] = []
                for (_, cookie) in cookies.enumerated() {
                    
                    let (_, entropyValue) = CommonTools.isHighEntropy(cookie?.cookie.value ?? "")
                    let entropyValueString = entropyValue.map { String(format: "%.2f", $0) } ?? "nil"
                    let httponlyDescription = cookie?.cookie.httpOnly != nil ? "YES" : "NO"
                    
                    var cookieEntry: [String: Any] = [:]
                    cookieEntry["01_\(cookie?.cookie.name ?? "")"] = cookie?.cookie.value ?? ""
                    cookieEntry["02_value_entropy"] = entropyValueString
                    cookieEntry["03_value_len"] = cookie?.cookie.value.count ?? 0
                    cookieEntry["04_sameSitePolicy"] = cookie?.cookie.sameSite ?? ""
                    cookieEntry["05_secure_"] = cookie?.cookie.secure ?? false
                    cookieEntry["06_httpOnly"] = httponlyDescription
                    // This sucks, should use the UI function that does exactly this
                    if let expiry = cookie?.cookie.expire {
                        let now = Date()
                        let duration = expiry.timeIntervalSince(now)
                        
                        let durationString: String
                        if duration < 0 {
                            durationString = "Expired \(-Int(duration) / 3600) hours ago"
                        } else if duration < 3600 {
                            durationString = "\(Int(duration / 60)) minutes"
                        } else if duration < 86400 {
                            durationString = "\(Int(duration / 3600)) hours"
                        } else if duration < 86400 * 30 {
                            durationString = "\(Int(duration / 86400)) days"
                        } else {
                            durationString = "\(Int(duration / (86400 * 30))) months"
                        }
                        cookieEntry["07_expires_in"] = durationString
                    } else {
                        cookieEntry["07_expires_in"] = "Session"
                    }
                    
                    cookieDetail.append(cookieEntry)
                }
                reportContent["21_cookie_detail"] = cookieDetail.isEmpty ? "none" : cookieDetail
                
                //findings for cookies
                let relevantCookie: [SecurityWarning.SourceType] = [.cookie]
                let sectionWarningsCookie = urlReport.warnings.filter { relevantCookie.contains($0.source) }
                var findings : [Any] = []
                if !sectionWarningsCookie.isEmpty {
                    for (index, warning) in sectionWarningsCookie.enumerated() {
                        findings.append(["finding-\(index) in \(warning.source)" : ["\(warning.severity), \(warning.message)", "penalty: \(warning.penalty)"]])
                    }
                }
                reportContent["22_cookie_findings"] = findings.isEmpty ? "none" : findings
            } // if cookie end
            
            //headers
            if let headers = online.parsedHeaders {
                var groupedHeaders: [String: [String: String]] = [:]
                
                groupedHeaders["Security_headers"] = headers.securityHeaders
                groupedHeaders["Tracking_headers"] = headers.trackingHeaders.filter { $0.key.lowercased() != "set-cookie" }
                groupedHeaders["Server_metadata"] = headers.serverHeaders
                groupedHeaders["Other_headers"] = headers.otherHeaders
                
                reportContent["23_headers"] = groupedHeaders
                
                //finding for headers
                let relevantHeader: [SecurityWarning.SourceType] = [.header]
                let sectionWarningsHeader = urlReport.warnings.filter { relevantHeader.contains($0.source) }
                var findings : [Any] = []
                if !sectionWarningsHeader.isEmpty {
                    for (index, warning) in sectionWarningsHeader.enumerated() {
                        findings.append(["finding-\(index) in \(warning.source)" : ["\(warning.severity), \(warning.message)", "penalty: \(warning.penalty)"]])
                    }
                }
                reportContent["24_header_findings"] = findings.isEmpty ? "none" : findings
            } // if header end
            
            //body / script ...
            let scripts = online.script4daUI
            
            if !scripts.isEmpty {
                //
                let totalCount = scripts.count
                let inlineCount = scripts.filter { $0.origin == .inline || $0.origin == .moduleInline }.count
                let dataCount = scripts.filter { $0.origin == .dataURI }.count
                let httpCount = scripts.filter { $0.origin == .httpExternal || $0.origin == .httpsExternal }.count
                let relativeCount = scripts.filter { $0.origin == .relative || $0.origin == .protocolRelative }.count
                let moduleExternalCount = scripts.filter { $0.origin == .moduleExternal || $0.origin == .moduleRelative }.count
                let dataScriptCount = scripts.filter { $0.origin == .dataScript }.count
                let unknownCount = scripts.filter { $0.origin == .unknown || $0.origin == .malformed }.count
                
                reportContent["25_scripts_count"] = ["total": totalCount,
                                                     "inline": inlineCount,
                                                     "dataURI": dataCount,
                                                     "httpExternal": httpCount,
                                                     "relative": relativeCount,
                                                     "moduleExternal": moduleExternalCount,
                                                     "dataScript": dataScriptCount,
                                                     "unknown": unknownCount]
                
                var inlineScripts: [Any] = []
                var externalScripts: [Any] = []
                var scriptsPreviews: [Any] = []
                
                for (index, script) in scripts.enumerated() {
                    if script.isInline {
                        let previewNeeded = script.findings?.contains(where: { $0.pos != nil && $0.pos != 0 }) ?? false
                        if previewNeeded { scriptsPreviews.append(index) }
                        inlineScripts.append([
                            "id": "script#\(index)",
                            "size": "\(script.size)B",
                            "context": script.context?.rawValue ?? "unknown",
                            "nonce": script.nonce ?? "none",
                            "is_module": script.isModule ?? "false",
                            "preview": previewNeeded ? "see object: ScriptPreviews : inlineScript_\(index)" : "none"
                        ])
                    } else {
                        externalScripts.append([
                            "src": script.extractedSrc ?? "unknown",
                            "origin": script.origin?.rawValue ?? "unknown",
                            "integrity": script.integrity ?? "none",
                            "crossorigin": script.crossOriginValue ?? "none"
                        ])
                    }
                }
                reportContent["26_script_summary"] = [
                    "inline": inlineScripts,
                    "external": externalScripts
                ]
                
                //findings for scripts / body
                let relevantScript: [SecurityWarning.SourceType] = [.body]
                let sectionWarningsBody = urlReport.warnings.filter { relevantScript.contains($0.source) }
                var findings : [Any] = []
                if !sectionWarningsBody.isEmpty {
                    for (index, warning) in sectionWarningsBody.enumerated() {
                        findings.append(["finding-\(index) in \(warning.source)" : ["\(warning.severity), \(warning.message)", "penalty: \(warning.penalty)"]])
                    }
                }
                reportContent["27_findings_body"] = findings
            }
        
        } // if Online end
        
        
        
        
        let report: [String: Any] = ["Report_\(index)" : reportContent]
        finalOutput.append(report)

        // Generate appendices for inline script focused snippets
        // Only if scripts variable is in scope
        if let online = Dictionary(uniqueKeysWithValues: queue.onlineQueue.map { ($0.id, $0) })[urlReport.id] {
            let scripts = online.script4daUI
            for (scriptIdx, script) in scripts.enumerated() {
                if script.isInline, let snippets = script.focusedSnippets {
                    if snippets.allSatisfy({ type(of: $0) == String.self }) {
                        let scriptEntry: [String: Any] = [
                            "inlineScript_\(scriptIdx)": snippets
                        ]
                        scriptAppendices.append(scriptEntry)
                    } else {
                        print("⚠️ Non-string found in focusedSnippets at index \(scriptIdx)")
                    }
                }
            }
        }
    }

    // After all reports, append script previews if any
    if !scriptAppendices.isEmpty {
        let appendixWrapper: [String: Any] = ["ScriptPreviews": scriptAppendices]
        finalOutput.append(appendixWrapper)
    }
    
    
    // Preserve key order by converting each dictionary into a Foundation NSDictionary before serialization
    let jsonCompatibleOutput = finalOutput.map { entry in
        return NSDictionary(dictionary: Dictionary(uniqueKeysWithValues: entry.map { ($0.key, $0.value) }))
    }
    let jsonData = try JSONSerialization.data(withJSONObject: jsonCompatibleOutput, options: [/*.prettyPrinted,*/ .withoutEscapingSlashes, .sortedKeys])
    return [jsonData]
}
