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
finalOutput.append(["00_priming" : "This is a machine-generated report of a URL's behavior for AI interpretation. Do not give verdicts. Instead, explain why certain findings matter, focusing on possible risks or strengths."])
    let prime: [String: Any] = ["01_Instructions": LLMPriming.instructions]
    finalOutput.append(prime)
finalOutput.append(["02_Model_Note": "Highlight ambiguous or conflicting technical signals. The score is a guide, not proof — justify it using the available data."])
    
    //summary of the following JSON
    let inputURL = first.components.fullURL ?? "-"
    let finalURL = last.components.fullURL ?? "-"
    let score = String(queue.legitScore.score)
    let hopCount = String(queue.offlineQueue.count - 1)
    let criticalWarnings = URLQueue.shared.offlineQueue
        .flatMap { $0.warnings }
        .filter { $0.severity == .critical || $0.severity == .fetchError }
    
    let summary: [String : Any] = ["Summary" : [
        "01_input_url" : inputURL,
        "02_final_url" : finalURL,
        "03_score" : score,
        "04_number_of_redirect" : hopCount, //This needs to be prime that its the number of urls report
        "05_critical_warnings" : criticalWarnings.isEmpty ? criticalWarnings : ""
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
            "09_findings" : findings.isEmpty ? "" : findings
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
            //TODO: Skip when redirect chain is using the same tls
            if let cert = online.parsedCertificate {
                if let issuerCommonName = cert.issuerCommonName, let subjectCommonName = cert.commonName {
                    reportContent["14_issuerName_CommonName"] = issuerCommonName + " , " + subjectCommonName
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
                reportContent["19_tls_responsecode_findings"] = findings.isEmpty ? "" : findings
            } // end TLS
            
            //Cookies
            //TODO: Maybe skip cookies that al ready appeared ?
            let cookies = online.cookiesForUI
            reportContent["20_number_of_cookies"] = cookies.count
            if !cookies.isEmpty {
                var cookieDetail: [Any] = []
                for (_, cookie) in cookies.enumerated() {
                    
                    let (_, entropyValue) = CommonTools.isHighEntropy(cookie?.cookie.value ?? "")
                    let entropyValueString = entropyValue.map { String(format: "%.2f", $0) } ?? "nil"
                    let httponlyDescription = cookie?.cookie.httpOnly != nil ? "YES" : "NO"
                    
                    var cookieEntry: [String: Any] = [:]
                    cookieEntry["01_key"] = cookie?.cookie.name ?? ""
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
                reportContent["21_cookie_detail"] = cookieDetail.isEmpty ? "" : cookieDetail
                
                //findings for cookies
                let relevantCookie: [SecurityWarning.SourceType] = [.cookie]
                let sectionWarningsCookie = urlReport.warnings.filter { relevantCookie.contains($0.source) }
                var findings : [Any] = []
                if !sectionWarningsCookie.isEmpty {
                    for (index, warning) in sectionWarningsCookie.enumerated() {
                        findings.append(["finding-\(index) in \(warning.source)" : ["\(warning.severity), \(warning.message)", "penalty: \(warning.penalty)"]])
                    }
                }
                reportContent["22_cookie_findings"] = findings.isEmpty ? "" : findings
            } // if cookie end
            
            //headers
            if let headers = online.parsedHeaders {
                var groupedHeaders: [String: [String: String]] = [:]
                
                groupedHeaders["01_Security_headers"] = headers.securityHeaders
                groupedHeaders["02_Tracking_headers"] = headers.trackingHeaders.filter { $0.key.lowercased() != "set-cookie" }
                //TODO: think about what matters and what matters less. To assess, the thrust by the model, maybe security header and server is enough?
                groupedHeaders["03_Server_metadata"] = headers.serverHeaders
                //                groupedHeaders["Other_headers"] = headers.otherHeaders
                
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
                reportContent["24_header_findings"] = findings.isEmpty ? "" : findings
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
                
                let inlineNonceCount = scripts.filter {
                    ($0.origin == .inline || $0.origin == .moduleInline) && ($0.nonce?.isEmpty == false)
                }.count
                
                let totalInlineSize = scripts.filter { $0.origin == .inline || $0.origin == .moduleInline }.reduce(0) { $0 + $1.size }
                
                reportContent["25_scripts_count"] = [
                    "01_total": totalCount,
                    "inline": inlineCount,
                    "inline_nonce": inlineNonceCount,
                    "inline_total_size": totalInlineSize,
                    "dataURI": dataCount,
                    "httpExternal": httpCount,
                    "relative": relativeCount,
                    "moduleExternal": moduleExternalCount,
                    "dataScript": dataScriptCount,
                    "unknown": unknownCount
                ]
                
                var inlineScripts: [Any] = []
                var externalScripts: [Any] = []
                var scriptsPreviews: [Any] = []
                
                for (index, script) in scripts.enumerated() {
                    if script.isInline {
                        let previewNeeded = script.findings?.contains(where: { $0.pos != nil && $0.pos != 0 }) ?? false
                        if !previewNeeded == false {
                            
                            if previewNeeded { scriptsPreviews.append(index) }
                            var findingsValue: [Any]
                            if previewNeeded {
                                // do NOT compress messages, because 1 message -> one snippet. Could theorically ask model " show snippet of keyword 3" or w/e
                                let messages = script.findings?.compactMap { $0.message }.joined(separator: ", ") ?? "unknown"
                                findingsValue = [["\(messages)"], "see Appendix object: ScriptPreviews → inlineScript_\(index)"]
                            } else {
                                findingsValue = [[""]]
                            }
                            inlineScripts.append([
                                "01_id": "script#\(index)",
                                "02_size": "\(script.size)B",
                                "03_context": script.context?.rawValue ?? "unknown",
                                "04_nonce": script.nonce ?? "",
                                "05_is_module": script.isModule ?? "false",
                                "06_findings": findingsValue
                            ])
                        }
                    } else {
                        if script.findings?.count ?? 0 > 0 {
                            externalScripts.append([
                                "01_src": script.extractedSrc ?? "unknown",
                                "02_origin": script.origin?.rawValue ?? "unknown",
                                "03_integrity": script.integrity ?? "",
                                "04_crossorigin": script.crossOriginValue ?? ""
                            ])
                        }
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
        // TODO: Using findings pos, or by editing the snippet object, so an indication can be given to the model about what is "suspicious" here
        if let online = Dictionary(uniqueKeysWithValues: queue.onlineQueue.map { ($0.id, $0) })[urlReport.id] {
            let scripts = online.script4daUI
            for (scriptIdx, script) in scripts.enumerated() {
                if script.isInline, let snippets = script.focusedSnippets {
                    if snippets.allSatisfy({ type(of: $0) == String.self }) {
                        let labeledSnippets = Dictionary(uniqueKeysWithValues:
                                                            snippets.enumerated().map { ("snippet_\($0.offset)", $0.element) }
                        )
                        let scriptEntry: [String: Any] = [
                            "inlineScript_\(scriptIdx)": labeledSnippets
                        ]
                        scriptAppendices.append(scriptEntry)
                    } else {
                        throw NSError(domain: "Non-string found in focusedSnippets at index \(scriptIdx)", code: -1)
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
    
    // Serialize the array of dictionaries to JSON data without sorting keys (preserves insertion order)
    let jsonData = try JSONSerialization.data(
        withJSONObject: finalOutput.map { NSDictionary(dictionary: $0) },
        options: [.withoutEscapingSlashes, .prettyPrinted, .sortedKeys]
    )
    
    // Convert JSON data to a string for prefix removal
    guard var jsonString = String(data: jsonData, encoding: .utf8) else {
        throw NSError(domain: "SerializationError", code: -1, userInfo: nil)
    }
    
// HORRIBLE TODO: create two parrallel arrays or tuple holding value and key. And process in order?? ?? ? ? ?  ? ??
    let prefixesToRemove = ["\"00_","\"01_","\"02_","\"03_","\"04_","\"05_","\"06_","\"07_","\"08_","\"09_",
                            "\"10_","\"11_","\"12_","\"13_","\"14_","\"15_","\"16_","\"17_","\"18_",
                            "\"19_","\"20_","\"21_","\"22_","\"23_","\"24_","\"25_","\"26_","\"27_"]
    for prefix in prefixesToRemove {
        jsonString = jsonString.replacingOccurrences(of: prefix, with: "\"")
    }

    guard let cleanedData = jsonString.data(using: .utf8) else {
        throw NSError(domain: "SerializationError", code: -1, userInfo: nil)
    }
    
    return [cleanedData]
}
