//
//  GenerateJSON.swift
//  LegitURL
//
//  Created by Chief Hakka on 27/05/2025.
//
//  Created to generate a compact, high-signal structured JSON object from URLQueue analysis results

import Foundation

func generateLLMJson(from queue: URLQueue, brief: Bool = false) throws -> [Data] {
    
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
    
    //User locale
    let userLocale = Locale.current.identifier
    
    //priming the model
    let (prime, instruction) = LLMPriming.loadPrimmingInstructions(brief: brief, locale: userLocale)
    finalOutput.append(prime)
    finalOutput.append(instruction)
    
    
    //summary of the following JSON
    let inputURL = first.components.fullURL ?? "-"
    let finalURL = last.components.fullURL ?? "-"
//    let score = String(queue.legitScore.score)
    let hopCount = String(queue.offlineQueue.count - 1)
//    let criticalWarnings = URLQueue.shared.offlineQueue
//        .flatMap { $0.warnings }
//        .filter { $0.severity == .critical || $0.severity == .fetchError }

    let warnings = generateWarningJson(urls: queue)
    
    let summary: [String : Any] = ["Summary" : [
        "01_input_url" : inputURL,
        "02_final_url" : finalURL,
//        "03_score" : score,
        "04_number_of_redirect" : hopCount, //This needs to be prime that its the number of urls report
//        "05_findings_summary_sorted": "descending by penalty",
        "06_findings" : warnings
    ]]
    
    finalOutput.append(summary)
    
    //-------------------------------------------------//
    //-------------------------------------------------//
    //-------------------------------------------------//
    //-------------------------------------------------//
    //MARK: Bail early for "brief" reports.
    
    if brief {
        return [try serializeAndClean(finalOutput)]
    }
    
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
        
        var reportContent: [String: Any] = [
            "01_FullURL" : urlReport.components.fullURL ?? "",
            "02_domain" : domain,
            "03_tld" : tld,
            "04_subdomain" : subdomain,
            "05_path" : path,
            "06_query" : query,
            "07_fragment" : fragment,
            "08_punycoded_host" : punycode,
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
                
            } // if cookie end
            
            //headers
            if let headers = online.parsedHeaders {
                var groupedHeaders: [String: [String: String]] = [:]
                
                groupedHeaders["01_Security_headers"] = headers.securityHeaders
                groupedHeaders["02_Tracking_headers"] = headers.trackingHeaders.filter { $0.key.lowercased() != "set-cookie" }
                //TODO: think about what matters and what matters less. To assess, the thrust by the model, maybe security header and server is enough?
                groupedHeaders["03_Server_metadata"] = headers.serverHeaders
                groupedHeaders["Other_headers"] = headers.otherHeaders
                
                reportContent["23_headers"] = groupedHeaders
                
            } // if header end
            
            //body / script ...
            let scripts = online.script4daUI
            let scriptSummary = ScriptSummaryBuilder.makeSummary(from: scripts)
            reportContent["24_Script"] = scriptSummary
            
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
    
    return [try serializeAndClean(finalOutput)]
}


//MARK: THE END FUNCTION IS HERE
func serializeAndClean(_ json: [[String: Any]]) throws -> Data {
    let jsonData = try JSONSerialization.data(
        withJSONObject: json.map { NSDictionary(dictionary: $0) },
        options: [.withoutEscapingSlashes, .sortedKeys, /*.prettyPrinted*/]
    )

    guard var jsonString = String(data: jsonData, encoding: .utf8) else {
        throw NSError(domain: "SerializationError", code: -1, userInfo: nil)
    }

    let prefixesToRemove = ["\"00_", "\"01_", "\"02_", "\"03_", "\"04_", "\"05_",
                            "\"06_", "\"07_", "\"08_", "\"09_", "\"10_", "\"11_",
                            "\"12_", "\"13_", "\"14_", "\"15_", "\"16_", "\"17_",
                            "\"18_", "\"19_", "\"20_", "\"21_", "\"22_", "\"23_",
                            "\"24_", "\"25_", "\"26_", "\"27_"]
    
    for prefix in prefixesToRemove {
        jsonString = jsonString.replacingOccurrences(of: prefix, with: "\"")
    }

    guard let cleanedData = jsonString.data(using: .utf8) else {
        throw NSError(domain: "SerializationError", code: -1, userInfo: nil)
    }

    return cleanedData
}

func generateWarningJson(urls: URLQueue) -> [Any] {
    var listOfWarnings: [Any] = []

    for url in urls.offlineQueue {
        let sortedFindings = url.warnings.sorted { $0.penalty > $1.penalty }

        guard !sortedFindings.isEmpty else { continue }

        let mapped = sortedFindings.map { warning in
            return [
//                "severity": warning.severity.rawValue.lowercased(),
//                "penalty": warning.penalty,
                "signal": warning.message
            ]
        }

        let urlEntry: [String: Any] = [
            "01_url": url.components.coreURL ?? "(unknown)",
            "02_findings": mapped
        ]

        listOfWarnings.append(urlEntry)
    }

    return listOfWarnings
}

struct ScriptSummaryBuilder {
    static func makeSummary(from scripts: [ScriptPreview]) -> Dictionary<String, Any> {
        let inlineScripts = scripts.filter { $0.origin == .inline || $0.origin == .moduleInline }
        let httpScripts = scripts.filter { $0.origin == .httpExternal || $0.origin == .httpsExternal }
        let relativeScripts = scripts.filter { $0.origin == .relative || $0.origin == .protocolRelative }
        let moduleExternalScripts = scripts.filter { $0.origin == .moduleExternal || $0.origin == .moduleRelative }
        let protocolRelativeScripts = scripts.filter {$0.origin == .protocolRelative}

        let inlineNonceCount = inlineScripts.filter { !($0.nonce?.isEmpty ?? true) }.count
        let totalInlineSize = inlineScripts.reduce(0) { $0 + $1.size }
        let largestInlineScriptSize = inlineScripts.map { $0.size }.max() ?? 0
        let externalScriptsTotal = httpScripts.count + relativeScripts.count + moduleExternalScripts.count
        let externalWithSRI = scripts.filter { !($0.integrity?.isEmpty ?? true) }.count
        let externalWithCrossOrigin = scripts.filter { !($0.crossOriginValue?.isEmpty ?? true) }.count

        let averageInline = inlineScripts.count > 0 ? totalInlineSize / inlineScripts.count : 0
        
        var scriptsPreviews: [Int] = []
        
        for (index, script) in scripts.enumerated() {
            if script.isInline {
                let previewNeeded = script.findings?.contains(where: { $0.pos != nil && $0.pos != 0 }) ?? false
                if previewNeeded {
                    scriptsPreviews.append(index)
                }
            }
        }

        var suspiciousSnippets: [[String: Any]] = []
        for idx in scriptsPreviews {
            let matching = scripts[idx]
            //nasty
            suspiciousSnippets.append([
                "size": matching.size,
                "nonce": !(matching.nonce?.isEmpty ?? true),
                "is_module": matching.isModule ?? false,
                "findings": matching.findings?.compactMap { $0.message } ?? [],
                "snippet_ref": "ScriptPreviews → inlineScript_\(idx)"
            ])
        }
        let externalDetail = generate_externalSrc(scripts: scripts)
        // TODO: Group external scripts by path prefix and detect known third-party services
        return [
                "01_summary": [
                    "01_total": scripts.count,
                    "02_inline": inlineScripts.count,
                    "03_external": externalScriptsTotal,
                    "04_protocol_relative": protocolRelativeScripts.count,
                    "05_total_inline_bytes": totalInlineSize,
                    "06_largest_inline_script": largestInlineScriptSize,
                    "07_average_inline_script": averageInline,
                    "08_inline_with_nonce": inlineNonceCount,
                    "09_inline_with_suspicious_calls": scriptsPreviews.count,
                    "10_external_with_sri": externalWithSRI,
                    "11_module_cross_origin": externalWithCrossOrigin,
                    "12_external_from_known_third_parties": 0, // placeholder to compute separately
                    "13_script_density_per_kb": 0.0 // placeholder to compute externally if needed
                ],
                "02_inline_scripts": suspiciousSnippets.map { snippet in
                    return [
                        "01_size": snippet["size"] ?? 0,
                        "02_has_nonce": snippet["nonce"] ?? false,
                        "03_is_module": snippet["is_module"] ?? false,
                        "04_findings": snippet["findings"] ?? [],
                        "05_focused_snippets": (snippet["snippet_ref"].map { [String(describing: $0)] } ?? [])
                    ]
                },
                "03_external_script_groups": externalDetail
        ]
    }
    private static func generate_externalSrc(scripts: [ScriptPreview]) -> [Any] {
        // Categorize scripts into absolute/protocol-relative, relative, and ignore others
        var absoluteScripts: [ScriptPreview] = []
        var relativeScripts: [ScriptPreview] = []

        for script in scripts {
            guard let src = script.extractedSrc else { continue }
            if src.hasPrefix("http") || src.hasPrefix("//") {
                absoluteScripts.append(script)
            } else if src.hasPrefix("/") || (!src.contains("://") && !src.hasPrefix("data:")) {
                relativeScripts.append(script)
            }
            // Others are ignored
        }

        func groupScripts(_ scripts: [ScriptPreview]) -> [[String: Any]] {
            var grouped: [String: [ScriptPreview]] = [:]
            for script in scripts {
                guard let src = script.extractedSrc else { continue }
                //chatGPT <3
                var prefix = src.components(separatedBy: "/").prefix(4).joined(separator: "/")
                if src.hasPrefix("http://") {
                    prefix = "http://" + prefix.dropFirst(5)
                } else if src.hasPrefix("https://") {
                    prefix = "https://" + prefix.dropFirst(8)
                } else if src.hasPrefix("//") {
                    prefix = "//" + prefix.dropFirst(2)
                }
                grouped[prefix, default: []].append(script)
            }
            return grouped.map { (prefix, scripts) in
                let sri_present = scripts.contains { !($0.integrity?.isEmpty ?? true) }
                let crossorigin_present = scripts.contains { !($0.crossOriginValue?.isEmpty ?? true) }

                let trimmedSamples = scripts.compactMap { $0.extractedSrc }.map {
                    $0.replacingOccurrences(of: prefix, with: "")
                }

                return [
                    "01_path_prefix": prefix,
                    "02_count": scripts.count,
                    "03_suffixes": trimmedSamples,
                    "04_sri_present": sri_present,
                    "05_crossorigin_present": crossorigin_present
                ]
            }
        }

        return [
            ["01_group_type": "absolute_or_protocol_relative", "groups": groupScripts(absoluteScripts)],
            ["02_group_type": "relative_path", "groups": groupScripts(relativeScripts)]
        ]
    }
}
