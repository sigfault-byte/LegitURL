//
//  GenerateJSON.swift
//  LegitURL
//
//  Created by Chief Hakka on 27/05/2025.
//
//  Created to generate a compact, high-signal structured JSON object from URLQueue analysis results
//TODO: This is a terrible JSON, explore the leads on MetaJSONBuilder etc.
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
//    let userLocale = Locale.current.identifier -> this is system hybrid hotdogwater
    var userLocale = Locale.preferredLanguages.first ?? "en" // this should be good ???
    if let dashIndex = userLocale.firstIndex(of: "-") {
        userLocale = String(userLocale.prefix(upTo: dashIndex))
    }
    if userLocale.isEmpty {
        userLocale = "en"
    }
    
    //priming the model
    let (prime, instruction) = LLMPriming.loadPrimmingInstructions(brief: brief, locale: userLocale)
    let metaBlock: [String: Any] = [
        "meta": [
            "01_taskOverview": prime,
            "02_modelContext": instruction
        ]
    ]
    finalOutput.append(metaBlock)
    
    
    //summary of the following JSON
    let inputURL = first.components.fullURL ?? ""
    let finalURL = last.components.fullURL ?? ""
//    let score = String(queue.legitScore.score)
    let hopCount = String(queue.offlineQueue.count - 1)
//    let criticalWarnings = URLQueue.shared.offlineQueue
//        .flatMap { $0.warnings }
//        .filter { $0.severity == .critical || $0.severity == .fetchError }

//    let warnings = generateWarningJson(urls: queue)
    
    
    
//-------------------------------------------------//
    //-------------------------------------------------//
    //-------------------------------------------------//
    //-------------------------------------------------//
    //MARK: Bail early for "brief" reports.
    
    if brief {
        var tlsInfo: [String: Any] = [:]
        if let cert = queue.onlineQueue.last?.parsedCertificate {
            
            if let issuerCommonName = cert.issuerCommonName, let subjectCommonName = cert.commonName {
                tlsInfo["issuerCommonNAme"] = issuerCommonName + " , " + subjectCommonName
            }
            if cert.certificatePolicyOIDs != nil {
                tlsInfo["certificatePolicy"] = cert.inferredValidationLevel.rawValue == "unknown"
                    ? cert.certificatePolicyOIDs
                    : cert.inferredValidationLevel.rawValue
            }
            if let notBefore = cert.notBefore {
                tlsInfo["notBefore"] = formatter.string(from: notBefore)
            }
            if let notAfter = cert.notAfter {
                tlsInfo["notAfter"] = formatter.string(from: notAfter)
            }
            if let subjectAlternativeNames = cert.subjectAlternativeNames {
                tlsInfo["numberOfSAN"] = subjectAlternativeNames.count
            }
        }
        
        let warnings = SecurityWarningTriage.generateWarningJson(urls: queue)
        
        let summary: [String : Any] = ["Summary" : [
                "01_inputUrl" : inputURL,
                "02_finalUrl" : finalURL,
                "03_encouteredUrls" : warnings["idMap"] ?? NSNull(),
                "04_numberOfRedirect" : hopCount, //This needs to be prime that its the number of urls report ?
                "05_lastURLTlsDetails" : tlsInfo,
                "06_findings" : warnings["findingsByUrls"] ?? NSNull()
            ]]

        finalOutput.append(summary)
        return [try serializeAndClean(finalOutput)]
    }
    
    // Loop URLs
    var reportArray: [[String: Any]] = []
    var scriptAppendices: [[String: Any]] = []
    for (_, urlReport) in queue.offlineQueue.enumerated() {
        
        //Offline element
        //shorthand
        let components = urlReport.components
        
        //Offline Var
        let domain: Any = components.extractedDomain ?? NSNull()
        let tld : Any = components.extractedTLD ?? NSNull()
        let subdomain: Any = components.subdomain ?? NSNull()
        let path: Any = components.path ?? NSNull()
        let query: Any = components.query ?? NSNull()
        let fragment: Any = components.fragment ?? NSNull()
        let punycode: Any = components.punycodeHostEncoded ?? NSNull()
        
        var reportContent: [String: Any] = [
            "01_url" : urlReport.components.fullURL ?? NSNull(),
            "02_domain" : domain,
            "03_tld" : tld,
            "04_subdomain" : subdomain,
            "05_path" : path,
            "06_query" : query,
            "07_fragment" : fragment,
            "08_punycodedHost" : punycode,
        ]
        
        // Online Var
        //HTTP response code
        let onlineMap = Dictionary(uniqueKeysWithValues: queue.onlineQueue.map { ($0.id, $0) })
        if let online = onlineMap[urlReport.id] {
            reportContent["10_requestedUrl"] = components.coreURL ?? "error"
            if let code = online.serverResponseCode {
                reportContent["11_responseCode"] = code
            }
            if let status = online.statusText {
                reportContent["12_statusText"] = status
            }
            if let finalRedirect = online.finalRedirectURL {
                reportContent["13_finalRedirect"] = finalRedirect.isEmpty
            }
            //TLS
            //TODO: Skip when redirect chain is using the same tls
            if let cert = online.parsedCertificate {
                var tlsInfo: [String: Any] = [:]
                if let issuerCommonName = cert.issuerCommonName, let subjectCommonName = cert.commonName {
                    tlsInfo["issuerCommonNAme"] = issuerCommonName + " , " + subjectCommonName
                }
                if cert.certificatePolicyOIDs != nil {
                    tlsInfo["certificatePolicy"] = cert.inferredValidationLevel.rawValue == "unknown"
                        ? cert.certificatePolicyOIDs
                        : cert.inferredValidationLevel.rawValue
                }
                if let notBefore = cert.notBefore {
                    tlsInfo["notBefore"] = formatter.string(from: notBefore)
                }
                if let notAfter = cert.notAfter {
                    tlsInfo["notAfter"] = formatter.string(from: notAfter)
                }
                if let subjectAlternativeNames = cert.subjectAlternativeNames {
                    tlsInfo["numberOfSAN"] = subjectAlternativeNames.count
                }
                reportContent["14_tls"] = tlsInfo
            }
            
            //Cookies
            //TODO: Maybe skip cookies that al ready appeared ?
            let cookies = online.cookiesForUI
            reportContent["15_numberOfCookies"] = cookies.count
            if !cookies.isEmpty {
                var cookieDetail: [Any] = []
                for (_, cookie) in cookies.enumerated() {
                    
                    let (_, entropyValue) = CommonTools.isHighEntropy(cookie?.cookie.value ?? "")
                    let roundedEntropy: Any = entropyValue.map { Double(round($0 * 10) / 10) } ?? NSNull()
                    let entropyValueFinal: Any = roundedEntropy

                    let httpOnly: Bool = cookie?.cookie.httpOnly ?? false
                    
                    var cookieEntry: [String: Any] = [:]
                    cookieEntry["01_key"] = cookie?.cookie.name ?? NSNull()
                    cookieEntry["02_valueEntropy"] = entropyValueFinal
                    cookieEntry["03_valueLen"] = cookie?.cookie.value.count ?? 0
                    cookieEntry["04_sameSitePolicy"] = cookie?.cookie.sameSite ?? NSNull()
                    cookieEntry["05_secure"] = cookie?.cookie.secure ?? false
                    cookieEntry["06_httpOnly"] = httpOnly
                    // This sucks, should use the UI function that does exactly this Convert to iso machine
                    if let expiry = cookie?.cookie.expire {
                        let isoFormatter = ISO8601DateFormatter()
                        isoFormatter.timeZone = TimeZone(secondsFromGMT: 0)
                        let isoString = isoFormatter.string(from: expiry)
                        cookieEntry["07_expires"] = ["type": "absolute", "value": isoString]
                    } else {
                        cookieEntry["07_expires"] = ["type": "session"]
                    }
                    
                    cookieDetail.append(cookieEntry)
                }
                reportContent["16_cookieDetail"] = cookieDetail.isEmpty ? NSNull(): cookieDetail
                
            } // if cookie end
            
            //headers
            if let headers = online.normalizedHeaders {
                let mergedHeaders = HeadersTriage.triage(headers, csp: online.cspOfHeader)
//                var mergedHeaders: [String: String] = [:]
//                headers.securityHeaders.forEach { mergedHeaders[$0.key] = $0.value }
//                headers.trackingHeaders.filter { $0.key.lowercased() != "set-cookie" }.forEach { mergedHeaders[$0.key] = $0.value }
//                headers.serverHeaders.forEach { mergedHeaders[$0.key] = $0.value }
//                headers.otherHeaders.forEach { mergedHeaders[$0.key] = $0.value }
                reportContent["17_headers"] = mergedHeaders.isEmpty ? NSNull() : mergedHeaders
            } // if header end
            
            //body / script ...
            let scripts = online.script4daUI
            let bodySize = online.humanBodySize ?? 0
            let scriptSummary = ScriptSummaryBuilder.makeSummary(from: scripts, bodySize: bodySize )
            reportContent["18_scripts"] = scriptSummary.isEmpty ? NSNull(): scriptSummary
            
            let warnings = SecurityWarningTriage.getRelevantSecurityWarnings(for: urlReport, with: [.host, .path, .query, .fragment, .redirect, .cookie, .header, .body , .tls , .getError , .responseCode])
            
            reportContent["19_findings"] = warnings.isEmpty ? NSNull() : warnings
            
        } // if Online end
        
        reportArray.append(reportContent)
        
        
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
    finalOutput.append(["reports": reportArray])
    
    // After all reports, append script previews if any
    if !scriptAppendices.isEmpty {
        let appendixWrapper: [String: Any] = ["scriptPreviews": scriptAppendices]
        finalOutput.append(appendixWrapper)
    }
    
    return [try serializeAndClean(finalOutput)]
}


//MARK: THE END FUNCTION IS HERE
func serializeAndClean(_ json: [[String: Any]]) throws -> Data {
    // Check for invalid JSON objects before attempting serialization
    #if DEBUG
    for (index, obj) in json.enumerated() {
        if !JSONSerialization.isValidJSONObject(obj) {
            print("FAILEDInvalid JSON object at index \(index):")
            dump(obj)
            throw NSError(domain: "Invalid JSON object", code: -1)
        }
    }
    #endif
    
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

struct ScriptSummaryBuilder {
    static func makeSummary(from scripts: [ScriptPreview], bodySize: Int) -> Dictionary<String, Any> {
        let inlineScripts = scripts.filter { $0.origin == .inline || $0.origin == .moduleInline }
        let httpScripts = scripts.filter { $0.origin == .httpExternal || $0.origin == .httpsExternal }
        let relativeScripts = scripts.filter { $0.origin == .relative || $0.origin == .protocolRelative }
        let moduleExternalScripts = scripts.filter { $0.origin == .moduleExternal || $0.origin == .moduleRelative }

        let inlineNonceCount = inlineScripts.filter { !($0.nonce?.isEmpty ?? true) }.count
        let totalInlineSize = inlineScripts.reduce(0) { $0 + $1.size }
        let largestInlineScriptSize = inlineScripts.map { $0.size }.max() ?? 0
        let externalScriptsTotal = httpScripts.count + relativeScripts.count + moduleExternalScripts.count
        let externalWithSRI = scripts.filter { !($0.integrity?.isEmpty ?? true) }.count
        let externalWithCrossOrigin = scripts.filter { !($0.crossOriginValue?.isEmpty ?? true) }.count

        let scritpDensityPerKB = scripts.count
        
//        scripts per 1000 bytes, a kind of “density per KB"
        let rawDensity = bodySize > 0 ? (Double(scritpDensityPerKB) / Double(bodySize)) * 1000 : 0.0
        let normalized = Double(round(rawDensity * 10) / 10)
        
//        let rounded = String(format: "%.3f", normalized)

        
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
                "isModule": matching.isModule ?? false,
                "findings": matching.findings?.compactMap { $0.message } ?? [],
                "snippet_ref": "inlineScript_\(idx)"
            ])
        }
        let externalDetail = generate_externalSrc(scripts: scripts)
        // TODO: Group external scripts by path prefix and detect known third-party services
        return [
                "01_summary": [
                    "01_count": [
                        "01_inline": inlineScripts.count,
                        "02_external": externalScriptsTotal
                    ],
                    "02_size": [
                        "04_totalInlineBytes": totalInlineSize,
                        "05_largestInline": largestInlineScriptSize,
                        "06_averageInline": averageInline
                    ],
                    "03_flags": [
                        "07_inlineWithNonce": inlineNonceCount,
                        "08_inlineSuspicious": scriptsPreviews.count,
                        "09_externalWithSri": externalWithSRI,
                        "10_externalWithCrossorigin": externalWithCrossOrigin
                    ],
                    "04_densityPerKilobyte": normalized
                ],
                "02_inlineScripts": suspiciousSnippets.map { snippet in
                    return [
                        "01_size": snippet["size"] ?? 0,
                        "02_hasNonce": snippet["nonce"] ?? false,
                        "03_isModule": snippet["is_module"] ?? false,
                        "04_findings": snippet["findings"] ?? NSNull(),
                        "05_focusedSnippets": (snippet["snippet_ref"].map { [String(describing: $0)] } ?? [])
                    ]
                },
                "03_externalScriptGroups": externalDetail
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
                    "01_pathPrefix": prefix,
                    "02_count": scripts.count,
                    "03_suffixes": trimmedSamples,
                    "04_sriPresent": sri_present,
                    "05_crossoriginPresent": crossorigin_present
                ]
            }
        }

        let absoluteGroups = groupScripts(absoluteScripts).map {
            var copy = $0
            copy["groupType"] = "absoluteOrProtocolRelative"
            return copy
        }

        let relativeGroups = groupScripts(relativeScripts).map {
            var copy = $0
            copy["groupType"] = "relativePath"
            return copy
        }

        return absoluteGroups + relativeGroups
    }
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
