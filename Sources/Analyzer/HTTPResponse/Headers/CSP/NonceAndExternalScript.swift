//
//  NonceAndExternalScript.swift
//  LegitURL
//
//  Created by Chief Hakka on 26/04/2025.
//

import Foundation
// Assess that the the scriptDirective either have nonce or external url except self
// If scriptValutToCheck is empty here, there is nothing to do, this would be a server config error?
//TODO: Add SHA check ! This should be cheap to compute, need some test run
//TODO: Fix the scoring from this static crap to using the penalty system
//TODO: This file is hotdogwater chaos, need a refactor!

//1
//Count scripts vs count nonces
//Suspicious if big mismatch
//2
//Match each script nonce to CSP nonce
//Block if no match
//3
//External src URL match
//Block if not allowed
//4
//Detect scripts missing nonce
//Block unless unsafe-inline or hash


//TODO: Need an example when there are externalsource but none of them are used.
struct NonceAndExternalScript {
    struct NormalizedScriptOrigin {
        let origin: String     // scheme://host:port
        let original: String   // full original URL for logging or UI
    }
    static func analyze( scriptValueToCheck: ScriptSourceToMatchCSP?,
                         scriptDirective: [Data: CSPValueType],
                         urlOrigin: String,
                         script: inout ScriptExtractionResult?) -> [SecurityWarning] {
        
        var warnings:[SecurityWarning] = []
        //        print("nonceList:", scriptValueToCheck?.nonceList ?? "")
        //        print("externalSources:", scriptValueToCheck?.externalSources ?? "")
        guard let scriptValueToCheck = scriptValueToCheck,
              (!scriptValueToCheck.nonceList.isEmpty || !scriptValueToCheck.externalSources.isEmpty) else {
            warnings.append(SecurityWarning(
                message: "No nonce or external script sources detected despite CSP script directive.",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: .header,
                machineMessage: "missing_nonce_and_external_script"
            ))
            return warnings
        }
        
        // script values to check nonce and external urls
        let nonceValueFromScript = Set(scriptValueToCheck.nonceList)
        let srcValueFromScript = scriptValueToCheck.externalSources
        
        // Normalize script sources for origin tracking
        var normalizedScriptOrigins: [NormalizedScriptOrigin] = []
        var seenOriginals = Set<String>()
        for src in srcValueFromScript {
            guard let url = URL(string: src) else {
                // If not a valid URL, skip normalization but still track original
                if !seenOriginals.contains(src) {
                    normalizedScriptOrigins.append(NormalizedScriptOrigin(origin: src, original: src))
                    seenOriginals.insert(src)
                }
                continue
            }
            let scheme = url.scheme ?? "https"
            let host = url.host ?? ""
            let port = url.port ?? (scheme == "https" ? 443 : 80)
            let normalizedOrigin = "\(scheme)://\(host):\(port)"
            if !seenOriginals.contains(src) {
                normalizedScriptOrigins.append(NormalizedScriptOrigin(origin: normalizedOrigin, original: src))
                seenOriginals.insert(src)
            }
        }
        
        let scriptSourceSet = Set(srcValueFromScript)
        if srcValueFromScript.count > scriptSourceSet.count {
            warnings.append(SecurityWarning(
                message: "Duplicate external script URLs found in page. This may indicate redundant script calls or suspicious behavior.",
                severity: .info,
                penalty: -2,
                url: urlOrigin,
                source: .body,
                machineMessage: "duplicate_external_script_urls"
            ))
        }
        
        
        
        
        
        // Only count inline scripts (not data URI) for nonceScriptCount
        let inlineCount = script?.scripts.compactMap {
            ($0.origin == .inline /*|| $0.origin == .dataURI*/) ? $0 : nil
        }.count
        let nonceScriptCount = script?.scripts.compactMap {
            ($0.origin == .inline && $0.noncePos != nil) ? $0 : nil
        }.count
        
        
        var specialSources: Set<String> = []
        
        var nonceValueFromDirective: [String] = []
        var srcValueFromDirective: Set<String> = []
        var rawSourcesFromDirective: [String] = []
        
        for (data, valueType) in scriptDirective {
            guard let stringValue = String(data: data, encoding: .utf8) else {
                warnings.append(SecurityWarning(
                    message: "Unable to decode directive value.",
                    severity: .suspicious,
                    penalty: -10,
                    url: urlOrigin,
                    source: .header,
                    machineMessage: "csp_decode_failed"
                ))
                continue
            }

            if stringValue.contains("nonce") {
                nonceValueFromDirective.append(stringValue)
                continue
            }
            
            if valueType == .source {
                let lowercased = stringValue.lowercased()
                
                // Store special sources (http:, https:, *, 'self') for fast checks
                if lowercased == "http:" || lowercased == "https:" || lowercased == "*" || lowercased.contains("'self'") {
                    if lowercased == "'self'" {
                        specialSources.insert("https://\(urlOrigin)")
                    } else {
                        specialSources.insert(lowercased)
                        continue
                    }
                }
                
                // Normalize value for path-based source check and handle wildcards
                var normalizedValue = lowercased
                // Handle wildcard domain
                if lowercased.hasPrefix("*.") {
                    normalizedValue = "https://" + lowercased
                } else if !lowercased.hasPrefix("http") {
                    normalizedValue = "https://" + normalizedValue
                }
                
                // Flag if path is improperly specified (excluding just "https://...")
                if let url = URL(string: normalizedValue), url.path != "" && url.path != "/" {
                    warnings.append(SecurityWarning(
                        message: "CSP directive includes path '\(lowercased)', which is invalid. CSP only accepts origins, not paths.",
                        severity: .info,
                        penalty: 0,
                        url: urlOrigin,
                        source: .header,
                        machineMessage: "csp_path_in_source"
                    ))
                }
                
                rawSourcesFromDirective.append(normalizedValue)
            }
        }
        srcValueFromDirective = Set(rawSourcesFromDirective)
        
        //        #if DEBUG
        //        print("Directive: ", nonceValueFromDirective)
        //        #endif
        
        var cleanedNonceFromDirective = Set(nonceValueFromDirective.map { $0.replacingOccurrences(of: "nonce-", with: "") })
        cleanedNonceFromDirective =  Set(cleanedNonceFromDirective.map { String($0.dropFirst().dropLast()) })
        var (isValid, warning): (Bool, [SecurityWarning]) = (true, [])
        if let firstNonce = cleanedNonceFromDirective.first {
            (isValid, warning) = checkNonceValue(firstNonce, urlOrigin: urlOrigin)
            if !isValid {
                warnings.append(contentsOf: warning)
            }
        }
        
        //                #if DEBUG
        //                print("Cleaned directive: ", cleanedNonceFromDirective)
        //                print("Nonce value from scripts:", nonceValueFromScript)
        //                #endif
        
        
        // Flag the missing nonce script, no penalty
        //        print("inlineOrDataURICount:", inlineOrDataURICount ?? -1)
        //        print("nonceScriptCount:", nonceScriptCount ?? -1)
        //        print("nonceValueFromDirective:", nonceValueFromDirective)
        if let inlineOrDataCount = inlineCount,
           inlineOrDataCount > 0,
           nonceScriptCount == 0,
           !nonceValueFromDirective.isEmpty
        {
            if var unwrapped = script {
                for index in unwrapped.scripts.indices {
                    let scriptItem = unwrapped.scripts[index]
                    if scriptItem.origin == .inline && scriptItem.nonceValue == nil {
                        unwrapped.scripts[index].findings4UI = (unwrapped.scripts[index].findings4UI ?? []) + [("Missing nonce (none used despite CSP)", .info, 0)]
                    }
                }
                script = unwrapped
            }
            warnings.append(SecurityWarning(
                message: "Inline scripts found but none use a nonce, even though a CSP nonce directive is present.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.nonceInCSPNoInline,
                url: urlOrigin,
                source: .header,
                machineMessage: "missing_nonce_with_csp_present"
            ))
        }
        
        if cleanedNonceFromDirective.count == nonceValueFromScript.count {
            // Imba one liner to clean the comparison, thanks chatGPT <3
            let missingNonces = nonceValueFromScript.subtracting(cleanedNonceFromDirective)
            
            if !missingNonces.isEmpty {
                let displayList = CommonTools.formatLimitedList(missingNonces, limit : 5)
                // There are some missing nonces
                warnings.append(SecurityWarning(
                    message: "Nonce mismatch detected. The following script nonces were not found in the CSP header: [\(displayList)]",
                    severity: .suspicious,
                    penalty: -10,
                    url: urlOrigin,
                    source: .header,
                    machineMessage: "nonce_mismatch_scripts_csp"
                ))
            }
            else if nonceValueFromScript == cleanedNonceFromDirective && !nonceValueFromScript.isEmpty {
                warnings.append(SecurityWarning(
                    message: "All inline scripts are protected with matching CSP nonces.",
                    severity: .good,
                    penalty: 15,
                    url: urlOrigin,
                    source: .header,
                    machineMessage: "nonce_all_matched"
                ))
            } else if cleanedNonceFromDirective != [] || nonceValueFromScript != [] {
                warnings.append(SecurityWarning(
                    message: "Nonce values in CSP header and script do not match.",
                    severity: .suspicious,
                    penalty: -10,
                    url: urlOrigin,
                    source: .header,
                    machineMessage: "nonce_values_missatch"
                ))
            }
        }
        //        waived of dataURI with nonce value -> still not good a SRI would be better.
        //        Doest work, nonce is only for inline
        //        if let script = script {
        //            let dataURIScripts = script.scripts.filter { $0.origin == .dataURI }
        //
        //            let allDataURIsHaveNonce = dataURIScripts.allSatisfy { $0.nonceValue != nil }
        //
        //            if allDataURIsHaveNonce && !dataURIScripts.isEmpty {
        //                warnings.append(SecurityWarning(
        //                    message: "All data URI scripts correctly have nonce verified values.",
        //                    severity: .info,
        //                    penalty: 30,
        //                    url: urlOrigin,
        //                    source: .header
        //                ))
        //            }
        //        }
        
        // Track how many scripts actually matched the CSP sources
        var usedScriptCount = 0
        //DEBUG
        //        for a in srcValueFromScript {
        //            print("url: ", a)
        //        }
        
        
        //MARK: Checking scrit src agains csp
        //already penalyzed in the csp analyzer
        var openBar: Bool = false
        
        if specialSources.contains("https") || specialSources.contains("*") {
            openBar = true
        }
        if !openBar {
            for originPair in normalizedScriptOrigins {
                if !isExternalScriptAllowed(scriptURL: originPair.original, allowedSources: srcValueFromDirective) {
                    if var unwrapped = script {
                        for index in unwrapped.scripts.indices {
                            let scriptItem = unwrapped.scripts[index]
                            if let scriptsSource = scriptItem.extractedSrc {
                                if scriptsSource == originPair.original {
                                    unwrapped.scripts[index].findings4UI = (unwrapped.scripts[index].findings4UI ?? []) + [("Source not covered by CSP", .info, 0)]
                                }
                            }
                        }
                        script = unwrapped
                    }
                    
                    warnings.append(SecurityWarning(
                        message: "External script '\(originPair.original)' not covered by CSP policy.",
                        severity: .suspicious,
                        penalty: -10,
                        url: urlOrigin,
                        source: .header,
                        machineMessage: "external_script_not_in_csp"
                    ))
                } else {
                    usedScriptCount += 1
                }
            }
        }
        
        //        #if DEBUG
        //        if var script = script {
        //            for index in script.scripts.indices {
        //                let scriptItem = script.scripts[index]
        //                print(scriptItem.findings4UI)
        //            }
        //        }
        //        #endif
        
        // After checking each external script
        if !openBar {
            var matchedSources = Set<String>()
//            print("---------------")
//            print("matchedSources: \(matchedSources)")
            for originPair in normalizedScriptOrigins {
                for directive in srcValueFromDirective {
                    if isExternalScriptAllowed(scriptURL: originPair.original, allowedSources: [directive]) {
                        matchedSources.insert(directive)
                        break
                    }
                }
            }

            let unusedSources = srcValueFromDirective.subtracting(matchedSources)
            if unusedSources.count >= 2 {
                warnings.append(SecurityWarning(
//                    message: #"""
//                    CSP script-src lists \#(srcValueFromDirective.count) sources, but only \#(matchedSources.count) were used. Consider removing unused entries: [\#(unusedSources.joined(separator: ", "))].
//                    """#,
                    message:"CSP script-src lists \(srcValueFromDirective.count) sources, but only \(matchedSources.count) were used.",
                    severity: .suspicious,
                    penalty: -5,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_CSP_TOO_MANY_URL_SOURCES],
                    machineMessage: "csp_\(matchedSources.count)_script_sources_unused"
                ))
            }
        }
        
        //        print("Total warnings generated:", warnings.count)
        //        for w in warnings {
        //            print("Warning:", w.message)
        //        }
        return warnings
    }
    
    static func isExternalScriptAllowed(scriptURL: String, allowedSources: Set<String>) -> Bool {
        // Normalize the script URL
        //PLAN :
        //        https://*.example.com ->  Any subdomain on port 443    ->    Step 3
        //        https://example.com -> Only root domain, port 443 -> Step 4
        //        https://example.com:8443 -> Only exact origin + port -> Step 4
        //        https: -> Any domain as long as it’s HTTPS -> Step 2 -> useless shortcut with openbar var
        //        * -> Literally anything  -> Step 1

        guard let scriptComponents = URL(string: scriptURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))) else {
            return false
        }

        let scriptScheme = scriptComponents.scheme ?? "https"
        let scriptHost = scriptComponents.host ?? ""
        let scriptPort = scriptComponents.port ?? (scriptScheme == "https" ? 443 : 80)
        let scriptOrigin = "\(scriptScheme)://\(scriptHost):\(scriptPort)"

//         Debug print for tracing
//        print("----------Checking script:", scriptURL)
//        print("----------Normalized origin:", scriptOrigin)

        for rawAllowedSource in allowedSources {
            var allowedSource = rawAllowedSource.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))

            if !allowedSource.hasPrefix("http") {
                allowedSource = "https://" + allowedSource
            }

//            // Only print for https or wildcard sources
//            if allowedSource.hasPrefix("https") || allowedSource == "*" {
//                print(" Trying allowed source:", allowedSource)
//            }

            // 3. Wildcard domain with optional port: https://*.example.com:PORT !
            if allowedSource.hasPrefix("https://*.") {
                let baseString = allowedSource.replacingOccurrences(of: "https://*.", with: "")
                let parts = baseString.split(separator: ":")
                let wildcardBase = parts.first.map(String.init) ?? ""
                let wildcardPort = parts.count > 1 ? Int(parts[1]) : 443

                if scriptHost.hasSuffix(wildcardBase) && scriptPort == wildcardPort {
//                    if allowedSource.hasPrefix("https") || allowedSource == "*" {
//                        print(" MATCHED with:", allowedSource)
//                    }
                    return true
                }
            }

            // 4. Full origin match (scheme://host:port)
            if let allowedComponents = URL(string: allowedSource),
               let allowedScheme = allowedComponents.scheme,
               let allowedHost = allowedComponents.host {
                let allowedPort = allowedComponents.port ?? (allowedScheme == "https" ? 443 : 80)
                let allowedOrigin = "\(allowedScheme)://\(allowedHost):\(allowedPort)"
                if scriptOrigin == allowedOrigin {
                    return true
                }
            }
        }

        return false
    }
    
    private static func checkNonceValue(_ nonce: String, urlOrigin: String) -> (Bool, [SecurityWarning]) {
        var warnings: [SecurityWarning] = []
        var isValid: Bool = false
        
        //TODO: Need multiple test regarding entropy. Usually 2~3 is english workds so i guess a nonce must be higher ?
        let (realNonce, entrValue) = CommonTools.isHighEntropy(nonce, 3.2)
        if !realNonce {
            let entropyValue = entrValue ?? 0
            warnings.append(SecurityWarning(
                message: "nonce value `\(nonce)` has a low entropy \(entropyValue).",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.nonceValueIsWeak,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_CSP_TOO_MANY_URL_SOURCES],
                machineMessage: "nonce_entropy_low"
            ))
        } else {
            isValid = true
        }
        
        return (isValid, warnings)
    }
    
}
