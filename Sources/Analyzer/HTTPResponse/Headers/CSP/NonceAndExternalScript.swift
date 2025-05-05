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



struct NonceAndExternalScript {
    static func analyze( scriptValueToCheck: ScriptSourceToMatchCSP?,
                         scriptDirective: [Data: CSPValueType],
                         urlOrigin: String,
                         script: inout ScriptExtractionResult?) -> [SecurityWarning] {
        
        var warnings:[SecurityWarning] = []
        
        guard let scriptValueToCheck = scriptValueToCheck,
              (!scriptValueToCheck.nonceList.isEmpty || !scriptValueToCheck.externalSources.isEmpty) else {
            warnings.append(SecurityWarning(
                message: "No nonce or external script sources detected despite CSP script directive.",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: .header
            ))
            return warnings
        }
        
        // script values to check nonce and external urls
        let nonceValueFromScript = Set(scriptValueToCheck.nonceList)
        let srcValueFromScript = scriptValueToCheck.externalSources
        
        // The compact map is eaiser to understand than using .some syntax ->
        // get number of nonce and inline or dataURI script
        let inlineOrDataURICount = script?.scripts.compactMap {
            ($0.origin == .inline || $0.origin == .dataURI) ? $0 : nil
        }.count
        let nonceScriptCount = script?.scripts.compactMap { $0.noncePos != nil ? $0 : nil }.count

        var nonceValueFromDirective: [String] = []
        var srcValueFromDirective: Set<String> = []

        // Flag the missing nonce script, no penalty
        if let inlineOrDataCount = inlineOrDataURICount,
           let nonceCount = nonceScriptCount,
           nonceCount > 0,
           inlineOrDataCount != nonceCount
        {
            if var script = script {
                for index in script.scripts.indices {
                    let scriptItem = script.scripts[index]
                    if scriptItem.nonceValue == nil && (scriptItem.origin == .inline || scriptItem.origin == .dataURI) {
                        script.scripts[index].findings4UI = (script.scripts[index].findings4UI ?? []) + [("Missing nonce value", .info)]
                    }
                }
            }
            warnings.append(SecurityWarning(
                message: "Some inline or data URI scripts don't have a nonce value despite CSP nonce directive. They'll likely be ignored by the browser.",
                severity: .info,
                penalty: 0,
                url: urlOrigin,
                source: .header
            ))
        }
        
        for (data, valueType) in scriptDirective {
            if let stringValue = String(data: data, encoding: .utf8) {
                if stringValue.contains("nonce") {
                    nonceValueFromDirective.append(stringValue)
                }
                else if valueType == .source {
                    if stringValue != "http:" && stringValue != "https:" && !stringValue.contains("'self'") {
                        srcValueFromDirective.insert(stringValue)
                    }
                }
            } else {
                warnings.append(SecurityWarning(
                    message: "Unable to decode directive value.",
                    severity: .suspicious,
                    penalty: -10,
                    url: urlOrigin,
                    source: .header
                ))
            }
        }
//        DEBUG
//        print("Directive: ", nonceValueFromDirective)
        var cleanedNonceFromDirective = Set(nonceValueFromDirective.map { $0.replacingOccurrences(of: "nonce-", with: "") })
        cleanedNonceFromDirective =  Set(cleanedNonceFromDirective.map { String($0.dropFirst().dropLast()) })
//        DEBUG
//        print("Cleaned directive: ", cleanedNonceFromDirective)
//        print("Nonce value from scripts:", nonceValueFromScript)
        
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
                    source: .header
                ))
            }
        } else {
            warnings.append(SecurityWarning(
                message: "Nonce values in CSP header and script do not match.",
                severity: .suspicious,
                penalty: -10,
                url: urlOrigin,
                source: .header
            ))
        }
//        waived of dataURI with nonce value -> still not good a SRI would be better.
        if let script = script {
            let dataURIScripts = script.scripts.filter { $0.origin == .dataURI }
            
            let allDataURIsHaveNonce = dataURIScripts.allSatisfy { $0.nonceValue != nil }
            
            if allDataURIsHaveNonce && !dataURIScripts.isEmpty {
                warnings.append(SecurityWarning(
                    message: "All data URI scripts correctly have nonce verified values.",
                    severity: .info,
                    penalty: 30,
                    url: urlOrigin,
                    source: .header
                ))
            }
        }
        
        // Track how many scripts actually matched the CSP sources
        var usedScriptCount = 0
//DEBUG
//        for a in srcValueFromScript {
//            print("url: ", a)
//        }
        
        for scriptSource in srcValueFromScript {
            if !isExternalScriptAllowed(scriptURL: scriptSource, allowedSources: srcValueFromDirective) {
                warnings.append(SecurityWarning(
                    message: "External script '\(scriptSource)' not covered by CSP policy.",
                    severity: .suspicious,
                    penalty: -10,
                    url: urlOrigin,
                    source: .header
                ))
            } else {
                usedScriptCount += 1
            }
        }

        // After checking each external script
        let authorizedSourceCount = srcValueFromDirective.count
        let excessiveSourceCount = authorizedSourceCount - usedScriptCount

        if excessiveSourceCount >= 2 {
            let softPenalty = max(excessiveSourceCount * -1, -20) // cap maximum penalty to -20
            warnings.append(SecurityWarning(
                message: "CSP script-src authorizes \(authorizedSourceCount) external sources, but only \(usedScriptCount) are used. Excessive permissions weaken the policy.",
                severity: .suspicious,
                penalty: softPenalty,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_CSP_TOO_MANY_URL_SOURCES]
            ))
        }
        
        return warnings
    }
    
    
    
    
    static func isExternalScriptAllowed(scriptURL: String, allowedSources: Set<String>) -> Bool {
        // Normalize the script URL
        guard let scriptComponents = URL(string: scriptURL.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))) else {
            return false
        }
        
        let scriptHost = scriptComponents.host ?? ""

        for rawAllowedSource in allowedSources {
            var allowedSource = rawAllowedSource.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "/"))

            // Normalize allowedSource into a parseable URL
            if !allowedSource.hasPrefix("http") {
                allowedSource = "https://" + allowedSource
            }
//DEBUG
//            print("allowedSource: \(allowedSource) vs scriptHost: \(scriptHost)")

            // 1. Wildcard "*"
            if allowedSource == "*" {
                return true
            }

            // 2. Allow any HTTPS
            if allowedSource == "https:" {
                if scriptComponents.scheme == "https" {
                    return true
                }
            }

            // 3. Wildcard domain "*.example.com"
            if allowedSource.hasPrefix("https://*.") {
                let baseDomain = allowedSource.replacingOccurrences(of: "https://*.", with: "")
                if scriptHost.hasSuffix(baseDomain) {
                    return true
                }
            }

            // 4. Full host match
            if let allowedComponents = URL(string: allowedSource),
               let allowedHost = allowedComponents.host {
                if scriptHost == allowedHost {
                    return true
                }
            }
        }
        
        return false
    }
}
