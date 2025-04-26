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
        let nonceValueFromScipt = Set(scriptValueToCheck.nonceList)
        let srcValueFromScript = scriptValueToCheck.externalSources
        
        // The compact map is eaiser to understand than using .some syntax ->
        // get number of nonce and inline script
        let inlineScriptCount = script?.scripts.compactMap { $0.origin == .inline ? $0 : nil }.count
        let nonceScriptCount = script?.scripts.compactMap { $0.noncePos != nil ? $0 : nil}.count
        
        var nonceValueFromDirective: [String] = []
        var srcValueFromDirective : [String] = []
        
        
        // Flag the missing nonce script, no penalty
        if let inlineCount = inlineScriptCount,
           let nonceCount = nonceScriptCount,
           nonceCount > 0,
           inlineCount != nonceCount
        {
            if script != nil {
                for index in script!.scripts.indices {
                    if script!.scripts[index].nonceValue == nil {
                        script!.scripts[index].findings4UI = (script!.scripts[index].findings4UI ?? []) + [("Missing nonce value", .info)]
                    }
                }
            }
            warnings.append(SecurityWarning(message: "Some inline script don't have a nonce value despite CSP nonce directive. They'll likely be ignored by the browser.",
                                            severity: .info,
                                            penalty: 0,
                                            url: urlOrigin,
                                            source: .header))
        }
    
    
    
    for (data, valueType) in scriptDirective {
        if let stringValue = String(data: data, encoding: .utf8) {
            switch valueType {
                case .nonce:
                    nonceValueFromDirective.append(stringValue)
                case .url:
                    srcValueFromDirective.append(stringValue)
                default:
                    break // Ignore 'self', 'unsafe-inline', sha256 hashes, etc. for now
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
    
    
    
    
    for nonceValue in nonceValueFromScipt {
        print ("nonceValue: \(nonceValue)")
    }
    
    for externalSource in srcValueFromScript {
        print ("externalSource: \(externalSource)")
    }
    
    return warnings
}

/// Checks if the script's nonce matches any allowed CSP header nonces
static func isScriptNonceMatching(headerNonces: Set<String>, scriptNonce: String?) -> Bool {
    guard let scriptNonce = scriptNonce else { return false }
    
    for headerNonce in headerNonces {
        let cleanHeaderNonce = headerNonce.replacingOccurrences(of: "nonce-", with: "")
        if scriptNonce == cleanHeaderNonce {
            return true
        }
    }
    
    return false
}
}
