//
//  ExternalAndNonceCheck.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/06/2025.
//
import Foundation


struct ExternalAndNonceCheck {
    
    static func analyze(scriptSrcFromCSP: [Data: CSPValueType],
                        scriptUsedNonce: ScriptSourceToMatchCSP?, // TODO: change the type name
                        scripts: inout ScriptExtractionResult?,
                        coreURL: String, CSPType: String)
    -> [SecurityWarning] {
#if DEBUG
        print("---------------------------START-----ExternalAndNonceCheck.swift --------------------------------")
        //        for (data, cspValue) in scriptSrcFromCSP {
        //            if cspValue == .keyword {
        //                print((String(data: data, encoding: .utf8) ?? ""))
        //            }
        //        }
#endif
        //MARK: ALL the variable needed
        //CSPType to not have double penalty
        let CSPRO = CSPType == "CSP" ? false : true
        //warning obj
        var warnings: [SecurityWarning] = []
        // copy of scripts to pop
        var scriptsUnwrapped = scripts?.scripts ?? []
        scriptsUnwrapped = scriptsUnwrapped.filter { $0.origin != .dataScript }
        // create the origin url to create a fake source representing 'self', coreURL is host + path. Scheme is always https, port is always 443 ... or should be
        // just trim path for now
        let hostOnly = coreURL.components(separatedBy: "/").first ?? ""
        
        //MARK: CSP VALUES
        // nonce value from CSP
        var nonceValuefromCSP = [String]()
        for (value, key) in scriptSrcFromCSP {
            if key == .nonce {
                nonceValuefromCSP.append(String(data: value, encoding: .utf8) ?? "")
            }
            //TODO:  if key == .hasHash
        }
        let CSPhasNonce = !nonceValuefromCSP.isEmpty
        
        //make a set and trim `nonce-` prefix
        let nonceCSPValueSet = Set(nonceValuefromCSP.map {
            $0
                .replacingOccurrences(of: "nonce-", with: "")
                .replacingOccurrences(of: "'", with: "")
                .replacingOccurrences(of: "\"", with: "")
        })
        
        // source from script-src
        //'self' in bytes ...
        let selfData: Data = "'self'".data(using: .utf8)!
        let dataData: Data = "'data:'".data(using: .utf8)!
        let strictDynData: Data = "'strict-dynamic'".data(using: .utf8)!
        //        let blobData: Data = "'blob:'".data(using: .utf8)!
        var CSPHasSelf: Bool = false
        var CSPHasData: Bool = false
        var CSPHasStrictDynamic: Bool = false
        //        var CSPHasBlob: Bool = false
        // bool to check if * or https: is inside -> they were al ready flag no need for a new warning
        var openBar: Bool = false
        
        
        var srcValuefromCSP: [String] = []
        for (value, key) in scriptSrcFromCSP {
            if key == .source {
                if value == dataData {
                    CSPHasData = true
                } else {
                    srcValuefromCSP.append(String(data: value, encoding: .utf8) ?? "")
                }
            } else if key == .wildcard {
                openBar = true
            } else if key == .keyword {
                if value == selfData {
                    let  selfValue = "https://" + hostOnly
                    CSPHasSelf = true
                    srcValuefromCSP.append(selfValue)
                } else if value == strictDynData {
                    CSPHasStrictDynamic = true
                }
            }
        }
        var srcValuefromCSPSet = Set(srcValuefromCSP.map {
            $0
                .replacingOccurrences(of: "'", with: "")
                .replacingOccurrences(of: "\"", with: "")
                .replacingOccurrences(of: "https://", with: "")
                .replacingOccurrences(of: "//", with: "")
        })
        
        if openBar {
            addWarning(warningsArray: &warnings, m: "wildcard (*) in script-src, skipping CSP script-src and script src check", s: .suspicious, p: -1, url: coreURL, source: .header)
            return warnings
        }
        //flag http
        let insecureSources = srcValuefromCSPSet.filter { $0.hasPrefix("http://") }
        
        for badSource in insecureSources {
            addWarning(warningsArray: &warnings,
                       m: "CSP source uses insecure scheme: \(badSource)",
                       s: .suspicious,
                       p: CSPRO ? 0 : -10,
                       url: coreURL,
                       source: .header,
                       machineMessage: "csp_http_source")
        }
        srcValuefromCSPSet = srcValuefromCSPSet.filter { !$0.hasPrefix("http://") }
        
        // check nonce count
        if nonceCSPValueSet.count > 1 {
            addWarning(warningsArray: &warnings, m: "Too many nonce values in script-src", s: .suspicious, p: CSPRO ? 0 : -10, url: coreURL, source: .header)
        }
        
        
        //MARK: SCRIPs VALUES
        // nonce and source from scripts
        var nonceValueFromScripts: [String] = []
        var srcValueFromScripts = [String]()
        
        // has relative path
        var scriptHasRelative: Bool = false
        
        if let scripts = scripts {
            for script in scripts.scripts {
                if let _ = script.origin, let nonceValue = script.nonceValue {
                    nonceValueFromScripts.append(nonceValue)
                }
                if let source = script.extractedSrc {
                    if (script.origin == .relative ||
                        script.origin == .protocolRelative ||
                        script.origin == .moduleRelative) {
                        scriptHasRelative = true
                    } else if (script.origin == .httpExternal ||
                               script.origin == .httpsExternal ||
                               script.origin == .moduleExternal
                    ) {
                        srcValueFromScripts.append(source)
                    }
                }
            }
        }
        
        let nonceValueFromScriptsSet = Set(nonceValueFromScripts)
        //TODO: This sucks and is from the old logic re-fac-tor ! ASAP
        var srcValueFromScriptsSet = Set(srcValueFromScripts.map {
            $0
                .replacingOccurrences(of: "'", with: "")
                .replacingOccurrences(of: "\"", with: "")
                .replacingOccurrences(of: "https://", with: "")
                .replacingOccurrences(of: "//", with: "")
        })
        
        //flag http
        let insecureSourcesScript = srcValueFromScriptsSet.filter { $0.hasPrefix("http://") }
        
        for badSource in insecureSourcesScript {
            addWarning(warningsArray: &warnings,
                       m: "Script source uses insecure scheme: \(badSource)",
                       s: .suspicious,
                       p: CSPRO ? 0 : -10,
                       url: coreURL,
                       source: .header,
                       machineMessage: "script_http_source")
        }
        srcValueFromScriptsSet = srcValueFromScriptsSet.filter { !$0.hasPrefix("http://") }
        
        
        //MARK: Nonce match
        if nonceValueFromScriptsSet.count > 1 {
            addWarning(warningsArray: &warnings, m: "Different nonce values in script attr", s: .info, p: 0, url: coreURL, source: .body)
        }
        //TODO: later will be use to match SHA ///////
        //check nonce entropy ? might be useless -> log as info ? -5 for now
        let nonceValue: String = nonceValueFromScriptsSet.first ?? ""
        if !nonceValue.isEmpty {
            let (isValid, warning) = checkNonceValue(nonceValue, urlOrigin: coreURL)
            if !isValid {
                warnings.append(contentsOf: warning)
            }
        }
        //nonce match
        let allNoncesValid = nonceValueFromScriptsSet.isSubset(of: nonceCSPValueSet)
        //        filter out nonce script that where whitelisted by nonce ... or hash in the future !
        if allNoncesValid {
            scriptsUnwrapped = scriptsUnwrapped.filter {
                guard let nonce = $0.nonceValue else { return true }  // keep if no nonce
                return !nonceCSPValueSet.contains(nonce)              // keep if nonce is not in CSP (invalid nonce)
            }
        }
        // if strict-dyn, no need to go further only protected source are executed
        if CSPHasStrictDynamic {
            if !scriptsUnwrapped.isEmpty {
                var scriptIDRemaining = Set<UUID>()
                for scriptpb in scriptsUnwrapped {
                    scriptIDRemaining.insert(scriptpb.id)
                }
                for id in scriptIDRemaining {
                    if let scriptToMatch = scripts?.scripts, !scriptToMatch.isEmpty {
                        for i in 0..<scripts!.scripts.count {
                            if scripts!.scripts[i].id == id {
                                if scripts!.scripts[i].findings4UI == nil {
                                    scripts!.scripts[i].findings4UI = []
                                }
                                scripts!.scripts[i].findings4UI?.append((
                                    message: "Strict-Dynamic CSP but non-protected script",
                                    severity: .suspicious,
                                    pos: nil
                                ))
                            }
                        }
                    }
                }
            } else if scriptsUnwrapped.isEmpty {
                addWarning(warningsArray: &warnings, m: "All script whitelisted by nonce in CSP", s: .good, p: CSPRO ? 0 : PenaltySystem.Penalty.allScripttNonced, url: coreURL, source: .header)
                return warnings
            }
            return warnings
        }
        // if scriptUnwrapped is empty, all script were cleaned by the nonce.
        if scriptsUnwrapped.isEmpty {
            addWarning(warningsArray: &warnings, m: "All script whitelisted by nonce in CSP", s: .good, p: CSPRO ? 0 : PenaltySystem.Penalty.allScripttNonced, url: coreURL, source: .header)
            return warnings
        }
        
        //MARK: Src check
        //filter out relative if CSP has sefl, but do not pop out the hostOnly added source, in case some script are using full url for relative script
        if CSPHasSelf && scriptHasRelative {
            scriptsUnwrapped = scriptsUnwrapped.filter { origin in
                guard let origin = origin.origin else { return true }
                return origin != .relative && origin != .moduleRelative
            }
        } else if scriptHasRelative {
            addWarning(warningsArray: &warnings,
                       m: "self missing from CSP but relative script are present",
                       s: .suspicious,
                       p: CSPRO ? 0 : -10,
                       url: coreURL,
                       source: .header)
        }
        // filter out datauri if csp has data:
        let scriptHasURILeft: Bool = scriptsUnwrapped.map { $0.origin == .dataURI }.contains(true)
        if CSPHasData && scriptHasURILeft {
            scriptsUnwrapped = scriptsUnwrapped.filter { $0.origin != .dataURI }
        }
        // TODO: filter out blob if csp has blob: ? -> need to detect blob first... no example need to build an example
        
        // Actual source external check
        
        var allowedSources: [AllowedSrc] = []
        for src in srcValuefromCSPSet {
            allowedSources.append(extractHostAndPath(from :src))
        }
        
        //        print("Allowed SRC------------------------------------")
        //        print(allowedSources)
        
        var idToPop = Set<UUID>()
        for remainingScript in scriptsUnwrapped {
            if let src = remainingScript.extractedSrc, src != ""  {
                let cleanedSRC = src
                    .replacingOccurrences(of: "'", with: "")
                    .replacingOccurrences(of: "\"", with: "")
                    .replacingOccurrences(of: "https://", with: "")
                    .replacingOccurrences(of: "//", with: "")
                let isAllowed = isScriptAllowedByCSP(scriptSrc: cleanedSRC, allowedSources: &allowedSources)
                if isAllowed {
                    idToPop.insert(remainingScript.id)
                }
            }
        }
        
        for id in idToPop {
            scriptsUnwrapped.removeAll { $0.id == id }
        }
        //        pop out self "fake" value hostOnly. Either it s been marked as used if the full host was used in script or there was relative. other wise it is ununsed.
        if CSPHasSelf && scriptHasRelative {
            allowedSources = allowedSources.filter { $0.host != hostOnly }
        }
        
        let unusedSources = allowedSources.filter { !$0.wasUsed }
        
        if !unusedSources.isEmpty {
            let count = unusedSources.count
            let preview = unusedSources.map { $0.host + ($0.path ?? "") }
            let previewList = preview.joined(separator: ", ")
            
            
            //TODO: Once enought test are done, this should give real penalties
            let message = count > 3
            ? "CSP defines \(count) script sources that were never used: \(previewList)"
            : "CSP defines unused script sources: \(previewList)"
            
            addWarning(
                warningsArray: &warnings,
                m: message,
                s: .info,
                p: 0,
                url: coreURL,
                source: .header,
                machineMessage: "csp_unused_sources"
            )
        }
        if !CSPhasNonce {
            scriptsUnwrapped = scriptsUnwrapped.filter {
                $0.origin != .inline && $0.origin != .moduleInline
            }
        }
        
        let remainingScriptsNotAllowed = scriptsUnwrapped.count
        if remainingScriptsNotAllowed > 0 {
            addWarning(
                warningsArray: &warnings,
                m: "Some script in the html are not allowed by the CSP: \(remainingScriptsNotAllowed)",
                s: .info,
                p: 0,
                url: coreURL,
                source: .header,
                machineMessage: "csp_unused_sources"
            )
        }
        
        
#if DEBUG
        print("REMAINING: ", scriptsUnwrapped.map {print($0.extractedSrc ?? "NOTHING", $0.origin?.rawValue ?? "NOTHING") } )
        print("--------------------------------END---ExternalAndNonceCheck.swift --------------------------------")
#endif
        return warnings
    }
    
    
    private static func isScriptAllowedByCSP(scriptSrc: String, allowedSources: inout [AllowedSrc]) -> Bool {
        for index in allowedSources.indices {
            let allowed = allowedSources[index]
            if allowed.host.hasPrefix("*.") {
                let suffix = String(allowed.host.dropFirst(2))
                let scriptHost = scriptSrc.components(separatedBy: "/").first ?? ""
                let labels = scriptHost.split(separator: ".")
                let suffixLabels = suffix.split(separator: ".")
                if labels.count > suffixLabels.count,
                   scriptHost.hasSuffix(suffix) {
                    allowedSources[index].wasUsed = true
                    return true
                }
            } else if allowed.path == nil {
                if let scriptHost = scriptSrc.components(separatedBy: "/").first,
                   scriptHost == allowed.host {
                    allowedSources[index].wasUsed = true
                    return true
                }
            } else if let path = allowed.path {
                let full = allowed.host + path
                if path.hasSuffix("/") {
                    if scriptSrc.hasPrefix(full) {
                        allowedSources[index].wasUsed = true
                        return true
                    }
                } else {
                    if scriptSrc == full {
                        allowedSources[index].wasUsed = true
                        return true
                    }
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
    
    // useless warning  helper
    private static func addWarning(warningsArray: inout [SecurityWarning],
                                   m: String, s: SecurityWarning.SeverityLevel,
                                   p: Int,
                                   url: String,
                                   source: SecurityWarning.SourceType,
                                   bitFlags: WarningFlags = [],
                                   machineMessage: String = "") {
        
        warningsArray.append(SecurityWarning(
            message: m,
            severity: s,
            penalty: p,
            url: url,
            source: source,
            bitFlags: bitFlags,
            machineMessage: machineMessage
        ))
    }
    
    // Helper to split a source into host + optional path
    private static func extractHostAndPath(from source: String) -> AllowedSrc {
        if let firstSlash = source.firstIndex(of: "/") {
            let host = String(source[..<firstSlash])
            let path = String(source[firstSlash...])
            return AllowedSrc(host: host, path: path)
        } else {
            return AllowedSrc(host: source, path: nil)
        }
    }
    
    struct AllowedSrc {
        let host: String
        let path: String?
        var wasUsed: Bool = false
    }
}
