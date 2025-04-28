//
//  HeaderAnalyzerFast.swift
//  LegitURL
//
//  Created by Chief Hakka on 24/04/2025.
//
import Foundation

struct CSPAnalyzer {
    static func analyze(_ headers: [String: String],
                        urlOrigin: String,
                        scriptValueToCheck: ScriptSourceToMatchCSP?, // To check nonce and external
                        script: inout ScriptExtractionResult?) // flag fails from the checks
    
    -> (warnings: [SecurityWarning], result: ClassifiedCSPResult) {
//Only CSP kinda need byte parsing. Permission policy might not need it.
//All others can be handled with strin analysis.
        
//        if let csp = headers["content-security-policy"] {
//            let babylonCSP = Data(csp.utf8)
//
//        }
        var warnings: [SecurityWarning] = []
        var directiveSlices: [Range<Int>] = []
        var directiveValues: [[Data: [Data]]] = []
        var structuredCSP: [String: [Data: CSPValueType]] = [:]
        let scriptValueToCheckUnwrapped = scriptValueToCheck ?? nil
//        var SrcScriptConfig: [String: Int32] = [:]
        
        
        var babylonCSP = headers["content-security-policy"]?.data(using: .utf8) ?? Data()
        if babylonCSP.isEmpty {
            babylonCSP = headers["content-security-policy-report-only"]?.data(using: .utf8) ?? Data()
        }
        guard !babylonCSP.isEmpty else {
            warnings.append(SecurityWarning(
                message: "Headers do not contain a Content-Security-Policy",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.missingCSP,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_CSP_MISSING]
            ))
            return (
                warnings,
                ClassifiedCSPResult(
                    structuredCSP: structuredCSP,
                    directiveBitFlags: [:],
                    directiveSourceTraits: [:]
                )
            )
        }
        
//        TODO: important to check regarding permission of all the various bs in its own file this otherwise too clutered here . Using string parsing is enough
//        let babylonPermissionsPolicy = headers["permissions-policy"]?.data(using: .utf8) ?? Data()
        
//        let babylonCSPSize = babylonCSP.count
        if babylonCSP.last != 0x3B {
            babylonCSP.append(0x3B)
            // Flag incomplete CSP as a soft misconfiguration -> no one gives a flyin f and alnost never puts it
//            warnings.append(SecurityWarning(
//                message: "CSP does not end with semicolon — likely malformed or incomplete.",
//                severity: .suspicious,
//                penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
//                url: urlOrigin,
//                source: .header,
//                bitFlags: [.HEADERS_CSP_MALFORMED]
//            ))
        }
        // Extract ranges for each directive block (split by ;)
        var lastStart = 0
        for i in 0..<babylonCSP.count {
            if babylonCSP[i] == HeadHeaderByteSignatures.semicolon {
                directiveSlices.append(lastStart..<i)
                lastStart = i + 1
            }
        }
        
        
        // clean slice, and sort them into a dict
        for slice in directiveSlices {
            let cleanedSlice = CSPUtils.cleaningCSPSlice(slice: slice, in: babylonCSP)
            
            if let parsedDirective = CSPUtils.parseDirectiveSlice(cleanedSlice) {
                directiveValues.append(parsedDirective)
            } else {
                warnings.append(SecurityWarning(
                    message: "Failed to parse CSP directive.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_CSP_MALFORMED]
                ))
            }
        }
        
        
        
        //Sorting into a dictionnary with keys as values and values as their nature
        var directiveCount: [String: Int] = [:]

        for slice in directiveValues {
            for (directiveNameData, valueList) in slice {
                guard let directiveName = String(data: directiveNameData, encoding: .utf8) else {
                    warnings.append(SecurityWarning(
                        message: "Unrecognized CSP directive encoding.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                        url: urlOrigin,
                        source: .header,
                        bitFlags: [.HEADERS_CSP_MALFORMED]
                    ))
                    continue
                }

                var finalDirectiveName = directiveName

                if let count = directiveCount[directiveName] {
                    finalDirectiveName = "\(directiveName)_\(count)"
                    directiveCount[directiveName] = count + 1

                    if count == 1 {
                        warnings.append(SecurityWarning(
                            message: "Duplicate CSP directive '\(directiveName)' detected.",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                            url: urlOrigin,
                            source: .header,
                            bitFlags: [.HEADERS_CSP_MALFORMED]
                        ))
                    }
                } else {
                    directiveCount[directiveName] = 1
                }

                var typedValues: [Data: CSPValueType] = [:]
                for value in valueList {
                    let valueType = CSPUtils.classifyCSPValue(value)
                    typedValues[value] = valueType
                }

                structuredCSP[finalDirectiveName] = typedValues
            }
        }
        
        // Check if critical directives are missing, this might need a higher penalty than missing CSP.
        let hasDefaultSrc = structuredCSP.keys.contains("default-src")
        let hasScriptSrc = structuredCSP.keys.contains("script-src")
        let hasObjectSrc = structuredCSP.keys.contains("object-src")
        let hasRequiredTrustedTypeFor = structuredCSP.keys.contains("require-trusted-types-for")

        if (!hasDefaultSrc && (!hasScriptSrc || !hasObjectSrc)) && !hasRequiredTrustedTypeFor {
            warnings.append(SecurityWarning(
                message: "CSP is missing both 'default-src' and a critical combination of 'script-src' and 'object-src'.",
                severity: .dangerous,
                penalty: PenaltySystem.Penalty.fakeCSP,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_FAKE_CSP]
            ))
//            VERY Specific else, i hate it
        } else if hasRequiredTrustedTypeFor {
            if let trustedTypesDirective = structuredCSP["require-trusted-types-for"] {
                let hasScriptRequirement = trustedTypesDirective.keys.contains(where: { data in
                    guard let stringValue = String(data: data, encoding: .utf8) else { return false }
                    return stringValue == "'script'"
                })
                
                if hasScriptRequirement {
                    // Now you know: require-trusted-types-for 'script' is correctly configured
                    warnings.append(SecurityWarning(
                        message: "Modern CSP: Trusted Types enforced for scripts.",
                        severity: .info,
                        penalty: 5, // small bonus very rare, very secured against xss ?
                        url: urlOrigin,
                        source: .header,
                        bitFlags: [.HEADERS_CSP_TRUSTED_TYPES]
                    ))
                } else {
                    // 'require-trusted-types-for' directive exists but doesn't target 'script'.)
                    warnings.append(SecurityWarning(
                        message: "CSP 'require-trusted-types-for' directive found but missing 'script' value. Potential misconfiguration.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.fakeCSP,
                        url: urlOrigin,
                        source: .header,
                        bitFlags: [.HEADERS_FAKE_CSP]
                    ))
                }
            }
        }
        
        let directiveBitFlags: [String: Int32] = parseCSP(structuredCSP)
        var scriptSrc: String = ""
        for _ in structuredCSP.keys {
            if structuredCSP.keys.contains("script-src") {
                scriptSrc = "script-src"
            } else if structuredCSP.keys.contains("default-src") {
                scriptSrc = "default-src"
            }
        }
        let warningsToAppend = CSPDirective.analyzeScriptOrDefaultSrc(directiveName: scriptSrc,
                                                                     bitFlagCSP: CSPBitFlag(rawValue: directiveBitFlags[scriptSrc] ?? 0),
                                                                     url: urlOrigin)
        warnings.append(contentsOf: warningsToAppend)
        
        
        
        // compare the script source and nonce only if the CSP directive script-src has urls except self or nonce value
        if let scriptDirective = structuredCSP[scriptSrc] {
            var hasNonce = false
            var hasExternalURL = false

            for (_, valueType) in scriptDirective {
                if valueType == .nonce {
                    hasNonce = true
                }
                if valueType == .url {
                    hasExternalURL = true
                }
            }

            if hasNonce || hasExternalURL {
                let extraWarnings = NonceAndExternalScript.analyze(
                    scriptValueToCheck: scriptValueToCheckUnwrapped,
                    scriptDirective: scriptDirective,
                    urlOrigin: urlOrigin,
                    script: &script
                )
                warnings.append(contentsOf: extraWarnings)
            }
        }
        

//                DEBUG
//        for (directive, values) in structuredCSP {
//            print("Directive: \(directive)")
//            for (value, type) in values {
//                let valStr = String(data: value, encoding: .utf8) ?? "(unknown)"
//                print("  ├─ \(valStr) → \(type)")
//            }
//        }

        var directiveSourceTraits: [String: DirectiveSourceInfo] = [:]

        for (directive, values) in structuredCSP {
            var urlCount = 0
            var hasHTTP = false
            var hasWildcard = false
            var hasOnlySelf = true
            var hasHTTPButLocalhost: Bool = false

            for (value, type) in values {
                if type == .url {
                    urlCount += 1
                    hasOnlySelf = false

                    if value.starts(with: Data("http:".utf8)) {
                        if value.starts(with: Data("http://localhost:".utf8)) || value.starts(with: Data("http://127.".utf8))  {
                            hasHTTPButLocalhost = true
                            break
                        }
                        hasHTTP = true
                    }
                    if value.starts(with: Data("*".utf8)) {
                        hasWildcard = true
                    }
                }
                if type == .scheme {
                    hasOnlySelf = false
                }
                if type == .keyword {
                    if value != Data("'self'".utf8) {
                        hasOnlySelf = false
                    }
                }
            }
            
            

            directiveSourceTraits[directive] = DirectiveSourceInfo(
                urlCount: urlCount,
                hasHTTP: hasHTTP,
                hasHTTPButLocalhost: hasHTTPButLocalhost,
                hasWildcard: hasWildcard,
                onlySelf: hasOnlySelf
            )
        }

        
        
        
        
//        Crazy tracking website like x.com
//        if scriptSrcCount > 20 && connectSrcCount > 50 {
//            warnings.append(SecurityWarning(
//                message: "CSP allows more than \(scriptSrcCount * connectSrcCount) dynamic script+connect combinations — likely tracking or malware vector.",
//                severity: .critical,
//                penalty: -100,
//                url: urlOrigin,
//                source: .header,
//                bitFlags: [.HEADERS_CSP_OVEREXPANDED]
//            ))
//        }
        
        
        
        return (
            warnings,
            ClassifiedCSPResult(
                structuredCSP: structuredCSP,
                directiveBitFlags: directiveBitFlags,
                directiveSourceTraits: directiveSourceTraits
            )
        )
    }
}
