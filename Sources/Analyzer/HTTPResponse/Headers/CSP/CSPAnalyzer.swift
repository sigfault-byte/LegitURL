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
        var structuredCSP: [String: [Data: CSPValueType]] = [:]
        let scriptValueToCheckUnwrapped = scriptValueToCheck ?? nil
        var originCSP = "CSP"
//        var SrcScriptConfig: [String: Int32] = [:]
        
        // Check if  CSP exists. OtherWise fall back to CSP-RO, but still flagged as a missign CSP.
        var babylonCSP = headers["content-security-policy"]?.data(using: .utf8) ?? Data()
//        csp-report-only does NOT enforce anything
        if babylonCSP.isEmpty {
            babylonCSP = headers["content-security-policy-report-only"]?.data(using: .utf8) ?? Data()
            if !babylonCSP.isEmpty {
                warnings.append(SecurityWarning(
                    message: "Only a Content-Security-Policy-Report-Only header was found. This policy does not enforce any security restrictions, it only reports violations.\nWe will still analyze its value, but it has no protective effect.",
                    severity: .dangerous,
                    penalty: PenaltySystem.Penalty.CSPReportOnly,
                    url: urlOrigin,
                    source: .header,
                    bitFlags: [.HEADERS_CSP_MISSING]
                ))
                originCSP = "CSP-RO"
            }
        }
        // return early
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
                    directiveSourceTraits: [:],
                    source: ""
                )
            )
        }
        
//        TODO: important to check regarding permission of all the various bs in its own file  otherwise too clutered here . Using string parsing is enough? or fast 'self / *' byte lookup might be better to catch only meaningfull value?
//        let babylonPermissionsPolicy = headers["permissions-policy"]?.data(using: .utf8) ?? Data()
        
//        let babylonCSPSize = babylonCSP.count
        //Clean and extract the CSP into a dictionnary : [String: [Data: CSPValueType]] = [:]
        let (ExtractedStructuredCSP, extractorWarnings) = CSPExtractor.extract(from: babylonCSP,
                                                                               url: urlOrigin)
        warnings.append(contentsOf: extractorWarnings)
        
        structuredCSP = ExtractedStructuredCSP
        
        //Check If script-src or default-src or require-trusted-types-for exists.
        let coreDirectiveWarnings = ScriptAndDefaultDirective.evaluate(structuredCSP: structuredCSP, url: urlOrigin)
        warnings.append(contentsOf: coreDirectiveWarnings)
        
        let directiveBitFlags: [String: Int32] = parseCSP(structuredCSP)
        
        //Check illogic missconfig, only appen script-src or default-src warnings
        let misconfigWarningsScriptAndDefautlSrc = CSPConfigAnalysis.analyze(directiveFlags: directiveBitFlags, url: urlOrigin)
        
        warnings.append(contentsOf: misconfigWarningsScriptAndDefautlSrc)
        
        var scriptSrc: String = ""
        for _ in structuredCSP.keys {
            if structuredCSP.keys.contains("script-src") {
                scriptSrc = "script-src"
                //TODO: Once the other directive are correctly flag and the UI follows, default source should be reflected on all missing
                //source to output precisely whath is happening
            } else if structuredCSP.keys.contains("default-src") {
                scriptSrc = "default-src"
            }
        }
        let warningsToAppend = ScriptAndDefaultDirective.analyze(directiveName: scriptSrc,
                                                                     bitFlagCSP: CSPBitFlag(rawValue: directiveBitFlags[scriptSrc] ?? 0),
                                                                 url: urlOrigin, source: originCSP)
        
        warnings.append(contentsOf: warningsToAppend)
        
        //TODO: Finish this !!!!!!!
        // compare the script source and nonce only if the CSP directive script-src has urls except self or nonce value
        if let scriptDirective = structuredCSP["script-src"] ?? structuredCSP["default-src"] {
            var hasNonce = false
            var hasExternalURL = false

            for (_, valueType) in scriptDirective {
                if valueType == .nonce {
                    hasNonce = true
                }
                if valueType == .source {
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
            //TODO: check if sha then check is the count match, and compute sha
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
                if type == .source {
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
                if type == .source {
                    hasOnlySelf = false
                }
                if type == .keyword {
                    if value != Data("'self'".utf8) && !value.isEmpty {
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
                directiveSourceTraits: directiveSourceTraits,
                source: originCSP
            )
        )
    }
}
