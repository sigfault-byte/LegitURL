//
//  HeaderAnalyzerFast.swift
//  LegitURL
//
//  Created by Chief Hakka on 24/04/2025.
//
import Foundation

struct CSPAndPPAnalyzer {
    static func analyze(_ headers: [String: String], urlOrigin: String) -> [SecurityWarning] {
//Only these headers key might require full byte-level parsing due to potential size or structural complexity.
//All others can be handled via string-level analysis.
        
//        if let csp = headers["content-security-policy"] {
//            let babylonCSP = Data(csp.utf8)
//
//        }
        var warnings: [SecurityWarning] = []
        var directiveSlices: [Range<Int>] = []
        var directiveValues: [[Data: [Data]]] = []
        var structuredCSP: [String: [Data: CSPValueType]] = [:]
        
        
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
            return warnings
        }
        
//        let babylonPermissionsPolicy = headers["permissions-policy"]?.data(using: .utf8) ?? Data()
        
//        let babylonCSPSize = babylonCSP.count
        if babylonCSP.last != 0x3B {
            babylonCSP.append(0x3B)
            // Flag incomplete CSP as a soft misconfiguration
            warnings.append(SecurityWarning(
                message: "CSP does not end with semicolon — likely malformed or incomplete.",
                severity: .suspicious,
                penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                url: urlOrigin,
                source: .header,
                bitFlags: [.HEADERS_CSP_MALFORMED]
            ))
        }
        // Extract ranges for each directive block (split by semicolon)
        var lastStart = 0
        for i in 0..<babylonCSP.count {
            if babylonCSP[i] == HeadHeaderByteSignatures.semicolon {
                directiveSlices.append(lastStart..<i)
                lastStart = i + 1
            }
        }
        
        
        
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

                // Flag if the directive already exists (duplicate)
                if structuredCSP[directiveName] != nil {
                    warnings.append(SecurityWarning(
                        message: "Duplicate CSP directive '\(directiveName)' detected.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                        url: urlOrigin,
                        source: .header,
                        bitFlags: [.HEADERS_CSP_MALFORMED]
                    ))
                }
                
                var typedValues: [Data: CSPValueType] = [:]
                for value in valueList {
                    let valueType = CSPUtils.classifyCSPValue(value)
                    typedValues[value] = valueType
                }
                
                structuredCSP[directiveName] = typedValues
            }
        }
        
        
        
        
//        DEBUG
        for (directive, values) in structuredCSP {
            print("🌐 Directive: \(directive)")
            for (value, type) in values {
                let valStr = String(data: value, encoding: .utf8) ?? "(unknown)"
                print("  ├─ \(valStr) → \(type)")
            }
        }
        

        

        // Future: Convert each header to Data, scan for delimiters, collect ranges

        return []
    }
}
