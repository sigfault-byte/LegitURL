//
//  CSPExtractor.swift
//  LegitURL
//
//  Created by Chief Hakka on 05/05/2025.
//
import Foundation

struct CSPExtractor {
    static func extract(from raw: Data, url: String) -> (structured: [String: [Data: CSPValueType]], warnings: [SecurityWarning]) {
        var raw = raw
        var warnings: [SecurityWarning] = []
        var directiveSlices: [Range<Int>] = []
        var directiveValues: [[Data: [Data]]] = []
        var structuredCSP: [String: [Data: CSPValueType]] = [:]

        if raw.last != 0x3B {
            raw.append(0x3B)
        }

        //white space is fully cleaned after splitting
        var lastStart = 0
        for i in 0..<raw.count {
            if raw[i] == HeaderByteSignatures.semicolon {
                directiveSlices.append(lastStart..<i)
                lastStart = i + 1
            }
        }

        for slice in directiveSlices {
            let cleanedSlice = CSPUtils.cleaningCSPSlice(slice: slice, in: raw)

            if let parsedDirective = CSPUtils.parseDirectiveSlice(cleanedSlice) {
                directiveValues.append(parsedDirective)
            } else {
                warnings.append(SecurityWarning(
                    message: "Failed to parse CSP directive.",
                    severity: .suspicious,
                    penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                    url: url,
                    source: .header,
                    bitFlags: [.HEADERS_CSP_MALFORMED]
                ))
            }
        }

        var directiveCount: [String: Int] = [:]

        for slice in directiveValues {
            for (directiveNameData, valueList) in slice {
                guard let directiveName = String(data: directiveNameData, encoding: .utf8) else {
                    warnings.append(SecurityWarning(
                        message: "Unrecognized CSP directive encoding.",
                        severity: .suspicious,
                        penalty: PenaltySystem.Penalty.malformedIncompleteCSP,
                        url: url,
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
                            url: url,
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

        return (structured: structuredCSP, warnings: warnings)
    }
}
