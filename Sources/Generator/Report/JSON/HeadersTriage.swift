//
//  HeadersTriage.swift
//  LegitURL
//
//  Created by Chief Hakka on 03/06/2025.
//
import Foundation
struct HeadersTriage {
    public static func triage(_ headers: [String: String], csp: ClassifiedCSPResult?) -> [String: Any] {
        var structuredheader = [String: Any]()

        for (key, value) in headers {
            if key.lowercased() == "set-cookie" {
                continue
            }
            if (key.lowercased() == "content-security-policy" || key == "content-security-policy-report-only"), let csp = csp {
                // flatten to strict key-value
                var cspFlat: [String: [String]] = [:]
                for (directive, values) in csp.structuredCSP {
                    var stringValues: [String] = []
                    for (key, _) in values {
                        if let decoded = String(data: key, encoding: .utf8) {
                            stringValues.append(decoded)
                        }
                    }
                    cspFlat[directive] = stringValues
                }
                if key == "content-security-policy-report-only" {
                    structuredheader["content_security_policy_report_only"] = cspFlat
                } else {
                    structuredheader["content_security_policy"] = cspFlat
                }
                continue
            } else {
                let snakeCaseKey = convertToSnakeCase(key)
                structuredheader[snakeCaseKey] = value
            }
        }

        return structuredheader
    }
}

func convertToSnakeCase(_ key: String) -> String {
    let delimiters = CharacterSet(charactersIn: "-")
    let parts = key.lowercased().components(separatedBy: delimiters)
    return parts.joined(separator: "_")
}
