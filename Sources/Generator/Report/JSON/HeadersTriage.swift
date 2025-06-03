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
            if (key.lowercased() == "content-security-policy" || key == "content-security-Policy-report-only"), let csp = csp {
                
                //flatten to strict key value
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
                structuredheader["contentSecurityPolicy"] = cspFlat
                continue
            } else {
                let camelCaseKey = convertToCamelCase(key)
                structuredheader[camelCaseKey] = value
            }
        }

        return structuredheader
    }
}

func convertToCamelCase(_ key: String) -> String {
    let delimiters = CharacterSet(charactersIn: "-_")
    let parts = key.lowercased().components(separatedBy: delimiters)
    guard let first = parts.first else { return key }

    let capitalizedRest = parts.dropFirst().map { $0.capitalized }
    return ([first] + capitalizedRest).joined()
}
