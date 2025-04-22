////
////  DeepScamHellCheck.swift
////  LegitURL
////
////  Created by Chief Hakka on 13/03/2025.
////
//
//import Foundation
//
//struct DeepScamHellCheck {
//    static func analyze(queryOrFragment: String, isFragment: Bool, urlOrigin: String) -> [SecurityWarning] {
//        var warnings: [SecurityWarning] = []
//        
//        let componentType = isFragment ? "Fragment" : "Query"
//
//        // Check for excessive slashes (excluding encoded ones)
//        if queryOrFragment.contains("/") {
//            let parts = queryOrFragment.split(separator: "/")
//
//            if !queryOrFragment.contains("=") && parts.count > 2 {
//                warnings.append(SecurityWarning(
//                    message: "\(componentType) contains multiple `/` but lacks structured key-value pairs. This may be an obfuscation trick used by scammers.",
//                    severity: .critical,
//                    url: urlOrigin,
//                    source: .offlineAnalysis
//                ))
//            }
//
//            // Flag known scam-like URL structures (e.g., `cl/129448_md/55/...`)
//            if queryOrFragment.range(of: #"cl/\d+_md/\d+/.+"#, options: .regularExpression) != nil {
//                warnings.append(SecurityWarning(
//                    message: "\(componentType) follows a known scam pattern (`cl/xyz/md/...`). This is commonly used for deceptive tracking and redirection.",
//                    severity: .critical,
//                    url: urlOrigin,
//                    source: .offlineAnalysis
//                ))
//            }
//        }
//
//        // Check for excessive special characters (possible encoding tricks)
//        let specialChars = CharacterSet(charactersIn: "*$^!<>|\\")
//        if queryOrFragment.rangeOfCharacter(from: specialChars) != nil {
//            warnings.append(SecurityWarning(
//                message: "\(componentType) contains unusual special characters. These are often used in phishing or encoded payloads.",
//                severity: .critical,
//                url: urlOrigin,
//                source: .offlineAnalysis
//            ))
//        }
//
//        // Check if the component is unusually long (possible encoding payload)
//        if queryOrFragment.count > 100 {
//            warnings.append(SecurityWarning(
//                message: "\(componentType) is unusually long, which may indicate an encoded payload or tracking injection.",
//                severity: .critical,
//                url: urlOrigin,
//                source: .offlineAnalysis
//            ))
//        }
//
//        return warnings
//    }
//}
